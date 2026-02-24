package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	resetRemote  bool
	resetConfirm bool
	resetWipeKeys bool
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset local or remote agent identity",
	Long: `Without flags, removes the .aw/context file in the current directory.

With --remote --confirm, clears the agent's identity on the server and
re-provisions a fresh keypair + identity claim.`,
	RunE: runReset,
}

func init() {
	resetCmd.Flags().BoolVar(&resetRemote, "remote", false, "Clear server identity and re-provision")
	resetCmd.Flags().BoolVar(&resetConfirm, "confirm", false, "Required for --remote to prevent accidental resets")
	resetCmd.Flags().BoolVar(&resetWipeKeys, "wipe-keys", false, "Also delete local key files for this account")
	rootCmd.AddCommand(resetCmd)
}

func runReset(cmd *cobra.Command, args []string) error {
	if resetRemote {
		return runResetRemote()
	}
	return runResetLocal()
}

// runResetLocal removes the .aw/context file in the current directory.
func runResetLocal() error {
	wd, err := os.Getwd()
	if err != nil {
		fatal(err)
	}

	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No .aw/context found in current directory tree.")
		return nil
	}

	if err := os.Remove(ctxPath); err != nil {
		fatal(err)
	}

	// Remove the .aw directory if it's now empty.
	awDir := filepath.Dir(ctxPath)
	entries, readErr := os.ReadDir(awDir)
	if readErr == nil && len(entries) == 0 {
		os.Remove(awDir)
	}

	fmt.Fprintf(os.Stderr, "Removed %s\n", ctxPath)
	return nil
}

// runResetRemote clears the server identity and re-provisions.
func runResetRemote() error {
	if !resetConfirm {
		fmt.Fprintln(os.Stderr, "Remote reset requires --confirm to prevent accidental identity resets.")
		fmt.Fprintln(os.Stderr, "Usage: aw reset --remote --confirm")
		os.Exit(2)
	}

	client, sel := mustResolveAPIKeyOnly()

	cfgPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(cfgPath)
	address := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)

	// Generate and persist the new keypair BEFORE touching the server.
	// If the server reset succeeds but disk write failed, the agent would
	// be bricked. A stale key file on disk is harmless.
	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		fatal(err)
	}
	signingKeyPath := awconfig.SigningKeyPath(keysDir, address)

	did := aweb.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Clear the server identity.
	_, err = client.ResetIdentity(ctx, &aweb.ResetIdentityRequest{Confirm: true})
	if err != nil {
		fatal(fmt.Errorf("server identity reset failed: %w", err))
	}
	fmt.Fprintln(os.Stderr, "Server identity cleared.")

	// Claim the new identity.
	_, err = client.ClaimIdentity(ctx, &aweb.ClaimIdentityRequest{
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   "self",
		Lifetime:  "persistent",
	})
	if err != nil {
		fatal(fmt.Errorf("identity re-claim failed (key saved at %s, retry with 'aw connect'): %w", signingKeyPath, err))
	}
	fmt.Fprintf(os.Stderr, "Identity claimed: %s\n", did)

	// Optionally wipe old key files (after successful claim).
	if resetWipeKeys && sel.SigningKey != "" && sel.SigningKey != signingKeyPath {
		if err := os.Remove(sel.SigningKey); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove old key: %v\n", err)
		}
		pubPath := strings.TrimSuffix(sel.SigningKey, ".key") + ".pub"
		os.Remove(pubPath)
	}

	// Best-effort ClawDID registration.
	serverOrigin := canonicalOrigin(sel.BaseURL)
	stableID := registerClawDIDWithHandle(
		ctx, resolveClawDIDRegistryURL(cfgPath),
		pub, priv, did, serverOrigin, address, nil,
	)

	// Update config. Always clear old stable ID since the old identity
	// is gone; only set the new one if ClawDID registration succeeded.
	updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
		acct, ok := cfg.Accounts[sel.AccountName]
		if !ok {
			return fmt.Errorf("account %q not found in config", sel.AccountName)
		}
		acct.DID = did
		acct.SigningKey = signingKeyPath
		acct.Custody = "self"
		acct.Lifetime = "persistent"
		acct.StableID = stableID
		cfg.Accounts[sel.AccountName] = acct
		return nil
	})
	if updateErr != nil {
		fatal(updateErr)
	}

	fmt.Fprintf(os.Stderr, "Config updated: %s\n", cfgPath)
	if stableID != "" {
		fmt.Fprintf(os.Stderr, "Stable ID: %s\n", stableID)
	}
	return nil
}
