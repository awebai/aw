package main

import (
	"context"
	"encoding/base64"
	"errors"
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
	resetRemote   bool
	resetConfirm  bool
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
		return err
	}

	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No .aw/context found in current directory tree.")
		return nil
	}

	if err := os.Remove(ctxPath); err != nil {
		return err
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
		return usageError("remote reset requires --confirm to prevent accidental identity resets; usage: aw reset --remote --confirm")
	}

	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	cfg, cfgErr := awconfig.LoadGlobalFrom(cfgPath)
	if cfgErr != nil {
		return cfgErr
	}
	keysDir := awconfig.KeysDir(cfgPath)

	wd, _ := os.Getwd()
	sel, selErr := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       accountFlag,
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if selErr != nil {
		return selErr
	}

	baseURL := strings.TrimSpace(sel.BaseURL)
	apiKey := strings.TrimSpace(sel.APIKey)
	if baseURL == "" {
		return usageError("missing server URL; set AWEB_URL (or configure a server in aw config)")
	}
	if apiKey == "" {
		return usageError("missing API key; set AWEB_API_KEY (or configure an account in aw config)")
	}

	baseURL, err = resolveWorkingBaseURL(baseURL)
	if err != nil {
		return err
	}
	sel.BaseURL = baseURL

	client, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		return err
	}

	serverName, err := awconfig.DeriveServerNameFromURL(baseURL)
	if err != nil {
		return err
	}

	// Generate and persist the new keypair BEFORE touching the server.
	// If the server reset succeeds but disk write failed, the agent would
	// be bricked. A stale key file on disk is harmless.
	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		return err
	}

	did := aweb.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	intro, err := client.Introspect(ctx)
	if err != nil {
		return err
	}
	agentID := strings.TrimSpace(intro.AgentID)
	alias := strings.TrimSpace(intro.Alias)
	if agentID == "" || alias == "" {
		return fmt.Errorf("server did not return agent identity for this API key (agent_id=%q alias=%q)", agentID, alias)
	}

	accountName := strings.TrimSpace(sel.AccountName)
	var existingSigningKey string
	if accountName == "" {
		for name, acct := range cfg.Accounts {
			if strings.TrimSpace(acct.AgentID) == agentID && strings.TrimSpace(acct.Server) == serverName {
				accountName = name
				existingSigningKey = strings.TrimSpace(acct.SigningKey)
				break
			}
		}
	}
	if accountName == "" {
		accountName = "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(agentID)
	}

	// Namespace slug is required for stable key file naming.
	namespaceSlug := strings.TrimSpace(sel.NamespaceSlug)
	if namespaceSlug == "" {
		proj, err := client.GetCurrentProject(ctx)
		if err != nil {
			return fmt.Errorf("failed to resolve namespace slug (GET /v1/projects/current): %w", err)
		}
		namespaceSlug = strings.TrimSpace(proj.Slug)
	}
	if namespaceSlug == "" {
		return errors.New("could not derive namespace slug for identity reset (empty project slug)")
	}

	address := deriveAgentAddress(namespaceSlug, sel.DefaultProject, alias)
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		return err
	}
	signingKeyPath := awconfig.SigningKeyPath(keysDir, address)

	// Clear the server identity.
	_, err = client.ResetIdentity(ctx, &aweb.ResetIdentityRequest{Confirm: true})
	if err != nil {
		return fmt.Errorf("server identity reset failed: %w", err)
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
		return fmt.Errorf("identity re-claim failed (key saved at %s, retry with 'aw connect'): %w", signingKeyPath, err)
	}
	fmt.Fprintf(os.Stderr, "Identity claimed: %s\n", did)

	// Optionally wipe old key files (after successful claim).
	oldSigningKey := strings.TrimSpace(sel.SigningKey)
	if oldSigningKey == "" {
		oldSigningKey = existingSigningKey
	}
	if resetWipeKeys && oldSigningKey != "" && oldSigningKey != signingKeyPath {
		if err := os.Remove(oldSigningKey); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove old key: %v\n", err)
		}
		pubPath := strings.TrimSuffix(oldSigningKey, ".key") + ".pub"
		os.Remove(pubPath)
	}

	// Best-effort ClawDID registration.
	serverOrigin := canonicalOrigin(baseURL)
	stableID := registerClawDIDWithHandle(
		ctx, resolveClawDIDRegistryURL(cfgPath),
		pub, priv, did, serverOrigin, address, nil,
	)

	// Update config. Always clear old stable ID since the old identity
	// is gone; only set the new one if ClawDID registration succeeded.
	updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
		if cfg.Servers == nil {
			cfg.Servers = map[string]awconfig.Server{}
		}
		if cfg.Accounts == nil {
			cfg.Accounts = map[string]awconfig.Account{}
		}
		cfg.Servers[serverName] = awconfig.Server{URL: baseURL}

		acct := cfg.Accounts[accountName]
		acct.Server = serverName
		acct.APIKey = apiKey
		acct.AgentID = agentID
		acct.AgentAlias = alias
		acct.NamespaceSlug = namespaceSlug
		acct.DID = did
		acct.SigningKey = signingKeyPath
		acct.Custody = "self"
		acct.Lifetime = "persistent"
		acct.StableID = stableID
		cfg.Accounts[accountName] = acct
		if strings.TrimSpace(cfg.DefaultAccount) == "" {
			cfg.DefaultAccount = accountName
		}
		return nil
	})
	if updateErr != nil {
		return updateErr
	}

	fmt.Fprintf(os.Stderr, "Config updated: %s\n", cfgPath)
	if stableID != "" {
		fmt.Fprintf(os.Stderr, "Stable ID: %s\n", stableID)
	}
	if err := writeOrUpdateContext(serverName, accountName); err != nil {
		// Non-fatal: context file is a convenience.
		fmt.Fprintf(os.Stderr, "Warning: failed to write .aw/context: %v\n", err)
	}
	return nil
}
