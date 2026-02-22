package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var didCmd = &cobra.Command{
	Use:   "did",
	Short: "DID and key management commands",
}

var didRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the agent's signing key",
	Long:  "Generate a new Ed25519 keypair, sign the rotation with the old key, and update the server and local config.",
	RunE:  runDidRotateKey,
}

var rotateKeySelfCustody bool

func init() {
	didRotateKeyCmd.Flags().BoolVar(&rotateKeySelfCustody, "self-custody", false, "Graduate from custodial to self-custody")
	didCmd.AddCommand(didRotateKeyCmd)
	rootCmd.AddCommand(didCmd)
}

func runDidRotateKey(cmd *cobra.Command, args []string) error {
	_, sel := mustResolve()

	// Custodial graduation: no local signing key, server signs on behalf.
	if rotateKeySelfCustody {
		if sel.Custody == aweb.CustodySelf {
			fatal(fmt.Errorf("account %q is already self-custody", sel.AccountName))
		}
		return runCustodialGraduation(sel)
	}

	// Load the current signing key.
	if sel.SigningKey == "" {
		fmt.Fprintln(os.Stderr, "No signing key configured. Use --self-custody to graduate from custodial to self-custody.")
		os.Exit(2)
	}

	oldPriv, err := awconfig.LoadSigningKey(sel.SigningKey)
	if err != nil {
		fatal(fmt.Errorf("load signing key: %w", err))
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	oldDID := sel.DID
	if oldDID == "" {
		fatal(fmt.Errorf("no DID configured for this account"))
	}

	// Create an identity client with the old key.
	identityClient, err := aweb.NewWithIdentity(sel.BaseURL, sel.APIKey, oldPriv, oldDID)
	if err != nil {
		fatal(fmt.Errorf("create identity client: %w", err))
	}

	// Generate new keypair.
	newPub, newPriv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	newDID := aweb.ComputeDIDKey(newPub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := identityClient.RotateKey(ctx, &aweb.RotateKeyRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      aweb.CustodySelf,
	})
	if err != nil {
		fatal(err)
	}

	// Persist locally: archive old key, save new keypair, update config.
	// Config update is last — it is atomic via UpdateGlobalAt, so partial
	// failure before that point leaves the config pointing at the old key.
	configPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(configPath)
	address := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)

	if err := awconfig.ArchiveKey(keysDir, oldDID, oldPub, oldPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to archive old key: %v\n", err)
	}
	if err := awconfig.SaveKeypair(keysDir, address, newPub, newPriv); err != nil {
		fatal(fmt.Errorf("save new keypair: %w", err))
	}
	keyPath := awconfig.SigningKeyPath(keysDir, address)
	if err := updateAccountIdentity(sel.AccountName, newDID, aweb.CustodySelf, keyPath); err != nil {
		fatal(err)
	}

	fmt.Printf("Key rotated successfully.\n")
	fmt.Printf("  old DID: %s\n", resp.OldDID)
	fmt.Printf("  new DID: %s\n", resp.NewDID)

	return nil
}

// runCustodialGraduation handles the --self-custody path for custodial agents.
// The server holds the old key and signs the rotation on behalf.
func runCustodialGraduation(sel *awconfig.Selection) error {
	// Generate new keypair locally.
	newPub, newPriv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	newDID := aweb.ComputeDIDKey(newPub)

	// Use a regular API-key client (no local signing key).
	c, err := aweb.NewWithAPIKey(sel.BaseURL, sel.APIKey)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// PUT with no rotation_signature — server signs on behalf.
	resp, err := c.RotateKeyCustodial(ctx, &aweb.RotateKeyCustodialRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      aweb.CustodySelf,
	})
	if err != nil {
		fatal(err)
	}

	// Save new keypair.
	configPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(configPath)
	address := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
	if err := awconfig.SaveKeypair(keysDir, address, newPub, newPriv); err != nil {
		fatal(fmt.Errorf("save new keypair: %w", err))
	}

	// Update config.
	keyPath := awconfig.SigningKeyPath(keysDir, address)
	if err := updateAccountIdentity(sel.AccountName, newDID, aweb.CustodySelf, keyPath); err != nil {
		fatal(err)
	}

	fmt.Printf("Graduated to self-custody.\n")
	fmt.Printf("  old DID: %s\n", resp.OldDID)
	fmt.Printf("  new DID: %s\n", resp.NewDID)

	return nil
}

// updateAccountIdentity updates DID, custody, and signing key path in the global config.
func updateAccountIdentity(accountName, newDID, custody, signingKeyPath string) error {
	configPath := mustDefaultGlobalPath()
	return awconfig.UpdateGlobalAt(configPath, func(cfg *awconfig.GlobalConfig) error {
		acct := cfg.Accounts[accountName]
		acct.DID = newDID
		acct.Custody = custody
		acct.SigningKey = signingKeyPath
		cfg.Accounts[accountName] = acct
		return nil
	})
}
