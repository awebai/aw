package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var idCmd = &cobra.Command{
	Use:   "id",
	Short: "Identity and key management commands",
}

var idRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the identity signing key",
	Long:  "Generate a new Ed25519 keypair, sign the rotation with the old key, and update the server and local config.",
	RunE:  runDidRotateKey,
}

var idLogCmd = &cobra.Command{
	Use:   "log [address]",
	Short: "Show an identity log",
	Long:  "Display rotation and status history. Without arguments, shows your own log.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDidLog,
}

var idCreatePermanentCmd = &cobra.Command{
	Use:   "create-permanent",
	Short: "Create a durable self-custodial identity in the current workspace",
	RunE:  runIDCreatePermanent,
}

var rotateKeySelfCustody bool

func init() {
	idCreatePermanentCmd.Flags().StringVar(&initAlias, "alias", "", "Permanent identity address name or routing alias")
	idCreatePermanentCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	idCreatePermanentCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	idCreatePermanentCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	idCreatePermanentCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	idCreatePermanentCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	idCreatePermanentCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	idCreatePermanentCmd.Flags().StringVar(&initRole, "role", "", "Workspace role (default: AWEB_ROLE or prompt in TTY, fallback: developer)")
	idCmd.AddCommand(idCreatePermanentCmd)
	idRotateKeyCmd.Flags().BoolVar(&rotateKeySelfCustody, "self-custody", false, "Graduate from custodial to self-custody")
	idCmd.AddCommand(idRotateKeyCmd)
	idCmd.AddCommand(idLogCmd)
	rootCmd.AddCommand(idCmd)
}

func runIDCreatePermanent(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, _, err := awconfig.LoadWorktreeContextFromDir(workingDir); err != nil {
		return usageError("aw id create-permanent requires an initialized workspace; run `aw init` or `aw project create` first")
	}
	c, sel, err := resolveAPIKeyOnly()
	if err != nil {
		return err
	}

	projectSlug := strings.TrimSpace(sel.NamespaceSlug)
	if projectSlug == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		project, err := c.GetCurrentProject(ctx)
		if err != nil {
			return err
		}
		projectSlug = strings.TrimSpace(project.Slug)
	}
	if projectSlug == "" {
		return fmt.Errorf("could not determine the current project for permanent identity creation")
	}

	suggestion := fetchInitSuggestion(sel.BaseURL, projectSlug, sel.APIKey)
	suggestedRoles := []string(nil)
	if suggestion != nil {
		suggestedRoles = suggestion.Roles
	}
	role := resolveRole(suggestedRoles, true)

	alias := strings.TrimSpace(initAlias)
	aliasExplicit := alias != ""
	if !aliasExplicit {
		alias = strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
		aliasExplicit = alias != ""
	}
	if !aliasExplicit {
		if suggestion != nil && strings.TrimSpace(suggestion.NamePrefix) != "" {
			alias = strings.TrimSpace(suggestion.NamePrefix)
		} else {
			alias = "alice"
		}
	}
	aliasWasDefaultSuggestion := !aliasExplicit
	if isTTY() && !aliasExplicit {
		value, err := promptString("Permanent identity name", alias)
		if err != nil {
			return err
		}
		aliasWasDefaultSuggestion = value == alias
		alias = strings.TrimSpace(value)
		if alias == "" {
			alias = "alice"
			aliasWasDefaultSuggestion = true
		}
	}

	opts := initOptions{
		Flow:                          flowProjectKey,
		WorkingDir:                    workingDir,
		BaseURL:                       sel.BaseURL,
		ServerName:                    sel.ServerName,
		NamespaceSlug:                 projectSlug,
		Alias:                         alias,
		AliasExplicit:                 aliasExplicit,
		RetrySuggestedAliasOnConflict: aliasWasDefaultSuggestion && !aliasExplicit,
		HumanName:                     resolveHumanName(),
		AgentType:                     resolveAgentType(),
		SaveConfig:                    initSaveConfig,
		SetDefault:                    initSetDefault,
		WriteContext:                  initWriteContext,
		AuthToken:                     sel.APIKey,
		WorkspaceRole:                 role,
		Lifetime:                      awid.LifetimePersistent,
	}

	result, err := executeInit(opts)
	if err != nil {
		return err
	}

	if jsonFlag {
		printJSON(result.Response)
	} else {
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, "Created permanent self-custodial identity")
	}
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + result.ExportBaseURL)
		fmt.Println("export AWEB_API_KEY=" + result.Response.APIKey)
		fmt.Println("export AWEB_PROJECT=" + result.ExportNamespace)
		fmt.Println("export AWEB_AGENT_ID=" + result.Response.AgentID)
		fmt.Println("export AWEB_AGENT_ALIAS=" + result.Response.Alias)
	}
	return nil
}

func runDidRotateKey(cmd *cobra.Command, args []string) error {
	c, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	// Custodial graduation: no local signing key, server signs on behalf.
	if rotateKeySelfCustody {
		if sel.Custody == awid.CustodySelf {
			return fmt.Errorf("identity %q is already self-custodial", sel.AccountName)
		}
		return runCustodialGraduation(sel)
	}

	if sel.SigningKey == "" {
		return usageError("no signing key configured; use --self-custody to graduate from custodial to self-custody")
	}
	if sel.DID == "" {
		return fmt.Errorf("no DID configured for this identity")
	}

	oldPriv := c.SigningKey()
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	oldDID := c.DID()

	// Generate new keypair.
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.RotateKey(ctx, &awid.RotateKeyRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      awid.CustodySelf,
	})
	if err != nil {
		return err
	}

	// Persist locally: archive old key, save new keypair, update config.
	// Config update is last — it is atomic via UpdateGlobalAt, so partial
	// failure before that point leaves the config pointing at the old key.
	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	keysDir := awconfig.KeysDir(configPath)
	address := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)

	if err := awid.ArchiveKey(keysDir, oldDID, oldPub, oldPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to archive old key: %v\n", err)
	}
	if err := awid.SaveKeypair(keysDir, address, newPub, newPriv); err != nil {
		return fmt.Errorf("save new keypair: %w", err)
	}
	keyPath := awid.SigningKeyPath(keysDir, address)
	if err := updateAccountIdentity(sel.AccountName, newDID, awid.CustodySelf, keyPath); err != nil {
		return err
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
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	newDID := awid.ComputeDIDKey(newPub)

	// Use a regular API-key client (no local signing key).
	c, err := aweb.NewWithAPIKey(sel.BaseURL, sel.APIKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// PUT with no rotation_signature — server signs on behalf.
	resp, err := c.RotateKeyCustodial(ctx, &awid.RotateKeyCustodialRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      awid.CustodySelf,
	})
	if err != nil {
		return err
	}

	// Save new keypair.
	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	keysDir := awconfig.KeysDir(configPath)
	address := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
	if err := awid.SaveKeypair(keysDir, address, newPub, newPriv); err != nil {
		return fmt.Errorf("save new keypair: %w", err)
	}

	// Update config.
	keyPath := awid.SigningKeyPath(keysDir, address)
	if err := updateAccountIdentity(sel.AccountName, newDID, awid.CustodySelf, keyPath); err != nil {
		return err
	}

	fmt.Printf("Graduated to self-custody.\n")
	fmt.Printf("  old DID: %s\n", resp.OldDID)
	fmt.Printf("  new DID: %s\n", resp.NewDID)

	return nil
}

func runDidLog(cmd *cobra.Command, args []string) error {
	c, err := resolveClient()
	if err != nil {
		return err
	}

	var address string
	if len(args) > 0 {
		address = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.AgentLog(ctx, address)
	if err != nil {
		return err
	}

	if len(resp.Entries) == 0 {
		fmt.Println("No log entries.")
		return nil
	}

	for _, e := range resp.Entries {
		fmt.Printf("[%s] %s\n", e.Timestamp, e.Operation)
		if e.DID != "" {
			fmt.Printf("  did: %s\n", e.DID)
		}
		if e.OldDID != "" {
			fmt.Printf("  old_did: %s\n", e.OldDID)
		}
		if e.NewDID != "" {
			fmt.Printf("  new_did: %s\n", e.NewDID)
		}
		if e.SignedBy != "" {
			fmt.Printf("  signed_by: %s\n", e.SignedBy)
		}
	}

	return nil
}

// updateAccountIdentity updates DID, custody, and signing key path in the global config.
func updateAccountIdentity(accountName, newDID, custody, signingKeyPath string) error {
	configPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	return awconfig.UpdateGlobalAt(configPath, func(cfg *awconfig.GlobalConfig) error {
		acct := cfg.Accounts[accountName]
		acct.DID = newDID
		acct.Custody = custody
		acct.SigningKey = signingKeyPath
		cfg.Accounts[accountName] = acct
		return nil
	})
}
