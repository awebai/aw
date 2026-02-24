package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	registerServer       string
	registerEmail        string
	registerUsername     string
	registerAlias        string
	registerHumanName    string
	registerNamespace    string
	registerCode         string
	registerSaveConfig   bool
	registerSetDefault   bool
	registerWriteContext bool
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new account on an aweb server",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for register — no credentials yet.
	},
	RunE: runRegister,
}

func init() {
	registerCmd.Flags().StringVar(&registerServer, "server-url", "", "Base URL for the aweb server (required)")
	registerCmd.Flags().StringVar(&registerEmail, "email", "", "Email address for the new account (required)")
	registerCmd.Flags().StringVar(&registerUsername, "username", "", "Username for the new account (required)")
	registerCmd.Flags().StringVar(&registerAlias, "alias", "", "Agent alias (required)")
	registerCmd.Flags().StringVar(&registerHumanName, "human-name", "", "Human name (optional)")
	registerCmd.Flags().StringVar(&registerNamespace, "namespace", "", "Target namespace for existing accounts (requires verification)")
	registerCmd.Flags().StringVar(&registerCode, "code", "", "Verification code (skips Register call; for existing accounts)")
	registerCmd.Flags().BoolVar(&registerSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	registerCmd.Flags().BoolVar(&registerSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	registerCmd.Flags().BoolVar(&registerWriteContext, "write-context", true, "Write/update .aw/context in the current worktree (non-secret pointer)")

	rootCmd.AddCommand(registerCmd)
}

func runRegister(cmd *cobra.Command, args []string) error {
	serverURL := strings.TrimSpace(registerServer)
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Missing server URL (use --server-url)")
		os.Exit(2)
	}

	baseURL, err := resolveWorkingBaseURL(serverURL)
	if err != nil {
		fatal(err)
	}

	serverName, _ := awconfig.DeriveServerNameFromURL(baseURL)

	email := strings.TrimSpace(registerEmail)
	if email == "" {
		fmt.Fprintln(os.Stderr, "Missing email (use --email)")
		os.Exit(2)
	}
	if at := strings.Index(email, "@"); at < 1 || at >= len(email)-1 {
		fmt.Fprintln(os.Stderr, "Invalid email address")
		os.Exit(2)
	}

	username := strings.TrimSpace(registerUsername)
	if username == "" {
		fmt.Fprintln(os.Stderr, "Missing username (use --username)")
		os.Exit(2)
	}

	alias := strings.TrimSpace(registerAlias)
	if alias == "" {
		fmt.Fprintln(os.Stderr, "Missing alias (use --alias)")
		os.Exit(2)
	}

	// When --code is provided, skip the Register call (which would send a
	// new verification code, invalidating the one the user already has) and
	// go straight to VerifyCode with bootstrap fields.
	code := strings.TrimSpace(registerCode)
	if code != "" {
		return runRegisterWithCode(baseURL, serverName, email, username, alias, code)
	}

	// Generate Ed25519 keypair and compute DID for self-custodial registration.
	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	did := aweb.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	req := &aweb.RegisterRequest{
		Email:     email,
		Username:  &username,
		Handle:    &username,
		Alias:     &alias,
		HumanName: strings.TrimSpace(registerHumanName),
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   aweb.CustodySelf,
		Lifetime:  aweb.LifetimePersistent,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	resp, err := client.Register(ctx, req)
	if err != nil {
		// Check for existing-account 409 before other error handling.
		if existing := aweb.ParseExistingAccount(err); existing != nil {
			return handleExistingAccount(ctx, client, existing, baseURL, serverName, email, alias, pub, priv, did)
		}

		code, isHTTP := aweb.HTTPStatusCode(err)
		if !isHTTP {
			fatal(err)
		}
		switch code {
		case 404:
			fatal(fmt.Errorf("this server does not support CLI registration. Visit %s to create an account", serverURL))
		case 409:
			body, _ := aweb.HTTPErrorBody(err)
			fatal(formatConflictError(body))
		case 429:
			fatal(fmt.Errorf("rate limited. Please try again later"))
		default:
			fatal(err)
		}
	}

	if strings.TrimSpace(registerNamespace) != "" {
		fmt.Fprintln(os.Stderr, "Note: --namespace is ignored for new accounts. Your first namespace is your handle.")
	}

	saveNewRegistration(ctx, resp, baseURL, serverName, email, username, alias, pub, priv, did, client)

	return nil
}

// saveNewRegistration persists credentials from a successful new-user registration.
func saveNewRegistration(
	ctx context.Context,
	resp *aweb.RegisterResponse,
	baseURL, serverName, email, username, alias string,
	pub, priv []byte,
	did string,
	client *aweb.Client,
) {
	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(resp.ProjectSlug)
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, namespaceSlug, resp.Alias)
	}

	address := deriveAgentAddress(resp.NamespaceSlug, resp.ProjectSlug, resp.Alias)
	cfgPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(cfgPath)
	signingKeyPath := awconfig.SigningKeyPath(keysDir, address)

	// Best-effort ClawDID registration. Only persist StableID on success.
	handle := "@" + username
	stableID := registerClawDIDWithHandle(ctx, resolveClawDIDRegistryURL(cfgPath), pub, priv, did, canonicalOrigin(baseURL), address, &handle)

	if registerSaveConfig {
		updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Servers == nil {
				cfg.Servers = map[string]awconfig.Server{}
			}
			if cfg.Accounts == nil {
				cfg.Accounts = map[string]awconfig.Account{}
			}
			if _, ok := cfg.Servers[serverName]; !ok || strings.TrimSpace(cfg.Servers[serverName].URL) == "" {
				cfg.Servers[serverName] = awconfig.Server{URL: baseURL}
			}
			cfg.Accounts[accountName] = awconfig.Account{
				Server:        serverName,
				APIKey:        resp.APIKey,
				AgentID:       resp.AgentID,
				AgentAlias:    resp.Alias,
				Email:         resp.Email,
				NamespaceSlug: namespaceSlug,
				DID:           resp.DID,
				StableID:      stableID,
				SigningKey:     signingKeyPath,
				Custody:       resp.Custody,
				Lifetime:      resp.Lifetime,
			}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || registerSetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		})
		if updateErr != nil {
			fatal(updateErr)
		}
	}

	// Save keypair after config is written so a failed config update
	// does not leave orphaned key files on disk.
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		fatal(err)
	}

	if registerWriteContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			fatal(err)
		}
	}

	printJSON(resp)

	if resp.VerificationRequired {
		fmt.Fprintf(os.Stderr, "\nA verification code was sent to %s.\n", email)
		if isTTY() {
			fmt.Fprint(os.Stderr, "Enter the 6-digit code to activate your agent (or press Enter to skip): ")
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" {
				vctx, vcancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer vcancel()
				vresp, verr := client.VerifyCode(vctx, &aweb.VerifyCodeRequest{
					Email: email,
					Code:  line,
				})
				if verr != nil {
					fmt.Fprintf(os.Stderr, "Verification failed: %v\nRun 'aw verify --code CODE' to try again.\n", verr)
				} else if vresp.Verified {
					fmt.Fprintln(os.Stderr, "Verified! Your agent is now active.")
				}
			} else {
				fmt.Fprintln(os.Stderr, "Run 'aw verify --code CODE' when you have the code.")
			}
		} else {
			fmt.Fprintln(os.Stderr, "Run 'aw verify --code CODE' to activate your agent.")
		}
	}
}

// runRegisterWithCode handles the case where --code is provided: skip the
// Register API call (which would invalidate the code) and go straight to
// VerifyCode with bootstrap fields.
func runRegisterWithCode(baseURL, serverName, email, username, alias, code string) error {
	nsSlug := strings.TrimSpace(registerNamespace)

	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	did := aweb.ComputeDIDKey(pub)

	client, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	var handlePtr *string
	if username != "" {
		h := "@" + username
		handlePtr = &h
	}

	return verifyAndBootstrap(client, baseURL, serverName, email, alias, nsSlug, code, pub, priv, did, handlePtr, nil)
}

// handleExistingAccount handles the 409 existing_account flow: prompt for
// verification code, then call verify-code with alias + namespace_slug to
// bootstrap the agent inline.
func handleExistingAccount(
	_ context.Context,
	client *aweb.Client,
	existing *aweb.ExistingAccountInfo,
	baseURL, serverName, email, alias string,
	pub, priv []byte,
	did string,
) error {
	fmt.Fprintf(os.Stderr, "Account already exists for %s.\n", email)
	fmt.Fprintf(os.Stderr, "A verification code has been sent to confirm your identity.\n")

	// Resolve target namespace.
	nsSlug := strings.TrimSpace(registerNamespace)
	if nsSlug == "" {
		if len(existing.Namespaces) == 1 {
			nsSlug = existing.Namespaces[0].Slug
			fmt.Fprintf(os.Stderr, "Using namespace: %s\n", nsSlug)
		} else if len(existing.Namespaces) > 1 && isTTY() {
			nsSlug = promptNamespaceChoice(existing.Namespaces)
		} else if len(existing.Namespaces) > 1 {
			fmt.Fprintln(os.Stderr, "Multiple namespaces available. Use --namespace to select one:")
			for _, ns := range existing.Namespaces {
				fmt.Fprintf(os.Stderr, "  %s (%s)\n", ns.Slug, ns.Tier)
			}
			os.Exit(2)
		} else {
			fmt.Fprintln(os.Stderr, "No namespaces available for this account.")
			os.Exit(2)
		}
	}

	// Read verification code from stdin.
	if isTTY() {
		fmt.Fprint(os.Stderr, "Enter the 6-digit code: ")
	}
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	code := strings.TrimSpace(line)
	if code == "" {
		if !isTTY() {
			msg := "No code entered. A verification code was sent by email.\n" +
				"To complete registration non-interactively, re-run with --code:\n" +
				fmt.Sprintf("  aw register --server-url %s --email %s --username %s --alias %s --namespace %s --code CODE\n",
					baseURL, email, registerUsername, alias, nsSlug)
			fmt.Fprint(os.Stderr, msg)
			return nil
		}
		fmt.Fprintln(os.Stderr, "No code entered.")
		os.Exit(2)
	}

	var handlePtr *string
	if existing.Handle != "" {
		h := "@" + existing.Handle
		handlePtr = &h
	}

	return verifyAndBootstrap(client, baseURL, serverName, email, alias, nsSlug, code, pub, priv, did, handlePtr, existing.Namespaces)
}

// verifyAndBootstrap calls VerifyCode, claims self-custody identity, and
// persists config + keypair. Shared by handleExistingAccount and
// runRegisterWithCode.
func verifyAndBootstrap(
	client *aweb.Client,
	baseURL, serverName, email, alias, nsSlug, code string,
	pub, priv []byte,
	did string,
	handlePtr *string,
	knownNamespaces []aweb.Namespace,
) error {
	vctx, vcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer vcancel()

	vresp, verr := client.VerifyCode(vctx, &aweb.VerifyCodeRequest{
		Email:         email,
		Code:          code,
		Alias:         alias,
		NamespaceSlug: nsSlug,
	})
	if verr != nil {
		vcode, ok := aweb.HTTPStatusCode(verr)
		if ok && vcode == 403 {
			msg := fmt.Sprintf("you don't have access to namespace %q", nsSlug)
			if len(knownNamespaces) > 0 {
				slugs := make([]string, len(knownNamespaces))
				for i, ns := range knownNamespaces {
					slugs[i] = ns.Slug
				}
				msg += fmt.Sprintf("\nYour namespaces: %s", strings.Join(slugs, ", "))
			}
			fmt.Fprintln(os.Stderr, msg)
			os.Exit(1)
		}
		if ok && vcode == 400 {
			body, _ := aweb.HTTPErrorBody(verr)
			fatal(formatVerifyError(body))
		}
		fatal(verr)
	}
	if !vresp.Verified {
		fatal(fmt.Errorf("verification failed"))
	}

	if vresp.APIKey == "" {
		fatal(fmt.Errorf("verification succeeded but no API key returned. The server may not support inline bootstrap — try 'aw init --cloud' instead"))
	}

	namespaceSlug := strings.TrimSpace(vresp.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = nsSlug
	}
	respAlias := strings.TrimSpace(vresp.Alias)
	if respAlias == "" {
		respAlias = alias
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, namespaceSlug, respAlias)
	}

	address := deriveAgentAddress(namespaceSlug, "", respAlias)
	cfgPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(cfgPath)

	// Claim self-custody identity using the new API key.
	authClient, authErr := aweb.NewWithAPIKey(baseURL, vresp.APIKey)
	if authErr != nil {
		fatal(authErr)
	}
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)
	claimCtx, claimCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer claimCancel()
	_, claimErr := authClient.ClaimIdentity(claimCtx, &aweb.ClaimIdentityRequest{
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   aweb.CustodySelf,
		Lifetime:  aweb.LifetimePersistent,
	})
	signingKeyPath := awconfig.SigningKeyPath(keysDir, address)
	if claimErr != nil {
		claimCode, ok := aweb.HTTPStatusCode(claimErr)
		if ok && claimCode == 409 {
			recoveredDID, recoveredKeyPath, _, _ := recoverIdentity409(claimCtx, authClient, keysDir, address)
			did = recoveredDID
			signingKeyPath = recoveredKeyPath
		} else {
			fatal(fmt.Errorf("identity claim failed: %w", claimErr))
		}
	}

	// Best-effort ClawDID registration.
	stableID := registerClawDIDWithHandle(vctx, resolveClawDIDRegistryURL(cfgPath), pub, priv, did, canonicalOrigin(baseURL), address, handlePtr)

	if registerSaveConfig {
		updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Servers == nil {
				cfg.Servers = map[string]awconfig.Server{}
			}
			if cfg.Accounts == nil {
				cfg.Accounts = map[string]awconfig.Account{}
			}
			if _, ok := cfg.Servers[serverName]; !ok || strings.TrimSpace(cfg.Servers[serverName].URL) == "" {
				cfg.Servers[serverName] = awconfig.Server{URL: baseURL}
			}
			cfg.Accounts[accountName] = awconfig.Account{
				Server:        serverName,
				APIKey:        vresp.APIKey,
				AgentID:       vresp.AgentID,
				AgentAlias:    respAlias,
				Email:         email,
				NamespaceSlug: namespaceSlug,
				DID:           did,
				StableID:      stableID,
				SigningKey:     signingKeyPath,
				Custody:       aweb.CustodySelf,
				Lifetime:      aweb.LifetimePersistent,
			}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || registerSetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		})
		if updateErr != nil {
			fatal(updateErr)
		}
	}

	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		fatal(err)
	}

	if registerWriteContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			fatal(err)
		}
	}

	printJSON(vresp)
	fmt.Fprintf(os.Stderr, "Verified! Agent %s/%s is now active.\n", namespaceSlug, respAlias)

	return nil
}

// promptNamespaceChoice displays a numbered list and prompts for selection.
func promptNamespaceChoice(namespaces []aweb.Namespace) string {
	fmt.Fprintln(os.Stderr, "Available namespaces:")
	for i, ns := range namespaces {
		fmt.Fprintf(os.Stderr, "  [%d] %s (%s)\n", i+1, ns.Slug, ns.Tier)
	}
	fmt.Fprint(os.Stderr, "Select namespace [1]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return namespaces[0].Slug
	}
	idx := 0
	if _, err := fmt.Sscanf(line, "%d", &idx); err != nil || idx < 1 || idx > len(namespaces) {
		fmt.Fprintf(os.Stderr, "Invalid selection. Use --namespace to specify, or try again.\n")
		os.Exit(2)
	}
	return namespaces[idx-1].Slug
}

// formatConflictError parses structured 409 error bodies from the server.
// Expected format: {"error": {"code": "USERNAME_TAKEN", "message": "...", "details": {...}}}
func formatConflictError(body string) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details struct {
				AttemptedUsername string `json:"attempted_username"`
				AttemptedAlias   string `json:"attempted_alias"`
				Source           string `json:"source"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err == nil && envelope.Error.Code != "" {
		switch envelope.Error.Code {
		case "USERNAME_TAKEN":
			name := envelope.Error.Details.AttemptedUsername
			return fmt.Errorf("username %q is already taken; use --username to choose a different one", name)
		case "ALIAS_TAKEN":
			name := envelope.Error.Details.AttemptedAlias
			return fmt.Errorf("alias %q is already taken; use --alias to choose a different one", name)
		default:
			if envelope.Error.Message != "" {
				return fmt.Errorf("%s", envelope.Error.Message)
			}
		}
	}
	// Fall back to generic message for unstructured errors.
	if strings.TrimSpace(body) != "" {
		return fmt.Errorf("registration failed: %s", body)
	}
	return fmt.Errorf("registration failed (conflict)")
}
