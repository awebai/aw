package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create and use an agent",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initServerURL       string
	initNamespaceSlug   string
	initNamespaceName   string
	initAlias           string
	initInviteToken     string
	initInjectDocs      bool
	initSetupHooks      bool
	initHumanName       string
	initAgentType       string
	initSaveConfig      bool
	initSetDefault      bool
	initWriteContext    bool
	initPrintExports    bool
	initCloudToken      string
	initCloudMode       bool
	initTargetNamespace string
	initRole            string
)

type initOptions struct {
	WorkingDir                    string
	BaseURL                       string
	ServerName                    string
	NamespaceSlug                 string
	NamespaceName                 string
	Alias                         string
	AliasExplicit                 bool
	RetrySuggestedAliasOnConflict bool
	HumanName                     string
	AgentType                     string
	SaveConfig                    bool
	SetDefault                    bool
	WriteContext                  bool
	CloudMode                     bool
	CloudToken                    string
	TargetNamespace               string
	BootstrapAPIKey               string
	InviteToken                   string
	AccountName                   string
	WorkspaceRole                 string
	Lifetime                      string // "persistent" (default) or "ephemeral"
}

type initResult struct {
	Response        *awid.InitResponse
	AccountName     string
	ServerName      string
	Role            string
	AttachResult    *contextAttachResult
	ExportBaseURL   string
	ExportNamespace string
	JoinedViaInvite bool
}

func init() {
	initCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	initCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	initCmd.Flags().StringVar(&initNamespaceSlug, "namespace", "", "Namespace slug (default: AWEB_NAMESPACE or prompt in TTY)")
	initCmd.Flags().StringVar(&initNamespaceName, "namespace-name", "", "Namespace display name (default: AWEB_NAMESPACE_NAME or namespace slug)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Agent alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initInviteToken, "invite", "", "CLI invite token (aw_inv_...)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Agent type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initCloudToken, "cloud-token", "", "Cloud auth bearer token for hosted aweb-cloud bootstrap (default: AWEB_CLOUD_TOKEN, then AWEB_API_KEY if non-aw_sk_, then existing aw_sk_ keys from config)")
	initCmd.Flags().BoolVar(&initCloudMode, "cloud", false, "Force hosted aweb-cloud bootstrap mode (skip probing /v1/init)")
	initCmd.Flags().StringVar(&initTargetNamespace, "target-namespace", "", "Create agent in a specific namespace (forces cloud mode; requires --alias)")
	initCmd.Flags().StringVar(&initRole, "role", "", "Workspace role (default: AWEB_ROLE or prompt in TTY, fallback: developer)")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	// When only --inject-docs or --setup-hooks are requested, operate on the
	// existing workspace without running the full init/register flow.
	if (initInjectDocs || initSetupHooks) && !initNeedsFullInit() {
		wd, _ := os.Getwd()
		repoRoot := resolveRepoRoot(wd)
		if initInjectDocs {
			printInjectDocsResult(InjectAgentDocs(repoRoot))
		}
		if initSetupHooks {
			hookResult := SetupClaudeHooks(repoRoot, isTTY())
			printClaudeHooksResult(hookResult)
		}
		return nil
	}

	opts, err := collectInitOptions()
	if err != nil {
		return err
	}
	result, err := executeInit(opts)
	if err != nil {
		return err
	}

	if jsonFlag {
		printJSON(result.Response)
	} else {
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.JoinedViaInvite)
	}
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + result.ExportBaseURL)
		fmt.Println("export AWEB_API_KEY=" + result.Response.APIKey)
		fmt.Println("export AWEB_NAMESPACE=" + result.ExportNamespace)
		fmt.Println("export AWEB_AGENT_ID=" + result.Response.AgentID)
		fmt.Println("export AWEB_AGENT_ALIAS=" + result.Response.Alias)
	}
	repoRoot := resolveRepoRoot(opts.WorkingDir)
	if initInjectDocs {
		printInjectDocsResult(InjectAgentDocs(repoRoot))
	}
	if initSetupHooks {
		hookResult := SetupClaudeHooks(repoRoot, isTTY())
		printClaudeHooksResult(hookResult)
	}
	if !jsonFlag {
		printInitNextSteps(initInjectDocs, initSetupHooks)
	}
	return nil
}

// initNeedsFullInit returns true if the user passed flags that require the
// full register flow (server-url, namespace, alias, invite, etc.) or if no
// .aw/context exists yet (first-time init).
func initNeedsFullInit() bool {
	if initServerURL != "" || initNamespaceSlug != "" || initAlias != "" || initInviteToken != "" {
		return true
	}
	wd, _ := os.Getwd()
	_, _, err := awconfig.LoadWorktreeContextFromDir(wd)
	return err != nil
}

func collectInitOptions() (initOptions, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return initOptions{}, err
	}

	targetNamespace := strings.TrimSpace(initTargetNamespace)
	inviteToken := strings.TrimSpace(initInviteToken)
	aliasFromFlag := strings.TrimSpace(initAlias)
	aliasFromEnv := strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
	if inviteToken != "" && !strings.HasPrefix(inviteToken, "aw_inv_") {
		return initOptions{}, usageError("invalid --invite token (expected aw_inv_...)")
	}
	if targetNamespace != "" && aliasFromFlag == "" && aliasFromEnv == "" {
		return initOptions{}, usageError("--target-namespace requires --alias (server cannot auto-assign in a specific namespace)")
	}
	baseURL, serverName, global, err := resolveBaseURLForInit(initServerURL, serverFlag)
	if err != nil {
		return initOptions{}, err
	}

	accountName := strings.TrimSpace(accountFlag)
	cloudMode := initCloudMode || targetNamespace != ""
	explicitCloudToken := strings.TrimSpace(initCloudToken)
	if !cloudMode {
		if explicitCloudToken != "" {
			cloudMode = true
		} else if v := strings.TrimSpace(os.Getenv("AWEB_CLOUD_TOKEN")); v != "" {
			cloudMode = true
		} else if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); v != "" {
			if !strings.HasPrefix(v, "aw_sk_") {
				cloudMode = true
			}
			// aw_sk_ keys are project API keys — they go through the
			// OSS init path as BootstrapAPIKey, not cloud bootstrap.
		}
	}

	nsSlug := strings.TrimSpace(initNamespaceSlug)
	if nsSlug == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_NAMESPACE"))
	}
	if nsSlug == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG"))
	}
	if nsSlug == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT"))
	}
	if inviteToken != "" {
		if targetNamespace != "" || nsSlug != "" || strings.TrimSpace(initNamespaceName) != "" || initCloudMode || strings.TrimSpace(initCloudToken) != "" {
			return initOptions{}, usageError("--invite cannot be combined with namespace/bootstrap flags")
		}
	}

	// Resolve aw_sk_ project key from AWEB_API_KEY early — needed for
	// namespace derivation and alias suggestion.
	bootstrapAPIKey := ""
	if !cloudMode {
		if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); strings.HasPrefix(v, "aw_sk_") {
			bootstrapAPIKey = v
		}
	}

	// When we have a project API key and no namespace, derive it from
	// the key via the authenticated suggestion endpoint.
	if nsSlug == "" && !cloudMode && inviteToken == "" && bootstrapAPIKey != "" {
		suggestion := fetchInitSuggestion(baseURL, "", bootstrapAPIKey)
		if slug := strings.TrimSpace(suggestion.ProjectSlug); slug != "" {
			nsSlug = slug
		}
	}
	if nsSlug == "" && !cloudMode && inviteToken == "" {
		if isTTY() {
			suggested := sanitizeSlug(filepath.Base(workingDir))
			v, err := promptString("Namespace", suggested)
			if err != nil {
				return initOptions{}, err
			}
			nsSlug = v
		} else {
			return initOptions{}, usageError("missing namespace (use --namespace or AWEB_NAMESPACE)")
		}
	}

	nsName := strings.TrimSpace(initNamespaceName)
	if nsName == "" {
		nsName = strings.TrimSpace(os.Getenv("AWEB_NAMESPACE_NAME"))
	}
	if nsName == "" {
		nsName = strings.TrimSpace(os.Getenv("AWEB_PROJECT_NAME"))
	}

	humanName := strings.TrimSpace(initHumanName)
	if humanName == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN"))
	}
	if humanName == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME"))
	}
	if humanName == "" {
		humanName = strings.TrimSpace(os.Getenv("USER"))
	}
	if humanName == "" {
		humanName = "developer"
	}

	agentType := strings.TrimSpace(initAgentType)
	if agentType == "" {
		agentType = strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE"))
	}
	if agentType == "" {
		agentType = "agent"
	}

	alias := aliasFromFlag
	aliasExplicit := alias != ""
	if !aliasExplicit {
		alias = aliasFromEnv
		aliasExplicit = alias != ""
	}

	cloudToken := ""
	if cloudMode {
		cloudToken = resolveCloudToken(baseURL, serverName, accountName, explicitCloudToken, global)
		if !aliasExplicit && strings.HasPrefix(cloudToken, "aw_sk_") && !isTTY() {
			return initOptions{}, usageError("--alias is required when bootstrapping a new agent with an existing API key (non-interactive)")
		}
	}
	if bootstrapAPIKey != "" && !aliasExplicit && !isTTY() {
		return initOptions{}, usageError("--alias is required when bootstrapping a new agent with an existing API key (non-interactive)")
	}

	// Fetch alias suggestion and available roles from the server.
	// Use the project key for auth when available so the server can
	// infer the project and return project-specific suggestions.
	authToken := cloudToken
	if authToken == "" {
		authToken = bootstrapAPIKey
	}
	var suggestedRoles []string
	aliasWasDefaultSuggestion := false
	if !aliasExplicit && inviteToken == "" {
		suggestion := fetchInitSuggestion(baseURL, nsSlug, authToken)
		if strings.TrimSpace(suggestion.NamePrefix) != "" {
			alias = suggestion.NamePrefix
		} else {
			alias = "alice"
		}
		suggestedRoles = suggestion.Roles
		aliasWasDefaultSuggestion = true
	}

	// Resolve role: --role flag > AWEB_ROLE env > TTY prompt > default "developer"
	role := strings.TrimSpace(initRole)
	if role == "" {
		role = strings.TrimSpace(os.Getenv("AWEB_ROLE"))
	}
	if role != "" {
		role = normalizeWorkspaceRole(role)
		if !isValidWorkspaceRole(role) {
			return initOptions{}, usageError("invalid role: use 1-2 words (letters/numbers) with hyphens/underscores allowed; max 50 chars")
		}
	} else if isTTY() && inviteToken == "" && !aliasExplicit {
		defaultRole := "developer"
		if len(suggestedRoles) > 0 {
			defaultRole = suggestedRoles[0]
			fmt.Fprintf(os.Stderr, "Available roles: %s\n", strings.Join(suggestedRoles, ", "))
		}
		v, err := promptString("Role", defaultRole)
		if err != nil {
			return initOptions{}, err
		}
		role = normalizeWorkspaceRole(strings.TrimSpace(v))
		if role == "" {
			role = "developer"
		}
	} else {
		role = "developer"
	}

	if isTTY() && !aliasExplicit && inviteToken == "" {
		v, err := promptString("Agent alias", alias)
		if err != nil {
			return initOptions{}, err
		}
		aliasWasDefaultSuggestion = v == alias
		alias = strings.TrimSpace(v)
		if alias == "" {
			alias = "alice"
			aliasWasDefaultSuggestion = true
		}
	}

	return initOptions{
		WorkingDir:                    workingDir,
		BaseURL:                       baseURL,
		ServerName:                    serverName,
		NamespaceSlug:                 nsSlug,
		NamespaceName:                 nsName,
		Alias:                         alias,
		AliasExplicit:                 aliasExplicit,
		RetrySuggestedAliasOnConflict: aliasWasDefaultSuggestion && !aliasExplicit,
		HumanName:                     humanName,
		AgentType:                     agentType,
		SaveConfig:                    initSaveConfig,
		SetDefault:                    initSetDefault,
		WriteContext:                  initWriteContext,
		CloudMode:                     cloudMode,
		CloudToken:                    cloudToken,
		TargetNamespace:               targetNamespace,
		BootstrapAPIKey:               bootstrapAPIKey,
		InviteToken:                   inviteToken,
		AccountName:                   accountName,
		WorkspaceRole:                 role,
	}, nil
}

// fetchInitSuggestion calls the suggest-alias-prefix endpoint, using an
// authenticated client when a project API key is available (so the server
// can infer the project without a namespace slug).
func fetchInitSuggestion(baseURL, nsSlug, cloudToken string) *awid.SuggestAliasPrefixResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When we have a project key, use it for auth so the server can
	// infer the project and suggest a project-specific alias.
	if strings.HasPrefix(cloudToken, "aw_sk_") && strings.TrimSpace(nsSlug) == "" {
		client, err := aweb.NewWithAPIKey(baseURL, cloudToken)
		if err != nil {
			return &awid.SuggestAliasPrefixResponse{}
		}
		suggestion, err := client.SuggestAliasPrefix(ctx, "")
		if err != nil {
			return &awid.SuggestAliasPrefixResponse{}
		}
		return suggestion
	}

	client, err := aweb.New(baseURL)
	if err != nil {
		return &awid.SuggestAliasPrefixResponse{}
	}
	suggestion, err := client.SuggestAliasPrefix(ctx, nsSlug)
	if err != nil {
		return &awid.SuggestAliasPrefixResponse{}
	}
	return suggestion
}

func executeInit(opts initOptions) (*initResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var bootstrapClient *aweb.Client
	var err error
	if opts.BootstrapAPIKey != "" {
		bootstrapClient, err = aweb.NewWithAPIKey(opts.BaseURL, opts.BootstrapAPIKey)
	} else {
		bootstrapClient, err = aweb.New(opts.BaseURL)
	}
	if err != nil {
		return nil, err
	}

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	did := awid.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	namespaceName := strings.TrimSpace(opts.NamespaceName)
	if namespaceName == "" {
		namespaceName = strings.TrimSpace(opts.NamespaceSlug)
	}

	req := &awid.InitRequest{
		ProjectSlug: opts.NamespaceSlug,
		ProjectName: namespaceName,
		HumanName:   opts.HumanName,
		AgentType:   opts.AgentType,
		DID:         did,
		PublicKey:   pubKeyB64,
		Custody:     awid.CustodySelf,
		Lifetime:    resolveInitLifetime(opts.Lifetime),
	}
	if strings.TrimSpace(opts.Alias) != "" {
		alias := strings.TrimSpace(opts.Alias)
		req.Alias = &alias
	}

	var resp *awid.InitResponse
	if opts.InviteToken != "" {
		resp, err = acceptInviteViaCloud(ctx, opts.BaseURL, opts.InviteToken, opts.Alias, opts.HumanName, opts.AgentType, did, pubKeyB64, resolveInitLifetime(opts.Lifetime))
	} else if opts.CloudMode {
		resp, err = bootstrapViaCloud(ctx, opts.BaseURL, opts.CloudToken, req, opts.TargetNamespace)
	} else if opts.BootstrapAPIKey == "" {
		resp, err = tryHeadlessOrInit(ctx, bootstrapClient, req, opts.BaseURL)
	} else {
		resp, err = bootstrapClient.Init(ctx, req)
	}
	if err != nil {
		return nil, err
	}

	if opts.RetrySuggestedAliasOnConflict && !resp.Created {
		req.Alias = nil
		if opts.CloudMode {
			resp, err = bootstrapViaCloud(ctx, opts.BaseURL, opts.CloudToken, req, opts.TargetNamespace)
		} else {
			resp, err = bootstrapClient.Init(ctx, req)
		}
		if err != nil {
			return nil, err
		}
	}

	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(resp.ProjectSlug)
	}
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(opts.NamespaceSlug)
	}
	if resp.Namespace != "" {
		namespaceSlug = resp.Namespace
	}

	accountName := strings.TrimSpace(opts.AccountName)
	if accountName == "" {
		accountName = deriveAccountName(opts.ServerName, namespaceSlug, resp.Alias)
	}

	address := resp.Address
	if address == "" {
		address = deriveAgentAddress(resp.NamespaceSlug, resp.ProjectSlug, resp.Alias)
	}
	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return nil, err
	}
	keysDir := awconfig.KeysDir(cfgPath)
	signingKeyPath := awid.SigningKeyPath(keysDir, address)
	if err := awid.SaveKeypair(keysDir, address, pub, priv); err != nil {
		return nil, err
	}

	stableID := strings.TrimSpace(resp.StableID)
	if opts.SaveConfig {
		if err := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Servers == nil {
				cfg.Servers = map[string]awconfig.Server{}
			}
			if cfg.Accounts == nil {
				cfg.Accounts = map[string]awconfig.Account{}
			}
			serverURL := opts.BaseURL
			if v := strings.TrimSpace(resp.ServerURL); v != "" {
				serverURL = v
			}
			cfg.Servers[opts.ServerName] = awconfig.Server{URL: serverURL}
			cfg.Accounts[accountName] = awconfig.Account{Account: awid.Account{
				Server:        opts.ServerName,
				APIKey:        resp.APIKey,
				AgentID:       resp.AgentID,
				AgentAlias:    resp.Alias,
				NamespaceSlug: namespaceSlug,
				DID:           resp.DID,
				StableID:      stableID,
				SigningKey:    signingKeyPath,
				Custody:       resp.Custody,
				Lifetime:      resp.Lifetime,
			}}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || opts.SetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if opts.WriteContext {
		if err := writeOrUpdateContextAt(opts.WorkingDir, opts.ServerName, accountName, true); err != nil {
			return nil, err
		}
	}

	var attachResult *contextAttachResult
	if opts.WriteContext {
		attachURL := opts.BaseURL
		if v := strings.TrimSpace(resp.ServerURL); v != "" {
			attachURL = v
		}
		authClient, err := aweb.NewWithAPIKey(attachURL, resp.APIKey)
		if err == nil {
			attachResult, err = autoAttachContext(opts.WorkingDir, authClient, strings.TrimSpace(opts.WorkspaceRole))
			if err != nil {
				debugLog("workspace attach: %v", err)
				fmt.Fprintf(os.Stderr, "Warning: could not attach workspace context (coordination may not be available on this server)\n")
			}
		}
	}

	exportBaseURL := opts.BaseURL
	if v := strings.TrimSpace(resp.ServerURL); v != "" {
		exportBaseURL = v
	}

	return &initResult{
		Response:        resp,
		AccountName:     accountName,
		ServerName:      opts.ServerName,
		Role:            opts.WorkspaceRole,
		AttachResult:    attachResult,
		ExportBaseURL:   exportBaseURL,
		ExportNamespace: namespaceSlug,
		JoinedViaInvite: opts.InviteToken != "",
	}, nil
}

func printInitSummary(resp *awid.InitResponse, accountName, serverName, role string, attachResult *contextAttachResult, joinedViaInvite bool) {
	if resp == nil {
		return
	}
	if joinedViaInvite {
		namespace := strings.TrimSpace(resp.Namespace)
		if namespace == "" {
			namespace = strings.TrimSpace(resp.NamespaceSlug)
		}
		if namespace == "" {
			namespace = strings.TrimSpace(resp.ProjectSlug)
		}
		fmt.Printf("Joined %s as %s\n", namespace, resp.Alias)
	} else {
		fmt.Printf("Initialized agent %s\n", resp.Alias)
	}
	if strings.TrimSpace(resp.NamespaceSlug) != "" {
		fmt.Printf("Namespace:  %s\n", strings.TrimSpace(resp.NamespaceSlug))
	}
	if strings.TrimSpace(role) != "" {
		fmt.Printf("Role:       %s\n", strings.TrimSpace(role))
	}
	if strings.TrimSpace(resp.Address) != "" {
		fmt.Printf("Address:    %s\n", strings.TrimSpace(resp.Address))
	}
	if strings.TrimSpace(serverName) != "" {
		fmt.Printf("Server:     %s\n", strings.TrimSpace(serverName))
	}
	if attachResult != nil {
		switch strings.TrimSpace(attachResult.ContextKind) {
		case "repo_worktree":
			if attachResult.Workspace != nil {
				fmt.Printf("Context:    attached %s\n", strings.TrimSpace(attachResult.Workspace.CanonicalOrigin))
			}
		case "local_dir":
			fmt.Println("Context:    attached local directory")
		}
	}
}

func printInitNextSteps(didInjectDocs, didSetupHooks bool) {
	if didInjectDocs && didSetupHooks {
		return
	}
	fmt.Println()
	fmt.Println("Next steps:")
	if !didInjectDocs {
		fmt.Println("  aw init --inject-docs    Add coordination instructions to CLAUDE.md / AGENTS.md")
	}
	if !didSetupHooks {
		fmt.Println("  aw init --setup-hooks    Set up Claude Code chat notification hook")
	}
}

// tryHeadlessOrInit attempts anonymous headless bootstrap first. If the
// server does not support the endpoint (404), falls back to /v1/init.
// baseURL is the resolved base URL (may end in /api); needed to construct
// a separate client for /api/v1/... endpoints that expect the host root.
func tryHeadlessOrInit(
	ctx context.Context,
	client *aweb.Client,
	initReq *awid.InitRequest,
	baseURL string,
) (*awid.InitResponse, error) {
	alias := ""
	if initReq.Alias != nil {
		alias = *initReq.Alias
	}
	// Headless bootstrap requires alias. Without one, fall back to
	// /v1/init which supports server-allocated aliases. If that also
	// fails (hosted servers may not expose /v1/init), surface an error
	// asking the user to specify --alias explicitly.
	if alias == "" {
		resp, initErr := client.Init(ctx, initReq)
		if initErr == nil {
			return resp, nil
		}
		if code, ok := awid.HTTPStatusCode(initErr); ok && code == 404 {
			return nil, fmt.Errorf("server requires an alias; specify one with --alias")
		}
		return nil, initErr
	}
	headlessReq := &awid.HeadlessBootstrapRequest{
		NamespaceSlug: initReq.ProjectSlug,
		Alias:         alias,
		AgentType:     initReq.AgentType,
		HumanName:     initReq.HumanName,
		DID:           initReq.DID,
		PublicKey:     initReq.PublicKey,
		Custody:       initReq.Custody,
		Lifetime:      initReq.Lifetime,
	}

	// The headless endpoint is at /api/v1/... which is relative to the
	// host root, not to the resolved base URL. Strip any /api suffix
	// to avoid doubling (e.g. host/api + /api/v1/... → host/api/api/...).
	rootURL, err := cloudRootBaseURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL for headless bootstrap: %w", err)
	}
	headlessClient, err := aweb.New(rootURL)
	if err != nil {
		return nil, err
	}

	headlessResp, err := headlessClient.HeadlessBootstrap(ctx, headlessReq)
	if err != nil {
		// If the server doesn't support headless bootstrap, fall back to /v1/init.
		if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
			debugLog("headless bootstrap not supported (404), falling back to /v1/init")
			return client.Init(ctx, initReq)
		}
		return nil, err
	}

	// Convert HeadlessBootstrapResponse to InitResponse for uniform handling.
	return &awid.InitResponse{
		Status:        "ok",
		ProjectID:     headlessResp.ProjectID,
		ProjectSlug:   headlessResp.ProjectSlug,
		AgentID:       headlessResp.AgentID,
		Alias:         headlessResp.Alias,
		APIKey:        headlessResp.APIKey,
		ServerURL:     headlessResp.ServerURL,
		NamespaceSlug: headlessResp.OrgSlug,
		Namespace:     headlessResp.Namespace,
		Address:       headlessResp.Address,
		Created:       headlessResp.Created,
		DID:           headlessResp.DID,
		StableID:      headlessResp.StableID,
		Custody:       headlessResp.Custody,
		Lifetime:      headlessResp.Lifetime,
	}, nil
}

func bootstrapViaCloud(
	ctx context.Context,
	baseURL string,
	token string,
	req *awid.InitRequest,
	namespaceSlug string,
) (*awid.InitResponse, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("hosted Cloud bootstrap requires --cloud-token, AWEB_CLOUD_TOKEN, or an existing aw_sk_ key in config")
	}

	cloudBaseURL, err := cloudRootBaseURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("hosted Cloud bootstrap requires a valid URL: %w", err)
	}

	cloudClient, err := aweb.NewWithAPIKey(cloudBaseURL, token)
	if err != nil {
		return nil, err
	}

	cloudReq := &awid.CloudBootstrapAgentRequest{
		Alias:         req.Alias,
		HumanName:     req.HumanName,
		AgentType:     req.AgentType,
		NamespaceSlug: namespaceSlug,
		DID:           req.DID,
		PublicKey:     req.PublicKey,
		Custody:       req.Custody,
		Lifetime:      req.Lifetime,
	}

	cloudResp, err := cloudClient.CloudBootstrapAgent(ctx, cloudReq)
	if err != nil {
		return nil, fmt.Errorf("cloud bootstrap failed: %w", err)
	}

	if strings.TrimSpace(cloudResp.APIKey) == "" {
		return nil, fmt.Errorf("cloud bootstrap failed: missing api_key in response")
	}

	return &awid.InitResponse{
		Status:        "ok",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		ProjectID:     cloudResp.ProjectID,
		ProjectSlug:   cloudResp.ProjectSlug,
		AgentID:       cloudResp.AgentID,
		Alias:         cloudResp.Alias,
		APIKey:        cloudResp.APIKey,
		NamespaceSlug: cloudResp.OrgSlug,
		Namespace:     cloudResp.Namespace,
		Address:       cloudResp.Address,
		ServerURL:     cloudResp.ServerURL,
		Created:       cloudResp.Created,
		DID:           cloudResp.DID,
		StableID:      cloudResp.StableID,
		Custody:       cloudResp.Custody,
		Lifetime:      cloudResp.Lifetime,
	}, nil
}

func acceptInviteViaCloud(
	ctx context.Context,
	baseURL string,
	token string,
	alias string,
	humanName string,
	agentType string,
	did string,
	publicKey string,
	lifetime string,
) (*awid.InitResponse, error) {
	client, err := newUnauthenticatedCloudClient(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invite accept requires a valid URL: %w", err)
	}
	req := &awid.InviteAcceptRequest{
		Token:     token,
		Alias:     strings.TrimSpace(alias),
		HumanName: humanName,
		AgentType: agentType,
		DID:       did,
		PublicKey: publicKey,
		Custody:   awid.CustodySelf,
		Lifetime:  lifetime,
	}
	resp, err := client.InviteAccept(ctx, req)
	if err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 422 && strings.TrimSpace(alias) == "" {
			if body, ok := awid.HTTPErrorBody(err); ok && strings.Contains(strings.ToLower(body), "alias") {
				return nil, usageError("alias is required (use --alias)")
			}
		}
		return nil, err
	}
	if strings.TrimSpace(resp.APIKey) == "" {
		return nil, fmt.Errorf("invite accept failed: missing api_key in response")
	}
	return &awid.InitResponse{
		Status:        "ok",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		ProjectID:     resp.ProjectID,
		ProjectSlug:   resp.ProjectSlug,
		AgentID:       resp.AgentID,
		Alias:         resp.Alias,
		APIKey:        resp.APIKey,
		ServerURL:     resp.ServerURL,
		NamespaceSlug: resp.OrgSlug,
		Namespace:     resp.Namespace,
		Address:       resp.Address,
		Created:       resp.Created,
		DID:           resp.DID,
		StableID:      resp.StableID,
		Custody:       resp.Custody,
		Lifetime:      resp.Lifetime,
	}, nil
}

func resolveInitLifetime(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	return awid.LifetimePersistent
}

func resolveInitAPIKey(baseURL, serverName, accountName string, global *awconfig.GlobalConfig) string {
	if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); strings.HasPrefix(v, "aw_sk_") {
		return v
	}
	if global == nil {
		return ""
	}

	candidates := make([]string, 0, 4)
	if v := strings.TrimSpace(accountName); v != "" {
		candidates = append(candidates, v)
	}
	for _, name := range sortedAccountNames(global) {
		acct := global.Accounts[name]
		if strings.TrimSpace(serverName) != "" && strings.TrimSpace(acct.Server) == strings.TrimSpace(serverName) {
			candidates = append(candidates, name)
		}
	}
	baseHost := hostFromBaseURL(baseURL)
	if baseHost != "" {
		for _, name := range sortedAccountNames(global) {
			acct := global.Accounts[name]
			srv, ok := global.Servers[strings.TrimSpace(acct.Server)]
			if !ok || strings.TrimSpace(srv.URL) == "" {
				continue
			}
			if hostFromBaseURL(srv.URL) == baseHost {
				candidates = append(candidates, name)
			}
		}
	}
	if v := strings.TrimSpace(global.DefaultAccount); v != "" {
		candidates = append(candidates, v)
	}

	seen := map[string]struct{}{}
	for _, accountName := range candidates {
		if _, dup := seen[accountName]; dup {
			continue
		}
		seen[accountName] = struct{}{}
		acct, ok := global.Accounts[accountName]
		if !ok {
			continue
		}
		if token := strings.TrimSpace(acct.APIKey); strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}

	for _, name := range sortedAccountNames(global) {
		if token := strings.TrimSpace(global.Accounts[name].APIKey); strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}

	return ""
}

func resolveCloudToken(baseURL, serverName, accountName, explicitToken string, global *awconfig.GlobalConfig) string {
	if v := strings.TrimSpace(explicitToken); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_CLOUD_TOKEN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); v != "" {
		return v
	}
	if global == nil {
		return ""
	}

	candidates := make([]string, 0, 4)
	if v := strings.TrimSpace(accountName); v != "" {
		candidates = append(candidates, v)
	}
	for _, name := range sortedAccountNames(global) {
		acct := global.Accounts[name]
		if strings.TrimSpace(serverName) != "" && strings.TrimSpace(acct.Server) == strings.TrimSpace(serverName) {
			candidates = append(candidates, name)
		}
	}
	baseHost := hostFromBaseURL(baseURL)
	if baseHost != "" {
		for _, name := range sortedAccountNames(global) {
			acct := global.Accounts[name]
			srv, ok := global.Servers[strings.TrimSpace(acct.Server)]
			if !ok || strings.TrimSpace(srv.URL) == "" {
				continue
			}
			if hostFromBaseURL(srv.URL) == baseHost {
				candidates = append(candidates, name)
			}
		}
	}
	if v := strings.TrimSpace(global.DefaultAccount); v != "" {
		candidates = append(candidates, v)
	}

	seen := map[string]struct{}{}
	for _, accountName := range candidates {
		if _, ok := seen[accountName]; ok {
			continue
		}
		seen[accountName] = struct{}{}
		acct, ok := global.Accounts[accountName]
		if !ok {
			continue
		}
		token := strings.TrimSpace(acct.APIKey)
		if token != "" && !strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}

	for _, name := range sortedAccountNames(global) {
		token := strings.TrimSpace(global.Accounts[name].APIKey)
		if token != "" && !strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}

	// Fall back to aw_sk_ keys — the server-side bootstrap endpoint accepts
	// them to add a new agent to the same namespace as the existing key.
	seenSK := map[string]struct{}{}
	for _, accountName := range candidates {
		if _, dup := seenSK[accountName]; dup {
			continue
		}
		seenSK[accountName] = struct{}{}
		acct, ok := global.Accounts[accountName]
		if !ok {
			continue
		}
		token := strings.TrimSpace(acct.APIKey)
		if token != "" && strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}
	for _, name := range sortedAccountNames(global) {
		token := strings.TrimSpace(global.Accounts[name].APIKey)
		if token != "" && strings.HasPrefix(token, "aw_sk_") {
			return token
		}
	}

	return ""
}

func cloudRootBaseURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/api")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func hostFromBaseURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

func sortedAccountNames(global *awconfig.GlobalConfig) []string {
	names := make([]string, 0, len(global.Accounts))
	for name := range global.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
