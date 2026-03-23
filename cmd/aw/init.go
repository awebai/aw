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
	Short: "Initialize a local workspace in an existing project",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initServerURL     string
	initNamespaceSlug string
	initNamespaceName string
	initAlias         string
	initName          string
	initInjectDocs    bool
	initSetupHooks    bool
	initHumanName     string
	initAgentType     string
	initSaveConfig    bool
	initSetDefault    bool
	initWriteContext  bool
	initPrintExports  bool
	initRole          string
	initPermanent     bool
)

// initFlow identifies which clean-slate workspace/identity creation path to use.
type initFlow int

const (
	// flowHeadless creates a project plus its first workspace identity.
	flowHeadless initFlow = iota

	// flowProjectKey initializes a workspace inside an existing project using
	// project authority.
	flowProjectKey

	// flowInvite accepts a spawn invite into another workspace.
	flowInvite
)

type initOptions struct {
	Flow                           initFlow
	WorkingDir                     string
	BaseURL                        string
	ServerName                     string
	NamespaceSlug                  string
	NamespaceName                  string
	IdentityHandle                 string
	IdentityHandleExplicit         bool
	RetrySuggestedHandleOnConflict bool
	HumanName                      string
	AgentType                      string
	SaveConfig                     bool
	SetDefault                     bool
	WriteContext                   bool
	AuthToken                      string // Bearer token for the selected flow
	InviteToken                    string
	AccountName                    string
	WorkspaceRole                  string
	Lifetime                       string // "ephemeral" (default) or "persistent"
}

type initResult struct {
	Response        *awid.InitResponse
	AccountName     string
	ServerName      string
	Role            string
	AttachResult    *contextAttachResult
	SigningKeyPath  string
	ExportBaseURL   string
	ExportNamespace string
	JoinedViaInvite bool
}

func init() {
	initCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	initCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initRole, "role", "", "Workspace role (default: AWEB_ROLE or prompt in TTY, fallback: developer)")
	initCmd.Flags().BoolVar(&initPermanent, "permanent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	// When only --inject-docs or --setup-hooks are requested, operate on the
	// existing workspace without running the full init flow.
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

	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) == "" {
		return usageError("aw init now initializes a workspace in an existing project; set AWEB_API_KEY to a project-scoped key or use `aw project create`")
	}

	opts, err := collectInitOptionsForFlow(flowProjectKey)
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
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, "Initialized workspace")
	}
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + result.ExportBaseURL)
		fmt.Println("export AWEB_API_KEY=" + result.Response.APIKey)
		fmt.Println("export AWEB_PROJECT=" + result.ExportNamespace)
		fmt.Println("export AWEB_ALIAS=" + result.Response.Alias)
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
// full init flow, or if no .aw/context exists yet (first-time init).
func initNeedsFullInit() bool {
	if initServerURL != "" || initAlias != "" || initName != "" || initRole != "" || initPermanent {
		return true
	}
	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) != "" {
		return true
	}
	wd, _ := os.Getwd()
	_, _, err := awconfig.LoadWorktreeContextFromDir(wd)
	return err != nil
}

func collectInitOptionsForFlow(flow initFlow) (initOptions, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return initOptions{}, err
	}
	if err := validateInitIdentityFlags(); err != nil {
		return initOptions{}, err
	}

	// --- Validation ---

	// --- Base URL and server resolution ---

	baseURL, serverName, _, err := resolveBaseURLForInit(initServerURL, serverFlag)
	if err != nil {
		return initOptions{}, err
	}
	accountName := strings.TrimSpace(accountFlag)

	// --- Auth token for this flow ---

	authToken := ""
	switch flow {
	case flowProjectKey:
		authToken = strings.TrimSpace(os.Getenv("AWEB_API_KEY"))
		if authToken == "" {
			return initOptions{}, usageError("aw init requires AWEB_API_KEY with a project-scoped key; use `aw project create` for a new project")
		}
		if !strings.HasPrefix(authToken, "aw_sk_") {
			return initOptions{}, usageError("aw init requires a project-scoped API key (aw_sk_...). Hosted permanent identities are created from the dashboard")
		}
	}

	// --- Suggestion (one call, reused for namespace + alias + roles) ---

	nsSlugForSuggestion := ""
	if flow != flowProjectKey {
		nsSlugForSuggestion = resolveNamespaceSlug()
	}
	suggestion := fetchInitSuggestion(baseURL, nsSlugForSuggestion, authToken)

	// --- Project ---

	nsSlug := ""
	if flow != flowProjectKey {
		nsSlug = resolveNamespaceSlug()
	}
	if nsSlug == "" && suggestion != nil {
		nsSlug = strings.TrimSpace(suggestion.ProjectSlug)
	}
	if nsSlug == "" && flow != flowProjectKey {
		if isTTY() {
			suggested := sanitizeSlug(filepath.Base(workingDir))
			v, err := promptString("Project", suggested)
			if err != nil {
				return initOptions{}, err
			}
			nsSlug = v
		} else {
			return initOptions{}, usageError("missing project slug (use --project or AWEB_PROJECT)")
		}
	}

	nsName := strings.TrimSpace(initNamespaceName)
	if nsName == "" && flow != flowProjectKey {
		nsName = strings.TrimSpace(os.Getenv("AWEB_PROJECT_NAME"))
	}

	// --- Human name and agent type ---

	humanName := resolveHumanName()
	agentType := resolveAgentType()

	// --- Alias ---

	handle := ""
	handleExplicit := false
	retrySuggestedHandleOnConflict := false
	if initPermanent {
		handle = strings.TrimSpace(initName)
		handleExplicit = true
	} else {
		handle = strings.TrimSpace(initAlias)
		handleExplicit = handle != ""
		if !handleExplicit {
			handle = strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
			handleExplicit = handle != ""
		}
		if !handleExplicit {
			if !isTTY() && flow == flowProjectKey {
				return initOptions{}, usageError("--alias is required when initializing an existing project workspace non-interactively")
			}
			if suggestion != nil && strings.TrimSpace(suggestion.NamePrefix) != "" {
				handle = strings.TrimSpace(suggestion.NamePrefix)
			} else {
				handle = "alice"
			}
		}
	}

	// --- Role ---

	var suggestedRoles []string
	if suggestion != nil {
		suggestedRoles = suggestion.Roles
	}
	role := resolveRole(suggestedRoles, true)

	// --- TTY prompts for alias (after role, so prompts are in logical order) ---

	if !initPermanent {
		handleWasDefaultSuggestion := !handleExplicit
		if isTTY() && !handleExplicit {
			v, err := promptString("Alias", handle)
			if err != nil {
				return initOptions{}, err
			}
			handleWasDefaultSuggestion = v == handle
			handle = strings.TrimSpace(v)
			if handle == "" {
				handle = "alice"
				handleWasDefaultSuggestion = true
			}
		}
		retrySuggestedHandleOnConflict = handleWasDefaultSuggestion && !handleExplicit
	}

	return initOptions{
		Flow:                           flow,
		WorkingDir:                     workingDir,
		BaseURL:                        baseURL,
		ServerName:                     serverName,
		NamespaceSlug:                  nsSlug,
		NamespaceName:                  nsName,
		IdentityHandle:                 handle,
		IdentityHandleExplicit:         handleExplicit,
		RetrySuggestedHandleOnConflict: retrySuggestedHandleOnConflict,
		HumanName:                      humanName,
		AgentType:                      agentType,
		SaveConfig:                     initSaveConfig,
		SetDefault:                     initSetDefault,
		WriteContext:                   initWriteContext,
		AuthToken:                      authToken,
		AccountName:                    accountName,
		WorkspaceRole:                  role,
		Lifetime:                       resolveInitLifetime(initPermanent),
	}, nil
}

func validateInitIdentityFlags() error {
	alias := strings.TrimSpace(initAlias)
	name := strings.TrimSpace(initName)
	if initPermanent {
		if alias != "" {
			return usageError("--alias cannot be used with --permanent; use --name")
		}
		if name == "" {
			return usageError("--name is required with --permanent")
		}
		return nil
	}
	if name != "" {
		return usageError("--name can only be used with --permanent")
	}
	return nil
}

func resolveNamespaceSlug() string {
	if v := strings.TrimSpace(initNamespaceSlug); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_PROJECT")); v != "" {
		return v
	}
	return ""
}

func resolveHumanName() string {
	if v := strings.TrimSpace(initHumanName); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	return "developer"
}

func resolveAgentType() string {
	if v := strings.TrimSpace(initAgentType); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE")); v != "" {
		return v
	}
	return "agent"
}

func resolveRole(suggestedRoles []string, allowPrompt bool) string {
	role := strings.TrimSpace(initRole)
	if role == "" {
		role = strings.TrimSpace(os.Getenv("AWEB_ROLE"))
	}
	if role != "" {
		role = normalizeWorkspaceRole(role)
		return role
	}
	if allowPrompt && isTTY() {
		defaultRole := "developer"
		if len(suggestedRoles) > 0 {
			defaultRole = suggestedRoles[0]
			fmt.Fprintf(os.Stderr, "Available roles: %s\n", strings.Join(suggestedRoles, ", "))
		}
		v, _ := promptString("Role", defaultRole)
		role = normalizeWorkspaceRole(strings.TrimSpace(v))
		if role != "" {
			return role
		}
	}
	return "developer"
}

// fetchInitSuggestion calls the suggest-alias-prefix endpoint.
// When authToken is set, uses an authenticated client (server infers
// project from the token). Otherwise uses an anonymous client with nsSlug.
func fetchInitSuggestion(baseURL, nsSlug, authToken string) *awid.SuggestAliasPrefixResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if strings.TrimSpace(authToken) != "" {
		client, err := aweb.NewWithAPIKey(baseURL, authToken)
		if err != nil {
			return &awid.SuggestAliasPrefixResponse{}
		}
		suggestion, err := client.SuggestAliasPrefix(ctx, nsSlug)
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
	lifetime := strings.TrimSpace(opts.Lifetime)
	if lifetime == "" {
		lifetime = resolveInitLifetime(initPermanent)
	}

	req := &awid.InitRequest{
		ProjectSlug: opts.NamespaceSlug,
		ProjectName: namespaceName,
		HumanName:   opts.HumanName,
		AgentType:   opts.AgentType,
		DID:         did,
		PublicKey:   pubKeyB64,
		Custody:     awid.CustodySelf,
		Lifetime:    lifetime,
	}
	if strings.TrimSpace(opts.IdentityHandle) != "" {
		handle := strings.TrimSpace(opts.IdentityHandle)
		req.Alias = &handle
	}

	var resp *awid.InitResponse
	switch opts.Flow {
	case flowInvite:
		resp, err = acceptInviteViaCloud(ctx, opts.BaseURL, opts.InviteToken, opts.IdentityHandle, opts.HumanName, opts.AgentType, did, pubKeyB64, lifetime)

	case flowProjectKey:
		var client *aweb.Client
		client, err = aweb.NewWithAPIKey(opts.BaseURL, opts.AuthToken)
		if err != nil {
			return nil, err
		}
		resp, err = client.Init(ctx, req)

	case flowHeadless:
		var client *aweb.Client
		client, err = aweb.New(opts.BaseURL)
		if err != nil {
			return nil, err
		}
		resp, err = tryHeadlessOrInit(ctx, client, req, opts.BaseURL)
		// On alias conflict, transition HEADLESS → PROJECT_KEY: use the
		// returned aw_sk_ key for authenticated retry via /v1/init.
		if err == nil && opts.RetrySuggestedHandleOnConflict && !resp.Created {
			if strings.TrimSpace(resp.APIKey) != "" {
				retryClient, retryErr := aweb.NewWithAPIKey(opts.BaseURL, resp.APIKey)
				if retryErr != nil {
					err = retryErr
				} else {
					req.Alias = nil
					resp, err = retryClient.Init(ctx, req)
				}
			}
		}
	}
	if err != nil {
		return nil, err
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
		SigningKeyPath:  signingKeyPath,
		ExportBaseURL:   exportBaseURL,
		ExportNamespace: namespaceSlug,
		JoinedViaInvite: opts.InviteToken != "",
	}, nil
}

func printInitSummary(resp *awid.InitResponse, accountName, serverName, role string, attachResult *contextAttachResult, signingKeyPath, headline string) {
	if resp == nil {
		return
	}
	project := strings.TrimSpace(resp.ProjectSlug)
	namespace := strings.TrimSpace(resp.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(resp.NamespaceSlug)
	}

	headline = strings.TrimSpace(headline)
	if headline == "" {
		headline = "Initialized workspace"
	}
	fmt.Println(headline)
	if strings.TrimSpace(resp.Alias) != "" {
		label := "Alias"
		if awid.IdentityClassFromLifetime(resp.Lifetime) == awid.IdentityClassPermanent {
			label = "Name"
		}
		fmt.Printf("%-11s %s\n", label+":", strings.TrimSpace(resp.Alias))
	}
	if identityClass := describeIdentityClass(strings.TrimSpace(resp.Lifetime)); identityClass != "" {
		fmt.Printf("Identity:   %s\n", identityClass)
	}
	if strings.TrimSpace(resp.Custody) != "" {
		fmt.Printf("Custody:    %s\n", strings.TrimSpace(resp.Custody))
	}
	if project != "" {
		fmt.Printf("Project:    %s\n", project)
	}
	if namespace != "" && namespace != project {
		fmt.Printf("Namespace:  %s\n", namespace)
	}
	if strings.TrimSpace(role) != "" {
		fmt.Printf("Role:       %s\n", strings.TrimSpace(role))
	}
	if strings.TrimSpace(resp.Address) != "" {
		label := "Address"
		if strings.TrimSpace(resp.Lifetime) == awid.LifetimeEphemeral {
			label = "Routing"
		}
		fmt.Printf("%-10s %s\n", label+":", strings.TrimSpace(resp.Address))
	}
	if strings.TrimSpace(serverName) != "" {
		fmt.Printf("Server:     %s\n", strings.TrimSpace(serverName))
	}
	if awid.IdentityClassFromLifetime(resp.Lifetime) == awid.IdentityClassPermanent && strings.TrimSpace(signingKeyPath) != "" {
		fmt.Printf("Key:        %s\n", strings.TrimSpace(signingKeyPath))
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
	// Headless bootstrap requires an explicit identifier. For ephemeral
	// identities that is a routing alias; for permanent identities the CLI
	// requires --name and maps it into the transport field here.
	// Without an explicit identifier, fall back to /v1/init which supports
	// server-allocated ephemeral aliases. If that also fails, surface an
	// error asking the user to specify --alias explicitly.
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
		NamespaceSlug: firstNonEmptyString(headlessResp.NamespaceSlug, headlessResp.OrgSlug),
		Namespace:     headlessResp.Namespace,
		Address:       headlessResp.Address,
		Created:       headlessResp.Created,
		DID:           headlessResp.DID,
		StableID:      headlessResp.StableID,
		Custody:       headlessResp.Custody,
		Lifetime:      headlessResp.Lifetime,
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
		NamespaceSlug: firstNonEmptyString(resp.NamespaceSlug, resp.OrgSlug),
		Namespace:     resp.Namespace,
		Address:       resp.Address,
		Created:       resp.Created,
		DID:           resp.DID,
		StableID:      resp.StableID,
		Custody:       resp.Custody,
		Lifetime:      resp.Lifetime,
	}, nil
}

func resolveInitLifetime(permanent bool) string {
	if permanent {
		return awid.LifetimePersistent
	}
	return awid.LifetimeEphemeral
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func describeIdentityClass(lifetime string) string {
	switch strings.TrimSpace(lifetime) {
	case awid.LifetimeEphemeral:
		return "ephemeral"
	case awid.LifetimePersistent:
		return "permanent"
	default:
		return strings.TrimSpace(lifetime)
	}
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
