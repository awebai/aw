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
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/awconfig"
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
	initHumanName       string
	initAgentType       string
	initSaveConfig      bool
	initSetDefault      bool
	initWriteContext    bool
	initPrintExports    bool
	initCloudToken      string
	initCloudMode       bool
	initTargetNamespace string
)

func init() {
	initCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	initCmd.Flags().StringVar(&initNamespaceSlug, "namespace", "", "Namespace slug (default: AWEB_NAMESPACE or prompt in TTY)")
	initCmd.Flags().StringVar(&initNamespaceName, "namespace-name", "", "Namespace display name (default: AWEB_NAMESPACE_NAME or namespace slug)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Agent alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Agent type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initCloudToken, "cloud-token", "", "Cloud auth bearer token for hosted aweb-cloud bootstrap (default: AWEB_CLOUD_TOKEN, then AWEB_API_KEY if non-aw_sk_, then existing aw_sk_ keys from config)")
	initCmd.Flags().BoolVar(&initCloudMode, "cloud", false, "Force hosted aweb-cloud bootstrap mode (skip probing /v1/init)")
	initCmd.Flags().StringVar(&initTargetNamespace, "target-namespace", "", "Create agent in a specific namespace (forces cloud mode; requires --alias)")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(initTargetNamespace) != "" {
		if strings.TrimSpace(initAlias) == "" && strings.TrimSpace(os.Getenv("AWEB_ALIAS")) == "" {
			return usageError("--target-namespace requires --alias (server cannot auto-assign in a specific namespace)")
		}
		initCloudMode = true
	}

	baseURL, serverName, global, err := resolveBaseURLForInit(initServerURL, serverFlag)
	if err != nil {
		return err
	}

	if !initCloudMode {
		if v := strings.TrimSpace(initCloudToken); v != "" {
			initCloudMode = true
		} else if v := strings.TrimSpace(os.Getenv("AWEB_CLOUD_TOKEN")); v != "" {
			initCloudMode = true
		} else if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); v != "" {
			if !strings.HasPrefix(v, "aw_sk_") {
				initCloudMode = true
			} else if strings.TrimSpace(initNamespaceSlug) == "" &&
				strings.TrimSpace(os.Getenv("AWEB_NAMESPACE")) == "" &&
				strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG")) == "" &&
				strings.TrimSpace(os.Getenv("AWEB_PROJECT")) == "" &&
				strings.TrimSpace(initTargetNamespace) == "" {
				// Hosted setup commands provide a project API key but no namespace.
				// In that case, bootstrap through Cloud and let the server infer the
				// owner/project namespace instead of prompting locally.
				initCloudMode = true
			}
		}
	}

	nsSlug := initNamespaceSlug
	if strings.TrimSpace(nsSlug) == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_NAMESPACE"))
	}
	// Backward compat: fall back to old env vars.
	if strings.TrimSpace(nsSlug) == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG"))
	}
	if strings.TrimSpace(nsSlug) == "" {
		nsSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT"))
	}

	if strings.TrimSpace(nsSlug) == "" && !initCloudMode {
		if isTTY() {
			wd, _ := os.Getwd()
			suggested := sanitizeSlug(filepath.Base(wd))
			v, err := promptString("Namespace", suggested)
			if err != nil {
				return err
			}
			nsSlug = v
		} else {
			return usageError("missing namespace (use --namespace or AWEB_NAMESPACE)")
		}
	}

	nsName := initNamespaceName
	if strings.TrimSpace(nsName) == "" {
		nsName = strings.TrimSpace(os.Getenv("AWEB_NAMESPACE_NAME"))
	}
	// Backward compat: fall back to old env var.
	if strings.TrimSpace(nsName) == "" {
		nsName = strings.TrimSpace(os.Getenv("AWEB_PROJECT_NAME"))
	}
	if strings.TrimSpace(nsName) == "" {
		nsName = nsSlug
	}

	humanName := initHumanName
	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("USER"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = "developer"
	}

	agentType := initAgentType
	if strings.TrimSpace(agentType) == "" {
		agentType = strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE"))
	}
	if strings.TrimSpace(agentType) == "" {
		agentType = "agent"
	}

	alias := strings.TrimSpace(initAlias)
	aliasExplicit := alias != ""
	if !aliasExplicit {
		alias = strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
		aliasExplicit = alias != ""
	}

	// When using an existing API key for cloud bootstrap, --alias is required
	// because the server cannot auto-assign unique aliases for peer agents.
	if initCloudMode && !aliasExplicit {
		token := resolveCloudToken(baseURL, serverName, global)
		if strings.HasPrefix(token, "aw_sk_") {
			return usageError("--alias is required when bootstrapping a new agent with an existing API key")
		}
	}

	aliasWasDefaultSuggestion := false
	if !aliasExplicit {
		bootstrapClient, err := aweb.New(baseURL)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		suggestion, err := bootstrapClient.SuggestAliasPrefix(ctx, nsSlug)
		if err != nil || strings.TrimSpace(suggestion.NamePrefix) == "" {
			alias = "alice"
		} else {
			alias = suggestion.NamePrefix
		}
		aliasWasDefaultSuggestion = true
	}

	if isTTY() && !aliasExplicit {
		v, err := promptString("Agent alias", alias)
		if err != nil {
			return err
		}
		aliasWasDefaultSuggestion = v == alias
		alias = strings.TrimSpace(v)
		if alias == "" {
			alias = "alice"
			aliasWasDefaultSuggestion = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var bootstrapClient *aweb.Client
	initAPIKey := resolveInitAPIKey(baseURL, serverName, global)
	if initAPIKey != "" {
		bootstrapClient, err = aweb.NewWithAPIKey(baseURL, initAPIKey)
	} else {
		bootstrapClient, err = aweb.New(baseURL)
	}
	if err != nil {
		return err
	}

	// Generate Ed25519 keypair for self-custodial identity.
	// Keypair generated once; reused on alias-retry so the DID stays
	// consistent with the registered key.
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	did := awid.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	req := &awid.InitRequest{
		ProjectSlug: nsSlug,
		ProjectName: nsName,
		HumanName:   humanName,
		AgentType:   agentType,
		DID:         did,
		PublicKey:   pubKeyB64,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
	}
	if strings.TrimSpace(alias) != "" {
		req.Alias = &alias
	}

	var resp *awid.InitResponse
	if initCloudMode {
		resp, err = bootstrapViaCloud(ctx, baseURL, serverName, global, req, strings.TrimSpace(initTargetNamespace))
	} else if initAPIKey == "" {
		// No credentials: use anonymous headless bootstrap for hosted servers.
		resp, err = tryHeadlessOrInit(ctx, bootstrapClient, req, baseURL)
	} else {
		resp, err = bootstrapClient.Init(ctx, req)
	}
	if err != nil {
		return err
	}

	// If we got an existing alias using the default suggestion, retry with server allocation.
	if !aliasExplicit && aliasWasDefaultSuggestion && !resp.Created {
		req.Alias = nil
		if initCloudMode {
			resp, err = bootstrapViaCloud(ctx, baseURL, serverName, global, req, strings.TrimSpace(initTargetNamespace))
		} else if initAPIKey == "" {
			resp, err = tryHeadlessOrInit(ctx, bootstrapClient, req, baseURL)
		} else {
			resp, err = bootstrapClient.Init(ctx, req)
		}
		if err != nil {
			return err
		}
	}

	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(resp.ProjectSlug)
	}
	if namespaceSlug == "" {
		namespaceSlug = nsSlug
	}
	// Prefer server-authoritative namespace domain.
	if resp.Namespace != "" {
		namespaceSlug = resp.Namespace
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, namespaceSlug, resp.Alias)
	}

	// Prefer server-authoritative address.
	address := resp.Address
	if address == "" {
		address = deriveAgentAddress(resp.NamespaceSlug, resp.ProjectSlug, resp.Alias)
	}
	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	keysDir := awconfig.KeysDir(cfgPath)
	signingKeyPath := awid.SigningKeyPath(keysDir, address)

	// Save keypair to disk BEFORE writing config. If config is written but
	// the key save fails, the agent would be bricked (config pointing to a
	// nonexistent key). An orphaned key file on disk is harmless.
	if err := awid.SaveKeypair(keysDir, address, pub, priv); err != nil {
		return err
	}

	stableID := strings.TrimSpace(resp.StableID)

	if initSaveConfig {
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
			cfg.Accounts[accountName] = awconfig.Account{Account: awid.Account{
				Server:        serverName,
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
			if strings.TrimSpace(cfg.DefaultAccount) == "" || initSetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		})
		if updateErr != nil {
			return updateErr
		}
	}

	if initWriteContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			return err
		}
	}

	var attachResult *contextAttachResult
	if initWriteContext {
		authClient, err := aweb.NewWithAPIKey(baseURL, resp.APIKey)
		if err == nil {
			workingDir, _ := os.Getwd()
			attachResult, err = autoAttachContext(workingDir, authClient)
			if err != nil {
				debugLog("workspace attach: %v", err)
				fmt.Fprintf(os.Stderr, "Warning: could not attach workspace context (coordination may not be available on this server)\n")
			}
		}
	}

	if jsonFlag {
		printJSON(resp)
	} else {
		printInitSummary(resp, accountName, serverName, attachResult)
	}
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + baseURL)
		fmt.Println("export AWEB_API_KEY=" + resp.APIKey)
		fmt.Println("export AWEB_NAMESPACE=" + namespaceSlug)
		fmt.Println("export AWEB_AGENT_ID=" + resp.AgentID)
		fmt.Println("export AWEB_AGENT_ALIAS=" + resp.Alias)
	}
	return nil
}

func printInitSummary(resp *awid.InitResponse, accountName, serverName string, attachResult *contextAttachResult) {
	if resp == nil {
		return
	}
	fmt.Printf("Initialized agent %s\n", resp.Alias)
	if strings.TrimSpace(resp.NamespaceSlug) != "" {
		fmt.Printf("Namespace:  %s\n", strings.TrimSpace(resp.NamespaceSlug))
	}
	if strings.TrimSpace(accountName) != "" {
		fmt.Printf("Account:    %s\n", strings.TrimSpace(accountName))
	}
	if strings.TrimSpace(serverName) != "" {
		fmt.Printf("Server:     %s\n", strings.TrimSpace(serverName))
	}
	if attachResult == nil {
		return
	}
	switch strings.TrimSpace(attachResult.ContextKind) {
	case "repo_worktree":
		if attachResult.Workspace != nil {
			fmt.Printf("Context:    attached %s\n", strings.TrimSpace(attachResult.Workspace.CanonicalOrigin))
		}
	case "local_dir":
		fmt.Println("Context:    attached local directory")
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
	serverName string,
	global *awconfig.GlobalConfig,
	req *awid.InitRequest,
	namespaceSlug string,
) (*awid.InitResponse, error) {
	token := resolveCloudToken(baseURL, serverName, global)
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
		Created:       cloudResp.Created,
		DID:           cloudResp.DID,
		StableID:      cloudResp.StableID,
		Custody:       cloudResp.Custody,
		Lifetime:      cloudResp.Lifetime,
	}, nil
}

func resolveInitAPIKey(baseURL, serverName string, global *awconfig.GlobalConfig) string {
	if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); strings.HasPrefix(v, "aw_sk_") {
		return v
	}
	if global == nil {
		return ""
	}

	candidates := make([]string, 0, 4)
	if v := strings.TrimSpace(accountFlag); v != "" {
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

func resolveCloudToken(baseURL, serverName string, global *awconfig.GlobalConfig) string {
	if v := strings.TrimSpace(initCloudToken); v != "" {
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
	if v := strings.TrimSpace(accountFlag); v != "" {
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
