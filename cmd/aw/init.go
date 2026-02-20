package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize agent credentials",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initURL          string
	initProjectSlug  string
	initProjectName  string
	initAlias        string
	initHumanName    string
	initAgentType    string
	initSaveConfig   bool
	initSetDefault   bool
	initWriteContext bool
	initPrintExports bool
	initCloudToken   string
	initCloudMode    bool
)

func init() {
	initCmd.Flags().StringVar(&initURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	initCmd.Flags().StringVar(&initProjectSlug, "project-slug", "", "Project slug (default: AWEB_PROJECT or prompt in TTY)")
	initCmd.Flags().StringVar(&initProjectName, "project-name", "", "Project name (default: AWEB_PROJECT_NAME or project-slug)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Agent alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Agent type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current worktree (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initCloudToken, "cloud-token", "", "Cloud auth bearer token for hosted aweb-cloud bootstrap (default: AWEB_CLOUD_TOKEN, then AWEB_API_KEY if non-aw_sk_, then existing aw_sk_ keys from config)")
	initCmd.Flags().BoolVar(&initCloudMode, "cloud", false, "Force hosted aweb-cloud bootstrap mode (skip probing /v1/init)")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	baseURL, serverName, global, err := resolveBaseURLForInit(initURL, serverFlag)
	if err != nil {
		fatal(err)
	}

	projectSlug := initProjectSlug
	if strings.TrimSpace(projectSlug) == "" {
		projectSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG"))
	}
	if strings.TrimSpace(projectSlug) == "" {
		projectSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT"))
	}

	if strings.TrimSpace(projectSlug) == "" {
		if isTTY() {
			wd, _ := os.Getwd()
			suggested := sanitizeSlug(filepath.Base(wd))
			v, err := promptString("Project slug", suggested)
			if err != nil {
				fatal(err)
			}
			projectSlug = v
		} else {
			fmt.Fprintln(os.Stderr, "Missing project slug (use --project-slug or AWEB_PROJECT)")
			os.Exit(2)
		}
	}

	projectName := initProjectName
	if strings.TrimSpace(projectName) == "" {
		projectName = strings.TrimSpace(os.Getenv("AWEB_PROJECT_NAME"))
	}
	if strings.TrimSpace(projectName) == "" {
		projectName = projectSlug
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
			fmt.Fprintln(os.Stderr, "--alias is required when bootstrapping a new agent with an existing API key")
			os.Exit(2)
		}
	}

	aliasWasDefaultSuggestion := false
	if !aliasExplicit {
		bootstrapClient, err := aweb.New(baseURL)
		if err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		suggestion, err := bootstrapClient.SuggestAliasPrefix(ctx, projectSlug)
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
			fatal(err)
		}
		aliasWasDefaultSuggestion = v == alias
		alias = strings.TrimSpace(v)
		if alias == "" {
			alias = "alice"
			aliasWasDefaultSuggestion = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bootstrapClient, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	req := &aweb.InitRequest{
		ProjectSlug: projectSlug,
		ProjectName: projectName,
		HumanName:   humanName,
		AgentType:   agentType,
	}
	if strings.TrimSpace(alias) != "" {
		req.Alias = &alias
	}

	var resp *aweb.InitResponse
	if initCloudMode {
		resp, err = bootstrapViaCloud(ctx, baseURL, serverName, global, req)
	} else {
		resp, err = bootstrapClient.Init(ctx, req)
	}
	if err != nil {
		fatal(err)
	}

	// If we got an existing alias using the default suggestion, retry with server allocation.
	if !aliasExplicit && aliasWasDefaultSuggestion && !resp.Created {
		req.Alias = nil
		if initCloudMode {
			resp, err = bootstrapViaCloud(ctx, baseURL, serverName, global, req)
		} else {
			resp, err = bootstrapClient.Init(ctx, req)
		}
		if err != nil {
			fatal(err)
		}
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, projectSlug, resp.Alias)
	}

	defaultProject := strings.TrimSpace(resp.ProjectSlug)
	if defaultProject == "" {
		defaultProject = projectSlug
	}

	if initSaveConfig {
		updateErr := awconfig.UpdateGlobalAt(mustDefaultGlobalPath(), func(cfg *awconfig.GlobalConfig) error {
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
				Server:         serverName,
				APIKey:         resp.APIKey,
				DefaultProject: defaultProject,
				AgentID:        resp.AgentID,
				AgentAlias:     resp.Alias,
			}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || initSetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		})
		if updateErr != nil {
			fatal(updateErr)
		}
	}

	if initWriteContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			fatal(err)
		}
	}

	printJSON(resp)
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + baseURL)
		fmt.Println("export AWEB_API_KEY=" + resp.APIKey)
		fmt.Println("export AWEB_PROJECT_ID=" + resp.ProjectID)
		fmt.Println("export AWEB_AGENT_ID=" + resp.AgentID)
		fmt.Println("export AWEB_AGENT_ALIAS=" + resp.Alias)
	}
	return nil
}

func bootstrapViaCloud(
	ctx context.Context,
	baseURL string,
	serverName string,
	global *awconfig.GlobalConfig,
	req *aweb.InitRequest,
) (*aweb.InitResponse, error) {
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

	cloudReq := &aweb.CloudBootstrapAgentRequest{
		Alias:     req.Alias,
		HumanName: req.HumanName,
		AgentType: req.AgentType,
	}

	cloudResp, err := cloudClient.CloudBootstrapAgent(ctx, cloudReq)
	if err != nil {
		return nil, fmt.Errorf("cloud bootstrap failed: %w", err)
	}

	if strings.TrimSpace(cloudResp.APIKey) == "" {
		return nil, fmt.Errorf("cloud bootstrap failed: missing api_key in response")
	}

	return &aweb.InitResponse{
		Status:      "ok",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		ProjectID:   cloudResp.ProjectID,
		ProjectSlug: cloudResp.ProjectSlug,
		AgentID:     cloudResp.AgentID,
		Alias:       cloudResp.Alias,
		APIKey:      cloudResp.APIKey,
		Created:     cloudResp.Created,
	}, nil
}

func resolveCloudToken(baseURL, serverName string, global *awconfig.GlobalConfig) string {
	if v := strings.TrimSpace(initCloudToken); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_CLOUD_TOKEN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); v != "" && !strings.HasPrefix(v, "aw_sk_") {
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
	// them to add a new agent to the same project as the existing key.
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

	// Last resort: AWEB_API_KEY with aw_sk_ prefix (skipped earlier in favor of JWT tokens).
	if v := strings.TrimSpace(os.Getenv("AWEB_API_KEY")); v != "" && strings.HasPrefix(v, "aw_sk_") {
		return v
	}

	return ""
}

func cloudRootBaseURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "/api" {
		u.Path = ""
	}
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
