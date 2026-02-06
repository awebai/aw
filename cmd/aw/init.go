package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
)

func init() {
	initCmd.Flags().StringVar(&initURL, "url", "", "Base URL for the aweb server (default: config selection, then http://localhost:8000)")
	initCmd.Flags().StringVar(&initProjectSlug, "project-slug", "", "Project slug (default: AWEB_PROJECT or prompt in TTY)")
	initCmd.Flags().StringVar(&initProjectName, "project-name", "", "Project name (default: AWEB_PROJECT_NAME or project-slug)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Agent alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Agent type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current worktree (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initCloudToken, "cloud-token", "", "Cloud auth bearer token for hosted aweb-cloud bootstrap (default: AWEB_CLOUD_TOKEN, then AWEB_API_KEY if non-aw_sk_*)")

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

	resp, err := bootstrapClient.Init(ctx, req)
	usedCloudBootstrap := false
	if err != nil {
		resp, usedCloudBootstrap, err = tryCloudBootstrapFallback(ctx, baseURL, serverName, global, req, err)
		if err != nil {
			fatal(err)
		}
	}

	// If we got an existing alias using the default suggestion, retry with server allocation.
	if !aliasExplicit && aliasWasDefaultSuggestion && !resp.Created {
		req.Alias = nil
		if usedCloudBootstrap {
			resp, err = bootstrapViaCloud(ctx, baseURL, serverName, global, req)
			if err != nil {
				fatal(err)
			}
		} else {
			resp, err = bootstrapClient.Init(ctx, req)
			if err != nil {
				resp, usedCloudBootstrap, err = tryCloudBootstrapFallback(ctx, baseURL, serverName, global, req, err)
				if err != nil {
					fatal(err)
				}
			}
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

func tryCloudBootstrapFallback(
	ctx context.Context,
	baseURL string,
	serverName string,
	global *awconfig.GlobalConfig,
	req *aweb.InitRequest,
	initErr error,
) (*aweb.InitResponse, bool, error) {
	status, ok := aweb.HTTPStatusCode(initErr)
	if !ok || (status != http.StatusForbidden && status != http.StatusNotFound) {
		return nil, false, initErr
	}

	resp, err := bootstrapViaCloud(ctx, baseURL, serverName, global, req)
	if err != nil {
		return nil, false, fmt.Errorf("init endpoint unavailable (%w); %v", initErr, err)
	}
	return resp, true, nil
}

func bootstrapViaCloud(
	ctx context.Context,
	baseURL string,
	serverName string,
	global *awconfig.GlobalConfig,
	req *aweb.InitRequest,
) (*aweb.InitResponse, error) {
	token := resolveCloudToken(serverName, global)
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("hosted Cloud bootstrap requires --cloud-token or AWEB_CLOUD_TOKEN")
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

func resolveCloudToken(serverName string, global *awconfig.GlobalConfig) string {
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

	candidates := make([]string, 0, 2)
	if v := strings.TrimSpace(accountFlag); v != "" {
		candidates = append(candidates, v)
	}
	if v := strings.TrimSpace(global.DefaultAccount); v != "" {
		candidates = append(candidates, v)
	}

	for _, accountName := range candidates {
		acct, ok := global.Accounts[accountName]
		if !ok {
			continue
		}
		if strings.TrimSpace(serverName) != "" && strings.TrimSpace(acct.Server) != strings.TrimSpace(serverName) {
			continue
		}
		token := strings.TrimSpace(acct.APIKey)
		if token != "" && !strings.HasPrefix(token, "aw_sk_") {
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
	if u.Path == "/api" {
		u.Path = ""
	}
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}
