package main

import (
	"context"
	"fmt"
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

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	baseURL, serverName, _, err := resolveBaseURLForInit(initURL, serverFlag)
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
	if err != nil {
		fatal(err)
	}

	// If we got an existing alias using the default suggestion, retry with server allocation.
	if !aliasExplicit && aliasWasDefaultSuggestion && !resp.Created {
		req.Alias = nil
		resp, err = bootstrapClient.Init(ctx, req)
		if err != nil {
			fatal(err)
		}
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, projectSlug, resp.Alias)
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
				DefaultProject: projectSlug,
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
