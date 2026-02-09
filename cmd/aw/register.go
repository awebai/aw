package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	registerServer      string
	registerEmail       string
	registerUsername    string
	registerAlias       string
	registerHumanName  string
	registerSaveConfig  bool
	registerSetDefault  bool
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
	registerCmd.Flags().StringVar(&registerServer, "server", "", "Base URL for the aweb server (required)")
	registerCmd.Flags().StringVar(&registerEmail, "email", "", "Email address for the new account (required)")
	registerCmd.Flags().StringVar(&registerUsername, "username", "", "Username (optional; server may auto-generate)")
	registerCmd.Flags().StringVar(&registerAlias, "alias", "", "Agent alias (optional; server may auto-generate)")
	registerCmd.Flags().StringVar(&registerHumanName, "human-name", "", "Human name (optional)")
	registerCmd.Flags().BoolVar(&registerSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	registerCmd.Flags().BoolVar(&registerSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	registerCmd.Flags().BoolVar(&registerWriteContext, "write-context", true, "Write/update .aw/context in the current worktree (non-secret pointer)")

	rootCmd.AddCommand(registerCmd)
}

func runRegister(cmd *cobra.Command, args []string) error {
	serverURL := strings.TrimSpace(registerServer)
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Missing server URL (use --server)")
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

	req := &aweb.RegisterRequest{
		Email:     email,
		HumanName: strings.TrimSpace(registerHumanName),
	}
	if v := strings.TrimSpace(registerUsername); v != "" {
		req.Username = &v
	}
	if v := strings.TrimSpace(registerAlias); v != "" {
		req.Alias = &v
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	resp, err := client.Register(ctx, req)
	if err != nil {
		code, isHTTP := aweb.HTTPStatusCode(err)
		if !isHTTP {
			fatal(err)
		}
		switch code {
		case 404:
			fatal(fmt.Errorf("this server does not support CLI registration. Visit %s to create an account", serverURL))
		case 409:
			body, _ := aweb.HTTPErrorBody(err)
			if strings.TrimSpace(body) != "" {
				fatal(fmt.Errorf("email or username already taken: %s", body))
			}
			fatal(fmt.Errorf("email or username already taken"))
		case 429:
			fatal(fmt.Errorf("rate limited. Please try again later"))
		default:
			fatal(err)
		}
	}

	alias := resp.Alias
	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, resp.ProjectSlug, alias)
	}

	if registerSaveConfig {
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
				DefaultProject: resp.ProjectSlug,
				AgentID:        resp.AgentID,
				AgentAlias:     resp.Alias,
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

	if registerWriteContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			fatal(err)
		}
	}

	printJSON(resp)
	return nil
}
