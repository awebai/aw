package main

import (
	"context"
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
	registerCmd.Flags().StringVar(&registerUsername, "username", "", "Username for the new account (required)")
	registerCmd.Flags().StringVar(&registerAlias, "alias", "", "Agent alias (required)")
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

	req := &aweb.RegisterRequest{
		Email:     email,
		Username:  &username,
		Alias:     &alias,
		HumanName: strings.TrimSpace(registerHumanName),
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
			fatal(formatConflictError(body))
		case 429:
			fatal(fmt.Errorf("rate limited. Please try again later"))
		default:
			fatal(err)
		}
	}

	accountName := strings.TrimSpace(accountFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, resp.ProjectSlug, resp.Alias)
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
				Email:          resp.Email,
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
