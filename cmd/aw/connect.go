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

var connectSetDefault bool

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to an aweb server using environment credentials",
	Long: `Reads AWEB_URL and AWEB_API_KEY from the environment (or .env.aweb),
validates them via introspect, and writes persistent config so future
commands work without environment variables.`,
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().BoolVar(&connectSetDefault, "set-default", false, "Set this account as default even if one already exists")
	rootCmd.AddCommand(connectCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	baseURL := strings.TrimSpace(os.Getenv("AWEB_URL"))
	apiKey := strings.TrimSpace(os.Getenv("AWEB_API_KEY"))

	if baseURL == "" {
		fmt.Fprintln(os.Stderr, "AWEB_URL is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
		os.Exit(2)
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "AWEB_API_KEY is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
		os.Exit(2)
	}

	baseURL, err := resolveWorkingBaseURL(baseURL)
	if err != nil {
		fatal(err)
	}

	serverName, _ := awconfig.DeriveServerNameFromURL(baseURL)

	client, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.Introspect(ctx)
	if err != nil {
		fatal(err)
	}

	if strings.TrimSpace(resp.AgentID) == "" {
		fmt.Fprintln(os.Stderr, "This API key is not agent-scoped (no agent_id). Use an agent-scoped key from the dashboard.")
		os.Exit(2)
	}

	alias := strings.TrimSpace(resp.Alias)
	agentID := strings.TrimSpace(resp.AgentID)

	// Derive account name from server + agent_id (stable across alias changes).
	accountName := "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(agentID)

	cfgPath := mustDefaultGlobalPath()
	updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
		if cfg.Servers == nil {
			cfg.Servers = map[string]awconfig.Server{}
		}
		if cfg.Accounts == nil {
			cfg.Accounts = map[string]awconfig.Account{}
		}

		// Check for existing account with same server+agent_id — update it.
		for name, acct := range cfg.Accounts {
			if strings.TrimSpace(acct.AgentID) == agentID && strings.TrimSpace(acct.Server) == serverName {
				accountName = name
				break
			}
		}

		if _, ok := cfg.Servers[serverName]; !ok || strings.TrimSpace(cfg.Servers[serverName].URL) == "" {
			cfg.Servers[serverName] = awconfig.Server{URL: baseURL}
		}

		cfg.Accounts[accountName] = awconfig.Account{
			Server:     serverName,
			APIKey:     apiKey,
			AgentID:    agentID,
			AgentAlias: alias,
		}

		if strings.TrimSpace(cfg.DefaultAccount) == "" || connectSetDefault {
			cfg.DefaultAccount = accountName
		}
		return nil
	})
	if updateErr != nil {
		fatal(updateErr)
	}

	if err := writeOrUpdateContext(serverName, accountName); err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Connected as %s", alias)
	if alias != "" {
		fmt.Fprintf(os.Stderr, " (%s)", agentID)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Config written to %s\n", cfgPath)

	// Print introspect output as JSON for scriptability.
	printJSON(resp)

	return nil
}
