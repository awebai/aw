package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

// resolveAgentID resolves the current agent's ID via introspect, falling back
// to the configured agent_id in the selection.
func resolveAgentID(ctx context.Context, client *aweb.Client, sel *awconfig.Selection) (string, error) {
	intro, err := client.Introspect(ctx)
	if err != nil {
		return "", err
	}
	if intro.AgentID == "" && sel.AgentID != "" {
		return sel.AgentID, nil
	}
	if intro.AgentID == "" {
		return "", fmt.Errorf("cannot determine agent_id: not an agent-scoped key")
	}
	return intro.AgentID, nil
}

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List your agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, err := resolveClient()
		if err != nil {
			return err
		}
		resp, err := client.ListAgents(ctx)
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Agent operations",
}

var agentAccessModeCmd = &cobra.Command{
	Use:   "access-mode [open|contacts_only]",
	Short: "Get or set agent access mode",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID, err := resolveAgentID(ctx, client, sel)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			// GET: list agents, find self, print access_mode.
			agents, err := client.ListAgents(ctx)
			if err != nil {
				return err
			}
			for _, a := range agents.Agents {
				if a.AgentID == agentID {
					printJSON(map[string]string{
						"agent_id":    a.AgentID,
						"access_mode": a.AccessMode,
					})
					return nil
				}
			}
			return fmt.Errorf("agent %s not found in agents list", agentID)
		}

		// SET: patch access mode.
		mode := args[0]
		if mode != "open" && mode != "contacts_only" {
			return usageError("invalid access mode: %s (must be \"open\" or \"contacts_only\")", mode)
		}

		resp, err := client.PatchAgent(ctx, agentID, &aweb.PatchAgentRequest{
			AccessMode: mode,
		})
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

var agentPrivacyCmd = &cobra.Command{
	Use:   "privacy [public|private]",
	Short: "Get or set agent privacy",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID, err := resolveAgentID(ctx, client, sel)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			agents, err := client.ListAgents(ctx)
			if err != nil {
				return err
			}
			for _, a := range agents.Agents {
				if a.AgentID == agentID {
					printJSON(map[string]string{
						"agent_id": a.AgentID,
						"privacy":  a.Privacy,
					})
					return nil
				}
			}
			return fmt.Errorf("agent %s not found in agents list", agentID)
		}

		privacy := args[0]
		if privacy != "public" && privacy != "private" {
			return usageError("invalid privacy: %s (must be \"public\" or \"private\")", privacy)
		}

		resp, err := client.PatchAgent(ctx, agentID, &aweb.PatchAgentRequest{
			Privacy: privacy,
		})
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentsCmd)
	agentCmd.AddCommand(agentAccessModeCmd)
	agentCmd.AddCommand(agentPrivacyCmd)
	rootCmd.AddCommand(agentCmd)
}
