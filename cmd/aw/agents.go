package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

// agentsListOutput wraps the server response with local config fields for display.
type agentsListOutput struct {
	*aweb.ListAgentsResponse
	NamespaceSlug string `json:"namespace_slug,omitempty"`
}

// agentPatchOutput wraps the server response with the agent's alias for display.
type agentPatchOutput struct {
	*aweb.PatchAgentResponse
	Alias string `json:"alias,omitempty"`
}

// mustAgentID resolves the current agent's ID via introspect, falling back
// to the configured agent_id in the selection.
func mustAgentID(ctx context.Context, client *aweb.Client, sel *awconfig.Selection) string {
	intro, err := client.Introspect(ctx)
	if err != nil {
		fatal(err)
	}
	if intro.AgentID == "" && sel.AgentID != "" {
		return sel.AgentID
	}
	if intro.AgentID == "" {
		fatal(fmt.Errorf("cannot determine agent_id: not an agent-scoped key"))
	}
	return intro.AgentID
}

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List your agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel := mustResolve()
		resp, err := client.ListAgents(ctx)
		if err != nil {
			fatal(err)
		}
		printOutput(agentsListOutput{
			ListAgentsResponse: resp,
			NamespaceSlug:      sel.NamespaceSlug,
		}, formatAgentsList)
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

		client, sel := mustResolve()
		agentID := mustAgentID(ctx, client, sel)

		if len(args) == 0 {
			// GET: list agents, find self, print access_mode.
			agents, err := client.ListAgents(ctx)
			if err != nil {
				fatal(err)
			}
			for _, a := range agents.Agents {
				if a.AgentID == agentID {
					printOutput(map[string]string{
						"agent_id":    a.AgentID,
						"alias":       a.Alias,
						"access_mode": a.AccessMode,
					}, formatAgentAccessMode)
					return nil
				}
			}
			fatal(fmt.Errorf("agent %s not found in agents list", agentID))
		}

		// SET: patch access mode.
		mode := args[0]
		if mode != "open" && mode != "contacts_only" {
			fatal(fmt.Errorf("invalid access mode: %s (must be \"open\" or \"contacts_only\")", mode))
		}

		resp, err := client.PatchAgent(ctx, agentID, &aweb.PatchAgentRequest{
			AccessMode: mode,
		})
		if err != nil {
			fatal(err)
		}
		printOutput(agentPatchOutput{
			PatchAgentResponse: resp,
			Alias:              sel.AgentAlias,
		}, formatAgentPatch)
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

		client, sel := mustResolve()
		agentID := mustAgentID(ctx, client, sel)

		if len(args) == 0 {
			agents, err := client.ListAgents(ctx)
			if err != nil {
				fatal(err)
			}
			for _, a := range agents.Agents {
				if a.AgentID == agentID {
					printOutput(map[string]string{
						"agent_id": a.AgentID,
						"alias":    a.Alias,
						"privacy":  a.Privacy,
					}, formatAgentPrivacy)
					return nil
				}
			}
			fatal(fmt.Errorf("agent %s not found in agents list", agentID))
		}

		privacy := args[0]
		if privacy != "public" && privacy != "private" {
			fatal(fmt.Errorf("invalid privacy: %s (must be \"public\" or \"private\")", privacy))
		}

		resp, err := client.PatchAgent(ctx, agentID, &aweb.PatchAgentRequest{
			Privacy: privacy,
		})
		if err != nil {
			fatal(err)
		}
		printOutput(agentPatchOutput{
			PatchAgentResponse: resp,
			Alias:              sel.AgentAlias,
		}, formatAgentPatch)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentsCmd)
	agentCmd.AddCommand(agentAccessModeCmd)
	agentCmd.AddCommand(agentPrivacyCmd)
	rootCmd.AddCommand(agentCmd)
}
