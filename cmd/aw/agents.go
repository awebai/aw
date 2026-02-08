package main

import (
	"context"
	"fmt"
	"os"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List agents in project",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ListAgents(ctx)
		if err != nil {
			fatal(err)
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

		client, sel := mustResolve()

		if len(args) == 0 {
			// GET: show current access mode.
			// Use introspect to find our agent_id, then list agents to find our entry.
			intro, err := client.Introspect(ctx)
			if err != nil {
				fatal(err)
			}
			if intro.AgentID == "" && sel.AgentID != "" {
				intro.AgentID = sel.AgentID
			}
			if intro.AgentID == "" {
				fmt.Fprintln(os.Stderr, "cannot determine agent_id: not an agent-scoped key")
				os.Exit(1)
			}
			agents, err := client.ListAgents(ctx)
			if err != nil {
				fatal(err)
			}
			for _, a := range agents.Agents {
				if a.AgentID == intro.AgentID {
					printJSON(map[string]string{
						"agent_id":    a.AgentID,
						"access_mode": a.AccessMode,
					})
					return nil
				}
			}
			fmt.Fprintf(os.Stderr, "agent %s not found in agents list\n", intro.AgentID)
			os.Exit(1)
		}

		// SET: patch access mode.
		mode := args[0]
		if mode != "open" && mode != "contacts_only" {
			fmt.Fprintf(os.Stderr, "invalid access mode: %s (must be \"open\" or \"contacts_only\")\n", mode)
			os.Exit(1)
		}

		intro, err := client.Introspect(ctx)
		if err != nil {
			fatal(err)
		}
		if intro.AgentID == "" && sel.AgentID != "" {
			intro.AgentID = sel.AgentID
		}
		if intro.AgentID == "" {
			fmt.Fprintln(os.Stderr, "cannot determine agent_id: not an agent-scoped key")
			os.Exit(1)
		}

		resp, err := client.PatchAgent(ctx, intro.AgentID, &aweb.PatchAgentRequest{
			AccessMode: mode,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentsCmd)
	agentCmd.AddCommand(agentAccessModeCmd)
	rootCmd.AddCommand(agentCmd)
}
