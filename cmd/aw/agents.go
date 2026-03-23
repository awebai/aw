package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// agentsListOutput wraps the server response with local config fields for display.
type agentsListOutput struct {
	*awid.ListAgentsResponse
	ProjectSlug string `json:"project_slug,omitempty"`
}

// identityPatchOutput wraps the server response with the identity alias for display.
type identityPatchOutput struct {
	*awid.PatchAgentResponse
	Alias string `json:"alias,omitempty"`
}

// resolveCurrentIdentityID resolves the current identity's server ID via
// introspect, falling back to the configured agent_id field in the selection.
func resolveCurrentIdentityID(ctx context.Context, client *aweb.Client, sel *awconfig.Selection) (string, error) {
	intro, err := client.Introspect(ctx)
	if err != nil {
		return "", err
	}
	if intro.AgentID == "" && sel.AgentID != "" {
		return sel.AgentID, nil
	}
	if intro.AgentID == "" {
		return "", fmt.Errorf("cannot determine identity id: API key is not bound to an identity")
	}
	return intro.AgentID, nil
}

var identitiesCmd = &cobra.Command{
	Use:   "identities",
	Short: "List identities in the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := client.ListAgents(ctx)
		if err != nil {
			return err
		}
		printOutput(agentsListOutput{
			ListAgentsResponse: resp,
			ProjectSlug:        sel.NamespaceSlug,
		}, formatAgentsList)
		return nil
	},
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Identity lifecycle, settings, and key management",
}

var agentAccessModeCmd = &cobra.Command{
	Use:   "access-mode [open|contacts_only]",
	Short: "Get or set identity access mode",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID, err := resolveCurrentIdentityID(ctx, client, sel)
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
					printOutput(map[string]string{
						"agent_id":    a.AgentID,
						"alias":       a.Alias,
						"access_mode": a.AccessMode,
					}, formatAgentAccessMode)
					return nil
				}
			}
			return fmt.Errorf("identity %s not found in identities list", agentID)
		}

		// SET: patch access mode.
		mode := args[0]
		if mode != "open" && mode != "contacts_only" {
			return fmt.Errorf("invalid access mode: %s (must be \"open\" or \"contacts_only\")", mode)
		}

		resp, err := client.PatchAgent(ctx, agentID, &awid.PatchAgentRequest{
			AccessMode: mode,
		})
		if err != nil {
			return err
		}
		printOutput(identityPatchOutput{
			PatchAgentResponse: resp,
			Alias:              sel.AgentAlias,
		}, formatAgentPatch)
		return nil
	},
}

var agentPrivacyCmd = &cobra.Command{
	Use:   "privacy [public|private]",
	Short: "Get or set identity privacy",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID, err := resolveCurrentIdentityID(ctx, client, sel)
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
					printOutput(map[string]string{
						"agent_id": a.AgentID,
						"alias":    a.Alias,
						"privacy":  a.Privacy,
					}, formatAgentPrivacy)
					return nil
				}
			}
			return fmt.Errorf("identity %s not found in identities list", agentID)
		}

		privacy := args[0]
		if privacy != "public" && privacy != "private" {
			return fmt.Errorf("invalid privacy: %s (must be \"public\" or \"private\")", privacy)
		}

		resp, err := client.PatchAgent(ctx, agentID, &awid.PatchAgentRequest{
			Privacy: privacy,
		})
		if err != nil {
			return err
		}
		printOutput(identityPatchOutput{
			PatchAgentResponse: resp,
			Alias:              sel.AgentAlias,
		}, formatAgentPatch)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(identitiesCmd)
	identityCmd.AddCommand(agentAccessModeCmd)
	identityCmd.AddCommand(agentPrivacyCmd)
	rootCmd.AddCommand(identityCmd)
}
