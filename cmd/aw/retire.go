package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var retireSuccessor string

var agentRetireCmd = &cobra.Command{
	Use:   "retire",
	Short: "Retire this agent with a successor",
	Long:  "Mark this agent as retired on the server. The successor's DID is resolved from their address and linked.",
	RunE:  runAgentRetire,
}

func init() {
	agentRetireCmd.Flags().StringVar(&retireSuccessor, "successor", "", "Successor agent address (namespace/alias)")
	agentRetireCmd.MarkFlagRequired("successor")
	agentCmd.AddCommand(agentRetireCmd)
}

func runAgentRetire(cmd *cobra.Command, args []string) error {
	c, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	// Validate successor address format.
	parts := strings.SplitN(retireSuccessor, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return usageError("successor must be namespace/alias, got %q", retireSuccessor)
	}

	if sel.SigningKey == "" {
		return fmt.Errorf("no signing key configured; retirement requires a self-custody identity")
	}
	if sel.DID == "" {
		return fmt.Errorf("no DID configured for this account")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve successor to get their DID, address, and agent_id.
	resolver := &aweb.ServerResolver{Client: c}
	successorIdentity, err := resolver.Resolve(ctx, retireSuccessor)
	if err != nil {
		return fmt.Errorf("resolve successor %q: %w", retireSuccessor, err)
	}
	if successorIdentity.AgentID == "" {
		return fmt.Errorf("successor %q has no agent_id (server may not support resolution)", retireSuccessor)
	}
	if successorIdentity.DID == "" {
		return fmt.Errorf("successor %q has no DID", retireSuccessor)
	}

	resp, err := c.RetireAgent(ctx, &aweb.RetireAgentRequest{
		SuccessorAgentID: successorIdentity.AgentID,
		SuccessorDID:     successorIdentity.DID,
		SuccessorAddress: successorIdentity.Address,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Agent retired.\n")
	fmt.Printf("  status: %s\n", resp.Status)
	fmt.Printf("  successor: %s (agent_id: %s)\n", retireSuccessor, resp.SuccessorAgentID)

	return nil
}
