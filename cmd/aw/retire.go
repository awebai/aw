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
	c, sel := mustResolve()

	// Validate successor address format.
	parts := strings.SplitN(retireSuccessor, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fatal(fmt.Errorf("successor must be namespace/alias, got %q", retireSuccessor))
	}

	if sel.SigningKey == "" {
		fatal(fmt.Errorf("no signing key configured; retirement requires a self-custody identity"))
	}
	if sel.DID == "" {
		fatal(fmt.Errorf("no DID configured for this account"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve successor's DID from their address.
	resolver := &aweb.ServerResolver{Client: c}
	successorIdentity, err := resolver.Resolve(ctx, retireSuccessor)
	if err != nil {
		fatal(fmt.Errorf("resolve successor %q: %w", retireSuccessor, err))
	}

	resp, err := c.RetireAgent(ctx, &aweb.RetireAgentRequest{
		SuccessorDID:     successorIdentity.DID,
		SuccessorAddress: successorIdentity.Address,
	})
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Agent retired.\n")
	fmt.Printf("  did: %s\n", resp.DID)
	fmt.Printf("  successor: %s (%s)\n", resp.SuccessorAddress, resp.SuccessorDID)
	fmt.Printf("  retired_at: %s\n", resp.RetiredAt)

	return nil
}
