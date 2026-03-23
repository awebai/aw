package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var retireSuccessor string

var identityReplaceCmd = &cobra.Command{
	Use:   "replace",
	Short: "Replace this permanent identity with a successor",
	Long:  "Link this permanent identity to its successor so continuity can move to the replacement identity.",
	RunE:  runIdentityReplace,
}

func init() {
	identityReplaceCmd.Flags().StringVar(&retireSuccessor, "successor", "", "Successor permanent identity address (namespace/name)")
	identityReplaceCmd.MarkFlagRequired("successor")
	identityCmd.AddCommand(identityReplaceCmd)
}

func runIdentityReplace(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("no signing key configured; replacement requires a self-custodial permanent identity")
	}
	if sel.DID == "" {
		return fmt.Errorf("no DID configured for this identity")
	}
	if awid.IdentityClassFromLifetime(sel.Lifetime) != awid.IdentityClassPermanent {
		return usageError("identity replace only applies to permanent identities; use `aw identity decommission --confirm` for ephemeral identities")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve successor to get their DID, address, and agent_id.
	resolver := &awid.ServerResolver{Client: c.Client}
	successorIdentity, err := resolver.Resolve(ctx, retireSuccessor)
	if err != nil {
		return fmt.Errorf("resolve successor %q: %w", retireSuccessor, err)
	}
	if successorIdentity.AgentID == "" {
		return fmt.Errorf("successor %q has no identity id (server may not support resolution)", retireSuccessor)
	}
	if successorIdentity.DID == "" {
		return fmt.Errorf("successor %q has no DID", retireSuccessor)
	}

	resp, err := c.RetireAgent(ctx, &awid.RetireAgentRequest{
		SuccessorAgentID: successorIdentity.AgentID,
		SuccessorDID:     successorIdentity.DID,
		SuccessorAddress: successorIdentity.Address,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Identity replaced.\n")
	fmt.Printf("  status: %s\n", resp.Status)
	fmt.Printf("  successor: %s (identity_id: %s)\n", retireSuccessor, resp.SuccessorAgentID)

	return nil
}
