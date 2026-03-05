package main

import (
	"context"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

// introspectOutput combines the server's introspect response with local identity fields.
type introspectOutput struct {
	aweb.IntrospectResponse
	DID      string `json:"did,omitempty"`
	Custody  string `json:"custody,omitempty"`
	Lifetime string `json:"lifetime,omitempty"`
}

var introspectCmd = &cobra.Command{
	Use:     "introspect",
	Aliases: []string{"whoami"},
	Short:   "Show current agent identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Introspect(ctx)
		if err != nil {
			return err
		}

		alias := resp.Alias
		if alias == "" {
			alias = sel.AgentAlias
		}

		out := introspectOutput{
			IntrospectResponse: *resp,
			DID:                sel.DID,
			Custody:            sel.Custody,
			Lifetime:           sel.Lifetime,
		}
		// Prefer server-returned values; fall back to local config.
		if out.NamespaceSlug == "" {
			out.NamespaceSlug = sel.NamespaceSlug
		}
		if out.Address == "" {
			out.Address = deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, alias)
		}
		printOutput(out, formatIntrospect)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
