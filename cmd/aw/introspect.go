package main

import (
	"context"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

// introspectOutput combines the server's introspect response with local identity fields.
type introspectOutput struct {
	aweb.IntrospectResponse
	DID       string `json:"did,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Custody   string `json:"custody,omitempty"`
	Lifetime  string `json:"lifetime,omitempty"`
}

var introspectCmd = &cobra.Command{
	Use:     "introspect",
	Aliases: []string{"whoami"},
	Short:   "Show current agent identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, sel := mustResolve()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Introspect(ctx)
		if err != nil {
			fatal(err)
		}

		// Extract base58btc-encoded public key from DID (the suffix after "did:key:").
		var pubKey string
		if sel.DID != "" {
			pubKey = strings.TrimPrefix(sel.DID, "did:key:")
		}

		out := introspectOutput{
			IntrospectResponse: *resp,
			DID:                sel.DID,
			PublicKey:           pubKey,
			Custody:            sel.Custody,
			Lifetime:           sel.Lifetime,
		}
		printJSON(out)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
