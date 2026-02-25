package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

var namespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Show current namespace",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Server endpoint is still /v1/projects/current; user-facing term is "namespace".
		resp, err := mustClient().GetCurrentProject(ctx)
		if err != nil {
			fatal(err)
		}
		printOutput(resp, formatNamespace)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(namespaceCmd)
}
