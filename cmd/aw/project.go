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
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Server endpoint is still /v1/projects/current; user-facing term is "namespace".
		resp, err := client.GetCurrentProject(ctx)
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(namespaceCmd)
}
