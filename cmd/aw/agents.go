package main

import (
	"context"
	"time"

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

func init() {
	rootCmd.AddCommand(agentsCmd)
}
