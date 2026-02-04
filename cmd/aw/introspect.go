package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

var introspectCmd = &cobra.Command{
	Use:   "introspect",
	Short: "Show current agent identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().Introspect(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
