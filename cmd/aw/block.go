package main

import (
	"context"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var blockCmd = &cobra.Command{
	Use:   "block <address>",
	Short: "Block a namespace or agent address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().Block(ctx, &aweb.BlockRequest{
			Address: args[0],
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

var blockListCmd = &cobra.Command{
	Use:   "list",
	Short: "List blocked addresses",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ListBlocked(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

var unblockCmd = &cobra.Command{
	Use:   "unblock <address>",
	Short: "Unblock a namespace or agent address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := mustClient().Unblock(ctx, args[0]); err != nil {
			fatal(err)
		}
		printJSON(map[string]string{"address": args[0], "status": "unblocked"})
		return nil
	},
}

func init() {
	blockCmd.AddCommand(blockListCmd)
	rootCmd.AddCommand(blockCmd)
	rootCmd.AddCommand(unblockCmd)
}
