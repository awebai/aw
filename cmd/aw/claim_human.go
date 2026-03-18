package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var claimHumanEmail string

var claimHumanCmd = &cobra.Command{
	Use:   "claim-human",
	Short: "Attach a human account to your org for dashboard access",
	RunE: func(cmd *cobra.Command, args []string) error {
		if claimHumanEmail == "" {
			return usageError("missing required flag: --email")
		}

		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		email := claimHumanEmail
		resp, err := client.ClaimHuman(ctx, &awid.ClaimHumanRequest{
			Email: email,
		})
		if err != nil {
			return err
		}

		printOutput(resp, func(v any) string {
			r := v.(*awid.ClaimHumanResponse)
			return fmt.Sprintf("Verification email sent to %s. %s\n", email, r.Message)
		})
		return nil
	},
}

func init() {
	claimHumanCmd.Flags().StringVar(&claimHumanEmail, "email", "", "Email address for human account claim")
	rootCmd.AddCommand(claimHumanCmd)
}
