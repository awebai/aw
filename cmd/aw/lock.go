package main

import (
	"context"
	"fmt"
	"os"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Distributed locks",
}

// lock acquire

var (
	lockAcquireResourceKey string
	lockAcquireTTLSeconds  int
)

var lockAcquireCmd = &cobra.Command{
	Use:   "acquire",
	Short: "Acquire a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockAcquireResourceKey == "" {
			fmt.Fprintln(os.Stderr, "Missing required flags")
			os.Exit(2)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ReservationAcquire(ctx, &aweb.ReservationAcquireRequest{
			ResourceKey: lockAcquireResourceKey,
			TTLSeconds:  lockAcquireTTLSeconds,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

// lock renew

var (
	lockRenewResourceKey string
	lockRenewTTLSeconds  int
)

var lockRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockRenewResourceKey == "" {
			fmt.Fprintln(os.Stderr, "Missing required flag: --resource-key")
			os.Exit(2)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ReservationRenew(ctx, &aweb.ReservationRenewRequest{
			ResourceKey: lockRenewResourceKey,
			TTLSeconds:  lockRenewTTLSeconds,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

// lock release

var lockReleaseResourceKey string

var lockReleaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Release a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockReleaseResourceKey == "" {
			fmt.Fprintln(os.Stderr, "Missing required flags")
			os.Exit(2)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ReservationRelease(ctx, &aweb.ReservationReleaseRequest{
			ResourceKey: lockReleaseResourceKey,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

// lock revoke

var lockRevokePrefix string

var lockRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke locks",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ReservationRevoke(ctx, &aweb.ReservationRevokeRequest{
			Prefix: lockRevokePrefix,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

// lock list

var lockListPrefix string

var lockListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active locks",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ReservationList(ctx, lockListPrefix)
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	lockAcquireCmd.Flags().StringVar(&lockAcquireResourceKey, "resource-key", "", "Opaque resource key")
	lockAcquireCmd.Flags().IntVar(&lockAcquireTTLSeconds, "ttl-seconds", 3600, "TTL seconds")

	lockRenewCmd.Flags().StringVar(&lockRenewResourceKey, "resource-key", "", "Opaque resource key")
	lockRenewCmd.Flags().IntVar(&lockRenewTTLSeconds, "ttl-seconds", 3600, "TTL seconds")

	lockReleaseCmd.Flags().StringVar(&lockReleaseResourceKey, "resource-key", "", "Opaque resource key")

	lockRevokeCmd.Flags().StringVar(&lockRevokePrefix, "prefix", "", "Optional prefix filter")

	lockListCmd.Flags().StringVar(&lockListPrefix, "prefix", "", "Prefix filter")

	lockCmd.AddCommand(lockAcquireCmd, lockRenewCmd, lockReleaseCmd, lockRevokeCmd, lockListCmd)
	rootCmd.AddCommand(lockCmd)
}
