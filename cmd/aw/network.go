package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

// publish

var (
	publishCapabilities string
	publishDescription  string
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish an agent to the network directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		agentID := sel.AgentID
		if agentID == "" {
			return usageError("No agent_id in config; run 'aw init' first")
		}

		var caps []string
		if publishCapabilities != "" {
			for _, cap := range strings.Split(publishCapabilities, ",") {
				cap = strings.TrimSpace(cap)
				if cap != "" {
					caps = append(caps, cap)
				}
			}
		}

		resp, err := c.NetworkPublishAgent(ctx, &aweb.NetworkPublishRequest{
			AgentID:      agentID,
			Capabilities: caps,
			Description:  publishDescription,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatPublish)
		return nil
	},
}

// unpublish

var unpublishAlias string

var unpublishCmd = &cobra.Command{
	Use:   "unpublish",
	Short: "Remove an agent from the network directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		alias := unpublishAlias
		if alias == "" {
			_, sel, err := resolveClientSelection()
			if err != nil {
				return err
			}
			alias = sel.AgentAlias
		}
		if alias == "" {
			return usageError("No alias specified and none in config; use --alias or run 'aw init' first")
		}

		c, err := resolveClient()
		if err != nil {
			return err
		}
		if err := c.NetworkUnpublishAgent(ctx, alias); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Unpublished %s\n", alias)
		return nil
	},
}

// directory

var (
	directoryCapability string
	directoryOrgSlug    string
	directoryQuery      string
	directoryLimit      int
)

var directoryCmd = &cobra.Command{
	Use:   "directory [org-slug/alias]",
	Short: "Search or look up agents in the network directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, err := resolveClient()
		if err != nil {
			return err
		}

		if len(args) == 1 {
			addr := aweb.ParseNetworkAddress(args[0])
			if !addr.IsNetwork {
				return usageError("Directory lookup requires org-slug/alias format, got: %q", args[0])
			}
			resp, err := c.NetworkDirectoryGet(ctx, addr.OrgSlug, addr.Alias)
			if err != nil {
				return err
			}
			printOutput(resp, formatDirectoryGet)
			return nil
		}

		resp, err := c.NetworkDirectorySearch(ctx, aweb.NetworkDirectoryParams{
			Capability: directoryCapability,
			OrgSlug:    directoryOrgSlug,
			Query:      directoryQuery,
			Limit:      directoryLimit,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatDirectorySearch)
		return nil
	},
}

func init() {
	publishCmd.Flags().StringVar(&publishCapabilities, "capabilities", "", "Comma-separated capabilities")
	publishCmd.Flags().StringVar(&publishDescription, "description", "", "Agent description")

	unpublishCmd.Flags().StringVar(&unpublishAlias, "alias", "", "Agent alias to unpublish (default: from config)")

	directoryCmd.Flags().StringVar(&directoryCapability, "capability", "", "Filter by capability")
	directoryCmd.Flags().StringVar(&directoryOrgSlug, "org-slug", "", "Filter by org slug")
	directoryCmd.Flags().StringVar(&directoryQuery, "query", "", "Search alias/description")
	directoryCmd.Flags().IntVar(&directoryLimit, "limit", 100, "Max results")

	rootCmd.AddCommand(publishCmd, unpublishCmd, directoryCmd)
}
