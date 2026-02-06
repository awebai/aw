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

		c, sel := mustResolve()
		agentID := sel.AgentID
		if agentID == "" {
			fmt.Fprintln(os.Stderr, "No agent_id in config; run 'aw init' first")
			os.Exit(2)
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
			fatal(err)
		}
		printJSON(resp)
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
			_, sel := mustResolve()
			alias = sel.AgentAlias
		}
		if alias == "" {
			fmt.Fprintln(os.Stderr, "No alias specified and none in config; use --alias or run 'aw init' first")
			os.Exit(2)
		}

		if err := mustClient().NetworkUnpublishAgent(ctx, alias); err != nil {
			fatal(err)
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

		c := mustClient()

		if len(args) == 1 {
			addr := aweb.ParseNetworkAddress(args[0])
			if !addr.IsNetwork {
				fmt.Fprintf(os.Stderr, "Directory lookup requires org-slug/alias format, got: %q\n", args[0])
				os.Exit(2)
			}
			resp, err := c.NetworkDirectoryGet(ctx, addr.OrgSlug, addr.Alias)
			if err != nil {
				fatal(err)
			}
			printJSON(resp)
			return nil
		}

		resp, err := c.NetworkDirectorySearch(ctx, aweb.NetworkDirectoryParams{
			Capability: directoryCapability,
			OrgSlug:    directoryOrgSlug,
			Query:      directoryQuery,
			Limit:      directoryLimit,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
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
