package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	inviteAlias   string
	inviteAccess  string
	inviteExpires string
	inviteUses    int
)

type inviteCreateOutput struct {
	*awid.InviteCreateResponse
	InitCommand string `json:"init_command"`
}

type inviteRevokeOutput struct {
	Status      string `json:"status"`
	TokenPrefix string `json:"token_prefix"`
}

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Create and manage CLI invite tokens",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		if inviteUses < 1 {
			return usageError("--uses must be >= 1")
		}
		expiresInSeconds, err := parseInviteExpirySeconds(inviteExpires)
		if err != nil {
			return err
		}
		accessMode, err := mapInviteAccessMode(inviteAccess)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.InviteCreate(ctx, &awid.InviteCreateRequest{
			AliasHint:        strings.TrimSpace(inviteAlias),
			AccessMode:       accessMode,
			MaxUses:          inviteUses,
			ExpiresInSeconds: expiresInSeconds,
		})
		if err != nil {
			return err
		}

		out := inviteCreateOutput{
			InviteCreateResponse: resp,
			InitCommand:          buildInviteInitCommand(resp.ServerURL, resp.Token, resp.AliasHint),
		}
		printOutput(out, formatInviteCreate)
		return nil
	},
}

var inviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List CLI invites",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.InviteList(ctx)
		if err != nil {
			return err
		}
		printOutput(resp, formatInviteList)
		return nil
	},
}

var inviteRevokeCmd = &cobra.Command{
	Use:   "revoke <prefix>",
	Short: "Revoke a CLI invite by token prefix",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		prefix := strings.TrimSpace(args[0])
		if prefix == "" {
			return usageError("invite prefix is required")
		}

		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		list, err := client.InviteList(ctx)
		if err != nil {
			return err
		}
		match, err := findInviteByPrefix(list.Invites, prefix)
		if err != nil {
			return err
		}
		if err := client.InviteRevoke(ctx, match.InviteID); err != nil {
			return err
		}
		printOutput(inviteRevokeOutput{
			Status:      "revoked",
			TokenPrefix: match.TokenPrefix,
		}, formatInviteRevoke)
		return nil
	},
}

func init() {
	inviteCmd.Flags().StringVar(&inviteAlias, "alias", "", "Pre-assign an alias hint for the invitee")
	inviteCmd.Flags().StringVar(&inviteAccess, "access", "open", "Access mode: project|owner|contacts|open")
	inviteCmd.Flags().StringVar(&inviteExpires, "expires", "24h", "Invite lifetime (examples: 24h, 7d)")
	inviteCmd.Flags().IntVar(&inviteUses, "uses", 1, "Maximum number of invite uses")
	inviteCmd.AddCommand(inviteListCmd)
	inviteCmd.AddCommand(inviteRevokeCmd)
	rootCmd.AddCommand(inviteCmd)
}

func parseInviteExpirySeconds(raw string) (int, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		value = "24h"
	}
	if strings.HasSuffix(value, "d") {
		days := strings.TrimSuffix(value, "d")
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil || n <= 0 {
			return 0, usageError("invalid --expires value (examples: 24h, 7d)")
		}
		return n * 24 * 60 * 60, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, usageError("invalid --expires value (examples: 24h, 7d)")
	}
	return int(d.Seconds()), nil
}

func mapInviteAccessMode(raw string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", "open":
		return "open", nil
	case "project", "project_only":
		return "project_only", nil
	case "owner", "owner_only":
		return "owner_only", nil
	case "contacts", "contacts_only":
		return "contacts_only", nil
	default:
		return "", usageError("invalid --access value (use project|owner|contacts|open)")
	}
}

func inviteTTLLabel(seconds int) string {
	if seconds%(24*60*60) == 0 {
		days := seconds / (24 * 60 * 60)
		if days == 1 {
			return "24h"
		}
		return fmt.Sprintf("%dd", days)
	}
	return formatDuration(seconds)
}

func buildInviteInitCommand(serverURL, token, alias string) string {
	var parts []string
	parts = append(parts, "aw", "init", "--invite", token)
	if rootURL, err := cloudRootBaseURL(serverURL); err == nil && strings.TrimSpace(rootURL) != "" {
		if strings.TrimSuffix(rootURL, "/") != strings.TrimSuffix(DefaultServerURL, "/") {
			parts = append(parts, "--server", rootURL)
		}
	}
	if strings.TrimSpace(alias) != "" {
		parts = append(parts, "--alias", alias)
	} else {
		parts = append(parts, "--alias", "<choose-an-alias>")
	}
	return strings.Join(parts, " ")
}

func formatInviteCreate(v any) string {
	out := v.(inviteCreateOutput)
	usesText := "single use"
	if out.MaxUses != 1 {
		usesText = fmt.Sprintf("%d uses", out.MaxUses)
	}
	ttl := inviteTTLLabel(ttlRemainingSeconds(out.ExpiresAt, time.Now().UTC()))
	if ttl == "0s" {
		ttl = out.ExpiresAt
	}
	return fmt.Sprintf("Invite created (expires in %s, %s)\n\nRun this on the target machine:\n  %s\n", ttl, usesText, out.InitCommand)
}

func formatInviteList(v any) string {
	resp := v.(*awid.InviteListResponse)
	if len(resp.Invites) == 0 {
		return "No invites.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-16s %-6s %-12s %s\n", "PREFIX", "ALIAS HINT", "USES", "EXPIRES", "CREATED")
	for _, invite := range resp.Invites {
		alias := strings.TrimSpace(invite.AliasHint)
		if alias == "" {
			alias = "—"
		}
		fmt.Fprintf(&b, "%-10s %-16s %-6s %-12s %s\n",
			invite.TokenPrefix,
			alias,
			fmt.Sprintf("%d/%d", invite.CurrentUses, invite.MaxUses),
			formatInviteDate(invite.ExpiresAt),
			formatInviteDate(invite.CreatedAt),
		)
	}
	return b.String()
}

func formatInviteDate(timestamp string) string {
	ts, ok := parseTimeBestEffort(timestamp)
	if !ok {
		return timestamp
	}
	return ts.UTC().Format("2006-01-02")
}

func formatInviteRevoke(v any) string {
	out := v.(inviteRevokeOutput)
	return fmt.Sprintf("Invite %s revoked\n", out.TokenPrefix)
}

func findInviteByPrefix(invites []awid.InviteListItem, prefix string) (*awid.InviteListItem, error) {
	var matches []awid.InviteListItem
	for i := range invites {
		if strings.HasPrefix(invites[i].TokenPrefix, prefix) {
			matches = append(matches, invites[i])
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("invite prefix %s not found", prefix)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("invite prefix %s is ambiguous", prefix)
	}
	return &matches[0], nil
}

func newUnauthenticatedCloudClient(baseURL string) (*aweb.Client, error) {
	rootURL, err := cloudRootBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return aweb.New(rootURL)
}
