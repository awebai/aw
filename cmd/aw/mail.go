package main

import (
	"context"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var mailCmd = &cobra.Command{
	Use:   "mail",
	Short: "Agent messaging",
}

// mail send

var (
	mailSendToAgentID string
	mailSendToAlias   string
	mailSendSubject   string
	mailSendBody      string
	mailSendPriority  string
)

var mailSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message to another agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mailSendToAgentID == "" && mailSendToAlias == "" {
			return usageError("missing required flag: --to-alias or --to-agent-id")
		}
		if mailSendBody == "" {
			return usageError("missing required flag: --body")
		}
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if strings.HasPrefix(mailSendToAlias, "@") {
			handle := strings.TrimPrefix(mailSendToAlias, "@")
			if handle == "" {
				return usageError("empty handle: use @username")
			}
			resp, err := client.SendDM(ctx, &aweb.DMRequest{
				ToHandle: handle,
				Subject:  mailSendSubject,
				Body:     mailSendBody,
				Priority: mailSendPriority,
			})
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		}

		addr := aweb.ParseNetworkAddress(mailSendToAlias)
		if addr.IsNetwork {
			resp, err := client.NetworkSendMail(ctx, &aweb.NetworkMailRequest{
				ToAddress: addr.String(),
				Subject:   mailSendSubject,
				Body:      mailSendBody,
				Priority:  mailSendPriority,
			})
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		}

		resp, err := client.SendMessage(ctx, &aweb.SendMessageRequest{
			ToAgentID: mailSendToAgentID,
			ToAlias:   mailSendToAlias,
			Subject:   mailSendSubject,
			Body:      mailSendBody,
			Priority:  aweb.MessagePriority(mailSendPriority),
		})
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

// mail inbox

var (
	mailInboxUnreadOnly bool
	mailInboxLimit      int
)

var mailInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Inbox(ctx, aweb.InboxParams{
			UnreadOnly: mailInboxUnreadOnly,
			Limit:      mailInboxLimit,
		})
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

// mail ack

var mailAckMessageID string

var mailAckCmd = &cobra.Command{
	Use:   "ack",
	Short: "Acknowledge a message",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mailAckMessageID == "" {
			return usageError("missing required flag: --message-id")
		}
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.AckMessage(ctx, mailAckMessageID)
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	mailSendCmd.Flags().StringVar(&mailSendToAgentID, "to-agent-id", "", "Recipient agent_id")
	mailSendCmd.Flags().StringVar(&mailSendToAlias, "to-alias", "", "Recipient alias")
	mailSendCmd.Flags().StringVar(&mailSendSubject, "subject", "", "Subject")
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", "Body")
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")

	mailInboxCmd.Flags().BoolVar(&mailInboxUnreadOnly, "unread-only", false, "Only unread")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")

	mailAckCmd.Flags().StringVar(&mailAckMessageID, "message-id", "", "Message ID to acknowledge")

	mailCmd.AddCommand(mailSendCmd, mailInboxCmd, mailAckCmd)
	rootCmd.AddCommand(mailCmd)
}
