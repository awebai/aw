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
			fmt.Fprintln(os.Stderr, "Missing required flag: --to-alias or --to-agent-id")
			os.Exit(2)
		}
		if mailSendBody == "" {
			fmt.Fprintln(os.Stderr, "Missing required flag: --body")
			os.Exit(2)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel := mustResolve()
		logsDir := defaultLogsDir()

		if strings.HasPrefix(mailSendToAlias, "@") {
			handle := strings.TrimPrefix(mailSendToAlias, "@")
			if handle == "" {
				fatal(fmt.Errorf("empty handle: use @username"))
			}
			resp, err := c.SendDM(ctx, &aweb.DMRequest{
				ToHandle: handle,
				Subject:  mailSendSubject,
				Body:     mailSendBody,
				Priority: mailSendPriority,
			})
			if err != nil {
				networkFatal(err, mailSendToAlias)
			}
			appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Dir:       "send",
				Channel:   "dm",
				MessageID: resp.MessageID,
				From:      deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias),
				To:        "@" + handle,
				Subject:   mailSendSubject,
				Body:      mailSendBody,
			})
			if jsonFlag {
				printJSON(resp)
			} else {
				fmt.Printf("Sent DM to %s (message_id=%s)\n", mailSendToAlias, resp.MessageID)
			}
			return nil
		}

		addr := aweb.ParseNetworkAddress(mailSendToAlias)
		if addr.IsNetwork {
			resp, err := c.NetworkSendMail(ctx, &aweb.NetworkMailRequest{
				ToAddress: addr.String(),
				Subject:   mailSendSubject,
				Body:      mailSendBody,
				Priority:  mailSendPriority,
			})
			if err != nil {
				networkFatal(err, addr.String())
			}
			appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Dir:       "send",
				Channel:   "mail",
				MessageID: resp.MessageID,
				From:      resp.FromAddress,
				To:        resp.ToAddress,
				Subject:   mailSendSubject,
				Body:      mailSendBody,
			})
			if jsonFlag {
				printJSON(resp)
			} else {
				fmt.Printf("Sent mail to %s (message_id=%s)\n", addr.String(), resp.MessageID)
			}
			return nil
		}

		target := mailSendToAlias
		if target == "" {
			target = mailSendToAgentID
		}
		resp, err := c.SendMessage(ctx, &aweb.SendMessageRequest{
			ToAgentID: mailSendToAgentID,
			ToAlias:   mailSendToAlias,
			Subject:   mailSendSubject,
			Body:      mailSendBody,
			Priority:  aweb.MessagePriority(mailSendPriority),
		})
		if err != nil {
			fatal(err)
		}
		appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "mail",
			MessageID: resp.MessageID,
			From:      deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias),
			To:        target,
			Subject:   mailSendSubject,
			Body:      mailSendBody,
		})
		if jsonFlag {
			printJSON(resp)
		} else {
			fmt.Printf("Sent mail to %s (message_id=%s)\n", target, resp.MessageID)
		}
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel := mustResolve()
		resp, err := c.Inbox(ctx, aweb.InboxParams{
			UnreadOnly: mailInboxUnreadOnly,
			Limit:      mailInboxLimit,
		})
		if err != nil {
			fatal(err)
		}
		logsDir := defaultLogsDir()
		for _, msg := range resp.Messages {
			// Only log unread messages to avoid duplicates on repeated inbox calls.
			if msg.ReadAt != nil {
				continue
			}
			appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
				Timestamp:    msg.CreatedAt,
				Dir:          "recv",
				Channel:      "mail",
				MessageID:    msg.MessageID,
				From:         msg.FromAddress,
				To:           msg.ToAddress,
				Subject:      msg.Subject,
				Body:         msg.Body,
				FromDID:      msg.FromDID,
				ToDID:        msg.ToDID,
				FromStableID: msg.FromStableID,
				ToStableID:   msg.ToStableID,
				Signature:    msg.Signature,
				SigningKeyID: msg.SigningKeyID,
				Verification: string(msg.VerificationStatus),
			})
		}
		printOutput(resp, formatMailInbox)
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
			fmt.Fprintln(os.Stderr, "Missing required flag: --message-id")
			os.Exit(2)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().AckMessage(ctx, mailAckMessageID)
		if err != nil {
			fatal(err)
		}
		printOutput(resp, formatMailAck)
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
