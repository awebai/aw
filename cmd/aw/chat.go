package main

import (
	"context"
	"fmt"
	"os"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Real-time chat",
}

func chatStderrCallback(kind, message string) {
	fmt.Fprintf(os.Stderr, "[chat:%s] %s\n", kind, message)
}

// chatSend routes a message through the OSS or network path based on the alias format.
func chatSend(ctx context.Context, toAlias, message string, opts chat.SendOptions) (*chat.SendResult, *awconfig.Selection, error) {
	c, sel := mustResolve()
	addr := aweb.ParseNetworkAddress(toAlias)
	if addr.IsNetwork {
		r, err := chat.SendNetwork(ctx, c, sel.AgentAlias, []string{addr.String()}, message, opts, chatStderrCallback)
		return r, sel, err
	}
	r, err := chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, opts, chatStderrCallback)
	return r, sel, err
}

func chatOpen(ctx context.Context, c *aweb.Client, alias string) (*chat.OpenResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.OpenNetwork(ctx, c, addr.String())
	}
	return chat.Open(ctx, c, alias)
}

func chatHistory(ctx context.Context, c *aweb.Client, alias string) (*chat.HistoryResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.HistoryNetwork(ctx, c, addr.String())
	}
	return chat.History(ctx, c, alias)
}

func chatExtendWait(ctx context.Context, c *aweb.Client, alias, message string) (*chat.ExtendWaitResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.ExtendWaitNetwork(ctx, c, addr.String(), message)
	}
	return chat.ExtendWait(ctx, c, alias, message)
}

func chatListen(ctx context.Context, c *aweb.Client, alias string, waitSeconds int) (*chat.SendResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.ListenNetwork(ctx, c, addr.String(), waitSeconds, chatStderrCallback)
	}
	return chat.Listen(ctx, c, alias, waitSeconds, chatStderrCallback)
}

func chatShowPending(ctx context.Context, c *aweb.Client, alias string) (*chat.SendResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.ShowPendingNetwork(ctx, c, addr.String())
	}
	return chat.ShowPending(ctx, c, alias)
}

// logChatEvent logs a single chat event to the communication log.
func logChatEvent(logsDir, accountName, myAddress string, ev chat.Event) {
	dir := "recv"
	if ev.FromAddress != "" {
		if ev.FromAddress == myAddress {
			dir = "send"
		}
	} else if ev.FromAgent == myAddress {
		dir = "send"
	}
	appendCommLog(logsDir, accountName, &CommLogEntry{
		Timestamp:    ev.Timestamp,
		Dir:          dir,
		Channel:      "chat",
		MessageID:    ev.MessageID,
		SessionID:    ev.SessionID,
		From:         ev.FromAddress,
		To:           ev.ToAddress,
		Body:         ev.Body,
		FromDID:      ev.FromDID,
		ToDID:        ev.ToDID,
		FromStableID: ev.FromStableID,
		ToStableID:   ev.ToStableID,
		Signature:    ev.Signature,
		SigningKeyID: ev.SigningKeyID,
		Verification: string(ev.VerificationStatus),
	})
}

// logChatEvents logs all message events from a list.
func logChatEvents(logsDir, accountName, myAddress string, events []chat.Event) {
	for _, ev := range events {
		if ev.Type != "message" {
			continue
		}
		logChatEvent(logsDir, accountName, myAddress, ev)
	}
}

// chat send-and-wait

var (
	chatSendAndWaitWait              int
	chatSendAndWaitStartConversation bool
	chatListenWait                   int
)

var chatSendAndWaitCmd = &cobra.Command{
	Use:   "send-and-wait <alias> <message>",
	Short: "Send a message and wait for a reply",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
		})
		if err != nil {
			networkFatal(err, args[0])
		}
		logsDir := defaultLogsDir()
		myAddr := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
		// Log the sent message.
		appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      myAddr,
			To:        args[0],
			Body:      args[1],
		})
		// Log any reply events.
		logChatEvents(logsDir, sel.AccountName, myAddr, result.Events)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat send-and-leave

var chatSendAndLeaveCmd = &cobra.Command{
	Use:   "send-and-leave <alias> <message>",
	Short: "Send a message and leave the conversation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:    0,
			Leaving: true,
		})
		if err != nil {
			networkFatal(err, args[0])
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias),
			To:        args[0],
			Body:      args[1],
		})
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat pending

var chatPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending chat sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := chat.Pending(ctx, mustClient())
		if err != nil {
			fatal(err)
		}
		printOutput(result, formatChatPending)
		return nil
	},
}

// chat open

var chatOpenCmd = &cobra.Command{
	Use:   "open <alias>",
	Short: "Open a chat session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel := mustResolve()
		result, err := chatOpen(ctx, c, args[0])
		if err != nil {
			fatal(err)
		}
		logsDir := defaultLogsDir()
		myAddr := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
		for _, m := range result.Messages {
			logChatEvent(logsDir, sel.AccountName, myAddr, m)
		}
		printOutput(result, formatChatOpen)
		return nil
	},
}

// chat history

var chatHistoryCmd = &cobra.Command{
	Use:   "history <alias>",
	Short: "Show chat history with alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, _ := mustResolve()
		result, err := chatHistory(ctx, c, args[0])
		if err != nil {
			fatal(err)
		}
		// History is a replay; skip logging to avoid duplicates.
		printOutput(result, formatChatHistory)
		return nil
	},
}

// chat extend-wait

var chatExtendWaitCmd = &cobra.Command{
	Use:   "extend-wait <alias> <message>",
	Short: "Ask the other party to wait longer",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel := mustResolve()
		result, err := chatExtendWait(ctx, c, args[0], args[1])
		if err != nil {
			fatal(err)
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias),
			To:        result.TargetAgent,
			Body:      args[1],
		})
		printOutput(result, formatChatExtendWait)
		return nil
	},
}

// chat listen

var chatListenCmd = &cobra.Command{
	Use:   "listen <alias>",
	Short: "Wait for a message without sending",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := chat.MaxSendTimeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, sel := mustResolve()
		result, err := chatListen(ctx, c, args[0], chatListenWait)
		if err != nil {
			fatal(err)
		}
		logsDir := defaultLogsDir()
		myAddr := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
		logChatEvents(logsDir, sel.AccountName, myAddr, result.Events)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat show-pending

var chatShowPendingCmd = &cobra.Command{
	Use:   "show-pending <alias>",
	Short: "Show pending messages for alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel := mustResolve()
		result, err := chatShowPending(ctx, c, args[0])
		if err != nil {
			fatal(err)
		}
		logsDir := defaultLogsDir()
		myAddr := deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias)
		logChatEvents(logsDir, sel.AccountName, myAddr, result.Events)
		printOutput(result, formatChatSend)
		return nil
	},
}

func init() {
	chatSendAndWaitCmd.Flags().IntVar(&chatSendAndWaitWait, "wait", chat.DefaultWait, "Seconds to wait for reply")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitStartConversation, "start-conversation", false, "Start conversation (5min default wait)")

	chatListenCmd.Flags().IntVar(&chatListenWait, "wait", chat.DefaultWait, "Seconds to wait for a message (0 = no wait)")

	chatCmd.AddCommand(chatSendAndWaitCmd, chatSendAndLeaveCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatExtendWaitCmd, chatShowPendingCmd, chatListenCmd)
	rootCmd.AddCommand(chatCmd)
}
