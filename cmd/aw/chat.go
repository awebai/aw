package main

import (
	"context"
	"fmt"
	"os"
	"time"

	aweb "github.com/awebai/aw"
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

// chat send

var (
	chatSendWait              int
	chatSendLeaveConversation bool
	chatSendStartConversation bool
)

var chatSendCmd = &cobra.Command{
	Use:   "send <alias> <message>",
	Short: "Send a chat message",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		toAlias := args[0]
		message := args[1]

		timeout := time.Duration(chatSendWait+30) * time.Second
		if timeout < 10*time.Second {
			timeout = 10 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		addr := aweb.ParseNetworkAddress(toAlias)
		if addr.IsNetwork {
			resp, err := mustClient().NetworkCreateChat(ctx, &aweb.NetworkChatCreateRequest{
				ToAddresses: []string{toAlias},
				Message:     message,
				Leaving:     chatSendLeaveConversation,
			})
			if err != nil {
				fatal(err)
			}
			printJSON(resp)
			return nil
		}

		c, sel := mustResolve()
		result, err := chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, chat.SendOptions{
			Wait:              chatSendWait,
			Leaving:           chatSendLeaveConversation,
			StartConversation: chatSendStartConversation,
		}, chatStderrCallback)
		if err != nil {
			fatal(err)
		}
		printJSON(result)
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
		printJSON(result)
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

		result, err := chat.Open(ctx, mustClient(), args[0])
		if err != nil {
			fatal(err)
		}
		printJSON(result)
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

		result, err := chat.History(ctx, mustClient(), args[0])
		if err != nil {
			fatal(err)
		}
		printJSON(result)
		return nil
	},
}

// chat hang-on

var chatHangOnCmd = &cobra.Command{
	Use:   "hang-on <alias> <message>",
	Short: "Send a hang-on message",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := chat.HangOn(ctx, mustClient(), args[0], args[1])
		if err != nil {
			fatal(err)
		}
		printJSON(result)
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

		result, err := chat.ShowPending(ctx, mustClient(), args[0])
		if err != nil {
			fatal(err)
		}
		printJSON(result)
		return nil
	},
}

func init() {
	chatSendCmd.Flags().IntVar(&chatSendWait, "wait", 60, "Seconds to wait for reply (0 = no wait)")
	chatSendCmd.Flags().BoolVar(&chatSendLeaveConversation, "leave-conversation", false, "Send and leave conversation")
	chatSendCmd.Flags().BoolVar(&chatSendStartConversation, "start-conversation", false, "Start conversation (5min default wait)")

	chatCmd.AddCommand(chatSendCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatHangOnCmd, chatShowPendingCmd)
	rootCmd.AddCommand(chatCmd)
}
