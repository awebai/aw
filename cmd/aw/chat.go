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
		toAlias := args[0]
		message := args[1]

		timeout := chat.MaxSendTimeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		addr := aweb.ParseNetworkAddress(toAlias)
		if addr.IsNetwork {
			resp, err := mustClient().NetworkCreateChat(ctx, &aweb.NetworkChatCreateRequest{
				ToAddresses: []string{addr.String()},
				Message:     message,
			})
			if err != nil {
				fatal(err)
			}
			printJSON(resp)
			return nil
		}

		c, sel := mustResolve()
		result, err := chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
		}, chatStderrCallback)
		if err != nil {
			fatal(err)
		}
		printJSON(result)
		return nil
	},
}

// chat send-and-leave

var chatSendAndLeaveCmd = &cobra.Command{
	Use:   "send-and-leave <alias> <message>",
	Short: "Send a message and leave the conversation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		toAlias := args[0]
		message := args[1]

		timeout := chat.MaxSendTimeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		addr := aweb.ParseNetworkAddress(toAlias)
		if addr.IsNetwork {
			resp, err := mustClient().NetworkCreateChat(ctx, &aweb.NetworkChatCreateRequest{
				ToAddresses: []string{addr.String()},
				Message:     message,
				Leaving:     true,
			})
			if err != nil {
				fatal(err)
			}
			printJSON(resp)
			return nil
		}

		c, sel := mustResolve()
		result, err := chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, chat.SendOptions{
			Wait:    0,
			Leaving: true,
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

// chat listen

var chatListenCmd = &cobra.Command{
	Use:   "listen <alias>",
	Short: "Wait for a message without sending",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := chat.MaxSendTimeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		result, err := chat.Listen(ctx, mustClient(), args[0], chatListenWait, chatStderrCallback)
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
	chatSendAndWaitCmd.Flags().IntVar(&chatSendAndWaitWait, "wait", chat.DefaultWait, "Seconds to wait for reply")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitStartConversation, "start-conversation", false, "Start conversation (5min default wait)")

	chatListenCmd.Flags().IntVar(&chatListenWait, "wait", chat.DefaultWait, "Seconds to wait for a message (0 = no wait)")

	chatCmd.AddCommand(chatSendAndWaitCmd, chatSendAndLeaveCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatHangOnCmd, chatShowPendingCmd, chatListenCmd)
	rootCmd.AddCommand(chatCmd)
}
