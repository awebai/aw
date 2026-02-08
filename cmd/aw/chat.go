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

// chatSend routes a message through the OSS or network path based on the alias format.
func chatSend(ctx context.Context, toAlias, message string, opts chat.SendOptions) (*chat.SendResult, error) {
	c, sel := mustResolve()
	addr := aweb.ParseNetworkAddress(toAlias)
	if addr.IsNetwork {
		return chat.SendNetwork(ctx, c, sel.AgentAlias, []string{addr.String()}, message, opts, chatStderrCallback)
	}
	return chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, opts, chatStderrCallback)
}

func chatOpen(ctx context.Context, alias string) (*chat.OpenResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.OpenNetwork(ctx, mustClient(), addr.String())
	}
	return chat.Open(ctx, mustClient(), alias)
}

func chatHistory(ctx context.Context, alias string) (*chat.HistoryResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.HistoryNetwork(ctx, mustClient(), addr.String())
	}
	return chat.History(ctx, mustClient(), alias)
}

func chatHangOn(ctx context.Context, alias, message string) (*chat.HangOnResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.HangOnNetwork(ctx, mustClient(), addr.String(), message)
	}
	return chat.HangOn(ctx, mustClient(), alias, message)
}

func chatListen(ctx context.Context, alias string, waitSeconds int) (*chat.SendResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.ListenNetwork(ctx, mustClient(), addr.String(), waitSeconds, chatStderrCallback)
	}
	return chat.Listen(ctx, mustClient(), alias, waitSeconds, chatStderrCallback)
}

func chatShowPending(ctx context.Context, alias string) (*chat.SendResult, error) {
	addr := aweb.ParseNetworkAddress(alias)
	if addr.IsNetwork {
		return chat.ShowPendingNetwork(ctx, mustClient(), addr.String())
	}
	return chat.ShowPending(ctx, mustClient(), alias)
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

		result, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
		})
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
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:    0,
			Leaving: true,
		})
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

		result, err := chatOpen(ctx, args[0])
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

		result, err := chatHistory(ctx, args[0])
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

		result, err := chatHangOn(ctx, args[0], args[1])
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

		result, err := chatListen(ctx, args[0], chatListenWait)
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

		result, err := chatShowPending(ctx, args[0])
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
