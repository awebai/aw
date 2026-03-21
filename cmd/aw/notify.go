package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Check for pending chat notifications for Claude Code hooks",
	Args:  cobra.NoArgs,
	RunE:  runNotify,
}

func init() {
	rootCmd.AddCommand(notifyCmd)
}

func runNotify(cmd *cobra.Command, args []string) error {
	c, sel, err := resolveClientSelection()
	if err != nil || c == nil || sel == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
	defer cancel()

	result, err := chat.Pending(ctx, c.Client)
	if err != nil || result == nil || len(result.Pending) == 0 {
		return nil
	}

	output := formatNotifyOutput(result, sel.AgentAlias)
	if output == "" {
		return nil
	}
	fmt.Print(formatHookOutput(output))
	return nil
}

func formatNotifyOutput(result *chat.PendingResult, selfAlias string) string {
	if result == nil || len(result.Pending) == 0 {
		return ""
	}

	var urgent []string
	var regular []string
	for _, pending := range result.Pending {
		from := strings.TrimSpace(pending.LastFrom)
		if from == "" {
			for _, participant := range pending.Participants {
				participant = strings.TrimSpace(participant)
				if participant == "" || participant == selfAlias {
					continue
				}
				from = participant
				break
			}
		}
		if from == "" {
			continue
		}
		if pending.SenderWaiting {
			urgent = append(urgent, from)
		} else {
			regular = append(regular, from)
		}
	}

	if len(urgent) == 0 && len(regular) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║         📬 AGENT: YOU HAVE PENDING CHAT MESSAGES             ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	for _, from := range urgent {
		sb.WriteString(padNotifyLine(fmt.Sprintf("║ ⚠️  URGENT: %s is WAITING for your reply", from)))
	}
	for _, from := range regular {
		sb.WriteString(padNotifyLine(fmt.Sprintf("║ 💬 Unread message from %s", from)))
	}
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║ YOU MUST RUN: aw chat pending                                ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("\n")
	return sb.String()
}

func padNotifyLine(line string) string {
	const width = 65
	if len(line) >= width {
		return line[:width] + "║\n"
	}
	return line + strings.Repeat(" ", width-len(line)) + "║\n"
}

func formatHookOutput(content string) string {
	output := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"additionalContext": content,
		},
	}
	data, _ := json.Marshal(output)
	return string(data)
}
