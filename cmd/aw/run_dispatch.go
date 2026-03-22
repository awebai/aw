package main

import (
	"context"
	"fmt"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	awrun "github.com/awebai/aw/run"
)

type runWakeValidator func(context.Context, awid.AgentEvent) (bool, error)

type runDispatcher struct {
	workPromptSuffix  string
	commsPromptSuffix string
	validateWake      runWakeValidator
}

func newRunDispatcher(settings awrun.Settings, validateWake runWakeValidator) awrun.Dispatcher {
	return runDispatcher{
		workPromptSuffix:  strings.TrimSpace(settings.WorkPromptSuffix),
		commsPromptSuffix: strings.TrimSpace(settings.CommsPromptSuffix),
		validateWake:      validateWake,
	}
}

func (d runDispatcher) Next(ctx context.Context, autofeed bool, wakeEvent *awid.AgentEvent) (awrun.DispatchDecision, error) {
	if wakeEvent == nil {
		return awrun.DispatchDecision{Skip: true}, nil
	}

	switch wakeEvent.Type {
	case awid.AgentEventMailMessage, awid.AgentEventChatMessage, awid.AgentEventActionableMail, awid.AgentEventActionableChat:
		if d.validateWake != nil && wakeEvent.IsActionableCoordination() {
			ok, err := d.validateWake(ctx, *wakeEvent)
			if err != nil {
				return awrun.DispatchDecision{}, err
			}
			if !ok {
				return awrun.DispatchDecision{Skip: true, WaitSeconds: awrun.DefaultWaitSeconds}, nil
			}
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(formatCommsWakePrompt(*wakeEvent), d.commsPromptSuffix),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
		if !autofeed {
			return awrun.DispatchDecision{Skip: true}, nil
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(formatWorkWakePrompt(*wakeEvent), d.workPromptSuffix),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	default:
		return awrun.DispatchDecision{Skip: true}, nil
	}
}

func newRunWakeValidator(client *aweb.Client) runWakeValidator {
	if client == nil || client.Client == nil {
		return nil
	}
	return func(ctx context.Context, evt awid.AgentEvent) (bool, error) {
		switch evt.Type {
		case awid.AgentEventActionableChat:
			return validateActionableChatWake(ctx, client, evt)
		case awid.AgentEventActionableMail:
			return validateActionableMailWake(ctx, client, evt)
		default:
			return true, nil
		}
	}
}

func validateActionableChatWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (bool, error) {
	sessionID := strings.TrimSpace(evt.SessionID)
	if sessionID == "" {
		return true, nil
	}
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return false, fmt.Errorf("check pending chat for wake %s: %w", sessionID, err)
	}
	for _, pending := range resp.Pending {
		if strings.TrimSpace(pending.SessionID) == sessionID {
			return true, nil
		}
	}
	return false, nil
}

func validateActionableMailWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (bool, error) {
	messageID := strings.TrimSpace(evt.MessageID)
	if messageID == "" {
		return true, nil
	}
	resp, err := client.Inbox(ctx, awid.InboxParams{UnreadOnly: true})
	if err != nil {
		return false, fmt.Errorf("check unread mail for wake %s: %w", messageID, err)
	}
	for _, msg := range resp.Messages {
		if strings.TrimSpace(msg.MessageID) == messageID {
			return true, nil
		}
	}
	return false, nil
}

func joinPromptSections(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, "\n\n")
}

func formatCommsWakePrompt(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventMailMessage, awid.AgentEventActionableMail:
		wakeMode := effectiveWakeMode(evt)
		parts := []string{
			fmt.Sprintf("Wake reason: new mail from %s.", formatWakeAlias(evt.FromAlias)),
			"Open your inbox, read the new mail, respond if needed, and update any relevant coordination state.",
		}
		if evt.Type == awid.AgentEventActionableMail {
			parts[0] = fmt.Sprintf("Wake reason: unread mail from %s.", formatWakeAlias(evt.FromAlias))
			if wakeMode == "interrupt" {
				parts[0] = fmt.Sprintf("Wake reason: urgent mail from %s.", formatWakeAlias(evt.FromAlias))
				parts[1] = "A coordination message needs immediate attention. Check unread mail first, respond to the blocking item, and then return to your prior task."
			}
		}
		if subject := strings.TrimSpace(evt.Subject); subject != "" {
			parts[0] = fmt.Sprintf("%s Subject: %q.", parts[0], subject)
		}
		if evt.UnreadCount > 0 {
			parts[0] = fmt.Sprintf("%s Unread: %d.", parts[0], evt.UnreadCount)
		}
		return strings.Join(parts, " ")
	case awid.AgentEventChatMessage, awid.AgentEventActionableChat:
		wakeMode := effectiveWakeMode(evt)
		parts := []string{
			fmt.Sprintf("Wake reason: new chat activity from %s.", formatWakeAlias(evt.FromAlias)),
			"Open the active chat, answer what is blocking them, and then continue your current work if nothing else changed.",
		}
		if evt.Type == awid.AgentEventActionableChat {
			parts[0] = fmt.Sprintf("Wake reason: chat from %s.", formatWakeAlias(evt.FromAlias))
			switch {
			case wakeMode == "interrupt":
				parts[0] = fmt.Sprintf("Wake reason: urgent chat from %s.", formatWakeAlias(evt.FromAlias))
				parts[1] = "Another agent is explicitly waiting on you. Open the chat immediately, unblock them, and then resume your work."
			case wakeMode == "idle":
				parts[1] = "Review the chat state when convenient, respond if needed, and then continue your current work."
			}
		}
		if sessionID := strings.TrimSpace(evt.SessionID); sessionID != "" {
			parts[0] = fmt.Sprintf("%s Session: %s.", parts[0], sessionID)
		}
		if evt.UnreadCount > 0 {
			parts[0] = fmt.Sprintf("%s Unread: %d.", parts[0], evt.UnreadCount)
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func effectiveWakeMode(evt awid.AgentEvent) string {
	mode := strings.ToLower(strings.TrimSpace(evt.WakeMode))
	if mode != "" {
		return mode
	}
	if evt.Type == awid.AgentEventActionableChat && evt.SenderWaiting {
		return "interrupt"
	}
	return ""
}

func formatWorkWakePrompt(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventWorkAvailable:
		return fmt.Sprintf(
			"Wake reason: work is available%s. Check ready work, claim the most appropriate task if needed, and continue the task-oriented cycle.",
			formatWakeTask(evt),
		)
	case awid.AgentEventClaimUpdate:
		status := ""
		if value := strings.TrimSpace(evt.Status); value != "" {
			status = fmt.Sprintf(" Status: %s.", value)
		}
		return fmt.Sprintf(
			"Wake reason: a claim changed%s.%s Review the updated claim state and adjust coordination before continuing.",
			formatWakeTask(evt),
			status,
		)
	case awid.AgentEventClaimRemoved:
		return fmt.Sprintf(
			"Wake reason: a claim was removed%s. Re-check ready work and coordination state before continuing.",
			formatWakeTask(evt),
		)
	default:
		return ""
	}
}

func formatWakeAlias(alias string) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "another agent"
	}
	return alias
}

func formatWakeTask(evt awid.AgentEvent) string {
	title := strings.TrimSpace(evt.Title)
	taskID := strings.TrimSpace(evt.TaskID)
	switch {
	case title != "" && taskID != "":
		return fmt.Sprintf(": %s (%s)", title, taskID)
	case title != "":
		return fmt.Sprintf(": %s", title)
	case taskID != "":
		return fmt.Sprintf(" (%s)", taskID)
	default:
		return ""
	}
}
