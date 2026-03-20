package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
	awrun "github.com/awebai/aw/run"
)

type runDispatcher struct {
	workPromptSuffix  string
	commsPromptSuffix string
}

func newRunDispatcher(settings awrun.Settings) awrun.Dispatcher {
	return runDispatcher{
		workPromptSuffix:  strings.TrimSpace(settings.WorkPromptSuffix),
		commsPromptSuffix: strings.TrimSpace(settings.CommsPromptSuffix),
	}
}

func (d runDispatcher) Next(_ context.Context, autofeed bool, wakeEvent *awid.AgentEvent) (awrun.DispatchDecision, error) {
	if wakeEvent == nil {
		return awrun.DispatchDecision{Skip: true}, nil
	}

	switch wakeEvent.Type {
	case awid.AgentEventMailMessage, awid.AgentEventChatMessage:
		return awrun.DispatchDecision{
			Prompt:      joinPromptSections(formatCommsWakePrompt(*wakeEvent), d.commsPromptSuffix),
			WaitSeconds: awrun.DefaultWaitSeconds,
		}, nil
	case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
		if !autofeed {
			return awrun.DispatchDecision{Skip: true}, nil
		}
		return awrun.DispatchDecision{
			Prompt:      joinPromptSections(formatWorkWakePrompt(*wakeEvent), d.workPromptSuffix),
			WaitSeconds: awrun.DefaultWaitSeconds,
		}, nil
	default:
		return awrun.DispatchDecision{Skip: true}, nil
	}
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
	case awid.AgentEventMailMessage:
		parts := []string{
			fmt.Sprintf("Wake reason: new mail from %s.", formatWakeAlias(evt.FromAlias)),
			"Open your inbox, read the new mail, respond if needed, and update any relevant coordination state.",
		}
		if subject := strings.TrimSpace(evt.Subject); subject != "" {
			parts[0] = fmt.Sprintf("%s Subject: %q.", parts[0], subject)
		}
		return strings.Join(parts, " ")
	case awid.AgentEventChatMessage:
		parts := []string{
			fmt.Sprintf("Wake reason: new chat activity from %s.", formatWakeAlias(evt.FromAlias)),
			"Open the active chat, answer what is blocking them, and then continue your current work if nothing else changed.",
		}
		if sessionID := strings.TrimSpace(evt.SessionID); sessionID != "" {
			parts[0] = fmt.Sprintf("%s Session: %s.", parts[0], sessionID)
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
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
