package run

import (
	"strings"

	aweb "github.com/awebai/aw"
)

func ParseControlSubmission(text string) ControlEvent {
	text = strings.TrimSpace(text)
	switch text {
	case "/quit", "/exit":
		return ControlEvent{Type: ControlQuit}
	case "/stop":
		return ControlEvent{Type: ControlStop}
	case "/wait":
		return ControlEvent{Type: ControlWait}
	case "/resume":
		return ControlEvent{Type: ControlResume}
	case "/autofeed on":
		return ControlEvent{Type: ControlAutofeedOn}
	case "/autofeed off":
		return ControlEvent{Type: ControlAutofeedOff}
	default:
		return ControlEvent{Type: ControlPrompt, Text: text}
	}
}

func FormatInputLine(promptLabel string, value string) string {
	if strings.TrimSpace(promptLabel) == "" {
		promptLabel = DefaultInputPromptLabel
	}
	if value == "" {
		return promptLabel
	}
	return promptLabel + value
}

func InputValueFromLine(line string, promptLabel string) string {
	line = strings.TrimLeft(line, " \t")
	if strings.TrimSpace(promptLabel) == "" {
		promptLabel = DefaultInputPromptLabel
	}
	trimmedPrompt := strings.TrimSpace(promptLabel)
	if line == "" || line == trimmedPrompt {
		return ""
	}
	if strings.HasPrefix(line, promptLabel) {
		return strings.TrimPrefix(line, promptLabel)
	}
	if strings.HasPrefix(line, trimmedPrompt) {
		return strings.TrimPrefix(line, trimmedPrompt)
	}
	return line
}

func ControlEventFromAgentEvent(evt aweb.AgentEvent) (ControlEvent, bool) {
	switch evt.Type {
	case aweb.AgentEventControlPause:
		return ControlEvent{Type: ControlWait}, true
	case aweb.AgentEventControlResume:
		return ControlEvent{Type: ControlResume}, true
	case aweb.AgentEventControlInterrupt:
		return ControlEvent{Type: ControlStop}, true
	default:
		return ControlEvent{}, false
	}
}
