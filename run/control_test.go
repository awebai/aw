package run

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseControlSubmissionHelp(t *testing.T) {
	event := ParseControlSubmission("/help")
	if event.Type != ControlHelp {
		t.Fatalf("expected ControlHelp, got %q", event.Type)
	}
}

func TestParseControlSubmissionRejectsUnknownSlashCommand(t *testing.T) {
	event := ParseControlSubmission("/foo")
	if event.Type != ControlUnknownCommand {
		t.Fatalf("expected ControlUnknownCommand, got %q", event.Type)
	}
	if event.Text != "/foo" {
		t.Fatalf("expected text '/foo', got %q", event.Text)
	}
}

func TestParseControlSubmissionPassesRegularText(t *testing.T) {
	event := ParseControlSubmission("hello world")
	if event.Type != ControlPrompt {
		t.Fatalf("expected ControlPrompt, got %q", event.Type)
	}
	if event.Text != "hello world" {
		t.Fatalf("expected text 'hello world', got %q", event.Text)
	}
}

func TestHelpEventPrintsCommands(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{}

	loop.applyControlEvent(ControlEvent{Type: ControlHelp}, st, false, nil)

	output := out.String()
	for _, cmd := range []string{"/wait", "/resume", "/stop", "/autofeed", "/quit", "/help"} {
		if !strings.Contains(output, cmd) {
			t.Errorf("help output missing %q, got %q", cmd, output)
		}
	}
}

func TestUnknownCommandEventPrintsError(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{}, &out)
	st := &state{}

	loop.applyControlEvent(ControlEvent{Type: ControlUnknownCommand, Text: "/foo"}, st, false, nil)

	output := out.String()
	if !strings.Contains(output, "unknown command: /foo") {
		t.Fatalf("expected unknown command error, got %q", output)
	}
	if !strings.Contains(output, "/help") {
		t.Fatalf("expected /help hint in error, got %q", output)
	}
}
