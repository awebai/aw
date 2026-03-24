package run

import "testing"

func TestFormatToolCallLinesUsesMinimalShellStyle(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": "go test ./... 2>&1",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != ">_ go test ./... 2>&1" {
		t.Fatalf("unexpected tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesKeepsToolNameForNonShellTools(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "View",
		Input: map[string]any{
			"path": "/tmp/image.png",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != ">_ View /tmp/image.png" {
		t.Fatalf("unexpected tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesCompactsMailSendCommands(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw mail send --to dave --subject "Review" --body "please take a look"`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != "-> dave (mail)" {
		t.Fatalf("unexpected mail tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesCompactsChatSendCommands(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw chat send-and-wait henry "can you review this?" --start-conversation`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != "-> henry (chat)" {
		t.Fatalf("unexpected chat tool line %q", lines[0])
	}
}
