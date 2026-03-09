package run

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestAppendScreenTextTracksCompleteAndPartialLines(t *testing.T) {
	lines := []string{}
	current := ""

	appendScreenText(&lines, &current, "first line\nsecond")
	appendScreenText(&lines, &current, " line\nthird line\n")

	if len(lines) != 3 {
		t.Fatalf("expected 3 completed lines, got %d", len(lines))
	}
	if lines[0] != "first line" || lines[1] != "second line" || lines[2] != "third line" {
		t.Fatalf("unexpected completed lines: %#v", lines)
	}
	if current != "" {
		t.Fatalf("expected no trailing partial line, got %q", current)
	}
}

func TestStyleScreenLineCategories(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{line: "run #1  12:00:00  >  prompt", want: "run_header"},
		{line: `- Bash("go test ./... 2>&1")`, want: "tool"},
		{line: "  -> ok", want: "result"},
		{line: "done  2.1s", want: "done"},
		{line: "info: session", want: "info"},
		{line: "type /wait, /autofeed off, /stop", want: "hint"},
		{line: "plain text", want: "plain"},
	}

	for _, tc := range cases {
		if got := screenLineStyleKind(tc.line); got != tc.want {
			t.Fatalf("line %q: expected %s, got %s", tc.line, tc.want, got)
		}
	}
}

func TestStyleScreenLineKeepsToolArgumentsNeutralOnFirstLine(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(`- View("/tmp/image.png")`, styles)
	want := styles.tool.Render(`- View(`) + `"/tmp/image.png"` + styles.tool.Render(`)`)
	if got != want {
		t.Fatalf("unexpected styled tool line %q", got)
	}
}

func TestStyleScreenLineColorsClosingParenOnContinuation(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(`       offset=48)`, styles)
	want := `       offset=48` + styles.tool.Render(`)`)
	if got != want {
		t.Fatalf("unexpected styled continuation line %q", got)
	}
}

func TestScreenControllerSetInputLineKeepsLeadingSpace(t *testing.T) {
	screen := &ScreenController{promptLabel: "aw:repo:rose> "}

	screen.SetInputLine("aw:repo:rose>  leading")

	if !screen.pending {
		t.Fatal("expected leading-space input to count as pending")
	}
	if screen.inputLine != "aw:repo:rose>  leading" {
		t.Fatalf("expected input line to preserve leading space, got %q", screen.inputLine)
	}
}

func TestIdentityPromptLabelUsesProjectRepoAndAlias(t *testing.T) {
	got := IdentityPromptLabel("aweb", "github.com/awebai/aw", "", "rose")
	if got != "aweb:aw:rose> " {
		t.Fatalf("expected identity prompt label, got %q", got)
	}
}

func TestShortRepoNameFallsBackToRepoOrigin(t *testing.T) {
	got := ShortRepoName("", "git@github.com:awebai/aw.git")
	if got != "aw" {
		t.Fatalf("expected repo short name from repo origin, got %q", got)
	}
}

func TestWrapScreenLineWrapsLongToolFields(t *testing.T) {
	lines := wrapScreenLine(`  command="git fetch origin main && git log --oneline origin/main -5"`, 32)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if line == "" || line[:2] != "  " {
			t.Fatalf("expected wrapped continuation lines to keep indentation, got %#v", lines)
		}
	}
}

func TestWrapScreenLineKeepsToolArgIndent(t *testing.T) {
	lines := wrapScreenLine(`       file_path="/Users/juanre/prj/beadhub-all/aw/run/screen.go",`, 40)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if line == "" || line[:7] != "       " {
			t.Fatalf("expected wrapped continuation lines to keep tool arg indentation, got %#v", lines)
		}
	}
}

func TestScreenViewAddsBottomBreathingSpace(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       []string{"line 1"},
			StatusLine:  "next run in 6s",
			InputLine:   "aw:repo:rose> hello",
			PromptLabel: "aw:repo:rose> ",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()

	view := model.View()
	if !strings.Contains(view, "\n\n next run in 6s") {
		t.Fatalf("expected blank line before status line, got %q", view)
	}
	if !strings.Contains(view, "next run in 6s") || !strings.Contains(view, "\n\naw:repo:rose> hello") {
		t.Fatalf("expected blank line between status and input, got %q", view)
	}
}

func TestInputVisualHeightWrapsLongInput(t *testing.T) {
	got := inputVisualHeight("aw:repo:rose> ", strings.Repeat("x", 40), 30)
	if got < 2 {
		t.Fatalf("expected wrapped input height > 1, got %d", got)
	}
}

func TestScreenViewGrowsInputFooterWhenInputWraps(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       []string{"line 1", "line 2"},
			StatusLine:  "next run in 6s",
			InputLine:   "aw:repo:rose> " + strings.Repeat("x", 40),
			PromptLabel: "aw:repo:rose> ",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	model.width = 30
	model.height = 10
	model.syncLayout()

	if model.input.Height() < 2 {
		t.Fatalf("expected multi-line input height, got %d", model.input.Height())
	}
	if model.viewport.Height >= 6 {
		t.Fatalf("expected viewport to shrink for wrapped input, got %d", model.viewport.Height)
	}

	view := model.View()
	if !strings.Contains(view, "next run in 6s") {
		t.Fatalf("expected status line in view, got %q", view)
	}
	if !strings.Contains(view, "aw:repo:rose> ") {
		t.Fatalf("expected prompt label in view, got %q", view)
	}
}

func TestScreenViewKeepsFirstWrappedInputLineVisibleDuringTyping(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			StatusLine:  "paused: /resume, /quit, or type a prompt",
			InputLine:   "aw:repo:rose> ",
			PromptLabel: "aw:repo:rose> ",
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	model.width = 30
	model.height = 10
	model.syncLayout()

	for range 20 {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
		model = updated.(screenModel)
	}

	if model.input.Height() < 2 {
		t.Fatalf("expected wrapped input height, got %d", model.input.Height())
	}

	view := model.View()
	if !strings.Contains(view, "aw:repo:rose> xxxxxxxxxxxx") {
		t.Fatalf("expected first wrapped line to remain visible, got %q", view)
	}

	continuation := "\n" + strings.Repeat(" ", lipgloss.Width(model.promptLabel)) + "xxx"
	if !strings.Contains(view, continuation) {
		t.Fatalf("expected wrapped continuation line to remain visible, got %q", view)
	}
}

func TestScreenExitConfirmationAcceptsYWithoutTypingIntoInput(t *testing.T) {
	confirmed := false
	model := newScreenModel(
		screenSnapshot{
			InputLine:   "aw:repo:rose> draft",
			PromptLabel: "aw:repo:rose> ",
			ExitConfirm: true,
		},
		nil,
		nil,
		nil,
		nil,
		func() { confirmed = true },
		nil,
	)

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	model = updated.(screenModel)

	if !confirmed {
		t.Fatal("expected y to confirm exit")
	}
	if model.input.Value() != "draft" {
		t.Fatalf("expected input to remain unchanged, got %q", model.input.Value())
	}
}

func TestScreenExitConfirmationCancelsAndResumesTyping(t *testing.T) {
	canceled := false
	model := newScreenModel(
		screenSnapshot{
			InputLine:   "aw:repo:rose> draft",
			PromptLabel: "aw:repo:rose> ",
			ExitConfirm: true,
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		func() { canceled = true },
	)

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	model = updated.(screenModel)

	if !canceled {
		t.Fatal("expected non-confirming input to cancel exit confirmation")
	}
	if model.exitConfirm {
		t.Fatal("expected exit confirmation mode to clear")
	}
	if model.input.Value() != "draftx" {
		t.Fatalf("expected typing to continue after canceling exit confirmation, got %q", model.input.Value())
	}
}
