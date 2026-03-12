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

func TestIdentityPromptLabelReturnsShortPrompt(t *testing.T) {
	got := IdentityPromptLabel("aweb", "github.com/awebai/aw", "", "rose")
	if got != ">> " {
		t.Fatalf("expected short prompt label, got %q", got)
	}
}

func TestComposeStatusLineShowsIdentityAlone(t *testing.T) {
	got := ComposeStatusLine("claude@aweb:aw:rose", "")
	if got != "claude@aweb:aw:rose" {
		t.Fatalf("expected identity alone, got %q", got)
	}
}

func TestComposeStatusLineAppendsTransientState(t *testing.T) {
	got := ComposeStatusLine("claude@aweb:aw:rose", "next run in 12s")
	if got != "claude@aweb:aw:rose · next run in 12s" {
		t.Fatalf("expected composed status, got %q", got)
	}
}

func TestComposeStatusLineShowsTransientAloneWhenNoIdentity(t *testing.T) {
	got := ComposeStatusLine("", "paused")
	if got != "paused" {
		t.Fatalf("expected transient alone, got %q", got)
	}
}

func TestStatusIdentityFormatsProviderAndIdentity(t *testing.T) {
	cases := []struct {
		provider string
		project  string
		repo     string
		alias    string
		want     string
	}{
		{"claude", "aweb", "aw", "rose", "claude@aweb:aw:rose"},
		{"codex", "aweb", "", "rose", "codex@aweb:rose"},
		{"claude", "", "", "rose", "claude@rose"},
		{"claude", "aweb", "aw", "", "claude@aweb:aw"},
		{"", "aweb", "aw", "rose", "aweb:aw:rose"},
		{"", "", "", "", ""},
	}
	for _, tc := range cases {
		got := StatusIdentity(tc.provider, tc.project, tc.repo, tc.alias)
		if got != tc.want {
			t.Fatalf("StatusIdentity(%q,%q,%q,%q) = %q, want %q", tc.provider, tc.project, tc.repo, tc.alias, got, tc.want)
		}
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

func TestTextareaGrowsOnSecondWrapWordBoundary(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       []string{"output"},
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 30
	model.height = 20
	model.syncLayout()

	// Type words that will wrap at word boundaries.
	// Available content width = 30 - 3 (">> ") = 27
	// "hello world more " = 17 chars, fits on one line
	for _, r := range "hello world " {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		model = updated.(screenModel)
	}
	heightAfterFirstWords := model.input.Height()

	// Add words to cause a first wrap
	for _, r := range "this is a longer sentence " {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		model = updated.(screenModel)
	}
	heightAfterFirstWrap := model.input.Height()
	if heightAfterFirstWrap <= heightAfterFirstWords {
		t.Fatalf("expected height to increase after first wrap: %d -> %d", heightAfterFirstWords, heightAfterFirstWrap)
	}

	// Add more words to cause a second wrap
	for _, r := range "and even more words keep going " {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		model = updated.(screenModel)
	}
	heightAfterSecondWrap := model.input.Height()
	if heightAfterSecondWrap <= heightAfterFirstWrap {
		t.Fatalf("expected height to increase after second wrap: %d -> %d", heightAfterFirstWrap, heightAfterSecondWrap)
	}

	// Verify the first line of input (with prompt) is visible
	inputView := model.input.View()
	if !strings.Contains(inputView, ">> hello") {
		t.Fatalf("expected first line of input visible after second wrap, got:\n%s", inputView)
	}
}

func TestArrowUpMovesConsecutivelyInMultiLineTextarea(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       make([]string, 50),
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 20
	model.syncLayout()

	// Set 3-line content with cursor at end (line 2)
	model.input.SetValue("line0\nline1\nline2")
	model.input.CursorEnd()
	model.syncLayout()

	line0 := model.input.Line()
	t.Logf("before Up: line=%d", line0)

	// First Up — cursor should move from line 2 to line 1
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(screenModel)

	line1 := model.input.Line()
	t.Logf("after 1st Up: line=%d", line1)

	// Second Up — cursor should move from line 1 to line 0
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(screenModel)

	line2 := model.input.Line()
	t.Logf("after 2nd Up: line=%d", line2)

	// Each Up should have moved to a different line
	if line1 == line0 {
		t.Fatalf("first Up didn't move: line stayed at %d", line0)
	}
	if line2 == line1 {
		t.Fatalf("second Up didn't move: line stayed at %d", line1)
	}
	if line2 >= line1 {
		t.Fatalf("second Up moved wrong direction: line went from %d to %d", line1, line2)
	}
}

func TestArrowUpNavigatesTextareaWhenInputHasContent(t *testing.T) {
	// Fill viewport with enough lines to be scrollable
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = "output line"
	}
	model := newScreenModel(
		screenSnapshot{
			Lines:       lines,
			InputLine:   ">> ",
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()
	model.viewport.GotoBottom()

	// Put multi-line content in textarea
	model.input.SetValue("line1\nline2")
	model.input.CursorEnd()
	model.syncLayout()

	// Press Up — should move cursor within textarea, not scroll viewport
	viewportYBefore := model.viewport.YOffset
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(screenModel)

	// Viewport should not have scrolled
	if model.viewport.YOffset != viewportYBefore {
		t.Fatalf("expected viewport to stay put when textarea has content, but YOffset changed from %d to %d", viewportYBefore, model.viewport.YOffset)
	}
}

func TestArrowUpScrollsViewportWhenInputIsEmpty(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       make([]string, 50), // enough to scroll
			InputLine:   ">> ",
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()
	model.viewport.GotoBottom()

	viewportYBefore := model.viewport.YOffset
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(screenModel)

	if model.viewport.YOffset >= viewportYBefore {
		t.Fatalf("expected viewport to scroll up when input is empty, YOffset stayed at %d", viewportYBefore)
	}
}

func TestArrowDownNavigatesTextareaWhenInputHasContent(t *testing.T) {
	model := newScreenModel(
		screenSnapshot{
			Lines:       make([]string, 50),
			InputLine:   ">> ",
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()

	model.input.SetValue("line1\nline2")
	model.input.CursorStart()
	model.syncLayout()

	viewportYBefore := model.viewport.YOffset
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(screenModel)

	if model.viewport.YOffset != viewportYBefore {
		t.Fatalf("expected viewport to stay put when textarea has content, but YOffset changed from %d to %d", viewportYBefore, model.viewport.YOffset)
	}
}

func TestViewportDoesNotAutoScrollWhenUserScrolledUp(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = "output line"
	}
	model := newScreenModel(
		screenSnapshot{
			Lines:       lines,
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()
	model.viewport.GotoBottom()

	// Scroll up via PgUp
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	model = updated.(screenModel)
	yAfterScroll := model.viewport.YOffset

	if model.viewport.AtBottom() {
		t.Fatal("expected viewport to not be at bottom after PgUp")
	}

	// Append new content — should NOT auto-scroll
	updated, _ = model.Update(screenAppendTextMsg("new output line\n"))
	model = updated.(screenModel)

	if model.viewport.YOffset != yAfterScroll {
		t.Fatalf("expected viewport to stay at %d when user scrolled up, but moved to %d", yAfterScroll, model.viewport.YOffset)
	}
}

func TestViewportAutoScrollsWhenAtBottom(t *testing.T) {
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = "output line"
	}
	model := newScreenModel(
		screenSnapshot{
			Lines:       lines,
			PromptLabel: ">> ",
		},
		nil, nil, nil, nil, nil, nil,
	)
	model.width = 40
	model.height = 10
	model.syncLayout()
	model.viewport.GotoBottom()
	yBefore := model.viewport.YOffset

	// Append new content — should auto-scroll to stay at bottom
	updated, _ := model.Update(screenAppendTextMsg("new output line\n"))
	model = updated.(screenModel)

	if model.viewport.YOffset <= yBefore {
		t.Fatalf("expected viewport to scroll down when at bottom, YOffset stayed at %d", yBefore)
	}
	if !model.viewport.AtBottom() {
		t.Fatal("expected viewport to be at bottom after auto-scroll")
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
