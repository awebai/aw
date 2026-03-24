package run

import (
	"strings"
	"testing"
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
		{line: "> fix the bug", want: "prompt"},
		{line: `>_ go test ./... 2>&1`, want: "tool"},
		{line: "<- dave (mail): please review this", want: "comms"},
		{line: "-> henry (chat)", want: "comms"},
		{line: "  -> ok", want: "result"},
		{line: "done  2.1s", want: "done"},
		{line: "info: session", want: "info"},
		{line: "type /wait, /autofeed off, /stop", want: "hint"},
		{line: "────────────────────────────────────────", want: "separator"},
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
	got := styleScreenLine(`>_ View /tmp/image.png`, styles)
	want := styles.tool.Render(`>_ View /tmp/image.png`)
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

func TestStyleScreenLineBoldsCommArrowAndAlias(t *testing.T) {
	styles := newScreenStyles()
	got := styleScreenLine(`<- dave (mail): merged to main`, styles)
	want := styles.comms.Render(`<- dave`) + ` (mail): merged to main`
	if got != want {
		t.Fatalf("unexpected styled comm line %q", got)
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

func TestWrapScreenLineUsesHangingIndentForCommLines(t *testing.T) {
	lines := wrapScreenLine(`<- dave (mail): this is a long coordination update that should wrap cleanly`, 28)
	if len(lines) < 2 {
		t.Fatalf("expected wrapped lines, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "   ") {
			t.Fatalf("expected hanging indent under alias start, got %#v", lines)
		}
	}
}

func TestScreenControllerFooterPlacesPromptAboveStatusWithoutDivider(t *testing.T) {
	screen := &ScreenController{
		promptLabel: ">> ",
		statusLine:  "paused",
		inputLine:   ">> hello",
		inputCursor: len([]rune("hello")),
		styles:      newScreenStyles(),
	}

	lines := screen.renderFooterLinesLocked(40)
	promptIdx := -1
	statusIdx := -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, "hello"):
			promptIdx = i
		case strings.Contains(line, "paused"):
			statusIdx = i
		}
	}

	if promptIdx < 0 || statusIdx < 0 {
		t.Fatalf("expected prompt and status in footer, got %#v", lines)
	}
	if promptIdx >= statusIdx {
		t.Fatalf("expected prompt before status, got %#v", lines)
	}
	if statusIdx-promptIdx < 2 {
		t.Fatalf("expected blank line between prompt and status, got %#v", lines)
	}
	if lines[statusIdx-1] != "" {
		t.Fatalf("expected blank line before status, got %#v", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "────") {
			t.Fatalf("expected footer divider to be absent, got %#v", lines)
		}
	}
}

func TestScreenControllerHistoryNavigation(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("first"))
	screen.handleInlineInput([]byte{'\r'})
	screen.handleInlineInput([]byte("second"))
	screen.handleInlineInput([]byte{'\r'})
	screen.handleInlineInput([]byte{0x1b, '[', 'A'})

	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "second" {
		t.Fatalf("expected first history recall to show latest entry, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'A'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "first" {
		t.Fatalf("expected second history recall to show older entry, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'B'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "second" {
		t.Fatalf("expected down arrow to move forward in history, got %q", got)
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'B'})
	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != "" {
		t.Fatalf("expected second down arrow to restore draft input, got %q", got)
	}
}

func TestScreenControllerBracketedPasteInsertsNewlines(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	// Simulate bracketed paste: ESC[200~ hello\nworld\nparagraph ESC[201~
	paste := []byte("\x1b[200~hello\nworld\nparagraph\x1b[201~")
	screen.handleInlineInput(paste)

	value := InputValueFromLine(screen.inputLine, screen.promptLabel)
	if value != "hello\nworld\nparagraph" {
		t.Fatalf("expected multi-line paste in buffer, got %q", value)
	}
	if screen.pasting {
		t.Fatal("expected pasting=false after paste end bracket")
	}

	// Should not have submitted anything yet — still in the input buffer
	var prompts []string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				prompts = append(prompts, evt.Text)
			}
		default:
			goto done
		}
	}
done:
	if len(prompts) != 0 {
		t.Fatalf("expected no prompt submissions during paste, got %v", prompts)
	}

	// Now press Enter to submit the full multi-line text
	screen.handleInlineInput([]byte{'\r'})
	var submitted string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				submitted = evt.Text
				goto submitted
			}
		default:
			t.Fatal("expected prompt event after Enter")
		}
	}
submitted:
	if submitted != "hello\nworld\nparagraph" {
		t.Fatalf("expected full multi-line text in submission, got %q", submitted)
	}
}

func TestScreenControllerNewlineStillSubmitsOutsidePaste(t *testing.T) {
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     ">> ",
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte("hello\r"))

	var submitted string
	for {
		select {
		case evt := <-screen.events:
			if evt.Type == ControlPrompt {
				submitted = evt.Text
				goto done
			}
		default:
			t.Fatal("expected prompt event after Enter")
		}
	}
done:
	if submitted != "hello" {
		t.Fatalf("expected single-line submission, got %q", submitted)
	}
}

func TestScreenControllerUpMovesWithinWrappedInputBeforeHistory(t *testing.T) {
	value := strings.Repeat("x", 100)
	screen := &ScreenController{
		promptLabel:   ">> ",
		inputLine:     FormatInputLine(">> ", value),
		inputCursor:   len([]rune(value)),
		history:       []string{"from-history"},
		historyIndex:  -1,
		desiredColumn: -1,
		events:        make(chan ControlEvent, 64),
	}

	screen.handleInlineInput([]byte{0x1b, '[', 'A'})

	if got := InputValueFromLine(screen.inputLine, screen.promptLabel); got != value {
		t.Fatalf("expected wrapped up-arrow to keep current input, got %q", got)
	}
	if screen.historyIndex != -1 {
		t.Fatalf("expected wrapped up-arrow to stay out of history, got historyIndex=%d", screen.historyIndex)
	}
	if screen.inputCursor >= len([]rune(value)) {
		t.Fatalf("expected wrapped up-arrow to move cursor within input, got cursor=%d", screen.inputCursor)
	}
}
