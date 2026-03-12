package run

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

type ScreenController struct {
	inputFile   *os.File
	outputFile  *os.File
	promptLabel string

	mu          sync.Mutex
	lines       []string
	current     string
	statusLine  string
	inputLine   string
	pending     bool
	active      bool
	exitConfirm bool

	events  chan ControlEvent
	program *tea.Program
	doneCh  chan error
}

var _ UI = (*ScreenController)(nil)

type screenSnapshot struct {
	Lines       []string
	Current     string
	StatusLine  string
	InputLine   string
	PromptLabel string
	ExitConfirm bool
}

type screenAppendTextMsg string
type screenSetStatusMsg string
type screenSetInputMsg string
type screenSetExitConfirmMsg bool
type screenQuitMsg struct{}

type screenModel struct {
	viewport    viewport.Model
	input       textarea.Model
	width       int
	height      int
	promptLabel string
	exitConfirm bool

	lines      []string
	current    string
	statusLine string
	styles     screenStyles

	onInputChanged func(string)
	onSubmitted    func(string)
	onInterrupt    func()
	onExitPrompt   func()
	onExitConfirm  func()
	onExitCancel   func()
}

type screenStyles struct {
	runHeader lipgloss.Style
	separator lipgloss.Style
	tool      lipgloss.Style
	result    lipgloss.Style
	done      lipgloss.Style
	info      lipgloss.Style
	status    lipgloss.Style
	hint      lipgloss.Style
}

const screenFooterBaseLines = 3

func NewScreenController(in io.Reader, out io.Writer) *ScreenController {
	inputFile, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(inputFile.Fd())) {
		return nil
	}

	outputFile, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(outputFile.Fd())) {
		return nil
	}

	return &ScreenController{
		inputFile:   inputFile,
		outputFile:  outputFile,
		promptLabel: DefaultInputPromptLabel,
		events:      make(chan ControlEvent, 64),
		inputLine:   DefaultInputPromptLabel,
	}
}

func (s *ScreenController) Start() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return nil
	}
	s.active = true
	snapshot := s.snapshotLocked()
	doneCh := make(chan error, 1)
	model := newScreenModel(
		snapshot,
		s.handleInputChanged,
		s.handleInputSubmitted,
		s.handleInterruptRequested,
		s.handleExitPromptRequested,
		s.handleExitConfirmed,
		s.handleExitCanceled,
	)
	program := tea.NewProgram(
		model,
		tea.WithInput(s.inputFile),
		tea.WithOutput(s.outputFile),
		tea.WithAltScreen(),
	)
	s.program = program
	s.doneCh = doneCh
	s.mu.Unlock()

	go func() {
		_, err := program.Run()
		doneCh <- err
	}()

	return nil
}

func (s *ScreenController) Stop() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil
	}
	s.active = false
	program := s.program
	doneCh := s.doneCh
	s.program = nil
	s.doneCh = nil
	s.pending = false
	s.mu.Unlock()

	if program != nil {
		program.Send(screenQuitMsg{})
	}
	if doneCh == nil {
		return nil
	}

	select {
	case err := <-doneCh:
		return err
	case <-time.After(2 * time.Second):
		return nil
	}
}

func (s *ScreenController) Events() <-chan ControlEvent {
	if s == nil {
		return nil
	}
	return s.events
}

func (s *ScreenController) HasPendingInput() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

func (s *ScreenController) AppendText(text string) {
	if s == nil {
		return
	}

	s.mu.Lock()
	appendScreenText(&s.lines, &s.current, text)
	program := s.program
	s.mu.Unlock()

	if program != nil {
		program.Send(screenAppendTextMsg(text))
	}
}

func (s *ScreenController) AppendLine(line string) {
	s.AppendText(line + "\n")
}

func (s *ScreenController) SetInputLine(line string) {
	if s == nil {
		return
	}

	value := InputValueFromLine(line, s.promptLabel)

	s.mu.Lock()
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	program := s.program
	s.mu.Unlock()

	if program != nil {
		program.Send(screenSetInputMsg(value))
	}
}

func (s *ScreenController) ClearInputLine() {
	if s == nil {
		return
	}
	s.SetInputLine(s.promptLabel)
}

func (s *ScreenController) SetStatusLine(line string) {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.statusLine = line
	program := s.program
	s.mu.Unlock()

	if program != nil {
		program.Send(screenSetStatusMsg(line))
	}
}

func (s *ScreenController) ClearStatusLine() {
	s.SetStatusLine("")
}

func (s *ScreenController) SetExitConfirmation(active bool) {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.exitConfirm = active
	program := s.program
	s.mu.Unlock()

	if program != nil {
		program.Send(screenSetExitConfirmMsg(active))
	}
}

func (s *ScreenController) SetPromptLabel(label string) {
	if s == nil {
		return
	}
	if strings.TrimSpace(label) == "" {
		label = DefaultInputPromptLabel
	}

	s.mu.Lock()
	s.promptLabel = label
	if s.inputLine == "" || s.inputLine == DefaultInputPromptLabel || s.inputLine == s.promptLabel {
		s.inputLine = label
	}
	program := s.program
	s.mu.Unlock()

	if program != nil {
		program.Send(screenSetInputMsg(""))
	}
}

func (s *ScreenController) HasActiveProgram() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.program != nil
}

func (s *ScreenController) snapshotLocked() screenSnapshot {
	lines := make([]string, len(s.lines))
	copy(lines, s.lines)
	return screenSnapshot{
		Lines:       lines,
		Current:     s.current,
		StatusLine:  s.statusLine,
		InputLine:   s.inputLine,
		PromptLabel: s.promptLabel,
		ExitConfirm: s.exitConfirm,
	}
}

func (s *ScreenController) emit(event ControlEvent) {
	select {
	case s.events <- event:
	default:
	}
}

func (s *ScreenController) handleInputChanged(value string) {
	s.mu.Lock()
	wasPending := s.pending
	s.pending = value != ""
	s.inputLine = FormatInputLine(s.promptLabel, value)
	s.mu.Unlock()

	if !wasPending && value != "" {
		s.emit(ControlEvent{Type: ControlTypingStarted})
	}
	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: value})
}

func (s *ScreenController) handleInputSubmitted(value string) {
	s.mu.Lock()
	s.pending = false
	s.inputLine = s.promptLabel
	s.mu.Unlock()

	s.emit(ControlEvent{Type: ControlBufferUpdated, Text: ""})
	if strings.TrimSpace(value) == "" {
		return
	}
	s.emit(ParseControlSubmission(value))
}

func (s *ScreenController) handleInterruptRequested() {
	s.emit(ControlEvent{Type: ControlInterrupt})
}

func (s *ScreenController) handleExitPromptRequested() {
	s.emit(ControlEvent{Type: ControlExitPrompt})
}

func (s *ScreenController) handleExitConfirmed() {
	s.emit(ControlEvent{Type: ControlExitConfirm})
}

func (s *ScreenController) handleExitCanceled() {
	s.emit(ControlEvent{Type: ControlExitCancel})
}

func newScreenModel(
	snapshot screenSnapshot,
	onInputChanged func(string),
	onSubmitted func(string),
	onInterrupt func(),
	onExitPrompt func(),
	onExitConfirm func(),
	onExitCancel func(),
) screenModel {
	input := textarea.New()
	input.Prompt = snapshot.PromptLabel
	input.ShowLineNumbers = false
	input.SetValue(InputValueFromLine(snapshot.InputLine, snapshot.PromptLabel))
	input.Focus()
	input.CharLimit = 0
	input.SetPromptFunc(lipgloss.Width(snapshot.PromptLabel), func(lineIdx int) string {
		if lineIdx == 0 {
			return snapshot.PromptLabel
		}
		return strings.Repeat(" ", lipgloss.Width(snapshot.PromptLabel))
	})
	input.FocusedStyle.CursorLine = lipgloss.NewStyle()
	input.FocusedStyle.Base = lipgloss.NewStyle()
	input.FocusedStyle.Text = lipgloss.NewStyle()
	input.BlurredStyle.CursorLine = lipgloss.NewStyle()
	input.BlurredStyle.Base = lipgloss.NewStyle()
	input.BlurredStyle.Text = lipgloss.NewStyle()

	model := screenModel{
		viewport:       viewport.New(0, 0),
		input:          input,
		promptLabel:    snapshot.PromptLabel,
		exitConfirm:    snapshot.ExitConfirm,
		lines:          snapshot.Lines,
		current:        snapshot.Current,
		statusLine:     snapshot.StatusLine,
		styles:         newScreenStyles(),
		onInputChanged: onInputChanged,
		onSubmitted:    onSubmitted,
		onInterrupt:    onInterrupt,
		onExitPrompt:   onExitPrompt,
		onExitConfirm:  onExitConfirm,
		onExitCancel:   onExitCancel,
	}
	model.syncViewport(true)
	return model
}

func newScreenStyles() screenStyles {
	return screenStyles{
		runHeader: lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "24", Dark: "12"}).Bold(true),
		separator: lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "247", Dark: "245"}),
		tool:      lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "130", Dark: "214"}).Bold(true),
		result:    lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "247", Dark: "242"}),
		done:      lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "28", Dark: "10"}).Bold(true),
		info:      lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "240", Dark: "8"}),
		status: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "236", Dark: "252"}).
			Background(lipgloss.AdaptiveColor{Light: "252", Dark: "236"}).
			Padding(0, 1),
		hint: lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "240", Dark: "8"}),
	}
}

func (m screenModel) Init() tea.Cmd {
	return nil
}

func (m screenModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = typed.Width
		m.height = typed.Height
		m.syncLayout()
		return m, nil
	case screenAppendTextMsg:
		wasAtBottom := m.viewport.AtBottom()
		appendScreenText(&m.lines, &m.current, string(typed))
		m.syncViewport(wasAtBottom)
		return m, nil
	case screenSetStatusMsg:
		m.statusLine = string(typed)
		return m, nil
	case screenSetInputMsg:
		if m.input.Value() != string(typed) {
			m.input.SetValue(string(typed))
			m.input.CursorEnd()
			m.syncLayout()
		}
		return m, nil
	case screenSetExitConfirmMsg:
		m.exitConfirm = bool(typed)
		return m, nil
	case screenQuitMsg:
		return m, tea.Quit
	case tea.KeyMsg:
		if m.exitConfirm {
			switch typed.Type {
			case tea.KeyCtrlC, tea.KeyCtrlD:
				if m.onExitConfirm != nil {
					m.onExitConfirm()
				}
				return m, nil
			case tea.KeyEsc:
				m.exitConfirm = false
				if m.onExitCancel != nil {
					m.onExitCancel()
				}
				return m, nil
			case tea.KeyRunes:
				if len(typed.Runes) == 1 {
					switch typed.Runes[0] {
					case 'y', 'Y':
						if m.onExitConfirm != nil {
							m.onExitConfirm()
						}
						return m, nil
					case 'n', 'N':
						m.exitConfirm = false
						if m.onExitCancel != nil {
							m.onExitCancel()
						}
						return m, nil
					}
				}
				m.exitConfirm = false
				if m.onExitCancel != nil {
					m.onExitCancel()
				}
			default:
				m.exitConfirm = false
				if m.onExitCancel != nil {
					m.onExitCancel()
				}
			}
		}

		switch typed.Type {
		case tea.KeyCtrlC:
			if m.onInterrupt != nil {
				m.onInterrupt()
			}
			return m, nil
		case tea.KeyCtrlD:
			if m.onExitPrompt != nil {
				m.onExitPrompt()
			}
			return m, nil
		case tea.KeyEnter:
			if m.onSubmitted != nil {
				m.onSubmitted(m.input.Value())
			}
			m.input.SetValue("")
			m.syncLayout()
			return m, nil
		case tea.KeyPgUp, tea.KeyPgDown:
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(typed)
			return m, cmd
		case tea.KeyUp, tea.KeyDown:
			if m.input.Value() != "" {
				// Navigate within textarea when it has content
			} else {
				var cmd tea.Cmd
				m.viewport, cmd = m.viewport.Update(typed)
				return m, cmd
			}
		case tea.KeyHome, tea.KeyEnd:
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(typed)
			return m, cmd
		}

		previous := m.input.Value()
		previousHeight := m.input.Height()
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(typed)
		m.syncLayout()
		if m.input.Height() > previousHeight {
			m.restoreWrappedInputViewport()
		}
		if m.input.Value() != previous && m.onInputChanged != nil {
			m.onInputChanged(m.input.Value())
		}
		return m, cmd
	}

	return m, nil
}

func (m screenModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}

	divider := m.styles.separator.Render(strings.Repeat("─", m.width))
	status := m.styles.status.Width(m.width).Render(m.statusText())
	return m.viewport.View() + "\n" + divider + "\n" + m.input.View() + "\n\n" + status
}

func (m *screenModel) syncLayout() {
	if m.width <= 0 || m.height <= 0 {
		return
	}

	m.input.SetWidth(m.width)
	inputHeight := m.textareaVisualHeight()
	maxInputHeight := max(1, m.height-screenFooterBaseLines-1)
	if inputHeight > maxInputHeight {
		inputHeight = maxInputHeight
	}
	m.input.SetHeight(inputHeight)

	outputHeight := m.height - (screenFooterBaseLines + inputHeight)
	if outputHeight < 1 {
		outputHeight = 1
	}

	m.viewport.Width = m.width
	m.viewport.Height = outputHeight
	m.syncViewport(false)
}

// textareaVisualHeight returns the number of visual lines the textarea
// content occupies using the textarea's own word-wrapping calculation.
func (m *screenModel) textareaVisualHeight() int {
	if m.input.Value() == "" {
		return 1
	}
	height := m.input.LineInfo().Height
	if height < 1 {
		return 1
	}
	return height
}

func (m *screenModel) syncViewport(autoBottom bool) {
	content := strings.Join(m.formattedOutputLines(), "\n")
	m.viewport.SetContent(content)
	if autoBottom {
		m.viewport.GotoBottom()
	}
}

func (m *screenModel) restoreWrappedInputViewport() {
	value := m.input.Value()
	cursorCol := inputCursorColumn(m.input)
	m.input.SetValue(value)
	m.input.SetCursor(cursorCol)
}

func (m screenModel) formattedOutputLines() []string {
	lines := make([]string, 0, len(m.lines)+1)
	for _, line := range m.lines {
		lines = appendWrappedStyledScreenLine(lines, line, m.width, m.styles)
	}
	if m.current != "" {
		lines = appendWrappedStyledScreenLine(lines, m.current, m.width, m.styles)
	}
	return lines
}

func (m screenModel) statusText() string {
	if strings.TrimSpace(m.statusLine) == "" {
		return ""
	}
	return truncateText(strings.TrimSpace(m.statusLine), max(1, m.width-2))
}

func inputVisualHeight(promptLabel string, value string, width int) int {
	if width <= 0 {
		return 1
	}

	promptWidth := lipgloss.Width(promptLabel)
	availableWidth := width - promptWidth
	if availableWidth < 1 {
		availableWidth = 1
	}

	lines := strings.Split(value, "\n")
	if len(lines) == 0 {
		return 1
	}

	height := 0
	for _, line := range lines {
		if line == "" {
			height++
			continue
		}
		currentWidth := 0
		height++
		for _, r := range line {
			runeWidth := lipgloss.Width(string(r))
			if runeWidth <= 0 {
				runeWidth = 1
			}
			if currentWidth+runeWidth > availableWidth {
				height++
				currentWidth = runeWidth
				continue
			}
			currentWidth += runeWidth
		}
	}

	if height < 1 {
		return 1
	}
	return height
}

func inputCursorColumn(input textarea.Model) int {
	info := input.LineInfo()
	return info.StartColumn + info.CharOffset
}

func appendScreenText(lines *[]string, current *string, text string) {
	text = strings.ReplaceAll(text, "\r", "")
	parts := strings.Split(text, "\n")
	if len(parts) == 1 {
		*current += parts[0]
		return
	}

	*current += parts[0]
	*lines = append(*lines, *current)
	for _, part := range parts[1 : len(parts)-1] {
		*lines = append(*lines, part)
	}
	*current = parts[len(parts)-1]
}

func appendWrappedStyledScreenLine(lines []string, line string, width int, styles screenStyles) []string {
	for _, wrapped := range wrapScreenLine(line, width) {
		lines = append(lines, styleScreenLine(wrapped, styles))
	}
	return lines
}

func wrapScreenLine(line string, width int) []string {
	if width <= 0 || lipgloss.Width(line) <= width {
		return []string{line}
	}

	indent := leadingWhitespace(line)
	tokens := splitWrapTokens(line)
	if len(tokens) == 0 {
		return []string{line}
	}

	lines := make([]string, 0, 4)
	current := ""
	lineIndent := ""

	for _, token := range tokens {
		if current == "" {
			trimmed := strings.TrimLeft(token, " ")
			if trimmed == "" {
				current = indent
			} else if indent != "" {
				current = indent + trimmed
			} else {
				current = trimmed
			}
			continue
		}

		candidate := current + token
		if lipgloss.Width(candidate) <= width {
			current = candidate
			continue
		}

		lines = append(lines, strings.TrimRight(current, " "))
		if lineIndent == "" {
			lineIndent = indent
			if lineIndent == "" {
				lineIndent = "  "
			}
		}

		trimmed := strings.TrimLeft(token, " ")
		if trimmed == "" {
			current = lineIndent
			continue
		}
		current = lineIndent + trimmed
		for lipgloss.Width(current) > width && width > lipgloss.Width(lineIndent) {
			available := max(1, width-lipgloss.Width(lineIndent))
			chunk, rest := splitWrapChunk(strings.TrimPrefix(current, lineIndent), available)
			lines = append(lines, lineIndent+chunk)
			if rest == "" {
				current = lineIndent
				break
			}
			current = lineIndent + rest
		}
	}

	if strings.TrimSpace(current) != "" {
		lines = append(lines, strings.TrimRight(current, " "))
	}
	if len(lines) == 0 {
		return []string{line}
	}
	return lines
}

func splitWrapTokens(line string) []string {
	parts := strings.SplitAfter(line, " ")
	if len(parts) == 0 {
		return []string{line}
	}
	return parts
}

func splitWrapChunk(s string, width int) (string, string) {
	if lipgloss.Width(s) <= width {
		return s, ""
	}
	runes := []rune(s)
	if width >= len(runes) {
		return s, ""
	}
	return string(runes[:width]), strings.TrimLeft(string(runes[width:]), " ")
}

func leadingWhitespace(s string) string {
	idx := 0
	for idx < len(s) && (s[idx] == ' ' || s[idx] == '\t') {
		idx++
	}
	return s[:idx]
}

func styleScreenLine(line string, styles screenStyles) string {
	switch screenLineStyleKind(line) {
	case "run_header":
		return styles.runHeader.Render(line)
	case "separator":
		return styles.separator.Render(line)
	case "tool":
		return styleScreenToolLine(line, styles)
	case "result":
		return styles.result.Render(line)
	case "done":
		return styles.done.Render(line)
	case "info":
		return styles.info.Render(line)
	case "hint":
		return styles.hint.Render(line)
	default:
		return styleScreenToolClosingParen(line, styles)
	}
}

func styleScreenToolLine(line string, styles screenStyles) string {
	idx := strings.Index(line, "(")
	if idx < 0 {
		return styles.tool.Render(line)
	}
	return styles.tool.Render(line[:idx+1]) + styleScreenToolClosingParen(line[idx+1:], styles)
}

func styleScreenToolClosingParen(line string, styles screenStyles) string {
	trimmed := strings.TrimRight(line, " ")
	if trimmed == "" || !strings.HasSuffix(trimmed, ")") {
		return line
	}
	suffixStart := len(trimmed) - 1
	return line[:suffixStart] + styles.tool.Render(")") + line[len(trimmed):]
}

func screenLineStyleKind(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "────"):
		return "separator"
	case strings.HasPrefix(trimmed, "run #"):
		return "run_header"
	case strings.HasPrefix(trimmed, "- ") && strings.Contains(trimmed, "("):
		return "tool"
	case strings.HasPrefix(trimmed, "->") || strings.HasPrefix(trimmed, "  ->"):
		return "result"
	case strings.HasPrefix(trimmed, "done"):
		return "done"
	case strings.HasPrefix(trimmed, "info:"):
		return "info"
	case strings.HasPrefix(trimmed, "type /"):
		return "hint"
	default:
		return "plain"
	}
}
