package run

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	awid "github.com/awebai/aw/awid"
)

type Loop struct {
	Provider          Provider
	Runner            CommandRunner
	Sleep             SleepFunc
	EventBus          *EventBus
	ServiceSupervisor ServiceSupervisor
	Out               io.Writer
	Control           InputController
	Dispatch          Dispatcher
	Now               func() time.Time
	InputPromptLabel  string
	StatusIdentity    string

	writeMu sync.Mutex
}

type state struct {
	Run                int
	CompactRuns        int
	RunLabel           string
	CumulativeCostUSD  float64
	SessionID          string
	RanOnce            bool
	RunInterrupted     bool
	PauseAfterRun      bool
	PauseNoticeShown   bool
	StopRequested      bool
	Paused             bool
	ExitConfirmPending bool
	Autofeed           bool
	NextPrompt         string
	PendingInput       bool
	InputBuffer        string
	StructuredOut      bool
	LastWakeEvent      *awid.AgentEvent
	LastRunError       string
	LastRunUsage       UsageStats
	HasRunUsage        bool
	ConnState          ConnectionState
}

const (
	pausedNoticeText = "paused. use /resume, /quit, or type a prompt to continue."
	pausedStatusText = "paused: /resume, /quit, or type a prompt"
	exitStatusText   = "exit aw run? [y/N]"
	helpText         = `available commands:
  /wait           pause after the current run
  /resume         resume from a pause
  /stop           stop the current run and pause
  /autofeed on    enable autofeed (work events wake the agent)
  /autofeed off   disable autofeed
  /quit           exit aw run
  /help           show this help`
)

func NewLoop(provider Provider, out io.Writer) *Loop {
	return &Loop{
		Provider:         provider,
		Runner:           RealCommandRunner,
		Sleep:            SleepWithContext,
		Out:              out,
		Now:              time.Now,
		InputPromptLabel: DefaultInputPromptLabel,
	}
}

func (l *Loop) Run(ctx context.Context, opts LoopOptions) error {
	if opts.MaxRuns < 0 {
		return fmt.Errorf("max runs must be >= 0")
	}
	if l.Provider == nil {
		return fmt.Errorf("provider is required")
	}
	if l.Runner == nil {
		l.Runner = RealCommandRunner
	}
	if l.Sleep == nil {
		l.Sleep = SleepWithContext
	}
	if l.Now == nil {
		l.Now = time.Now
	}
	if l.Out == nil {
		l.Out = io.Discard
	}
	if l.Dispatch == nil && strings.TrimSpace(opts.Prompt) == "" && strings.TrimSpace(opts.InitialPrompt) == "" {
		return fmt.Errorf("prompt cannot be empty when dispatch is unavailable")
	}

	state := &state{Autofeed: opts.Autofeed}
	if l.Control != nil {
		if err := l.Control.Start(); err != nil {
			return err
		}
		defer func() { _ = l.Control.Stop() }()
	}
	serviceSupervisor := l.ServiceSupervisor
	if serviceSupervisor == nil && len(opts.Services) > 0 {
		serviceSupervisor = NewServiceManager(l.println)
	}
	if serviceSupervisor != nil && len(opts.Services) > 0 {
		if err := serviceSupervisor.Start(ctx, opts.Services, opts.WorkingDir); err != nil {
			return err
		}
		defer func() { _ = serviceSupervisor.Stop() }()
	}
	if l.EventBus != nil {
		l.EventBus.onStateChange = func(cs ConnectionState) {
			state.ConnState = cs
			if state.RunLabel != "" {
				l.setStatusLine(formatRunStatus(state))
			}
		}
		l.EventBus.Start(ctx)
		defer l.EventBus.Stop()
	}

	for {
		decision, err := l.nextPrompt(ctx, opts, state)
		if err != nil {
			return err
		}
		if decision.Skip {
			if err := l.waitForWork(ctx, decision.WaitSeconds, state); err != nil {
				if state.StopRequested && errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			continue
		}

		missionPrompt := resolveMissionPrompt(strings.TrimSpace(opts.Prompt), decision.MissionPrompt)
		prompt := composePromptWithServices(missionPrompt, decision.Prompt, opts.Services)
		displayPrompt := displayPrompt(missionPrompt, decision.Prompt)
		if strings.TrimSpace(prompt) == "" {
			if l.Dispatch == nil && state.Run > 0 && strings.TrimSpace(opts.Prompt) == "" && strings.TrimSpace(opts.InitialPrompt) != "" {
				l.println("done: initial prompt consumed; use a persistent base prompt.")
				return nil
			}
			return fmt.Errorf("prompt cannot be empty")
		}
		state.Run++
		if err := l.runOnce(ctx, opts, state, prompt, displayPrompt); err != nil {
			if state.StopRequested && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return nil
			}
			return err
		}
		if state.ExitConfirmPending {
			if err := l.waitForExitConfirmation(ctx, state); err != nil {
				if state.StopRequested && errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		}
		compacted, err := l.maybeAutoCompact(ctx, opts, state)
		if err != nil {
			if state.StopRequested && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return nil
			}
			return err
		}
		if compacted {
			if opts.MaxRuns > 0 && state.Run >= opts.MaxRuns {
				l.printf("\ndone: reached max-runs (%d)\n", opts.MaxRuns)
				return nil
			}
			continue
		}
		if opts.MaxRuns > 0 && state.Run >= opts.MaxRuns {
			l.printf("\ndone: reached max-runs (%d)\n", opts.MaxRuns)
			return nil
		}
		if err := l.waitForNextCycle(ctx, decision.WaitSeconds, state); err != nil {
			if state.StopRequested && errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

func (l *Loop) nextPrompt(ctx context.Context, opts LoopOptions, st *state) (DispatchDecision, error) {
	queuedMissionPrompt := strings.TrimSpace(st.NextPrompt)
	if queuedMissionPrompt != "" {
		st.NextPrompt = ""
	}
	explicitMissionPrompt := queuedMissionPrompt
	if explicitMissionPrompt == "" && st.Run == 0 {
		explicitMissionPrompt = strings.TrimSpace(opts.InitialPrompt)
	}
	if explicitMissionPrompt != "" {
		return DispatchDecision{MissionPrompt: explicitMissionPrompt, WaitSeconds: opts.WaitSeconds}, nil
	}
	if l.Dispatch != nil {
		decision, err := l.Dispatch.Next(ctx, st.Autofeed, st.LastWakeEvent)
		if err != nil {
			l.printf("info: dispatch failed: %v\n", err)
			l.println("info: waiting for dispatch recovery before starting a run.")
			return DispatchDecision{WaitSeconds: opts.IdleWaitSeconds, Skip: true}, nil
		}
		return decision, nil
	}
	// Without an external dispatcher, run one cycle then rely on wake/control
	// signals for subsequent cycles when event streaming is available.
	if st.Run > 0 && l.EventBus != nil {
		return DispatchDecision{WaitSeconds: opts.WaitSeconds, Skip: true}, nil
	}
	return DispatchDecision{MissionPrompt: explicitMissionPrompt, WaitSeconds: opts.WaitSeconds}, nil
}

func (l *Loop) runOnce(ctx context.Context, opts LoopOptions, st *state, prompt string, display string) error {
	l.clearStatusLine()
	st.LastRunError = ""
	st.LastRunUsage = UsageStats{}
	st.HasRunUsage = false
	expectedSessionID := strings.TrimSpace(st.SessionID)
	followUpRun := st.RanOnce
	buildOpts := BuildOptions{
		AllowedTools: opts.AllowedTools,
		Model:        opts.Model,
	}
	if followUpRun {
		if expectedSessionID == "" {
			return fmt.Errorf("provider %s did not report a session id for the previous run; cannot guarantee continuity", l.Provider.Name())
		}
		buildOpts.SessionID = expectedSessionID
		buildOpts.ContinueSession = true
	} else if opts.ContinueMode {
		buildOpts.ContinueSession = true
	}

	argv, err := l.Provider.BuildCommand(prompt, buildOpts)
	if err != nil {
		return err
	}

	if followUpRun {
		l.printf("\n%s\n", runSeparator)
	}

	if display == "/compact" {
		st.RunLabel = "compact"
		l.printf("\ninfo: compacting context\n\n")
	} else {
		st.RunLabel = "active"
		l.printf("\n> %s\n\n", truncateText(display, 80))
	}
	l.setStatusLine(formatRunStatus(st))
	l.renderInputPrompt(st)

	presenter := &presenterState{}
	st.StructuredOut = false
	observedSessionID := ""
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)

	var busInterrupts <-chan BusEvent
	if l.EventBus != nil {
		busInterrupts = l.EventBus.Interrupts()
	}

	go func() {
		errCh <- l.Runner(runCtx, opts.WorkingDir, argv, func(line string) {
			l.handleOutputLine(line, presenter, st, &observedSessionID)
		}, nil)
	}()

	for {
		select {
		case err := <-errCh:
			st.RunLabel = ""
			l.drainPendingControlEvents(st, true)
			st.RanOnce = true
			if st.RunInterrupted {
				st.Paused = true
				st.PauseAfterRun = true
				st.RunInterrupted = false
				return nil
			}
			st.RunInterrupted = false
			if strings.TrimSpace(st.LastRunError) != "" {
				return errors.New(st.LastRunError)
			}
			if followUpRun {
				switch {
				case strings.TrimSpace(observedSessionID) == "":
					return fmt.Errorf("provider %s did not report a session id for follow-up run", l.Provider.Name())
				case observedSessionID != expectedSessionID:
					return fmt.Errorf("provider %s switched sessions unexpectedly: expected %s, got %s", l.Provider.Name(), expectedSessionID, observedSessionID)
				}
			}
			return err
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, true, cancel)
		case busEvt := <-busInterrupts:
			l.applyBusInterrupt(busEvt, st, cancel)
		case <-ctx.Done():
			cancel()
			st.StopRequested = true
			return ctx.Err()
		}
	}
}

func (l *Loop) maybeAutoCompact(ctx context.Context, opts LoopOptions, st *state) (bool, error) {
	if opts.CompactThresholdPct <= 0 || st == nil || !st.HasRunUsage {
		return false, nil
	}
	pct := st.LastRunUsage.ContextPct()
	if pct <= float64(opts.CompactThresholdPct) {
		return false, nil
	}
	st.CompactRuns++
	l.printf("\ninfo: context %.1f%% exceeds %d%%; running compact\n", pct, opts.CompactThresholdPct)
	if err := l.runOnce(ctx, opts, st, "/compact", "/compact"); err != nil {
		return false, err
	}
	return true, nil
}


func (l *Loop) drainPendingControlEvents(st *state, activeRun bool) {
	for {
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, activeRun, nil)
		default:
			return
		}
	}
}

func (l *Loop) handleOutputLine(line string, presenter *presenterState, st *state, observedSessionID *string) {
	event, err := l.Provider.ParseOutput(line)
	if err != nil {
		l.runPresenterEnsureTextSpacing(presenter)
		l.println(line)
		presenter.lastWasStructured = false
		presenter.lastWasText = false
		presenter.lastTextEndedWithNewline = true
		return
	}
	if sid := l.Provider.SessionID(event); sid != "" {
		st.SessionID = sid
		if observedSessionID != nil {
			*observedSessionID = sid
		}
	}
	statusChanged := false
	if event != nil && event.Usage != nil {
		st.LastRunUsage = *event.Usage
		st.HasRunUsage = true
		statusChanged = true
	}
	if event != nil && event.CostUSD != nil {
		st.CumulativeCostUSD += *event.CostUSD
		statusChanged = true
	}
	if statusChanged {
		l.setStatusLine(formatRunStatus(st))
	}
	switch event.Type {
	case EventText:
		l.runPresenterEnsureTextSpacing(presenter)
		l.print(event.Text)
		presenter.lastWasText = true
		presenter.lastWasStructured = false
		presenter.lastTextEndedWithNewline = strings.HasSuffix(event.Text, "\n")
	case EventToolCall:
		st.StructuredOut = true
		l.runPresenterEnsureStructuredSpacing(presenter)
		for _, call := range event.ToolCalls {
			for _, line := range formatToolCallLines(call) {
				l.printf("%s\n", line)
			}
		}
		presenter.lastWasStructured = true
	case EventToolResult:
		st.StructuredOut = true
		l.runPresenterEnsureStructuredSpacing(presenter)
		if text := strings.TrimSpace(event.Text); text != "" {
			l.printf("  -> %s\n", truncateText(text, 150))
		}
		presenter.lastWasStructured = true
	case EventDone:
		if event.IsError && strings.TrimSpace(event.Text) != "" {
			st.LastRunError = strings.TrimSpace(event.Text)
			st.StructuredOut = true
			l.runPresenterEnsureStructuredSpacing(presenter)
			l.printf("%s\n", formatDone(event))
			presenter.lastWasStructured = true
		}
	case EventSystem:
		// System info suppressed from display
	}
	l.renderInputPrompt(st)
}

func (l *Loop) runPresenterEnsureTextSpacing(presenter *presenterState) {
	if presenter != nil && presenter.lastWasStructured {
		l.print("\n")
		presenter.lastWasStructured = false
	}
}

func (l *Loop) runPresenterEnsureStructuredSpacing(presenter *presenterState) {
	if presenter == nil {
		return
	}
	if presenter.lastWasText {
		if presenter.lastTextEndedWithNewline {
			l.print("\n")
		} else {
			l.print("\n\n")
		}
		presenter.lastWasText = false
		presenter.lastTextEndedWithNewline = false
	}
}

func (l *Loop) waitForNextCycle(ctx context.Context, waitSeconds int, st *state) error {
	if st.StopRequested {
		return context.Canceled
	}
	if l.Control == nil {
		return l.idle(ctx, waitSeconds)
	}
	if strings.TrimSpace(st.NextPrompt) != "" {
		return nil
	}
	if st.PauseAfterRun || st.Paused {
		st.Paused = true
		st.PauseAfterRun = false
		if !st.PendingInput && !st.PauseNoticeShown {
			l.println(pausedNoticeText)
			st.PauseNoticeShown = true
		}
		return l.waitWhilePaused(ctx, st)
	}
	return l.idleWithControls(ctx, waitSeconds, st)
}

func (l *Loop) waitForWork(ctx context.Context, waitSeconds int, st *state) error {
	if l.EventBus != nil {
		return l.waitForBusEvents(ctx, waitSeconds, st)
	}
	return l.idleWithControlsLabel(ctx, waitSeconds, st, "waiting for work")
}

func (l *Loop) waitForBusEvents(ctx context.Context, waitSeconds int, st *state) error {
	if waitSeconds <= 0 {
		return nil
	}
	if st.StopRequested {
		return context.Canceled
	}
	if strings.TrimSpace(st.NextPrompt) != "" {
		return nil
	}

	bus := l.EventBus

	// Drain anything already queued.
	if evt, ok := bus.Queue().Pop(); ok {
		return l.processWakeEvent(ctx, evt, st)
	}

	remaining := time.Duration(waitSeconds) * time.Second
	timer := time.NewTimer(remaining)
	defer timer.Stop()

	for {
		select {
		case <-bus.Queue().Ready():
			evt, ok := bus.Queue().Pop()
			if !ok {
				continue
			}
			if !l.shouldWakeForBusEvent(evt, st) {
				continue
			}
			return l.processWakeEvent(ctx, evt, st)
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				return nil
			}
			if st.Paused {
				return l.waitWhilePaused(ctx, st)
			}
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *Loop) shouldWakeForBusEvent(evt BusEvent, st *state) bool {
	autofeed := st != nil && st.Autofeed
	if evt.Priority == PriorityCoordination && !autofeed {
		return false
	}
	return true
}

func (l *Loop) processWakeEvent(ctx context.Context, evt BusEvent, st *state) error {
	st.LastWakeEvent = &evt.Event
	return nil
}

// applyBusInterrupt handles an interrupt-priority event from the EventBus
// during an active run.
func (l *Loop) applyBusInterrupt(evt BusEvent, st *state, cancel context.CancelFunc) {
	switch evt.Event.Type {
	case awid.AgentEventControlInterrupt:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = true
		st.PauseAfterRun = true
		st.RunInterrupted = true
		l.println("\nstopped current run. " + pausedNoticeText)
		st.PauseNoticeShown = true
		if cancel != nil {
			cancel()
		}
	case awid.AgentEventControlPause:
		st.PauseAfterRun = true
		l.println("\nwill pause after this run.")
	}
}

func (l *Loop) waitWhilePaused(ctx context.Context, st *state) error {
	for {
		if st.StopRequested {
			return context.Canceled
		}
		if st.ExitConfirmPending {
			if err := l.waitForExitConfirmation(ctx, st); err != nil {
				return err
			}
		}
		if strings.TrimSpace(st.NextPrompt) != "" {
			st.Paused = false
			return nil
		}
		if !st.Paused {
			return nil
		}
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if st.ExitConfirmPending {
				if err := l.waitForExitConfirmation(ctx, st); err != nil {
					return err
				}
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				st.Paused = false
				return nil
			}
			if !st.Paused {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *Loop) idle(ctx context.Context, seconds int) error {
	if seconds <= 0 {
		return nil
	}
	for remaining := seconds; remaining > 0; remaining-- {
		l.renderIdleLine("next run", remaining, nil)
		if err := l.Sleep(ctx, time.Second); err != nil {
			l.clearStatusLine()
			return err
		}
	}
	l.clearStatusLine()
	return nil
}

func (l *Loop) idleWithControls(ctx context.Context, seconds int, st *state) error {
	return l.idleWithControlsLabel(ctx, seconds, st, "next run")
}

func (l *Loop) idleWithControlsLabel(ctx context.Context, seconds int, st *state, label string) error {
	if seconds <= 0 {
		return nil
	}
	for remaining := seconds; remaining > 0; remaining-- {
		l.renderIdleLine(label, remaining, st)
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if st.ExitConfirmPending {
				if err := l.waitForExitConfirmation(ctx, st); err != nil {
					return err
				}
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				return nil
			}
			if st.Paused {
				return l.waitWhilePaused(ctx, st)
			}
			remaining++
		case <-ctx.Done():
			l.clearStatusLine()
			return ctx.Err()
		default:
			if err := l.Sleep(ctx, time.Second); err != nil {
				l.clearStatusLine()
				return err
			}
		}
	}
	l.clearStatusLine()
	return nil
}

func (l *Loop) controlEvents() <-chan ControlEvent {
	if l.Control == nil {
		return nil
	}
	return l.Control.Events()
}

func (l *Loop) applyControlEvent(event ControlEvent, st *state, activeRun bool, cancel context.CancelFunc) {
	switch event.Type {
	case ControlHelp:
		l.println(helpText)
		l.renderInputPrompt(st)
		return
	case ControlUnknownCommand:
		l.printf("unknown command: %s — type /help for available commands\n", event.Text)
		l.renderInputPrompt(st)
		return
	case ControlExitConfirm:
		l.confirmExit(st, activeRun, cancel)
		return
	case ControlExitCancel:
		l.cancelExitConfirmation(st)
		l.renderInputPrompt(st)
		return
	case ControlInterrupt:
		switch {
		case st.ExitConfirmPending:
			l.confirmExit(st, activeRun, cancel)
			return
		case st.PendingInput || st.InputBuffer != "":
			l.clearPendingInput(st)
			return
		case activeRun && cancel != nil:
			event = ControlEvent{Type: ControlStop}
		default:
			l.offerExit(st)
			l.renderInputPrompt(st)
			return
		}
	case ControlExitPrompt:
		if st.ExitConfirmPending {
			l.confirmExit(st, activeRun, cancel)
			return
		}
		l.offerExit(st)
		l.renderInputPrompt(st)
		return
	}

	if st.ExitConfirmPending {
		l.cancelExitConfirmation(st)
	}

	switch event.Type {
	case ControlTypingStarted:
		st.PendingInput = true
		if !activeRun {
			st.Paused = true
		}
		l.renderInputPrompt(st)
	case ControlBufferUpdated:
		st.InputBuffer = event.Text
		st.PendingInput = event.Text != ""
		if !activeRun && st.PendingInput {
			st.Paused = true
		}
		l.renderInputPrompt(st)
	case ControlPrompt:
		st.PendingInput = false
		st.InputBuffer = ""
		st.NextPrompt = strings.TrimSpace(event.Text)
		st.Paused = false
		st.PauseNoticeShown = false
		if st.Autofeed {
			st.Autofeed = false
			l.announceAutofeedState(false, "disabled for manual conversation. use /autofeed on to re-enable.")
		}
		if activeRun {
			l.printf("\nqueued prompt override: %s\n", truncateText(st.NextPrompt, 80))
			if st.RunLabel != "" {
				l.setStatusLine(formatRunStatus(st))
			}
		}
		l.renderInputPrompt(st)
	case ControlWait:
		st.PendingInput = false
		st.InputBuffer = ""
		st.PauseAfterRun = true
		st.Paused = !activeRun
		if activeRun {
			l.println("\nwill pause after this run.")
		} else {
			l.println(pausedNoticeText)
			st.PauseNoticeShown = true
		}
	case ControlResume:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = false
		st.PauseNoticeShown = false
		if activeRun {
			st.PauseAfterRun = false
		}
		l.renderInputPrompt(st)
	case ControlAutofeedOn:
		st.Autofeed = true
		l.announceAutofeedState(true, "on. work events can wake the agent.")
		l.renderInputPrompt(st)
	case ControlAutofeedOff:
		st.Autofeed = false
		l.announceAutofeedState(false, "off. only comms can wake the agent.")
		l.renderInputPrompt(st)
	case ControlStreamError:
		if text := strings.TrimSpace(event.Text); text != "" {
			l.printf("info: event stream error: %s\n", text)
		} else {
			l.println("info: event stream error")
		}
		l.renderInputPrompt(st)
	case ControlQuit:
		l.confirmExit(st, activeRun, cancel)
	case ControlStop:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = true
		st.PauseAfterRun = true
		if activeRun && cancel != nil {
			st.RunInterrupted = true
			l.println("\nstopped current run. " + pausedNoticeText)
			st.PauseNoticeShown = true
			cancel()
			return
		}
		l.println(pausedNoticeText)
		st.PauseNoticeShown = true
	}
}

func (l *Loop) renderInputPrompt(st *state) {
	if st == nil {
		return
	}
	if screen := l.screen(); screen != nil && screen.HasActiveProgram() {
		return
	}
	if !st.PendingInput && !st.Paused && st.InputBuffer == "" {
		if screen := l.screen(); screen != nil {
			screen.ClearInputLine()
		}
		return
	}
	prompt := FormatInputLine(l.promptLabel(), st.InputBuffer)
	if st.Paused && st.InputBuffer == "" {
		prompt = l.promptLabel()
	}
	if screen := l.screen(); screen != nil {
		screen.SetInputLine(prompt)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintf(l.Out, "\r\033[K%s", prompt)
}

func (l *Loop) promptLabel() string {
	if strings.TrimSpace(l.InputPromptLabel) == "" {
		return DefaultInputPromptLabel
	}
	return l.InputPromptLabel
}

func (l *Loop) renderIdleLine(label string, remaining int, st *state) {
	line := fmt.Sprintf("%s in %ds", label, remaining)
	if screen := l.screen(); screen != nil {
		screen.SetStatusLine(ComposeStatusLine(l.StatusIdentity, line))
		l.renderInputPrompt(st)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if st != nil && strings.TrimSpace(st.InputBuffer) != "" {
		line = fmt.Sprintf("%s  >  %s", line, st.InputBuffer)
	}
	fmt.Fprintf(l.Out, "\r\033[K%s", line)
}

func (l *Loop) announceAutofeedState(enabled bool, detail string) {
	l.println("info: autofeed " + detail)
	mode := "off"
	if enabled {
		mode = "on"
	}
	l.setStatusLine("autofeed " + mode)
}

func (l *Loop) print(text string) {
	if screen := l.screen(); screen != nil {
		screen.AppendText(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprint(l.Out, text)
}

func (l *Loop) printf(format string, args ...any) {
	if screen := l.screen(); screen != nil {
		screen.AppendText(fmt.Sprintf(format, args...))
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintf(l.Out, format, args...)
}

func (l *Loop) println(text string) {
	if screen := l.screen(); screen != nil {
		screen.AppendLine(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintln(l.Out, text)
}

func (l *Loop) offerExit(st *state) {
	if st == nil {
		return
	}
	st.ExitConfirmPending = true
	l.setExitConfirmation(true)
	l.setStatusLine(exitStatusText)
	if l.screen() == nil {
		l.println(exitStatusText)
	}
}

func (l *Loop) cancelExitConfirmation(st *state) {
	if st == nil || !st.ExitConfirmPending {
		return
	}
	st.ExitConfirmPending = false
	l.setExitConfirmation(false)
	if st.Paused {
		l.setStatusLine(pausedStatusText)
		return
	}
	l.clearStatusLine()
}

func (l *Loop) confirmExit(st *state, activeRun bool, cancel context.CancelFunc) {
	if st == nil {
		return
	}
	st.PendingInput = false
	st.InputBuffer = ""
	st.StopRequested = true
	st.Paused = false
	st.PauseNoticeShown = false
	st.PauseAfterRun = false
	st.ExitConfirmPending = false
	l.setExitConfirmation(false)
	l.clearStatusLine()
	l.renderInputPrompt(st)
	if activeRun && cancel != nil {
		l.println("\nquitting.")
		cancel()
	}
}

func (l *Loop) clearPendingInput(st *state) {
	if st == nil {
		return
	}
	st.PendingInput = false
	st.InputBuffer = ""
	if screen := l.screen(); screen != nil {
		screen.ClearInputLine()
		return
	}
	l.renderInputPrompt(st)
}

func (l *Loop) waitForExitConfirmation(ctx context.Context, st *state) error {
	if st == nil || !st.ExitConfirmPending {
		return nil
	}
	l.setStatusLine(exitStatusText)
	for st.ExitConfirmPending && !st.StopRequested {
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if st.StopRequested {
		return context.Canceled
	}
	return nil
}

func (l *Loop) setStatusLine(text string) {
	if screen := l.screen(); screen != nil {
		screen.SetStatusLine(ComposeStatusLine(l.StatusIdentity, text))
	}
}

func (l *Loop) clearStatusLine() {
	if screen := l.screen(); screen != nil {
		if strings.TrimSpace(l.StatusIdentity) != "" {
			screen.SetStatusLine(l.StatusIdentity)
		} else {
			screen.ClearStatusLine()
		}
	}
}

func (l *Loop) setExitConfirmation(active bool) {
	if screen := l.screen(); screen != nil {
		screen.SetExitConfirmation(active)
	}
}

func (l *Loop) screen() UI {
	if l == nil || l.Control == nil {
		return nil
	}
	screen, _ := l.Control.(UI)
	return screen
}

func resolveMissionPrompt(basePrompt string, overridePrompt string) string {
	overridePrompt = strings.TrimSpace(overridePrompt)
	if overridePrompt != "" {
		return overridePrompt
	}
	return strings.TrimSpace(basePrompt)
}

func composePrompt(missionPrompt string, cyclePrompt string) string {
	missionPrompt = strings.TrimSpace(missionPrompt)
	cyclePrompt = strings.TrimSpace(cyclePrompt)
	if missionPrompt == "" {
		return cyclePrompt
	}
	if cyclePrompt == "" {
		return missionPrompt
	}
	return fmt.Sprintf("Primary mission:\n%s\n\nCurrent cycle:\n%s", missionPrompt, cyclePrompt)
}

func composePromptWithServices(missionPrompt string, cyclePrompt string, services []ServiceConfig) string {
	base := composePrompt(missionPrompt, cyclePrompt)
	servicesSection := FormatServicesPromptSection(services)
	if servicesSection == "" {
		return base
	}
	if strings.TrimSpace(base) == "" {
		return servicesSection
	}
	return fmt.Sprintf("%s\n\n%s", base, servicesSection)
}

func displayPrompt(missionPrompt string, cyclePrompt string) string {
	cyclePrompt = strings.TrimSpace(cyclePrompt)
	if cyclePrompt != "" {
		return cyclePrompt
	}
	return strings.TrimSpace(missionPrompt)
}

func SleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func RealCommandRunner(ctx context.Context, dir string, argv []string, onLine func(string), _ any) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		onLine(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return fmt.Errorf("%w: %s", err, stderrText)
		}
		return err
	}
	return nil
}

