package run

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type fakeInputController struct {
	events chan ControlEvent
}

func newFakeInputController() *fakeInputController {
	return &fakeInputController{events: make(chan ControlEvent, 32)}
}

func (f *fakeInputController) Start() error                { return nil }
func (f *fakeInputController) Stop() error                 { return nil }
func (f *fakeInputController) Events() <-chan ControlEvent { return f.events }
func (f *fakeInputController) HasPendingInput() bool       { return false }

type recordingUI struct {
	*fakeInputController
	statusMu sync.Mutex
	statuses []string
	outputMu sync.Mutex
	output   string
}

func newRecordingUI() *recordingUI {
	return &recordingUI{fakeInputController: newFakeInputController()}
}

func (r *recordingUI) AppendText(text string) {
	r.outputMu.Lock()
	defer r.outputMu.Unlock()
	r.output += text
}

func (r *recordingUI) AppendLine(text string) {
	r.AppendText(text + "\n")
}
func (r *recordingUI) SetInputLine(string)      {}
func (r *recordingUI) ClearInputLine()          {}
func (r *recordingUI) SetExitConfirmation(bool) {}
func (r *recordingUI) HasActiveProgram() bool   { return true }

func (r *recordingUI) SetStatusLine(text string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.statuses = append(r.statuses, text)
}

func (r *recordingUI) ClearStatusLine() {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.statuses = append(r.statuses, "")
}

func (r *recordingUI) sawStatusContaining(substr string) bool {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	for _, status := range r.statuses {
		if strings.Contains(status, substr) {
			return true
		}
	}
	return false
}

func (r *recordingUI) sawOutputContaining(substr string) bool {
	r.outputMu.Lock()
	defer r.outputMu.Unlock()
	return strings.Contains(r.output, substr)
}

type fakeDispatcher struct {
	decisions []DispatchDecision
	index     int
}

func (d *fakeDispatcher) Next(_ context.Context, _ bool, _ *awid.AgentEvent) (DispatchDecision, error) {
	if d.index >= len(d.decisions) {
		return DispatchDecision{}, errors.New("no dispatch decision available")
	}
	decision := d.decisions[d.index]
	d.index++
	return decision, nil
}

type recordingDispatcher struct {
	decision DispatchDecision
	events   []*awid.AgentEvent
}

func (d *recordingDispatcher) Next(_ context.Context, _ bool, wakeEvent *awid.AgentEvent) (DispatchDecision, error) {
	if wakeEvent == nil {
		d.events = append(d.events, nil)
		return d.decision, nil
	}
	copy := *wakeEvent
	d.events = append(d.events, &copy)
	return d.decision, nil
}

type fakeProvider struct {
	event *Event
}

func (fakeProvider) Name() string { return "fake" }

func (fakeProvider) BuildCommand(prompt string, opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", prompt}, nil
}

func (f fakeProvider) ParseOutput(line string) (*Event, error) {
	return f.event, nil
}

func (fakeProvider) SessionID(event *Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func TestLoopMaintainsClaudeSessionContinuity(t *testing.T) {
	var commands [][]string
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		commands = append(commands, append([]string(nil), argv...))
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	controller := newFakeInputController()
	loop.Control = controller
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "persistent mission", WaitSeconds: 1},
			{MissionPrompt: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}
	if strings.Contains(strings.Join(commands[0], " "), "resume") {
		t.Fatalf("first run should not resume an existing session: %q", strings.Join(commands[0], " "))
	}
	if !strings.Contains(strings.Join(commands[1], " "), "--continue") {
		t.Fatalf("second run should continue the same session: %q", strings.Join(commands[1], " "))
	}
}

func TestLoopMaintainsCodexSessionContinuity(t *testing.T) {
	var commands [][]string
	loop := NewLoop(CodexProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		commands = append(commands, append([]string(nil), argv...))
		onLine(`{"type":"thread.started","thread_id":"019ccab4-4844-7ff3-80f2-b2d3b0c25e79"}`)
		onLine(`{"type":"turn.completed"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "persistent mission", WaitSeconds: 1},
			{MissionPrompt: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}
	if strings.Contains(strings.Join(commands[0], " "), "resume") {
		t.Fatalf("first codex run should start fresh, got %q", strings.Join(commands[0], " "))
	}
	if !strings.Contains(strings.Join(commands[1], " "), "resume 019ccab4-4844-7ff3-80f2-b2d3b0c25e79") {
		t.Fatalf("second codex run should use exact session id, got %q", strings.Join(commands[1], " "))
	}
}

func TestLoopWaitForWorkWakesOnChatMessage(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventChatMessage, FromAlias: "mia"},
	)
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, &state{})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for wake on chat message")
	}
	cancel()
	bus.Stop()
}

func TestEventBusDeliversInterruptDuringRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		if evt.Event.Type != awid.AgentEventControlInterrupt {
			t.Fatalf("expected control_interrupt, got %s", evt.Event.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for interrupt from bus")
	}
	cancel()
	bus.Stop()
}

func TestLoopDoesNotSuppressBdhSpecificEchoText(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{
			Type: EventText,
			Text: "Primary mission:\nAGENTS.md instructions\nProject Context\n",
		},
	}, &out)
	st := &state{}

	loop.handleOutputLine("ignored", &presenterState{}, st, nil)

	got := out.String()
	if !strings.Contains(got, "AGENTS.md instructions") {
		t.Fatalf("expected echoed prompt text to be preserved, got %q", got)
	}
	if strings.Contains(got, "[suppressed prompt/policy echo]") {
		t.Fatalf("unexpected suppression marker in output: %q", got)
	}
}

func TestLoopInitialPromptOnlyWaitsForWakeInsteadOfTimerExit(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "what are we working on?",
			WaitSeconds:   1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled after explicit cancel, got %v", err)
	}
}

func TestLoopBasePromptDoesNotAutoRerunWithoutWake(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			Prompt:      "persistent mission",
			WaitSeconds: 1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if runCount != 1 {
		t.Fatalf("expected exactly one run without wake events, got %d", runCount)
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled after explicit cancel, got %v", err)
	}
}

func TestFormatRunStatusOmitsRunLabel(t *testing.T) {
	st := &state{RunLabel: "run 3"}
	got := formatRunStatus(st)
	if got != "" {
		t.Fatalf("expected empty status with only run label, got %q", got)
	}
}

func TestFormatWaitStatusShowsConnectionStateAndAutofeed(t *testing.T) {
	st := &state{Autofeed: true, ConnState: ConnReconnecting}
	got := formatWaitStatus("waiting for prompt", st)
	want := "waiting for prompt · autofeed · reconnecting..."
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsContextAndCost(t *testing.T) {
	st := &state{
		RunLabel:    "run 1",
		HasRunUsage: true,
		LastRunUsage: UsageStats{
			InputTokens:       45000,
			ContextWindowSize: 100000,
		},
		CumulativeCostUSD: 0.05,
		Autofeed:          true,
		ConnState:         ConnStreaming,
	}
	got := formatRunStatus(st)
	want := "ctx 45% · $0.05 · autofeed · streaming"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsReconnecting(t *testing.T) {
	st := &state{
		RunLabel:          "run 1",
		CumulativeCostUSD: 0.05,
		ConnState:         ConnReconnecting,
	}
	got := formatRunStatus(st)
	want := "$0.05 · reconnecting..."
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsQueuedWhenPromptPending(t *testing.T) {
	st := &state{
		RunLabel:   "run 1",
		NextPrompt: "fix the bug",
	}
	got := formatRunStatus(st)
	if got != "queued" {
		t.Fatalf("expected 'queued', got %q", got)
	}
}

func TestFormatRunStatusOmitsQueuedWhenNoPromptPending(t *testing.T) {
	st := &state{RunLabel: "run 1"}
	got := formatRunStatus(st)
	if strings.Contains(got, "queued") {
		t.Fatalf("expected no 'queued' indicator without pending prompt, got %q", got)
	}
}

func TestHandleOutputLineAccumulatesCost(t *testing.T) {
	cost := 0.05
	provider := &fakeProvider{
		event: &Event{
			Type:    EventDone,
			CostUSD: &cost,
			Session: "sess-1",
		},
	}
	var out bytes.Buffer
	loop := NewLoop(provider, &out)
	st := &state{RunLabel: "run 1"}
	presenter := &presenterState{}
	sid := ""

	loop.handleOutputLine("event1", presenter, st, &sid)
	if st.CumulativeCostUSD != 0.05 {
		t.Fatalf("expected 0.05, got %f", st.CumulativeCostUSD)
	}

	loop.handleOutputLine("event2", presenter, st, &sid)
	if st.CumulativeCostUSD != 0.10 {
		t.Fatalf("expected 0.10, got %f", st.CumulativeCostUSD)
	}
}

func TestAutoCompactShowsDistinctLabel(t *testing.T) {
	var out bytes.Buffer
	provider := fakeProvider{
		event: &Event{
			Type:    EventDone,
			Session: "sess-42",
			Usage: &UsageStats{
				InputTokens:       90000,
				ContextWindowSize: 100000,
			},
		},
	}
	loop := NewLoop(provider, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "work", WaitSeconds: 0},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		MaxRuns:             1,
		CompactThresholdPct: 80,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "info: compacting context") {
		t.Fatalf("expected compact info line, got %q", output)
	}
	if strings.Count(output, "> work") != 1 {
		t.Fatalf("expected exactly one '> work' prompt (not duplicated by compact), got %q", output)
	}
}

func TestAutoCompactDoesNotCountTowardMaxRuns(t *testing.T) {
	var out bytes.Buffer
	realRunCount := 0
	compactRunCount := 0
	provider := fakeProvider{
		event: &Event{
			Type:    EventDone,
			Session: "sess-42",
			Usage: &UsageStats{
				InputTokens:       90000,
				ContextWindowSize: 100000,
			},
		},
	}
	loop := NewLoop(provider, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		if len(argv) > 1 && argv[1] == "/compact" {
			compactRunCount++
		} else {
			realRunCount++
		}
		onLine("done")
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "work", WaitSeconds: 0},
			{MissionPrompt: "work", WaitSeconds: 0},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		MaxRuns:             2,
		CompactThresholdPct: 80,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if realRunCount != 2 {
		t.Fatalf("expected 2 real runs, got %d", realRunCount)
	}
	if compactRunCount != 2 {
		t.Fatalf("expected 2 compact runs (one after each real run), got %d", compactRunCount)
	}
}

func TestRunSeparatorAppearsBetweenRuns(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "first", WaitSeconds: 0},
			{MissionPrompt: "second", WaitSeconds: 0},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{MaxRuns: 2})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, runSeparator) {
		t.Fatalf("expected run separator between runs, got:\n%s", output)
	}
	firstPromptIdx := strings.Index(output, "> first")
	separatorIdx := strings.Index(output, runSeparator)
	secondPromptIdx := strings.Index(output, "> second")
	if separatorIdx <= firstPromptIdx {
		t.Fatalf("separator should appear after first prompt")
	}
	if separatorIdx >= secondPromptIdx {
		t.Fatalf("separator should appear before second prompt")
	}
}

func TestNoSeparatorBeforeFirstRun(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "first", WaitSeconds: 0},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{MaxRuns: 1})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, runSeparator) {
		t.Fatalf("expected no separator before first run, got:\n%s", output)
	}
}

func TestEventBusDisconnectsWhenServerReturns404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/events/stream") {
			http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	bus := NewEventBus(EventBusConfig{
		Stream: NewEventStreamOpener(client),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	// Wait for the bus goroutine to exit on 404.
	select {
	case <-bus.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bus to disconnect on 404")
	}

	if bus.State() != ConnDisconnected {
		t.Fatalf("expected disconnected, got %s", bus.State())
	}
	cancel()
	bus.Stop()
}

func TestLoopContinuesViaTimeoutWhenBusDisconnected(t *testing.T) {
	// EventBus that immediately disconnects (404).
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			return nil, &awid.APIError{StatusCode: 404, Body: "not found"}
		},
	})

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{MissionPrompt: "first", WaitSeconds: 1},
			{MissionPrompt: "second", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if runCount != 2 {
		t.Fatalf("expected 2 runs via timeout fallback, got %d", runCount)
	}
}

// --- EventBus integration tests ---

func newTestEventBus(events ...awid.AgentEvent) *EventBus {
	source := newFakeEventSource(events...)
	called := false
	return NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})
}

func TestLoopEventBusWakesOnMailMessage(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventMailMessage, FromAlias: "alice"},
	)
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "hello",
			WaitSeconds:   30,
		})
	}()

	// Wait for the bus event to wake the loop into a second run wait.
	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestNextPromptConsumesWakeEventAfterDispatch(t *testing.T) {
	dispatcher := &recordingDispatcher{
		decision: DispatchDecision{Prompt: "handle wake"},
	}
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Dispatch = dispatcher

	st := &state{
		Run:           1,
		LastWakeEvent: &awid.AgentEvent{Type: awid.AgentEventMailMessage, FromAlias: "alice"},
	}
	opts := LoopOptions{WaitSeconds: 5, IdleWaitSeconds: 9}

	first, err := loop.nextPrompt(context.Background(), opts, st)
	if err != nil {
		t.Fatalf("nextPrompt returned error: %v", err)
	}
	if first.Prompt != "handle wake" {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	if st.LastWakeEvent != nil {
		t.Fatalf("expected wake event to be consumed, got %+v", st.LastWakeEvent)
	}

	second, err := loop.nextPrompt(context.Background(), opts, st)
	if err != nil {
		t.Fatalf("second nextPrompt returned error: %v", err)
	}
	if len(dispatcher.events) != 2 {
		t.Fatalf("expected two dispatch calls, got %d", len(dispatcher.events))
	}
	if dispatcher.events[0] == nil || dispatcher.events[0].FromAlias != "alice" {
		t.Fatalf("expected first dispatch to receive wake event, got %+v", dispatcher.events[0])
	}
	if dispatcher.events[1] != nil {
		t.Fatalf("expected second dispatch to receive nil wake event, got %+v", dispatcher.events[1])
	}
	if second.Prompt != "handle wake" {
		t.Fatalf("unexpected second decision: %+v", second)
	}
}

func TestLoopShowsStartupStatusBeforeFirstPromptWhileEventBusRuns(t *testing.T) {
	ui := newRecordingUI()
	bus := newTestEventBus()

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui
	loop.EventBus = bus
	loop.StatusIdentity = "claude@aweb:aw:rose"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{WaitSeconds: 30})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ui.sawStatusContaining("claude@aweb:aw:rose · waiting for prompt") {
			cancel()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context canceled, got %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	_ = <-done
	t.Fatal("timed out waiting for startup status line")
}

func TestLoopShowsFreshStartGreetingWithoutContinue(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui
	loop.StatusIdentity = "claude@aweb:aw:rose"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{WaitSeconds: 30})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ui.sawOutputContaining("__ ___      __  _    __ ___") && ui.sawOutputContaining("The aweb agent runner") && ui.sawOutputContaining("type /help for controls, or enter a prompt to begin") {
			cancel()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context canceled, got %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	_ = <-done
	t.Fatal("timed out waiting for startup greeting")
}

func TestLoopSkipsFreshStartGreetingInContinueMode(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			WaitSeconds:  30,
			ContinueMode: true,
		})
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if ui.sawOutputContaining("The aweb agent runner") {
		t.Fatal("did not expect startup greeting in continue mode")
	}
}

func TestLoopEventBusInterruptDuringRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runStarted := make(chan struct{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		close(runStarted)
		// Block until context is cancelled by interrupt.
		<-ctx.Done()
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return ctx.Err()
	}
	controller := newFakeInputController()
	loop.Control = controller

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "work",
			WaitSeconds:   1,
		})
	}()

	// Wait for run to start.
	select {
	case <-runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run to start")
	}

	// The interrupt should cancel the run and pause.
	time.Sleep(200 * time.Millisecond)

	// Send /resume to unpause, then cancel.
	controller.events <- ControlEvent{Type: ControlQuit}
	controller.events <- ControlEvent{Type: ControlExitConfirm}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected clean exit, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to exit")
	}

	if !strings.Contains(out.String(), "stopped current run") {
		t.Fatalf("expected interrupt notice, got %q", out.String())
	}
}

func TestLoopEventBusBasePromptWaitsForEvents(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			Prompt:      "persistent mission",
			WaitSeconds: 1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if runCount != 1 {
		t.Fatalf("expected exactly one run without wake events, got %d", runCount)
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestWaitForBusEventsSkipsCoordinationWithoutAutofeed(t *testing.T) {
	// Pre-queue a coordination event, then a communication event.
	bus := newTestEventBus()
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable, TaskID: "t1"}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventMailMessage, FromAlias: "alice"}})

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	// Autofeed OFF — coordination should be skipped, mail should wake.
	st := &state{Autofeed: false}
	err := loop.waitForBusEvents(context.Background(), 30, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LastWakeEvent == nil {
		t.Fatal("expected LastWakeEvent to be set")
	}
	if st.LastWakeEvent.Type != awid.AgentEventMailMessage {
		t.Fatalf("expected mail message wake (skipping coordination), got %s", st.LastWakeEvent.Type)
	}
}

func TestApplyBusInterruptResumeClearsPause(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:           true,
		PauseAfterRun:    true,
		PauseNoticeShown: true,
	}

	loop.applyBusInterrupt(BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}, st, nil)

	if st.Paused {
		t.Fatal("expected Paused to be cleared")
	}
	if st.PauseAfterRun {
		t.Fatal("expected PauseAfterRun to be cleared")
	}
	if st.PauseNoticeShown {
		t.Fatal("expected PauseNoticeShown to be cleared")
	}
}

func TestRemoteResumeDeliveredThroughBusInterrupts(t *testing.T) {
	// Verify control_resume reaches the interrupts channel.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlResume},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		if evt.Event.Type != awid.AgentEventControlResume {
			t.Fatalf("expected control_resume, got %s", evt.Event.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resume interrupt")
	}
	cancel()
	bus.Stop()
}

func TestWaitForBusEventsDrainsQueueAfterReady(t *testing.T) {
	// Simulate the bug: two events arrive close together.
	// The first is filtered (coordination, no autofeed), the second should wake.
	bus := newTestEventBus()

	// Pre-push both events before waitForBusEvents is called.
	// This simulates them arriving between Ready() checks.
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventMailMessage, FromAlias: "bob"}})

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	// The initial drain should skip coordination and find the mail.
	st := &state{Autofeed: false}
	err := loop.waitForBusEvents(context.Background(), 30, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LastWakeEvent == nil || st.LastWakeEvent.Type != awid.AgentEventMailMessage {
		t.Fatalf("expected mail wake, got %v", st.LastWakeEvent)
	}
}

func TestWaitForBusEventsDrainsQueueFromReadySignal(t *testing.T) {
	// Test the Ready() path (not the initial drain): coordination then mail
	// arrive after waitForBusEvents enters the select loop.
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	st := &state{Autofeed: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	// Let the goroutine enter the select loop.
	time.Sleep(50 * time.Millisecond)

	// Push coordination first, then mail. Only one Ready() signal fires.
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventMailMessage, FromAlias: "carol"}})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — mail event stuck in queue after coordination was filtered")
	}

	if st.LastWakeEvent == nil || st.LastWakeEvent.FromAlias != "carol" {
		t.Fatalf("expected carol mail wake, got %v", st.LastWakeEvent)
	}
}

func TestRemoteResumeUnblocksPausedLoop(t *testing.T) {
	// A remote control_resume sent while the loop is paused should
	// unblock waitWhilePaused via the EventBus interrupts channel.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlResume},
	)

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus

	st := &state{Paused: true, PauseAfterRun: true, PauseNoticeShown: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitWhilePaused(ctx, st)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitWhilePaused returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out — remote resume did not unblock paused loop")
	}

	if st.Paused {
		t.Fatal("expected Paused=false after remote resume")
	}
}

func TestRemotePauseDuringIdleWait(t *testing.T) {
	// A remote control_pause sent while idle (waitForBusEvents) should
	// cause the loop to enter the paused state. We send pause then resume
	// so waitWhilePaused unblocks and the function returns.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlPause},
	)

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus

	st := &state{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	// Give the pause event time to be consumed, then send resume
	// to unblock waitWhilePaused.
	time.Sleep(200 * time.Millisecond)
	bus.interrupts <- BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out — remote pause+resume did not complete during idle wait")
	}

	// After pause+resume, PauseAfterRun should have been set (pause)
	// then cleared (resume).
	if st.Paused {
		t.Fatal("expected Paused=false after resume")
	}
}

func TestRemoteInterruptDuringIdleDoesNotLeakIntoNextRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)

	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.EventBus = bus
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}

	st := &state{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	time.Sleep(200 * time.Millisecond)
	bus.interrupts <- BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for idle interrupt+resume")
	}

	if st.RunInterrupted {
		t.Fatal("expected RunInterrupted=false after idle interrupt handling")
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, st, "review", "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if st.Paused {
		t.Fatal("expected next run to finish without re-pausing")
	}
	if st.PauseAfterRun {
		t.Fatal("expected PauseAfterRun=false after next run")
	}
}

func TestLoopAllowsInteractiveStartWithoutPrompt(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &out)
	controller := newFakeInputController()
	loop.Control = controller
	ran := make(chan []string, 1)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		ran <- append([]string(nil), argv...)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error {
		return SleepWithContext(ctx, 10*time.Millisecond)
	}

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(context.Background(), LoopOptions{
			WaitSeconds: 1,
			MaxRuns:     1,
		})
	}()

	time.Sleep(100 * time.Millisecond)
	controller.events <- ControlEvent{Type: ControlPrompt, Text: "hello from user"}

	select {
	case argv := <-ran:
		if len(argv) < 2 || argv[1] != "hello from user" {
			t.Fatalf("unexpected command argv %q", argv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for manual prompt to start first run")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to finish after first manual run")
	}
}

func TestRunOnceSurfacesProviderStderr(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, ok := stderrSink.(*commandOutputSinks)
		if !ok || sinks == nil || sinks.stderrLine == nil {
			t.Fatal("expected stderr sinks")
		}
		sinks.stderrLine("approval required")
		onLine("done")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, &state{}, "review", "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "provider stderr: approval required") {
		t.Fatalf("expected streamed stderr in output, got %q", got)
	}
}

func TestRunOnceSurfacesProviderStdoutPartial(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, ok := stderrSink.(*commandOutputSinks)
		if !ok || sinks == nil || sinks.stdoutPartial == nil {
			t.Fatal("expected stdout partial sink")
		}
		sinks.stdoutPartial("Allow? [y/N]")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, &state{}, "review", "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "provider stdout: Allow? [y/N]") {
		t.Fatalf("expected streamed stdout partial in output, got %q", got)
	}
}

func TestHandleRawProviderChunkPTYStartsOnFreshLineWithoutLabel(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventText, Text: "Juan"},
	}, &out)
	presenter := &presenterState{}
	st := &state{}

	loop.handleOutputLine("ignored", presenter, st, nil)
	loop.handleRawProviderChunk("", "Allow? [y/N]", presenter)

	got := out.String()
	if strings.Contains(got, "provider tty:") {
		t.Fatalf("expected PTY output to omit provider tty label, got %q", got)
	}
	if !strings.Contains(got, "Allow? [y/N]") {
		t.Fatalf("expected PTY partial output, got %q", got)
	}
	if strings.Contains(got, "JuanAllow? [y/N]") {
		t.Fatalf("expected PTY chunk to start on a fresh line, got %q", got)
	}
	if !strings.Contains(got, "Juan\nAllow? [y/N]") {
		t.Fatalf("expected PTY chunk to be separated from prior text, got %q", got)
	}
}

func TestRealCommandRunnerStreamsPartialStderrBeforeExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	stderrSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "printf 'approval required' >&2; sleep 1",
		}, func(string) {}, &commandOutputSinks{
			stderrPartial: func(chunk string) {
				select {
				case stderrSeen <- chunk:
				default:
				}
			},
		})
	}()

	select {
	case got := <-stderrSeen:
		if got != "approval required" {
			t.Fatalf("unexpected stderr line %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for stderr before process exit")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerStreamsPartialStdoutBeforeExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	stdoutSeen := make(chan string, 1)
	done := make(chan error, 1)
	lineSeen := make(chan string, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "printf 'Allow? [y/N]'; sleep 1",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			stdoutPartial: func(chunk string) {
				select {
				case stdoutSeen <- chunk:
				default:
				}
			},
		})
	}()

	select {
	case got := <-stdoutSeen:
		if got != "Allow? [y/N]" {
			t.Fatalf("unexpected stdout partial %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for stdout partial before process exit")
	}

	select {
	case got := <-lineSeen:
		t.Fatalf("did not expect line callback for partial stdout, got %q", got)
	case <-time.After(200 * time.Millisecond):
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerAcceptsProviderInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "read answer; printf '%s\\n' \"$answer\"",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			stdinReady: func(w io.WriteCloser) {
				_, _ = io.WriteString(w, "y\n")
			},
		})
	}()

	select {
	case got := <-lineSeen:
		if got != "y" {
			t.Fatalf("unexpected stdout line %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for provider stdin round-trip")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerPTYProvidesTTYAndAcceptsInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY test uses POSIX shell semantics")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	partialSeen := make(chan string, 1)
	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "test -t 0 || exit 42; printf 'Allow? [y/N]'; read answer; printf '\\n%s\\n' \"$answer\"",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			usePTY: true,
			ptyPartial: func(chunk string) {
				select {
				case partialSeen <- chunk:
				default:
				}
			},
			stdinReady: func(w io.WriteCloser) {
				go func() {
					time.Sleep(100 * time.Millisecond)
					_, _ = io.WriteString(w, "y\n")
				}()
			},
		})
	}()

	select {
	case got := <-partialSeen:
		if got != "Allow? [y/N]" {
			t.Fatalf("unexpected PTY partial %q", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for PTY partial prompt")
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-lineSeen:
			if got == "" {
				continue
			}
			if got != "y" {
				t.Fatalf("unexpected PTY stdout line %q", got)
			}
			goto ptyDone
		case <-deadline:
			t.Fatal("timed out waiting for PTY input round-trip")
		}
	}

ptyDone:

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PTY runner to finish")
	}
}
