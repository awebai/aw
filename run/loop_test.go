package run

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
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

type fakeWakeStream struct {
	events chan aweb.AgentEvent
	errs   chan error
}

func newFakeWakeStream() *fakeWakeStream {
	return &fakeWakeStream{
		events: make(chan aweb.AgentEvent, 32),
		errs:   make(chan error, 1),
	}
}

func (f *fakeWakeStream) Stream(context.Context, time.Time) (<-chan aweb.AgentEvent, <-chan error) {
	return f.events, f.errs
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

	err := loop.Run(context.Background(), LoopOptions{
		Prompt:      "persistent mission",
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

	err := loop.Run(context.Background(), LoopOptions{
		Prompt:      "persistent mission",
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
	stream := newFakeWakeStream()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.WakeStream = stream

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(context.Background(), LoopOptions{
			Prompt:      "persistent mission",
			WaitSeconds: 30,
			MaxRuns:     2,
		})
	}()

	time.Sleep(20 * time.Millisecond)
	stream.events <- aweb.AgentEvent{Type: aweb.AgentEventChatMessage, FromAlias: "mia"}

	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
