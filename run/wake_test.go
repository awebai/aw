package run

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

func TestClientWakeStreamRetriesEarlyEOF(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		if n == 1 {
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		_, _ = w.Write([]byte("event: chat_message\ndata: {\"message_id\":\"m1\",\"from_alias\":\"mia\",\"session_id\":\"s1\"}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	wake := NewClientWakeStream(client)
	wake.RetryDelay = 10 * time.Millisecond
	wake.MaxRetryDelay = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, errs := wake.Stream(ctx, time.Now().Add(500*time.Millisecond))

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case evt, ok := <-events:
			if !ok {
				continue
			}
			if evt.Type != awid.AgentEventChatMessage || evt.FromAlias != "mia" {
				t.Fatalf("unexpected event: %#v", evt)
			}
			cancel()
			if requests.Load() < 2 {
				t.Fatalf("expected at least 2 stream attempts, got %d", requests.Load())
			}
			return
		case err, ok := <-errs:
			if !ok || err == nil {
				continue
			}
			t.Fatalf("unexpected error: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestClientWakeStreamRetriesTransientOpenError(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n == 1 {
			http.Error(w, `{"detail":"temporary"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: connected\ndata: {\"agent_id\":\"a1\",\"project_id\":\"p1\"}\n\n"))
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	wake := NewClientWakeStream(client)
	wake.RetryDelay = 10 * time.Millisecond
	wake.MaxRetryDelay = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, errs := wake.Stream(ctx, time.Now().Add(500*time.Millisecond))

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case evt, ok := <-events:
			if !ok {
				continue
			}
			if evt.Type != awid.AgentEventConnected || evt.AgentID != "a1" {
				t.Fatalf("unexpected event: %#v", evt)
			}
			cancel()
			if requests.Load() < 2 {
				t.Fatalf("expected retry after transient failure, got %d requests", requests.Load())
			}
			return
		case err, ok := <-errs:
			if !ok || err == nil {
				continue
			}
			t.Fatalf("unexpected error: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestClientWakeStreamFailsFastOnClientError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	client, err := awid.NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	wake := NewClientWakeStream(client)
	wake.RetryDelay = 10 * time.Millisecond
	wake.MaxRetryDelay = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, errs := wake.Stream(ctx, time.Now().Add(500*time.Millisecond))

	select {
	case evt := <-events:
		t.Fatalf("unexpected event: %#v", evt)
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for error")
	}
}
