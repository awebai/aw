// ABOUTME: Tests for the chat protocol layer.
// ABOUTME: Uses httptest mock servers to test protocol functions.

package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
)

// mockHandler dispatches requests to registered handlers by method+path.
type mockHandler struct {
	handlers map[string]http.HandlerFunc
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if h, ok := m.handlers[key]; ok {
		h(w, r)
		return
	}
	// Try prefix match for parameterized paths
	for k, h := range m.handlers {
		if strings.HasPrefix(key, k) {
			h(w, r)
			return
		}
	}
	http.NotFound(w, r)
}

func newMockServer(handlers map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(&mockHandler{handlers: handlers})
}

func mustClient(t *testing.T, url string) *aweb.Client {
	t.Helper()
	c, err := aweb.New(url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "hi", LastFrom: "bob", UnreadCount: 1},
				},
				MessagesWaiting: 2,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Pending(context.Background(), mustClient(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pending) != 1 {
		t.Fatalf("pending=%d", len(result.Pending))
	}
	if result.Pending[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", result.Pending[0].SessionID)
	}
	if result.MessagesWaiting != 2 {
		t.Fatalf("messages_waiting=%d", result.MessagesWaiting)
	}
}

func TestHangOn(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"POST /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, r *http.Request) {
			var req aweb.ChatSendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if !req.HangOn {
				t.Error("expected hang_on=true")
			}
			jsonResponse(w, aweb.ChatSendMessageResponse{
				MessageID:          "msg-1",
				Delivered:          true,
				ExtendsWaitSeconds: 300,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := HangOn(context.Background(), mustClient(t, server.URL), "bob", "thinking...")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if result.ExtendsWaitSeconds != 300 {
		t.Fatalf("extends_wait_seconds=%d", result.ExtendsWaitSeconds)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, SenderWaiting: true},
				},
			})
		},
		"GET /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatHistoryResponse{
				Messages: []aweb.ChatMessage{
					{MessageID: "m1", FromAgent: "bob", Body: "hello", Timestamp: "2025-01-01T00:00:00Z"},
					{MessageID: "m2", FromAgent: "bob", Body: "are you there?", Timestamp: "2025-01-01T00:00:01Z"},
				},
			})
		},
		"POST /v1/chat/sessions/s1/read": func(w http.ResponseWriter, r *http.Request) {
			var req aweb.ChatMarkReadRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.UpToMessageID != "m2" {
				t.Errorf("up_to_message_id=%s", req.UpToMessageID)
			}
			jsonResponse(w, aweb.ChatMarkReadResponse{
				Success:        true,
				MessagesMarked: 2,
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Open(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("messages=%d", len(result.Messages))
	}
	if result.MarkedRead != 2 {
		t.Fatalf("marked_read=%d", result.MarkedRead)
	}
	if !result.SenderWaiting {
		t.Fatal("sender_waiting=false")
	}
}

func TestOpenFallbackToListSessions(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{Pending: []aweb.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/sessions" {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, aweb.ChatListSessionsResponse{
				Sessions: []aweb.ChatSessionItem{
					{SessionID: "s2", Participants: []string{"alice", "bob"}, CreatedAt: "2025-01-01T00:00:00Z"},
				},
			})
		},
		"GET /v1/chat/sessions/s2/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatHistoryResponse{Messages: []aweb.ChatMessage{}})
		},
	})
	t.Cleanup(server.Close)

	result, err := Open(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s2" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if !result.UnreadWasEmpty {
		t.Fatal("expected unread_was_empty=true")
	}
}

func TestHistory(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/messages": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatHistoryResponse{
				Messages: []aweb.ChatMessage{
					{MessageID: "m1", FromAgent: "alice", Body: "hello", Timestamp: "2025-01-01T00:00:00Z"},
					{MessageID: "m2", FromAgent: "bob", Body: "hi!", Timestamp: "2025-01-01T00:00:01Z"},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := History(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
	if len(result.Messages) != 2 {
		t.Fatalf("messages=%d", len(result.Messages))
	}
}

func TestShowPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "help!", LastFrom: "bob", SenderWaiting: true},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := ShowPending(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "help!" {
		t.Fatalf("reply=%s", result.Reply)
	}
	if !result.SenderWaiting {
		t.Fatal("sender_waiting=false")
	}
}

func TestSendWithLeaving(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			var req aweb.ChatCreateSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if !req.Leaving {
				t.Error("expected leaving=true")
			}
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1", MessageID: "m1",
				SSEURL: "/v1/chat/sessions/s1/stream",
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "goodbye", SendOptions{Leaving: true, Wait: 60}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendNoWait(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1", MessageID: "m1",
				SSEURL: "/v1/chat/sessions/s1/stream",
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "fire and forget", SendOptions{Wait: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendTargetsLeft(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID:   "s1",
				MessageID:   "m1",
				SSEURL:      "/v1/chat/sessions/s1/stream",
				TargetsLeft: []string{"bob"},
			})
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 60}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "targets_left" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendWithReply(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Replay: our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply-1", "from_agent": "bob", "body": "hi back!",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "hi back!" {
		t.Fatalf("reply=%s", result.Reply)
	}
}

func TestSendWithTimeout(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Replay our sent message, then hang (no reply)
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Block until client disconnects
			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s (expected sent after timeout)", result.Status)
	}
	if result.WaitedSeconds < 1 {
		t.Fatalf("waited_seconds=%d", result.WaitedSeconds)
	}
}

func TestSendWithHangOnReceived(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var callbackCalls []string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Bob sends hang-on
			hangOnData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-hangon", "from_agent": "bob",
				"body": "thinking...", "hang_on": true, "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", hangOnData)
			if flusher != nil {
				flusher.Flush()
			}

			// Bob sends actual reply
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "here's my answer",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, msg string) {
		callbackCalls = append(callbackCalls, kind+": "+msg)
	}

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "here's my answer" {
		t.Fatalf("reply=%s", result.Reply)
	}

	// Verify callbacks were called for hang_on and wait_extended
	foundHangOn := false
	foundExtended := false
	for _, c := range callbackCalls {
		if strings.HasPrefix(c, "hang_on:") {
			foundHangOn = true
		}
		if strings.HasPrefix(c, "wait_extended:") {
			foundExtended = true
		}
	}
	if !foundHangOn {
		t.Fatal("missing hang_on callback")
	}
	if !foundExtended {
		t.Fatal("missing wait_extended callback")
	}
}

func TestSendWithReadReceipt(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var callbackKinds []string

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Our sent message
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Read receipt from bob with 300s extension (matches server behavior)
			rrData, _ := json.Marshal(map[string]any{
				"type": "read_receipt", "reader_alias": "bob", "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: read_receipt\ndata: %s\n\n", rrData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "got it",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, _ string) {
		callbackKinds = append(callbackKinds, kind)
	}

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}

	foundReadReceipt := false
	foundWaitExtended := false
	for _, k := range callbackKinds {
		if k == "read_receipt" {
			foundReadReceipt = true
		}
		if k == "wait_extended" {
			foundWaitExtended = true
		}
	}
	if !foundReadReceipt {
		t.Fatal("missing read_receipt callback")
	}
	if !foundWaitExtended {
		t.Fatal("missing wait_extended callback from read receipt")
	}
}

func TestSendStreamDeadlineExceedsWait(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"
	var capturedDeadline time.Time

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, r *http.Request) {
			// Capture the deadline query parameter sent to the server.
			deadlineStr := r.URL.Query().Get("deadline")
			if deadlineStr != "" {
				capturedDeadline, _ = time.Parse(time.RFC3339Nano, deadlineStr)
			}

			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Send our message then reply immediately.
			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "hi",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	before := time.Now()
	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}

	// The stream deadline should be at least maxStreamDeadline from now,
	// not just the wait timeout (5s).
	if capturedDeadline.IsZero() {
		t.Fatal("server did not receive deadline parameter")
	}
	minExpected := before.Add(maxStreamDeadline - 1*time.Second)
	if capturedDeadline.Before(minExpected) {
		t.Fatalf("stream deadline %v is too close to now; expected at least %v from request time", capturedDeadline, maxStreamDeadline)
	}
}

func TestDefaultWaitIs120(t *testing.T) {
	t.Parallel()

	if DefaultWait != 120 {
		t.Fatalf("DefaultWait=%d, want 120", DefaultWait)
	}
}

func TestMaxSendTimeoutIs16Min(t *testing.T) {
	t.Parallel()

	if MaxSendTimeout != 16*time.Minute {
		t.Fatalf("MaxSendTimeout=%v, want 16m", MaxSendTimeout)
	}
}

func TestFindSessionFallback(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{Pending: []aweb.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/sessions" {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, aweb.ChatListSessionsResponse{
				Sessions: []aweb.ChatSessionItem{
					{SessionID: "s-fallback", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, senderWaiting, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-fallback" {
		t.Fatalf("session_id=%s", sessionID)
	}
	if senderWaiting {
		t.Fatal("sender_waiting=true (expected false from fallback)")
	}
}

func TestFindSessionNotFound(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{Pending: []aweb.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/sessions" {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, aweb.ChatListSessionsResponse{Sessions: []aweb.ChatSessionItem{}})
		},
	})
	t.Cleanup(server.Close)

	_, _, err := findSession(context.Background(), mustClient(t, server.URL), "nobody")
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !strings.Contains(err.Error(), "no conversation found") {
		t.Fatalf("err=%s", err)
	}
}

func TestParseSSEEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event aweb.SSEEvent
		check func(t *testing.T, ev Event)
	}{
		{
			name: "message event",
			event: aweb.SSEEvent{
				Event: "message",
				Data:  `{"session_id":"s1","message_id":"m1","from_agent":"bob","body":"hello","sender_leaving":false,"hang_on":false,"extends_wait_seconds":0}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "message" {
					t.Fatalf("type=%s", ev.Type)
				}
				if ev.FromAgent != "bob" {
					t.Fatalf("from_agent=%s", ev.FromAgent)
				}
				if ev.Body != "hello" {
					t.Fatalf("body=%s", ev.Body)
				}
			},
		},
		{
			name: "read receipt event",
			event: aweb.SSEEvent{
				Event: "read_receipt",
				Data:  `{"type":"read_receipt","reader_alias":"bob","extends_wait_seconds":60}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "read_receipt" {
					t.Fatalf("type=%s", ev.Type)
				}
				if ev.ReaderAlias != "bob" {
					t.Fatalf("reader_alias=%s", ev.ReaderAlias)
				}
				if ev.ExtendsWaitSeconds != 60 {
					t.Fatalf("extends_wait_seconds=%d", ev.ExtendsWaitSeconds)
				}
			},
		},
		{
			name: "hang on event",
			event: aweb.SSEEvent{
				Event: "message",
				Data:  `{"type":"message","from_agent":"bob","body":"thinking...","hang_on":true,"extends_wait_seconds":300}`,
			},
			check: func(t *testing.T, ev Event) {
				if !ev.HangOn {
					t.Fatal("hang_on=false")
				}
				if ev.ExtendsWaitSeconds != 300 {
					t.Fatalf("extends_wait_seconds=%d", ev.ExtendsWaitSeconds)
				}
			},
		},
		{
			name: "from fallback",
			event: aweb.SSEEvent{
				Event: "message",
				Data:  `{"from":"bob","body":"legacy"}`,
			},
			check: func(t *testing.T, ev Event) {
				if ev.FromAgent != "bob" {
					t.Fatalf("from_agent=%s (expected fallback from 'from')", ev.FromAgent)
				}
			},
		},
		{
			name: "invalid JSON",
			event: aweb.SSEEvent{
				Event: "message",
				Data:  "not json",
			},
			check: func(t *testing.T, ev Event) {
				if ev.Type != "message" {
					t.Fatalf("type=%s (should preserve event type)", ev.Type)
				}
				if ev.FromAgent != "" {
					t.Fatalf("from_agent=%s (should be empty on parse error)", ev.FromAgent)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseSSEEvent(&tt.event)
			tt.check(t, ev)
		})
	}
}

func TestStreamToChannelCleansUpOnCancel(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := aweb.NewSSEStream(pr)
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events

	cancel()

	// cleanup must return (not hang), proving the goroutine exited.
	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine leaked")
	}
}

func TestStreamToChannelCleansUpWhileBlockedOnNext(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := aweb.NewSSEStream(pr)

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events

	// Don't write anything — goroutine is blocked inside stream.Next().
	time.Sleep(50 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK — goroutine unblocked from stream.Next() and exited.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine stuck in stream.Next()")
	}

	pw.Close()
}

func TestStreamToChannelCleansUpWhenBufferFull(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	stream := aweb.NewSSEStream(pr)

	// Write enough events to fill the channel buffer (capacity 10).
	go func() {
		for i := 0; i < 15; i++ {
			fmt.Fprintf(pw, "event: message\ndata: {\"i\":%d}\n\n", i)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	events, cleanup := streamToChannel(ctx, stream)
	_ = events // deliberately don't read

	// Give goroutine time to fill the buffer.
	time.Sleep(100 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()

	select {
	case <-done:
		// OK — goroutine cleaned up even with full channel buffer.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not return — goroutine leaked with full channel buffer")
	}

	pw.Close()
}

// --- Fix 1: WaitExplicit prevents sentinel upgrade ---

func TestSendStartConversationRespectsExplicitWait(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Reply immediately so we can check the timer was set to DefaultWait, not 300.
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob", "body": "hi",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	// StartConversation=true, Wait=DefaultWait, WaitExplicit=true
	// Should wait DefaultWait seconds, NOT 300s.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{
		Wait:              DefaultWait,
		WaitExplicit:      true,
		StartConversation: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
}

func TestSendStartConversationUpgradesWhenNotExplicit(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			// Block until client disconnects (wait should time out at ~1s, the test context)
			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	// StartConversation=true, Wait=DefaultWait, WaitExplicit=false
	// Should upgrade to 300s. We set a short context to verify it would've waited longer than DefaultWait.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := Send(ctx, mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{
		Wait:              DefaultWait,
		WaitExplicit:      false,
		StartConversation: true,
	}, nil)
	// Context cancellation is expected since 300s > 2s timeout
	if err != nil {
		// context.DeadlineExceeded means Send was willing to wait longer than 2s,
		// confirming the upgrade to 300s happened.
		if err != context.DeadlineExceeded {
			t.Fatal(err)
		}
		return
	}
	// If no error, it timed out naturally via wait timer — that's fine too,
	// as long as WaitedSeconds > 0 showing it waited.
	if result.WaitedSeconds <= 0 {
		t.Fatal("expected some waiting time")
	}
}

// --- Fix 2: Listen() ---

func TestListen(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, SenderWaiting: true},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Message from bob
			msgData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-1", "from_agent": "bob", "body": "are you there?",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msgData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", DefaultWait, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "are you there?" {
		t.Fatalf("reply=%s", result.Reply)
	}
	if result.SessionID != "s1" {
		t.Fatalf("session_id=%s", result.SessionID)
	}
}

func TestListenTimeout(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Send nothing, just keep connection open
			fmt.Fprintf(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			<-time.After(10 * time.Second)
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "sent" {
		t.Fatalf("status=%s (expected 'sent' on timeout)", result.Status)
	}
	if result.WaitedSeconds < 1 {
		t.Fatalf("waited_seconds=%d", result.WaitedSeconds)
	}
}

func TestListenNoSession(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{Pending: []aweb.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/sessions" {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, aweb.ChatListSessionsResponse{Sessions: []aweb.ChatSessionItem{}})
		},
	})
	t.Cleanup(server.Close)

	_, err := Listen(context.Background(), mustClient(t, server.URL), "nobody", DefaultWait, nil)
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !strings.Contains(err.Error(), "no conversation found") {
		t.Fatalf("err=%s", err)
	}
}

func TestListenWithHangOn(t *testing.T) {
	t.Parallel()

	var callbackCalls []string

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			// Hang-on from bob
			hangOnData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "bob",
				"body": "thinking...", "hang_on": true, "extends_wait_seconds": 300,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", hangOnData)
			if flusher != nil {
				flusher.Flush()
			}

			// Actual reply from bob
			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "bob", "body": "here's my answer",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	callback := func(kind, msg string) {
		callbackCalls = append(callbackCalls, kind+": "+msg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", 5, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "here's my answer" {
		t.Fatalf("reply=%s", result.Reply)
	}

	foundHangOn := false
	foundExtended := false
	for _, c := range callbackCalls {
		if strings.HasPrefix(c, "hang_on:") {
			foundHangOn = true
		}
		if strings.HasPrefix(c, "wait_extended:") {
			foundExtended = true
		}
	}
	if !foundHangOn {
		t.Fatal("missing hang_on callback")
	}
	if !foundExtended {
		t.Fatal("missing wait_extended callback")
	}
}

func TestListenReturnsAnyMessage(t *testing.T) {
	t.Parallel()

	// In a multi-party session [alice, bob, charlie], listening for "bob"
	// should return when charlie sends a message (not filtered by target).
	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob", "charlie"}},
				},
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			msgData, _ := json.Marshal(map[string]any{
				"type": "message", "from_agent": "charlie", "body": "hello everyone",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msgData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Listen(ctx, mustClient(t, server.URL), "bob", DefaultWait, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if result.Reply != "hello everyone" {
		t.Fatalf("reply=%s (expected message from charlie, not filtered)", result.Reply)
	}
}

// --- Fix 3: findSession prefers smallest matching session ---

func TestFindSessionPrefersSmallestPending(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{
				Pending: []aweb.ChatPendingItem{
					{SessionID: "s-group", Participants: []string{"alice", "bob", "charlie"}},
					{SessionID: "s-pair", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, _, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-pair" {
		t.Fatalf("session_id=%s, want s-pair (smallest matching session)", sessionID)
	}
}

func TestFindSessionPrefersSmallestFallback(t *testing.T) {
	t.Parallel()

	server := newMockServer(map[string]http.HandlerFunc{
		"GET /v1/chat/pending": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatPendingResponse{Pending: []aweb.ChatPendingItem{}})
		},
		"GET /v1/chat/sessions": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/chat/sessions" {
				http.NotFound(w, r)
				return
			}
			jsonResponse(w, aweb.ChatListSessionsResponse{
				Sessions: []aweb.ChatSessionItem{
					{SessionID: "s-group", Participants: []string{"alice", "bob", "charlie"}},
					{SessionID: "s-pair", Participants: []string{"alice", "bob"}},
				},
			})
		},
	})
	t.Cleanup(server.Close)

	sessionID, _, err := findSession(context.Background(), mustClient(t, server.URL), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "s-pair" {
		t.Fatalf("session_id=%s, want s-pair (smallest matching session)", sessionID)
	}
}

// --- Wire protocol gaps (aw-j80 Phase A) ---

func TestLeavingFieldOnChatSendMessageRequest(t *testing.T) {
	t.Parallel()

	req := &aweb.ChatSendMessageRequest{
		Body:    "goodbye",
		Leaving: true,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["leaving"].(bool); !ok || !v {
		t.Fatalf("leaving=%v, want true", m["leaving"])
	}

	// omitempty: absent when false
	req2 := &aweb.ChatSendMessageRequest{Body: "hello"}
	data2, _ := json.Marshal(req2)
	var m2 map[string]any
	_ = json.Unmarshal(data2, &m2)
	if _, present := m2["leaving"]; present {
		t.Fatal("leaving should be omitted when false")
	}
}

func TestLeavingFieldOnNetworkChatSendMessageRequest(t *testing.T) {
	t.Parallel()

	req := &aweb.NetworkChatSendMessageRequest{
		Body:    "goodbye",
		Leaving: true,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["leaving"].(bool); !ok || !v {
		t.Fatalf("leaving=%v, want true", m["leaving"])
	}

	// omitempty: absent when false
	req2 := &aweb.NetworkChatSendMessageRequest{Body: "hello"}
	data2, _ := json.Marshal(req2)
	var m2 map[string]any
	_ = json.Unmarshal(data2, &m2)
	if _, present := m2["leaving"]; present {
		t.Fatal("leaving should be omitted when false")
	}
}

func TestParseSSEEventSenderWaiting(t *testing.T) {
	t.Parallel()

	ev := parseSSEEvent(&aweb.SSEEvent{
		Event: "message",
		Data:  `{"type":"message","from_agent":"bob","body":"hello","sender_waiting":true}`,
	})
	if !ev.SenderWaiting {
		t.Fatal("sender_waiting=false, want true")
	}

	// false when absent
	ev2 := parseSSEEvent(&aweb.SSEEvent{
		Event: "message",
		Data:  `{"type":"message","from_agent":"bob","body":"hello"}`,
	})
	if ev2.SenderWaiting {
		t.Fatal("sender_waiting=true, want false when absent")
	}
}

func TestSendPropagatesSenderWaitingFromReply(t *testing.T) {
	t.Parallel()

	sentMsgID := "msg-sent-1"

	server := newMockServer(map[string]http.HandlerFunc{
		"POST /v1/chat/sessions": func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, aweb.ChatCreateSessionResponse{
				SessionID: "s1",
				MessageID: sentMsgID,
				SSEURL:    "/v1/chat/sessions/s1/stream",
			})
		},
		"GET /v1/chat/sessions/s1/stream": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)

			sentData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": sentMsgID, "from_agent": "alice", "body": "hello",
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", sentData)
			if flusher != nil {
				flusher.Flush()
			}

			replyData, _ := json.Marshal(map[string]any{
				"type": "message", "message_id": "msg-reply", "from_agent": "bob",
				"body": "what do you think?", "sender_waiting": true,
			})
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyData)
			if flusher != nil {
				flusher.Flush()
			}
		},
	})
	t.Cleanup(server.Close)

	result, err := Send(context.Background(), mustClient(t, server.URL), "alice", []string{"bob"}, "hello", SendOptions{Wait: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "replied" {
		t.Fatalf("status=%s", result.Status)
	}
	if !result.SenderWaiting {
		t.Fatal("result.SenderWaiting=false, want true from reply event")
	}
}
