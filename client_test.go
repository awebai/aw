package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntrospectAddsBearerHeader(t *testing.T) {
	t.Parallel()

	wantProjectID := "11111111-1111-1111-1111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": wantProjectID})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProjectID != wantProjectID {
		t.Fatalf("project_id=%s", resp.ProjectID)
	}
}

func TestChatStreamRequestsEventStream(t *testing.T) {
	t.Parallel()

	var gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: {\"ok\":true}\n\n"))
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.ChatStream(context.Background(), "sess", time.Now().Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if gotAccept != "text/event-stream" {
		t.Fatalf("accept=%q", gotAccept)
	}

	ev, err := stream.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "message" {
		t.Fatalf("event=%q", ev.Event)
	}
	if !strings.Contains(ev.Data, "\"ok\":true") {
		t.Fatalf("data=%q", ev.Data)
	}
}

func TestChatSendMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions/test-session/messages" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Body != "hello" {
			t.Fatalf("body=%q", body.Body)
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-1",
			Delivered:          true,
			ExtendsWaitSeconds: 0,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-1" {
		t.Fatalf("message_id=%s", resp.MessageID)
	}
	if !resp.Delivered {
		t.Fatal("delivered=false")
	}
}

func TestChatSendMessageExtendWait(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !body.ExtendWait {
			t.Fatal("expected extend_wait=true")
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-2",
			Delivered:          true,
			ExtendsWaitSeconds: 300,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{
		Body:       "thinking...",
		ExtendWait: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExtendsWaitSeconds != 300 {
		t.Fatalf("extends_wait_seconds=%d", resp.ExtendsWaitSeconds)
	}
}

func TestChatListSessions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
			Sessions: []ChatSessionItem{
				{SessionID: "s1", Participants: []string{"alice", "bob"}, CreatedAt: "2025-01-01T00:00:00Z"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("sessions=%d", len(resp.Sessions))
	}
	if resp.Sessions[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", resp.Sessions[0].SessionID)
	}
	if len(resp.Sessions[0].Participants) != 2 {
		t.Fatalf("participants=%d", len(resp.Sessions[0].Participants))
	}
}

func TestGetCurrentProject(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/projects/current" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"project_id": "proj-abc",
			"slug":       "my-project",
			"name":       "My Project",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.GetCurrentProject(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProjectID != "proj-abc" {
		t.Fatalf("project_id=%s", resp.ProjectID)
	}
	if resp.Slug != "my-project" {
		t.Fatalf("slug=%s", resp.Slug)
	}
	if resp.Name != "My Project" {
		t.Fatalf("name=%s", resp.Name)
	}
}

func TestReservationRevoke(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/reservations/revoke" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["prefix"] != "test-" {
			t.Fatalf("prefix=%v", body["prefix"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"revoked_count": 2,
			"revoked_keys":  []string{"test-lock-1", "test-lock-2"},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ReservationRevoke(context.Background(), &ReservationRevokeRequest{
		Prefix: "test-",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RevokedCount != 2 {
		t.Fatalf("revoked_count=%d", resp.RevokedCount)
	}
	if len(resp.RevokedKeys) != 2 {
		t.Fatalf("revoked_keys=%v", resp.RevokedKeys)
	}
}

func TestChatPendingItemNullTimeRemaining(t *testing.T) {
	t.Parallel()

	raw := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":false,"time_remaining_seconds":null}`
	var item ChatPendingItem
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatal(err)
	}
	if item.TimeRemainingSeconds != nil {
		t.Fatalf("expected nil, got %d", *item.TimeRemainingSeconds)
	}

	raw2 := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":true,"time_remaining_seconds":42}`
	var item2 ChatPendingItem
	if err := json.Unmarshal([]byte(raw2), &item2); err != nil {
		t.Fatal(err)
	}
	if item2.TimeRemainingSeconds == nil || *item2.TimeRemainingSeconds != 42 {
		t.Fatalf("expected 42, got %v", item2.TimeRemainingSeconds)
	}
}

func TestHTTPStatusHelpers(t *testing.T) {
	t.Parallel()

	err := &apiError{StatusCode: 404, Body: "not found"}
	status, ok := HTTPStatusCode(err)
	if !ok || status != 404 {
		t.Fatalf("status=(%d,%v)", status, ok)
	}
	body, ok := HTTPErrorBody(err)
	if !ok || body != "not found" {
		t.Fatalf("body=(%q,%v)", body, ok)
	}

	status, ok = HTTPStatusCode(context.DeadlineExceeded)
	if ok || status != 0 {
		t.Fatalf("non-api status=(%d,%v)", status, ok)
	}
	body, ok = HTTPErrorBody(context.Canceled)
	if ok || body != "" {
		t.Fatalf("non-api body=(%q,%v)", body, ok)
	}
}

func TestPatchAgentAccessMode(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath, gotContentType string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id":    "agent-1",
			"access_mode": "open",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.PatchAgent(context.Background(), "agent-1", &PatchAgentRequest{
		AccessMode: "open",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPatch {
		t.Fatalf("method=%s", gotMethod)
	}
	if gotPath != "/v1/agents/agent-1" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("content-type=%s", gotContentType)
	}
	if gotBody["access_mode"] != "open" {
		t.Fatalf("access_mode=%v", gotBody["access_mode"])
	}
	if resp.AccessMode != "open" {
		t.Fatalf("access_mode=%s", resp.AccessMode)
	}
}
