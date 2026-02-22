package aweb

import (
	"context"
	"crypto/ed25519"
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

func TestRegisterResponseIncludesEmail(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/register" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_key":               "aw_sk_test",
			"agent_id":              "agent-1",
			"alias":                 "alice",
			"username":              "testuser",
			"email":                 "test@example.com",
			"project_slug":          "default",
			"project_name":          "Default",
			"server_url":            "http://localhost",
			"verification_required": true,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	alias := "alice"
	username := "testuser"
	resp, err := c.Register(context.Background(), &RegisterRequest{
		Email:    "test@example.com",
		Alias:    &alias,
		Username: &username,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Email != "test@example.com" {
		t.Fatalf("email=%q, want test@example.com", resp.Email)
	}
}

func TestRegisterRequestIncludesIdentityFields(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_key":      "aw_sk_test",
			"agent_id":     "agent-1",
			"alias":        "alice",
			"username":     "testuser",
			"email":        "test@example.com",
			"project_slug": "default",
			"did":          "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"custody":      "self",
			"lifetime":     "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	alias := "alice"
	username := "testuser"
	resp, err := c.Register(context.Background(), &RegisterRequest{
		Email:     "test@example.com",
		Alias:     &alias,
		Username:  &username,
		DID:       "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		PublicKey: "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
		Custody:   "self",
		Lifetime:  "persistent",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify request body includes identity fields.
	if gotBody["did"] != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("request did=%v", gotBody["did"])
	}
	if gotBody["public_key"] != "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY" {
		t.Fatalf("request public_key=%v", gotBody["public_key"])
	}
	if gotBody["custody"] != "self" {
		t.Fatalf("request custody=%v", gotBody["custody"])
	}
	if gotBody["lifetime"] != "persistent" {
		t.Fatalf("request lifetime=%v", gotBody["lifetime"])
	}

	// Verify response includes identity fields.
	if resp.DID != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("response did=%q", resp.DID)
	}
	if resp.Custody != "self" {
		t.Fatalf("response custody=%q", resp.Custody)
	}
	if resp.Lifetime != "persistent" {
		t.Fatalf("response lifetime=%q", resp.Lifetime)
	}
}

func TestRegisterRequestOmitsEmptyIdentityFields(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_key":      "aw_sk_test",
			"agent_id":     "agent-1",
			"alias":        "alice",
			"username":     "testuser",
			"email":        "test@example.com",
			"project_slug": "default",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	alias := "alice"
	username := "testuser"
	_, err = c.Register(context.Background(), &RegisterRequest{
		Email:    "test@example.com",
		Alias:    &alias,
		Username: &username,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Identity fields should be omitted when empty (backward compat).
	for _, key := range []string{"did", "public_key", "custody", "lifetime"} {
		if _, ok := gotBody[key]; ok {
			t.Fatalf("expected %q to be omitted, got %v", key, gotBody[key])
		}
	}
}

func TestVerifyCode(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/verify-code" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		// Should be unauthenticated.
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Fatalf("unexpected auth header: %q", auth)
		}
		var body VerifyCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Email != "test@example.com" {
			t.Fatalf("email=%s", body.Email)
		}
		if body.Code != "123456" {
			t.Fatalf("code=%s", body.Code)
		}
		_ = json.NewEncoder(w).Encode(VerifyCodeResponse{
			Verified:           true,
			Username:           "testuser",
			RegistrationSource: "cli",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.VerifyCode(context.Background(), &VerifyCodeRequest{
		Email: "test@example.com",
		Code:  "123456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Verified {
		t.Fatal("verified=false")
	}
	if resp.Username != "testuser" {
		t.Fatalf("username=%s", resp.Username)
	}
}

func TestInitRequestIncludesIdentityFields(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":       "ok",
			"project_id":   "proj-1",
			"project_slug": "default",
			"agent_id":     "agent-1",
			"alias":        "alice",
			"api_key":      "aw_sk_test",
			"created":      true,
			"did":          "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"custody":      "self",
			"lifetime":     "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	alias := "alice"
	resp, err := c.Init(context.Background(), &InitRequest{
		ProjectSlug: "default",
		Alias:       &alias,
		DID:         "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		PublicKey:    "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
		Custody:      "self",
		Lifetime:     "persistent",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify request body.
	if gotBody["did"] != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("request did=%v", gotBody["did"])
	}
	if gotBody["public_key"] != "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY" {
		t.Fatalf("request public_key=%v", gotBody["public_key"])
	}

	// Verify response.
	if resp.DID != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("response did=%q", resp.DID)
	}
	if resp.Custody != "self" {
		t.Fatalf("response custody=%q", resp.Custody)
	}
	if resp.Lifetime != "persistent" {
		t.Fatalf("response lifetime=%q", resp.Lifetime)
	}
}

func TestCloudBootstrapRequestIncludesIdentityFields(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org_id":       "org-1",
			"org_slug":     "mycompany",
			"org_name":     "My Company",
			"project_id":   "proj-1",
			"project_slug": "default",
			"project_name": "Default",
			"server_url":   "http://localhost",
			"api_key":      "aw_sk_test",
			"agent_id":     "agent-1",
			"alias":        "alice",
			"created":      true,
			"did":          "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			"custody":      "custodial",
			"lifetime":     "ephemeral",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "cloud-token")
	if err != nil {
		t.Fatal(err)
	}
	alias := "alice"
	resp, err := c.CloudBootstrapAgent(context.Background(), &CloudBootstrapAgentRequest{
		Alias:     &alias,
		DID:       "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		PublicKey: "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
		Custody:   "custodial",
		Lifetime:  "ephemeral",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify request body.
	if gotBody["did"] != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("request did=%v", gotBody["did"])
	}
	if gotBody["public_key"] != "Lm/M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY" {
		t.Fatalf("request public_key=%v", gotBody["public_key"])
	}
	if gotBody["custody"] != "custodial" {
		t.Fatalf("request custody=%v", gotBody["custody"])
	}
	if gotBody["lifetime"] != "ephemeral" {
		t.Fatalf("request lifetime=%v", gotBody["lifetime"])
	}

	// Verify response.
	if resp.DID != "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" {
		t.Fatalf("response did=%q", resp.DID)
	}
	if resp.Custody != "custodial" {
		t.Fatalf("response custody=%q", resp.Custody)
	}
	if resp.Lifetime != "ephemeral" {
		t.Fatalf("response lifetime=%q", resp.Lifetime)
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

func TestNewWithIdentitySetsFields(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	c, err := NewWithIdentity("http://localhost:8000", "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	if c.SigningKey() == nil {
		t.Fatal("SigningKey is nil")
	}
	if !c.SigningKey().Equal(priv) {
		t.Fatal("SigningKey does not match")
	}
	if c.DID() != did {
		t.Fatalf("DID=%q, want %q", c.DID(), did)
	}
}

func TestNewWithIdentityValidation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	if _, err := NewWithIdentity("http://localhost:8000", "aw_sk_test", nil, did); err == nil {
		t.Fatal("expected error for nil signingKey")
	}
	if _, err := NewWithIdentity("http://localhost:8000", "aw_sk_test", priv, ""); err == nil {
		t.Fatal("expected error for empty did")
	}
	if _, err := NewWithIdentity("http://localhost:8000", "aw_sk_test", priv, "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"); err == nil {
		t.Fatal("expected error for mismatched did")
	}
}

func TestNewWithAPIKeyLeavesIdentityNil(t *testing.T) {
	t.Parallel()

	c, err := NewWithAPIKey("http://localhost:8000", "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	if c.SigningKey() != nil {
		t.Fatal("expected nil SigningKey for legacy client")
	}
	if c.DID() != "" {
		t.Fatalf("expected empty DID for legacy client, got %q", c.DID())
	}
}

func TestPutHelper(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]string
	if err := c.put(context.Background(), "/v1/agents/me/rotate", map[string]string{"key": "val"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method=%s, want PUT", gotMethod)
	}
	if gotPath != "/v1/agents/me/rotate" {
		t.Fatalf("path=%s", gotPath)
	}
	if out["status"] != "ok" {
		t.Fatalf("status=%q", out["status"])
	}
	if gotBody["key"] != "val" {
		t.Fatalf("body key=%q, want %q", gotBody["key"], "val")
	}
}

func TestDeregister(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Deregister(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s, want DELETE", gotMethod)
	}
	if gotPath != "/v1/agents/me" {
		t.Fatalf("path=%s, want /v1/agents/me", gotPath)
	}
}

func TestDeregisterAgent(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeregisterAgent(context.Background(), "mycompany", "researcher"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s, want DELETE", gotMethod)
	}
	if gotPath != "/v1/agents/mycompany/researcher" {
		t.Fatalf("path=%s, want /v1/agents/mycompany/researcher", gotPath)
	}
	if gotAuth != "Bearer aw_sk_test" {
		t.Fatalf("auth=%q", gotAuth)
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

func TestSendMessageSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	resp, err := c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Subject: "task complete",
		Body:    "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-1" {
		t.Fatalf("MessageID=%q", resp.MessageID)
	}

	// Verify identity fields are present.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["signing_key_id"] != did {
		t.Fatalf("signing_key_id=%v, want %s", gotBody["signing_key_id"], did)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing or empty")
	}

	// Verify using the same field mapping that Inbox() uses.
	// This simulates a receive-side round-trip verification.
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: gotBody["timestamp"].(string),
		Signature: sig,
	}
	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestSendMessageNoSignatureWithoutIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Identity fields should not be present.
	if _, exists := gotBody["from_did"]; exists {
		t.Fatal("from_did should not be set for legacy client")
	}
	if _, exists := gotBody["signature"]; exists {
		t.Fatal("signature should not be set for legacy client")
	}
	if _, exists := gotBody["signing_key_id"]; exists {
		t.Fatal("signing_key_id should not be set for legacy client")
	}
}

func TestSendMessageSignsWithToAgentID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAgentID: "agent-uuid-123",
		Subject:   "task complete",
		Body:      "results attached",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signature should bind to the ToAgentID when ToAlias is empty.
	env := &MessageEnvelope{
		FromDID:   did,
		To:        "agent-uuid-123",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: gotBody["timestamp"].(string),
		Signature: gotBody["signature"].(string),
	}
	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestNetworkSendMailSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
			"from_address": "myco/agent",
			"to_address":   "otherco/monitor",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.NetworkSendMail(context.Background(), &NetworkMailRequest{
		ToAddress: "otherco/monitor",
		Subject:   "update",
		Body:      "status ok",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
	if gotBody["signing_key_id"] != did {
		t.Fatalf("signing_key_id=%v", gotBody["signing_key_id"])
	}
}

func TestSendDMSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message_id":   "msg-1",
			"status":       "delivered",
			"delivered_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SendDM(context.Background(), &DMRequest{
		ToHandle: "juanre",
		Body:     "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
}

func TestChatCreateSessionSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_id": "sess-1",
			"message_id": "msg-1",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChatCreateSession(context.Background(), &ChatCreateSessionRequest{
		ToAliases: []string{"otherco/monitor"},
		Message:   "hey",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing")
	}

	// Verify the signature covers the chat envelope.
	env := &MessageEnvelope{
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "chat",
		Body:      "hey",
		Timestamp: gotBody["timestamp"].(string),
		Signature: sig,
	}
	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestChatSendMessageSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message_id": "msg-1",
			"delivered":  true,
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ChatSendMessage(context.Background(), "sess-1", &ChatSendMessageRequest{
		Body: "message in chat",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
}

func TestNetworkCreateChatSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_id": "sess-1",
			"message_id": "msg-1",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.NetworkCreateChat(context.Background(), &NetworkChatCreateRequest{
		ToAddresses: []string{"otherco/monitor"},
		Message:     "hey there",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
}

func TestNetworkChatSendMessageSignsWhenIdentitySet(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message_id": "msg-1",
			"delivered":  true,
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.NetworkChatSendMessage(context.Background(), "sess-1", &NetworkChatSendMessageRequest{
		Body: "network chat msg",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v", gotBody["from_did"])
	}
	if gotBody["signature"] == nil || gotBody["signature"] == "" {
		t.Fatal("signature missing")
	}
}

func TestInboxVerifiesSignedMessages(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// Build a valid signed envelope.
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "mail",
		Subject:   "hello",
		Body:      "world",
		Timestamp: "2026-02-22T00:00:00Z",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "myco/agent",
				"to_alias":       "otherco/monitor",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       did,
				"to_did":         "",
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified", msg.VerificationStatus)
	}
}

func TestInboxUnverifiedWithoutDID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":    "msg-1",
				"from_agent_id": "agent-uuid",
				"from_alias":    "myco/agent",
				"subject":       "hello",
				"body":          "world",
				"priority":      "normal",
				"created_at":    "2026-02-22T00:00:00Z",
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Unverified {
		t.Fatalf("VerificationStatus=%q, want unverified", msg.VerificationStatus)
	}
}

func TestInboxFailedBadSignature(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "myco/agent",
				"subject":        "hello",
				"body":           "world",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       did,
				"signature":      "dGhpcyBpcyBhIGJhZCBzaWduYXR1cmU", // invalid sig
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Failed {
		t.Fatalf("VerificationStatus=%q, want failed", msg.VerificationStatus)
	}
}

func TestChatHistoryVerifiesSignedMessages(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "",
		Type:      "chat",
		Subject:   "",
		Body:      "hello chat",
		Timestamp: "2026-02-22T00:00:00Z",
	}
	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent":     "myco/agent",
				"body":           "hello chat",
				"timestamp":      "2026-02-22T00:00:00Z",
				"from_did":       did,
				"signature":      sig,
				"signing_key_id": did,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "sess-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("len=%d", len(resp.Messages))
	}
	msg := resp.Messages[0]
	if msg.VerificationStatus != Verified {
		t.Fatalf("VerificationStatus=%q, want verified", msg.VerificationStatus)
	}
}
