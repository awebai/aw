package aweb

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
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
		MessageID: gotBody["message_id"].(string),
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
		MessageID: gotBody["message_id"].(string),
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
		MessageID: gotBody["message_id"].(string),
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
		MessageID: "msg-1",
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
		MessageID: "msg-1",
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

func TestRotateKeySendsSignedRequest(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(pub)

	newPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/me/rotate" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"old_did":    oldDID,
			"new_did":    newDID,
			"rotated_at": "2026-02-22T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, oldDID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.RotateKey(context.Background(), &RotateKeyRequest{
		NewDID:       newDID,
		NewPublicKey: newPub,
		Custody:      CustodySelf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OldDID != oldDID {
		t.Fatalf("OldDID=%q", resp.OldDID)
	}
	if resp.NewDID != newDID {
		t.Fatalf("NewDID=%q", resp.NewDID)
	}

	// Verify request fields.
	if gotBody["new_did"] != newDID {
		t.Fatalf("new_did=%v", gotBody["new_did"])
	}
	if gotBody["custody"] != CustodySelf {
		t.Fatalf("custody=%v", gotBody["custody"])
	}
	// Verify rotation_signature is present.
	rotSig, ok := gotBody["rotation_signature"].(string)
	if !ok || rotSig == "" {
		t.Fatal("rotation_signature missing")
	}
	if gotBody["new_public_key"] == nil || gotBody["new_public_key"] == "" {
		t.Fatal("new_public_key missing")
	}

	// Verify the rotation signature using the old public key.
	status, err := VerifyRotationSignature(pub, oldDID, newDID, gotBody["timestamp"].(string), rotSig)
	if err != nil {
		t.Fatalf("VerifyRotationSignature: %v", err)
	}
	if !status {
		t.Fatal("rotation signature invalid")
	}
}

func TestRotateKeyRequiresIdentity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server")
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RotateKey(context.Background(), &RotateKeyRequest{
		NewDID:  "did:key:z6MkTest",
		Custody: CustodySelf,
	})
	if err == nil {
		t.Fatal("expected error for legacy client")
	}
}

func TestAgentLogSelf(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/me/log" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"operation": "create",
					"did":       "did:key:z6MkOldKey",
					"timestamp": "2026-03-15T10:00:00Z",
					"signed_by": "did:key:z6MkOldKey",
				},
				{
					"operation": "rotate",
					"old_did":   "did:key:z6MkOldKey",
					"new_did":   "did:key:z6MkNewKey",
					"timestamp": "2026-06-01T12:00:00Z",
					"signed_by": "did:key:z6MkOldKey",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.AgentLog(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("entries=%d", len(resp.Entries))
	}
	if resp.Entries[0].Operation != "create" {
		t.Fatalf("entry[0].operation=%s", resp.Entries[0].Operation)
	}
	if resp.Entries[0].DID != "did:key:z6MkOldKey" {
		t.Fatalf("entry[0].did=%s", resp.Entries[0].DID)
	}
	if resp.Entries[1].Operation != "rotate" {
		t.Fatalf("entry[1].operation=%s", resp.Entries[1].Operation)
	}
	if resp.Entries[1].OldDID != "did:key:z6MkOldKey" {
		t.Fatalf("entry[1].old_did=%s", resp.Entries[1].OldDID)
	}
	if resp.Entries[1].NewDID != "did:key:z6MkNewKey" {
		t.Fatalf("entry[1].new_did=%s", resp.Entries[1].NewDID)
	}
	if resp.Entries[1].SignedBy != "did:key:z6MkOldKey" {
		t.Fatalf("entry[1].signed_by=%s", resp.Entries[1].SignedBy)
	}
}

func TestAgentLogPeer(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/acme/bot/log" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"operation": "create",
					"did":       "did:key:z6MkPeer",
					"timestamp": "2026-01-01T00:00:00Z",
					"signed_by": "did:key:z6MkPeer",
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.AgentLog(context.Background(), "acme/bot")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries=%d", len(resp.Entries))
	}
	if resp.Entries[0].DID != "did:key:z6MkPeer" {
		t.Fatalf("entry[0].did=%s", resp.Entries[0].DID)
	}
}

func TestRetireAgentSendsSignedRequest(t *testing.T) {
	t.Parallel()

	_, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPriv.Public().(ed25519.PublicKey))

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/agents/me/retire" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"did":               oldDID,
			"status":            "retired",
			"successor_did":     gotBody["successor_did"],
			"successor_address": gotBody["successor_address"],
			"retired_at":        "2026-06-15T10:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", oldPriv, oldDID)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.RetireAgent(context.Background(), &RetireAgentRequest{
		SuccessorDID:     "did:key:z6MkSuccessor",
		SuccessorAddress: "acme/analyst",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["status"] != "retired" {
		t.Fatalf("status=%s", gotBody["status"])
	}
	if gotBody["successor_did"] != "did:key:z6MkSuccessor" {
		t.Fatalf("successor_did=%s", gotBody["successor_did"])
	}
	if gotBody["successor_address"] != "acme/analyst" {
		t.Fatalf("successor_address=%s", gotBody["successor_address"])
	}
	if resp.Status != "retired" {
		t.Fatalf("resp.status=%s", resp.Status)
	}
	if resp.RetiredAt != "2026-06-15T10:00:00Z" {
		t.Fatalf("resp.retired_at=%s", resp.RetiredAt)
	}
}

func TestRetireAgentRequiresIdentity(t *testing.T) {
	t.Parallel()

	c, err := NewWithAPIKey("http://localhost", "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RetireAgent(context.Background(), &RetireAgentRequest{
		SuccessorDID:     "did:key:z6MkSuccessor",
		SuccessorAddress: "acme/analyst",
	})
	if err == nil {
		t.Fatal("expected error for client without identity")
	}
}

func TestSendMessageIncludesMessageID(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(priv.Public().(ed25519.PublicKey))

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "server-returned-id"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/bot",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// message_id should be a valid UUID v4 generated by signEnvelope.
	msgID := gotBody["message_id"]
	if msgID == "" {
		t.Fatal("message_id is empty")
	}
	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRE.MatchString(msgID) {
		t.Fatalf("message_id=%q is not a valid UUID v4", msgID)
	}
}

func TestSendMessageNoMessageIDWithoutIdentity(t *testing.T) {
	t.Parallel()

	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "server-generated"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/bot",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Without identity, message_id should be empty (server generates it).
	if gotBody["message_id"] != "" {
		t.Fatalf("message_id=%q, expected empty for custodial client", gotBody["message_id"])
	}
}

func TestSendMessageResolvesRecipientDID(t *testing.T) {
	t.Parallel()

	// Sender identity.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// Recipient identity.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/resolve/otherco/monitor":
			_ = json.NewEncoder(w).Encode(serverResolveResponse{
				DID:     recipientDID,
				Address: "otherco/monitor",
			})
		case r.URL.Path == "/v1/messages":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, "aw_sk_test", priv, did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("myco/agent")
	c.SetResolver(&ServerResolver{Client: c})

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify to_did is transmitted on the wire.
	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did on wire=%v, want %s", gotBody["to_did"], recipientDID)
	}

	// Verify the signature covers the recipient DID.
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     recipientDID,
		Type:      "mail",
		Body:      "hello",
		Timestamp: gotBody["timestamp"].(string),
		MessageID: gotBody["message_id"].(string),
		Signature: gotBody["signature"].(string),
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestInboxRecipientBindingMismatch(t *testing.T) {
	t.Parallel()

	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	// Message signed with wrong to_did (not the receiver's DID).
	wrongRecipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongRecipientDID := ComputeDIDKey(wrongRecipientPub)

	// The receiver's actual DID.
	receiverPub, receiverPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverDID := ComputeDIDKey(receiverPub)
	_ = receiverPriv // not used for signing, only for identity

	env := &MessageEnvelope{
		From:      "sender/agent",
		FromDID:   senderDID,
		To:        "receiver/agent",
		ToDID:     wrongRecipientDID,
		Type:      "mail",
		Subject:   "test",
		Body:      "misrouted",
		Timestamp: "2026-02-22T00:00:00Z",
		MessageID: "msg-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"messages": []map[string]any{{
				"message_id":     "msg-1",
				"from_agent_id":  "agent-uuid",
				"from_alias":     "sender/agent",
				"to_alias":       "receiver/agent",
				"subject":        "test",
				"body":           "misrouted",
				"priority":       "normal",
				"created_at":     "2026-02-22T00:00:00Z",
				"from_did":       senderDID,
				"to_did":         wrongRecipientDID,
				"signature":      sig,
				"signing_key_id": senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	// Create receiver client with identity — to_did won't match.
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
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
	// Signature is valid but to_did doesn't match receiver → IdentityMismatch.
	msg := resp.Messages[0]
	if msg.VerificationStatus != IdentityMismatch {
		t.Fatalf("VerificationStatus=%q, want identity_mismatch", msg.VerificationStatus)
	}
}

func TestSendMessageNoResolverLeavesToDIDEmpty(t *testing.T) {
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
	// No resolver set — to_did should remain empty.

	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToAlias: "otherco/monitor",
		Body:    "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify to_did is absent on the wire.
	if v, ok := gotBody["to_did"]; ok {
		t.Fatalf("to_did should be absent on wire, got %v", v)
	}

	// Verify signature is valid without to_did.
	env := &MessageEnvelope{
		From:      "myco/agent",
		FromDID:   did,
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: gotBody["timestamp"].(string),
		MessageID: gotBody["message_id"].(string),
		Signature: gotBody["signature"].(string),
	}
	status, verifyErr := VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestInboxTOFUPinFirstContact(t *testing.T) {
	t.Parallel()

	// Generate sender identity and sign a message.
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   senderDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hello",
		Body:      "first contact",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-tofu-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-tofu-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "hello",
				Body:        "first contact",
				CreatedAt:   env.Timestamp,
				FromDID:     senderDID,
				Signature:   sig,
				SigningKeyID: senderDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%s, want verified", resp.Messages[0].VerificationStatus)
	}

	// Pin should have been created.
	if _, ok := ps.Pins[senderDID]; !ok {
		t.Fatal("pin should have been created for sender DID")
	}
	if ps.Addresses["otherco/sender"] != senderDID {
		t.Fatalf("address reverse index should map to sender DID, got %q", ps.Addresses["otherco/sender"])
	}
	firstSeen := ps.Pins[senderDID].FirstSeen

	// Second contact — same sender, same DID → should stay Verified and update last_seen.
	resp, err = c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("returning contact: status=%s, want verified", resp.Messages[0].VerificationStatus)
	}
	if ps.Pins[senderDID].FirstSeen != firstSeen {
		t.Fatal("first_seen should not change on returning contact")
	}
}

func TestInboxTOFUPinMismatch(t *testing.T) {
	t.Parallel()

	// Original sender.
	senderPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	originalDID := ComputeDIDKey(senderPub)

	// Impostor with different key claiming same address.
	impostorPub, impostorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	impostorDID := ComputeDIDKey(impostorPub)

	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   impostorDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hello",
		Body:      "impostor message",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-impostor-1",
	}
	sig, err := SignMessage(impostorPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-impostor-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "hello",
				Body:        "impostor message",
				CreatedAt:   env.Timestamp,
				FromDID:     impostorDID,
				Signature:   sig,
				SigningKeyID: impostorDID,
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the original DID for this address.
	ps := NewPinStore()
	ps.StorePin(originalDID, "otherco/sender", "", "")

	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}
	// Signature is valid for impostorDID, but TOFU pin expects originalDID → mismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch", resp.Messages[0].VerificationStatus)
	}
}

func TestInboxRotationAnnouncementAccepted(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key (sender has rotated to this).
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Create the rotation announcement: old key signs {new_did, old_did, timestamp}.
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := canonicalRotationJSON(oldDID, newDID, rotationTS)
	rotationSig := ed25519.Sign(oldPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "post-rotation",
		Body:      "hello after rotation",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-rotated-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-rotated-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "post-rotation",
				Body:        "hello after rotation",
				CreatedAt:   env.Timestamp,
				FromDID:     newDID,
				Signature:   sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the old DID.
	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Rotation announcement is valid → message should be accepted as Verified.
	if resp.Messages[0].VerificationStatus != Verified {
		t.Fatalf("status=%s, want verified (rotation should be accepted)", resp.Messages[0].VerificationStatus)
	}

	// Pin should be updated to the new DID.
	if ps.Addresses["otherco/sender"] != newDID {
		t.Fatalf("pin should be updated to new DID, got %q", ps.Addresses["otherco/sender"])
	}
	if _, ok := ps.Pins[newDID]; !ok {
		t.Fatal("new DID should be pinned")
	}
	// Old DID's pin entry should be cleaned up.
	if _, ok := ps.Pins[oldDID]; ok {
		t.Fatal("old DID pin entry should be removed after rotation")
	}
}

func TestInboxRotationAnnouncementInvalid(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key (sender claims rotation).
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Forged rotation announcement: new key signs (not old key).
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := canonicalRotationJSON(oldDID, newDID, rotationTS)
	forgedSig := ed25519.Sign(newPriv, []byte(rotationPayload)) // Wrong key!
	forgedSigStr := base64.RawStdEncoding.EncodeToString(forgedSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "forged rotation",
		Body:      "should be rejected",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-forged-rot-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-forged-rot-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "forged rotation",
				Body:        "should be rejected",
				CreatedAt:   env.Timestamp,
				FromDID:     newDID,
				Signature:   sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: forgedSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-pin the old DID.
	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Forged announcement → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (forged rotation)", resp.Messages[0].VerificationStatus)
	}

	// Pin should NOT be updated.
	if ps.Addresses["otherco/sender"] != oldDID {
		t.Fatalf("pin should remain old DID, got %q", ps.Addresses["otherco/sender"])
	}
}

func TestInboxRotationAnnouncementUnrelatedOldDID(t *testing.T) {
	t.Parallel()

	// Pinned key (the real sender).
	pinnedPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pinnedDID := ComputeDIDKey(pinnedPub)

	// Attacker's key (unrelated to the pinned identity).
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerDID := ComputeDIDKey(attackerPriv.Public().(ed25519.PublicKey))

	// New key the attacker wants to rotate to.
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Attacker crafts a rotation announcement from their own key (not the pinned one).
	// The signature is valid (attacker signs with their own key), but old_did != pinned DID.
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := canonicalRotationJSON(attackerDID, newDID, rotationTS)
	rotationSig := ed25519.Sign(attackerPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "hijack attempt",
		Body:      "attacker tries to take over",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-hijack-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-hijack-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "hijack attempt",
				Body:        "attacker tries to take over",
				CreatedAt:   env.Timestamp,
				FromDID:     newDID,
				Signature:   sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          attackerDID, // NOT the pinned DID!
					NewDID:          newDID,
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	// Pin the REAL sender's DID.
	ps := NewPinStore()
	ps.StorePin(pinnedDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Rotation announcement has valid signature but old_did != pinned DID → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (old_did doesn't match pinned DID)", resp.Messages[0].VerificationStatus)
	}

	// Pin must NOT be updated to the attacker's new DID.
	if ps.Addresses["otherco/sender"] != pinnedDID {
		t.Fatalf("pin should remain pinned DID, got %q", ps.Addresses["otherco/sender"])
	}
}

func TestInboxRotationAnnouncementNewDIDMismatch(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// The DID declared in the rotation announcement (ra.NewDID).
	declaredPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	declaredDID := ComputeDIDKey(declaredPub)

	// The actual sender key (from_did in the message) — differs from ra.NewDID.
	senderPub, senderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID := ComputeDIDKey(senderPub)

	// Rotation announcement: old key signs old→declared (not old→sender).
	rotationTS := time.Now().UTC().Format(time.RFC3339)
	rotationPayload := canonicalRotationJSON(oldDID, declaredDID, rotationTS)
	rotationSig := ed25519.Sign(oldPriv, []byte(rotationPayload))
	rotationSigStr := base64.RawStdEncoding.EncodeToString(rotationSig)

	// Message signed by the actual sender (from_did = senderDID ≠ ra.NewDID).
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   senderDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "mismatch test",
		Body:      "new_did != from_did",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-newdid-mismatch-1",
	}
	sig, err := SignMessage(senderPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-newdid-mismatch-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "mismatch test",
				Body:        "new_did != from_did",
				CreatedAt:   env.Timestamp,
				FromDID:     senderDID,
				Signature:   sig,
				SigningKeyID: senderDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          declaredDID, // Different from from_did!
					Timestamp:       rotationTS,
					OldKeySignature: rotationSigStr,
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// ra.NewDID != from_did → rotation rejected → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (ra.NewDID != from_did)", resp.Messages[0].VerificationStatus)
	}
}

func TestInboxRotationAnnouncementEmptyFields(t *testing.T) {
	t.Parallel()

	// Old key (currently pinned).
	oldPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)

	// New key.
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDID := ComputeDIDKey(newPub)

	// Message signed by the new key.
	env := &MessageEnvelope{
		From:      "otherco/sender",
		FromDID:   newDID,
		To:        "myco/agent",
		Type:      "mail",
		Subject:   "empty fields test",
		Body:      "rotation with missing fields",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MessageID: "msg-empty-rot-1",
	}
	sig, err := SignMessage(newPriv, env)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages: []InboxMessage{{
				MessageID:   "msg-empty-rot-1",
				FromAgentID: "agent-1",
				FromAlias:   "otherco/sender",
				ToAlias:     "myco/agent",
				Subject:     "empty fields test",
				Body:        "rotation with missing fields",
				CreatedAt:   env.Timestamp,
				FromDID:     newDID,
				Signature:   sig,
				SigningKeyID: newDID,
				RotationAnnouncement: &RotationAnnouncement{
					OldDID:          oldDID,
					NewDID:          newDID,
					Timestamp:       "", // Missing timestamp!
					OldKeySignature: "",  // Missing signature!
				},
			}},
		})
	}))
	t.Cleanup(server.Close)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverDID := ComputeDIDKey(receiverPub)
	c, err := NewWithIdentity(server.URL, "aw_sk_test", receiverPriv, receiverDID)
	if err != nil {
		t.Fatal(err)
	}

	ps := NewPinStore()
	ps.StorePin(oldDID, "otherco/sender", "", "")
	c.SetPinStore(ps, "")

	resp, err := c.Inbox(context.Background(), InboxParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}

	// Malformed rotation announcement → IdentityMismatch.
	if resp.Messages[0].VerificationStatus != IdentityMismatch {
		t.Fatalf("status=%s, want identity_mismatch (empty rotation fields)", resp.Messages[0].VerificationStatus)
	}

	// Pin must NOT be updated.
	if ps.Addresses["otherco/sender"] != oldDID {
		t.Fatalf("pin should remain old DID, got %q", ps.Addresses["otherco/sender"])
	}
}
