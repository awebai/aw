package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseExistingAccountFromHTTPError(t *testing.T) {
	t.Parallel()

	body := `{"existing_account":true,"verification_required":true,"email":"juan@example.com","handle":"juan","namespaces":[{"slug":"juan","tier":"free"},{"slug":"mycompany","tier":"paid"}]}`

	err := &apiError{StatusCode: 409, Body: body}
	info := ParseExistingAccount(err)
	if info == nil {
		t.Fatal("expected ExistingAccountInfo, got nil")
	}
	if !info.ExistingAccount {
		t.Fatal("existing_account=false")
	}
	if !info.VerificationRequired {
		t.Fatal("verification_required=false")
	}
	if info.Email != "juan@example.com" {
		t.Fatalf("email=%q", info.Email)
	}
	if info.Handle != "juan" {
		t.Fatalf("handle=%q", info.Handle)
	}
	if len(info.Namespaces) != 2 {
		t.Fatalf("got %d namespaces, want 2", len(info.Namespaces))
	}
	if info.Namespaces[0].Slug != "juan" || info.Namespaces[0].Tier != "free" {
		t.Fatalf("ns[0]=%+v", info.Namespaces[0])
	}
	if info.Namespaces[1].Slug != "mycompany" || info.Namespaces[1].Tier != "paid" {
		t.Fatalf("ns[1]=%+v", info.Namespaces[1])
	}
}

func TestParseExistingAccountNon409(t *testing.T) {
	t.Parallel()

	err := &apiError{StatusCode: 400, Body: `{"error":"bad request"}`}
	if info := ParseExistingAccount(err); info != nil {
		t.Fatalf("expected nil for 400, got %+v", info)
	}
}

func TestParseExistingAccountOldFormat(t *testing.T) {
	t.Parallel()

	// Old-style 409 body without existing_account field — should return nil.
	err := &apiError{StatusCode: 409, Body: `{"error":{"code":"USERNAME_TAKEN","message":"username taken"}}`}
	if info := ParseExistingAccount(err); info != nil {
		t.Fatalf("expected nil for old-style 409, got %+v", info)
	}
}

func TestRegisterRequestSendsHandle(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(RegisterResponse{
			APIKey:  "aw_sk_test",
			AgentID: "agent-1",
			Alias:   "alice",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	username := "testuser"
	handle := "testuser"
	_, err = c.Register(context.Background(), &RegisterRequest{
		Email:    "test@example.com",
		Username: &username,
		Handle:   &handle,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both username and handle must be present on the wire.
	if gotBody["username"] != "testuser" {
		t.Fatalf("username=%v, want testuser", gotBody["username"])
	}
	if gotBody["handle"] != "testuser" {
		t.Fatalf("handle=%v, want testuser", gotBody["handle"])
	}
}
