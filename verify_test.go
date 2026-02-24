package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyCodeWithInlineBootstrap(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/verify-code" {
			t.Fatalf("path=%s", r.URL.Path)
		}

		var body VerifyCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Email != "juan@example.com" {
			t.Fatalf("email=%q", body.Email)
		}
		if body.Code != "123456" {
			t.Fatalf("code=%q", body.Code)
		}
		if body.Alias != "researcher" {
			t.Fatalf("alias=%q", body.Alias)
		}
		if body.NamespaceSlug != "mycompany" {
			t.Fatalf("namespace_slug=%q", body.NamespaceSlug)
		}

		_ = json.NewEncoder(w).Encode(VerifyCodeResponse{
			Verified:           true,
			Username:           "juan",
			RegistrationSource: "cli",
			APIKey:             "aw_sk_new",
			AgentID:            "agent-42",
			Alias:              "researcher",
			NamespaceSlug:      "mycompany",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.VerifyCode(context.Background(), &VerifyCodeRequest{
		Email:         "juan@example.com",
		Code:          "123456",
		Alias:         "researcher",
		NamespaceSlug: "mycompany",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Verified {
		t.Fatal("verified=false")
	}
	if resp.APIKey != "aw_sk_new" {
		t.Fatalf("api_key=%q", resp.APIKey)
	}
	if resp.AgentID != "agent-42" {
		t.Fatalf("agent_id=%q", resp.AgentID)
	}
	if resp.Alias != "researcher" {
		t.Fatalf("alias=%q", resp.Alias)
	}
	if resp.NamespaceSlug != "mycompany" {
		t.Fatalf("namespace_slug=%q", resp.NamespaceSlug)
	}
}
