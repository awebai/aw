package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
