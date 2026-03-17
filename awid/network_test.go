package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetworkDirectorySearch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/network/directory" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.URL.Query().Get("capability") != "translate" {
			t.Fatalf("capability=%s", r.URL.Query().Get("capability"))
		}
		_ = json.NewEncoder(w).Encode(NetworkDirectoryResponse{
			Agents: []NetworkDirectoryAgent{{OrgSlug: "acme", Alias: "translator", Capabilities: []string{"translate"}}},
			Total:  1,
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkDirectorySearch(context.Background(), NetworkDirectoryParams{Capability: "translate"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 || resp.Agents[0].Alias != "translator" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestNetworkDirectoryGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/network/directory/acme/researcher" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(NetworkDirectoryAgent{
			OrgSlug:      "acme",
			OrgName:      "Acme Corp",
			Alias:        "researcher",
			Capabilities: []string{"research"},
			Description:  "Research agent",
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkDirectoryGet(context.Background(), "acme", "researcher")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Alias != "researcher" || resp.OrgSlug != "acme" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestNetworkPublishAgent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/publish" {
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
		var body NetworkPublishRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AgentID != "agent-1" {
			t.Fatalf("agent_id=%s", body.AgentID)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(NetworkPublishResponse{
			OrgID:       "org-1",
			AgentID:     "agent-1",
			Alias:       "researcher",
			PublishedAt: "2026-02-06T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkPublishAgent(context.Background(), &NetworkPublishRequest{
		AgentID:      "agent-1",
		Capabilities: []string{"research"},
		Description:  "Research agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentID != "agent-1" || resp.Alias != "researcher" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestNetworkUnpublishAgent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/agents/researcher/publish" {
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	err := c.NetworkUnpublishAgent(context.Background(), "researcher")
	if err != nil {
		t.Fatal(err)
	}
}
