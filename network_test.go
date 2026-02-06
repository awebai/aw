package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetworkSendMail(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/api/v1/network/mail" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", got)
		}
		var body NetworkMailRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.ToAddress != "acme/researcher" {
			t.Fatalf("to_address=%q", body.ToAddress)
		}
		if body.Body != "hello network" {
			t.Fatalf("body=%q", body.Body)
		}
		_ = json.NewEncoder(w).Encode(NetworkMailResponse{
			MessageID:   "net-msg-1",
			Status:      "sent",
			DeliveredAt: "2026-02-06T00:00:00Z",
			FromAddress: "myorg/myalias",
			ToAddress:   "acme/researcher",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.NetworkSendMail(context.Background(), &NetworkMailRequest{
		ToAddress: "acme/researcher",
		Body:      "hello network",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "net-msg-1" {
		t.Fatalf("message_id=%s", resp.MessageID)
	}
	if resp.ToAddress != "acme/researcher" {
		t.Fatalf("to_address=%s", resp.ToAddress)
	}
}

func TestNetworkCreateChat(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/api/v1/network/chat" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body NetworkChatCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.ToAddresses) != 1 || body.ToAddresses[0] != "acme/bot" {
			t.Fatalf("to_addresses=%v", body.ToAddresses)
		}
		_ = json.NewEncoder(w).Encode(NetworkChatCreateResponse{
			SessionID:        "net-sess-1",
			MessageID:        "net-msg-2",
			Participants:     []string{"myorg/me", "acme/bot"},
			SSEURL:           "/api/v1/network/chat/net-sess-1/stream",
			TargetsConnected: []string{},
			TargetsLeft:      []string{},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.NetworkCreateChat(context.Background(), &NetworkChatCreateRequest{
		ToAddresses: []string{"acme/bot"},
		Message:     "hey",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "net-sess-1" {
		t.Fatalf("session_id=%s", resp.SessionID)
	}
}

func TestNetworkChatSendMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/network/chat/sess-1/messages" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(NetworkChatSendMessageResponse{
			MessageID: "msg-3",
			Delivered: true,
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkChatSendMessage(context.Background(), "sess-1", &NetworkChatSendMessageRequest{Body: "follow up"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-3" {
		t.Fatalf("message_id=%s", resp.MessageID)
	}
}

func TestNetworkChatPending(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/network/chat/pending" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(NetworkChatPendingResponse{
			Pending:         []NetworkChatPendingItem{{SessionID: "s1", UnreadCount: 3}},
			MessagesWaiting: 3,
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkChatPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Pending) != 1 || resp.Pending[0].SessionID != "s1" {
		t.Fatalf("pending=%+v", resp.Pending)
	}
}

func TestNetworkChatMarkRead(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/network/chat/sess-1/read" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(NetworkChatMarkReadResponse{
			Success:        true,
			MessagesMarked: 5,
		})
	}))
	t.Cleanup(server.Close)

	c, _ := NewWithAPIKey(server.URL, "aw_sk_test")
	resp, err := c.NetworkChatMarkRead(context.Background(), "sess-1", &NetworkChatMarkReadRequest{UpToMessageID: "msg-5"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Success || resp.MessagesMarked != 5 {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestNetworkDirectorySearch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/network/directory" {
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
		if r.URL.Path != "/api/v1/network/directory/acme/researcher" {
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
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/publish" {
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
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/agents/researcher/publish" {
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
