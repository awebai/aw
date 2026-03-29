package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

func mustWebClient(t *testing.T, url string) *aweb.Client {
	t.Helper()
	c, err := aweb.New(url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestResolveMailWakeMarksRead verifies that resolveMailWake acks the message
// after fetching it from the inbox.
func TestResolveMailWakeMarksRead(t *testing.T) {
	t.Parallel()

	var ackedMessageID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{MessageID: "msg-1", FromAlias: "alice", Subject: "hello", Body: "world"},
				},
			})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			parts := strings.Split(r.URL.Path, "/")
			ackedMessageID = parts[3] // /v1/messages/{id}/ack
			json.NewEncoder(w).Encode(awid.AckResponse{MessageID: ackedMessageID})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveMailWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		MessageID: "msg-1",
		FromAlias: "alice",
		Subject:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatal("should not skip")
	}
	if ackedMessageID != "msg-1" {
		t.Fatalf("expected ack for msg-1, got %q", ackedMessageID)
	}
}

// TestMarkChatHistoryReadRetriesOnFailure verifies that markChatHistoryRead
// retries once when ChatMarkRead fails.
func TestMarkChatHistoryReadRetriesOnFailure(t *testing.T) {
	t.Parallel()

	var markReadCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read") {
			markReadCalls++
			if markReadCalls == 1 {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	markChatHistoryRead(context.Background(), client, "s1", []awid.ChatMessage{
		{MessageID: "m1", FromAgent: "bob", Body: "hello"},
	})
	if markReadCalls != 2 {
		t.Fatalf("mark_read calls=%d, want 2 (initial + retry)", markReadCalls)
	}
}

// TestMarkChatHistoryReadSavesDeliveredIDs verifies that markChatHistoryRead
// writes delivered message IDs to the dedup cache so aw chat open can filter
// them if mark-read fails.
func TestMarkChatHistoryReadSavesDeliveredIDs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read") {
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	cacheDir := t.TempDir()
	client := mustWebClient(t, server.URL)
	markChatHistoryRead(context.Background(), client, "s1", []awid.ChatMessage{
		{MessageID: "m1", FromAgent: "bob", Body: "hello"},
		{MessageID: "m2", FromAgent: "bob", Body: "world"},
	}, cacheDir)

	seen := chat.LoadDeliveredIDs(cacheDir, "s1")
	if len(seen) != 2 {
		t.Fatalf("delivered cache has %d IDs, want 2", len(seen))
	}
	if !seen["m1"] || !seen["m2"] {
		t.Fatalf("missing expected message IDs in cache: %v", seen)
	}
}

// TestResolveChatWakeMarksRead verifies that resolveChatWake marks messages
// as read after fetching the pending conversation.
func TestResolveChatWakeMarksRead(t *testing.T) {
	t.Parallel()

	var markedReadSessionID string
	var markedReadUpTo string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "hey", LastFrom: "alice", SenderWaiting: true, UnreadCount: 1},
				},
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "chat-msg-1", FromAgent: "alice", Body: "hey"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			// /v1/chat/sessions/{id}/read → parts: ["", "v1", "chat", "sessions", "{id}", "read"]
			parts := strings.Split(r.URL.Path, "/")
			markedReadSessionID = parts[4]
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			markedReadUpTo = req.UpToMessageID
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatal("should not skip")
	}
	if markedReadSessionID != "s1" {
		t.Fatalf("expected mark-read for session s1, got %q", markedReadSessionID)
	}
	if markedReadUpTo != "chat-msg-1" {
		t.Fatalf("expected mark-read up to chat-msg-1, got %q", markedReadUpTo)
	}
}
