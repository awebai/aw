package aweb

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// --- Mail ---

type NetworkMailRequest struct {
	ToAddress    string `json:"to_address"`
	Subject      string `json:"subject,omitempty"`
	Body         string `json:"body"`
	Priority     string `json:"priority,omitempty"`
	ThreadID     string `json:"thread_id,omitempty"`
	FromDID      string `json:"from_did,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
}

type NetworkMailResponse struct {
	MessageID   string `json:"message_id"`
	Status      string `json:"status"`
	DeliveredAt string `json:"delivered_at"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

func (c *Client) NetworkSendMail(ctx context.Context, req *NetworkMailRequest) (*NetworkMailResponse, error) {
	sf, err := c.signEnvelope(&MessageEnvelope{
		To:      req.ToAddress,
		Type:    "mail",
		Subject: req.Subject,
		Body:    req.Body,
	})
	if err != nil {
		return nil, err
	}
	req.FromDID = sf.FromDID
	req.Signature = sf.Signature
	req.SigningKeyID = sf.SigningKeyID
	req.Timestamp = sf.Timestamp
	req.MessageID = sf.MessageID

	var out NetworkMailResponse
	if err := c.post(ctx, "/v1/network/mail", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Chat ---

type NetworkChatCreateRequest struct {
	ToAddresses  []string `json:"to_addresses"`
	Message      string   `json:"message"`
	Leaving      bool     `json:"leaving,omitempty"`
	FromDID      string   `json:"from_did,omitempty"`
	Signature    string   `json:"signature,omitempty"`
	SigningKeyID string   `json:"signing_key_id,omitempty"`
	Timestamp    string   `json:"timestamp,omitempty"`
	MessageID    string   `json:"message_id,omitempty"`
}

type NetworkChatCreateResponse struct {
	SessionID        string   `json:"session_id"`
	MessageID        string   `json:"message_id"`
	Participants     []string `json:"participants"`
	SSEURL           string   `json:"sse_url"`
	TargetsConnected []string `json:"targets_connected"`
	TargetsLeft      []string `json:"targets_left"`
}

func (c *Client) NetworkCreateChat(ctx context.Context, req *NetworkChatCreateRequest) (*NetworkChatCreateResponse, error) {
	sf, err := c.signEnvelope(&MessageEnvelope{
		To:   strings.Join(req.ToAddresses, ","),
		Type: "chat",
		Body: req.Message,
	})
	if err != nil {
		return nil, err
	}
	req.FromDID = sf.FromDID
	req.Signature = sf.Signature
	req.SigningKeyID = sf.SigningKeyID
	req.Timestamp = sf.Timestamp
	req.MessageID = sf.MessageID

	var out NetworkChatCreateResponse
	if err := c.post(ctx, "/v1/network/chat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type NetworkChatSendMessageRequest struct {
	Body         string `json:"body"`
	ExtendWait   bool   `json:"hang_on,omitempty"`
	FromDID      string `json:"from_did,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
}

type NetworkChatSendMessageResponse struct {
	MessageID          string `json:"message_id"`
	Delivered          bool   `json:"delivered"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

func (c *Client) NetworkChatSendMessage(ctx context.Context, sessionID string, req *NetworkChatSendMessageRequest) (*NetworkChatSendMessageResponse, error) {
	if sessionID == "" {
		return nil, errors.New("aweb: sessionID is required")
	}
	// In-session messages: To is empty because the session implies recipients.
	sf, err := c.signEnvelope(&MessageEnvelope{
		Type: "chat",
		Body: req.Body,
	})
	if err != nil {
		return nil, err
	}
	req.FromDID = sf.FromDID
	req.Signature = sf.Signature
	req.SigningKeyID = sf.SigningKeyID
	req.Timestamp = sf.Timestamp
	req.MessageID = sf.MessageID

	var out NetworkChatSendMessageResponse
	if err := c.post(ctx, "/v1/network/chat/"+urlPathEscape(sessionID)+"/messages", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// NetworkChatHistory fetches messages for a network chat session.
// Reuses ChatHistoryParams and ChatHistoryResponse since the wire format is identical.
func (c *Client) NetworkChatHistory(ctx context.Context, p ChatHistoryParams) (*ChatHistoryResponse, error) {
	if p.SessionID == "" {
		return nil, errors.New("aweb: sessionID is required")
	}
	path := "/v1/network/chat/" + urlPathEscape(p.SessionID) + "/messages"
	sep := "?"
	if p.UnreadOnly {
		path += sep + "unread_only=true"
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
	}
	var out ChatHistoryResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		env := &MessageEnvelope{
			From:         m.FromAgent,
			FromDID:      m.FromDID,
			ToDID:        m.ToDID,
			Type:         "chat",
			Body:         m.Body,
			Timestamp:    m.Timestamp,
			FromStableID: m.FromStableID,
			ToStableID:   m.ToStableID,
			MessageID:    m.MessageID,
			Signature:    m.Signature,
			SigningKeyID: m.SigningKeyID,
		}
		// Error is encoded in VerificationStatus; discard it.
		m.VerificationStatus, _ = VerifyMessage(env)
	}
	return &out, nil
}

type NetworkChatMarkReadRequest struct {
	UpToMessageID string `json:"up_to_message_id"`
}

type NetworkChatMarkReadResponse struct {
	Success        bool `json:"success"`
	MessagesMarked int  `json:"messages_marked"`
}

func (c *Client) NetworkChatMarkRead(ctx context.Context, sessionID string, req *NetworkChatMarkReadRequest) (*NetworkChatMarkReadResponse, error) {
	if sessionID == "" {
		return nil, errors.New("aweb: sessionID is required")
	}
	var out NetworkChatMarkReadResponse
	if err := c.post(ctx, "/v1/network/chat/"+urlPathEscape(sessionID)+"/read", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type NetworkChatPendingItem struct {
	SessionID            string   `json:"session_id"`
	Participants         []string `json:"participants"`
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	UnreadCount          int      `json:"unread_count"`
	LastActivity         string   `json:"last_activity"`
	SenderWaiting        bool     `json:"sender_waiting"`
	TimeRemainingSeconds *int     `json:"time_remaining_seconds"`
}

type NetworkChatPendingResponse struct {
	Pending         []NetworkChatPendingItem `json:"pending"`
	MessagesWaiting int                      `json:"messages_waiting"`
}

func (c *Client) NetworkChatPending(ctx context.Context) (*NetworkChatPendingResponse, error) {
	var out NetworkChatPendingResponse
	if err := c.get(ctx, "/v1/network/chat/pending", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// NetworkChatStream opens an SSE stream for a network chat session.
// after controls replay: if non-nil, the server replays only messages created after
// that timestamp; if nil, no replay (server polls from now).
func (c *Client) NetworkChatStream(ctx context.Context, sessionID string, deadline time.Time, after *time.Time) (*SSEStream, error) {
	if sessionID == "" {
		return nil, errors.New("aweb: sessionID is required")
	}
	path := "/v1/network/chat/" + urlPathEscape(sessionID) + "/stream?deadline=" + urlQueryEscape(deadline.UTC().Format(time.RFC3339Nano))
	if after != nil && !after.IsZero() {
		path += "&after=" + urlQueryEscape(after.UTC().Format(time.RFC3339Nano))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.sseClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return nil, &apiError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return NewSSEStream(resp.Body), nil
}

// --- Directory ---

type NetworkDirectoryAgent struct {
	OrgName      string   `json:"org_name"`
	OrgSlug      string   `json:"org_slug"`
	Alias        string   `json:"alias"`
	Capabilities []string `json:"capabilities"`
	Description  string   `json:"description"`
}

type NetworkDirectoryResponse struct {
	Agents []NetworkDirectoryAgent `json:"agents"`
	Total  int                     `json:"total"`
}

type NetworkDirectoryParams struct {
	Capability string
	OrgSlug    string
	Query      string
	Limit      int
}

func (c *Client) NetworkDirectorySearch(ctx context.Context, p NetworkDirectoryParams) (*NetworkDirectoryResponse, error) {
	path := "/v1/network/directory"
	sep := "?"
	if p.Capability != "" {
		path += sep + "capability=" + urlQueryEscape(p.Capability)
		sep = "&"
	}
	if p.OrgSlug != "" {
		path += sep + "org_slug=" + urlQueryEscape(p.OrgSlug)
		sep = "&"
	}
	if p.Query != "" {
		path += sep + "q=" + urlQueryEscape(p.Query)
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
	}
	var out NetworkDirectoryResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) NetworkDirectoryGet(ctx context.Context, orgSlug, alias string) (*NetworkDirectoryAgent, error) {
	var out NetworkDirectoryAgent
	if err := c.get(ctx, "/v1/network/directory/"+urlPathEscape(orgSlug)+"/"+urlPathEscape(alias), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Publish / Unpublish ---

type NetworkPublishRequest struct {
	AgentID      string   `json:"agent_id"`
	Capabilities []string `json:"capabilities,omitempty"`
	Description  string   `json:"description,omitempty"`
}

type NetworkPublishResponse struct {
	OrgID        string   `json:"org_id"`
	AgentID      string   `json:"agent_id"`
	Alias        string   `json:"alias"`
	Capabilities []string `json:"capabilities"`
	Description  string   `json:"description"`
	PublishedAt  string   `json:"published_at"`
}

func (c *Client) NetworkPublishAgent(ctx context.Context, req *NetworkPublishRequest) (*NetworkPublishResponse, error) {
	var out NetworkPublishResponse
	if err := c.post(ctx, "/v1/agents/publish", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) NetworkUnpublishAgent(ctx context.Context, alias string) error {
	return c.delete(ctx, "/v1/agents/"+urlPathEscape(alias)+"/publish")
}
