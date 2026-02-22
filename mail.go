package aweb

import (
	"context"
)

type MessagePriority string

const (
	PriorityLow    MessagePriority = "low"
	PriorityNormal MessagePriority = "normal"
	PriorityHigh   MessagePriority = "high"
	PriorityUrgent MessagePriority = "urgent"
)

type SendMessageRequest struct {
	ToAgentID    string          `json:"to_agent_id,omitempty"`
	ToAlias      string          `json:"to_alias,omitempty"`
	Subject      string          `json:"subject,omitempty"`
	Body         string          `json:"body"`
	Priority     MessagePriority `json:"priority,omitempty"`
	ThreadID     *string         `json:"thread_id,omitempty"`
	FromDID      string          `json:"from_did,omitempty"`
	ToDID        string          `json:"to_did,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	SigningKeyID string          `json:"signing_key_id,omitempty"`
	Timestamp    string          `json:"timestamp,omitempty"`
	MessageID    string          `json:"message_id,omitempty"`
}

type SendMessageResponse struct {
	MessageID   string `json:"message_id"`
	Status      string `json:"status"`
	DeliveredAt string `json:"delivered_at"`
}

func (c *Client) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	to := req.ToAlias
	if to == "" {
		to = req.ToAgentID
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		To:      to,
		Type:    "mail",
		Subject: req.Subject,
		Body:    req.Body,
	})
	if err != nil {
		return nil, err
	}
	req.FromDID = sf.FromDID
	req.ToDID = sf.ToDID
	req.Signature = sf.Signature
	req.SigningKeyID = sf.SigningKeyID
	req.Timestamp = sf.Timestamp
	req.MessageID = sf.MessageID

	var out SendMessageResponse
	if err := c.post(ctx, "/v1/messages", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type InboxMessage struct {
	MessageID          string             `json:"message_id"`
	FromAgentID        string             `json:"from_agent_id"`
	FromAlias          string             `json:"from_alias"`
	ToAlias            string             `json:"to_alias,omitempty"`
	Subject            string             `json:"subject"`
	Body               string             `json:"body"`
	Priority           MessagePriority    `json:"priority"`
	ThreadID           *string            `json:"thread_id"`
	ReadAt             *string            `json:"read_at"`
	CreatedAt          string             `json:"created_at"`
	FromDID            string             `json:"from_did,omitempty"`
	ToDID              string             `json:"to_did,omitempty"`
	FromStableID       string             `json:"from_stable_id,omitempty"`
	ToStableID         string             `json:"to_stable_id,omitempty"`
	Signature          string             `json:"signature,omitempty"`
	SigningKeyID       string             `json:"signing_key_id,omitempty"`
	VerificationStatus VerificationStatus `json:"verification_status,omitempty"`
}

type InboxResponse struct {
	Messages []InboxMessage `json:"messages"`
}

type InboxParams struct {
	UnreadOnly bool
	Limit      int
}

func (c *Client) Inbox(ctx context.Context, p InboxParams) (*InboxResponse, error) {
	path := "/v1/messages/inbox"
	sep := "?"
	if p.UnreadOnly {
		path += sep + "unread_only=true"
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
		sep = "&"
	}
	var out InboxResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		env := &MessageEnvelope{
			From:         m.FromAlias,
			FromDID:      m.FromDID,
			To:           m.ToAlias,
			ToDID:        m.ToDID,
			Type:         "mail",
			Subject:      m.Subject,
			Body:         m.Body,
			Timestamp:    m.CreatedAt,
			FromStableID: m.FromStableID,
			ToStableID:   m.ToStableID,
			MessageID:    m.MessageID,
			Signature:    m.Signature,
			SigningKeyID: m.SigningKeyID,
		}
		// Error is encoded in VerificationStatus; discard it.
		m.VerificationStatus, _ = VerifyMessage(env)
		m.VerificationStatus = c.checkRecipientBinding(m.VerificationStatus, m.ToDID)
		m.VerificationStatus = c.CheckTOFUPin(m.VerificationStatus, m.FromAlias, m.FromDID)
	}
	return &out, nil
}

type AckResponse struct {
	MessageID      string `json:"message_id"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

func (c *Client) AckMessage(ctx context.Context, messageID string) (*AckResponse, error) {
	var out AckResponse
	if err := c.post(ctx, "/v1/messages/"+urlPathEscape(messageID)+"/ack", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
