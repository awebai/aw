package aweb

import "context"

// DMRequest is sent to POST /v1/network/dm for human DM addressing.
type DMRequest struct {
	ToHandle     string `json:"to_handle"`
	Subject      string `json:"subject,omitempty"`
	Body         string `json:"body"`
	Priority     string `json:"priority,omitempty"`
	FromDID      string `json:"from_did,omitempty"`
	ToDID        string `json:"to_did,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
}

// DMResponse is returned by POST /v1/network/dm.
type DMResponse struct {
	MessageID   string `json:"message_id"`
	Status      string `json:"status"`
	DeliveredAt string `json:"delivered_at"`
}

// SendDM sends a direct message to a human by @handle.
func (c *Client) SendDM(ctx context.Context, req *DMRequest) (*DMResponse, error) {
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		To:      "@" + req.ToHandle,
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

	var out DMResponse
	if err := c.post(ctx, "/v1/network/dm", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
