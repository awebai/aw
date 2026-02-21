package aweb

import "context"

// BlockRequest is sent to POST /v1/network/blocked.
type BlockRequest struct {
	Address string `json:"address"`
}

// BlockResponse is returned by POST /v1/network/blocked.
type BlockResponse struct {
	Address   string `json:"address"`
	BlockedAt string `json:"blocked_at"`
}

// Block adds a namespace or agent address to the blocked list.
func (c *Client) Block(ctx context.Context, req *BlockRequest) (*BlockResponse, error) {
	var out BlockResponse
	if err := c.post(ctx, "/v1/network/blocked", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unblock removes a namespace or agent address from the blocked list.
func (c *Client) Unblock(ctx context.Context, address string) error {
	return c.delete(ctx, "/v1/network/blocked/"+urlPathEscape(address))
}

// BlockedEntry represents a single blocked address.
type BlockedEntry struct {
	Address   string `json:"address"`
	BlockedAt string `json:"blocked_at"`
}

// ListBlockedResponse is returned by GET /v1/network/blocked.
type ListBlockedResponse struct {
	Blocked []BlockedEntry `json:"blocked"`
}

// ListBlocked returns the list of blocked addresses.
func (c *Client) ListBlocked(ctx context.Context) (*ListBlockedResponse, error) {
	var out ListBlockedResponse
	if err := c.get(ctx, "/v1/network/blocked", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
