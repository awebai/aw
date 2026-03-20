package awid

import (
	"context"
	"fmt"
)

// InviteCreateRequest is sent to POST /api/v1/invites/cli.
type InviteCreateRequest struct {
	AliasHint        string `json:"alias_hint,omitempty"`
	AccessMode       string `json:"access_mode,omitempty"`
	MaxUses          int    `json:"max_uses,omitempty"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

// InviteCreateResponse is returned by POST /api/v1/invites/cli.
type InviteCreateResponse struct {
	InviteID    string `json:"invite_id"`
	Token       string `json:"token"`
	TokenPrefix string `json:"token_prefix"`
	AliasHint   string `json:"alias_hint,omitempty"`
	AccessMode  string `json:"access_mode"`
	MaxUses     int    `json:"max_uses"`
	ExpiresAt   string `json:"expires_at"`
	Namespace   string `json:"namespace"`
	ServerURL   string `json:"server_url"`
}

// InviteListItem is returned by GET /api/v1/invites/cli.
type InviteListItem struct {
	InviteID    string `json:"invite_id"`
	TokenPrefix string `json:"token_prefix"`
	AliasHint   string `json:"alias_hint,omitempty"`
	AccessMode  string `json:"access_mode"`
	MaxUses     int    `json:"max_uses"`
	CurrentUses int    `json:"current_uses"`
	ExpiresAt   string `json:"expires_at"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// InviteListResponse is returned by GET /api/v1/invites/cli.
type InviteListResponse struct {
	Invites []InviteListItem `json:"invites"`
}

// InviteAcceptRequest is sent to POST /api/v1/invites/cli/accept.
type InviteAcceptRequest struct {
	Token     string `json:"token"`
	Alias     string `json:"alias,omitempty"`
	HumanName string `json:"human_name,omitempty"`
	AgentType string `json:"agent_type,omitempty"`
	DID       string `json:"did,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Custody   string `json:"custody,omitempty"`
	Lifetime  string `json:"lifetime,omitempty"`
}

// InviteAcceptResponse is returned by POST /api/v1/invites/cli/accept.
type InviteAcceptResponse struct {
	OrgID       string `json:"org_id,omitempty"`
	OrgSlug     string `json:"org_slug,omitempty"`
	ProjectID   string `json:"project_id"`
	ProjectSlug string `json:"project_slug"`
	Namespace   string `json:"namespace"`
	AgentID     string `json:"agent_id"`
	Alias       string `json:"alias"`
	Address     string `json:"address"`
	APIKey      string `json:"api_key"`
	ServerURL   string `json:"server_url"`
	DID         string `json:"did,omitempty"`
	StableID    string `json:"stable_id,omitempty"`
	Custody     string `json:"custody,omitempty"`
	Lifetime    string `json:"lifetime,omitempty"`
	AccessMode  string `json:"access_mode"`
	Created     bool   `json:"created"`
}

// InviteCreate creates a CLI invite token in the current hosted context.
func (c *Client) InviteCreate(ctx context.Context, req *InviteCreateRequest) (*InviteCreateResponse, error) {
	if req == nil {
		req = &InviteCreateRequest{}
	}
	var out InviteCreateResponse
	if err := c.Post(ctx, "/api/v1/invites/cli", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// InviteList returns the caller's CLI invites in the current hosted context.
func (c *Client) InviteList(ctx context.Context) (*InviteListResponse, error) {
	var out InviteListResponse
	if err := c.Get(ctx, "/api/v1/invites/cli", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// InviteRevoke revokes a CLI invite by its invite_id.
func (c *Client) InviteRevoke(ctx context.Context, inviteID string) error {
	if inviteID == "" {
		return fmt.Errorf("aweb: invite_id is required")
	}
	return c.Delete(ctx, "/api/v1/invites/cli/"+urlPathEscape(inviteID))
}

// InviteAccept accepts a CLI invite token and bootstraps a new agent.
func (c *Client) InviteAccept(ctx context.Context, req *InviteAcceptRequest) (*InviteAcceptResponse, error) {
	if req == nil || req.Token == "" {
		return nil, fmt.Errorf("aweb: token is required")
	}
	var out InviteAcceptResponse
	if err := c.Post(ctx, "/api/v1/invites/cli/accept", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
