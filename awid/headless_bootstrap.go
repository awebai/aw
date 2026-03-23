package awid

import (
	"context"
	"fmt"
)

// HeadlessBootstrapRequest is sent to POST /api/v1/bootstrap/headless-agent.
// This endpoint is unauthenticated and rate-limited. It creates a free org,
// managed namespace, default project, first workspace, and first identity in one call.
type HeadlessBootstrapRequest struct {
	NamespaceSlug string `json:"namespace_slug"`
	Alias         string `json:"alias"`
	AgentType     string `json:"agent_type,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	DID           string `json:"did,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Custody       string `json:"custody,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
}

// HeadlessBootstrapResponse is returned by POST /api/v1/bootstrap/headless-agent.
type HeadlessBootstrapResponse struct {
	OrgID         string `json:"org_id"`
	OrgSlug       string `json:"org_slug"`
	ProjectID     string `json:"project_id"`
	ProjectSlug   string `json:"project_slug"`
	NamespaceSlug string `json:"namespace_slug,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	AgentID       string `json:"agent_id"`
	Alias         string `json:"alias"`
	Address       string `json:"address,omitempty"`
	APIKey        string `json:"api_key"`
	ServerURL     string `json:"server_url,omitempty"`
	DID           string `json:"did,omitempty"`
	StableID      string `json:"stable_id,omitempty"`
	Custody       string `json:"custody,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
	Created       bool   `json:"created"`
}

// HeadlessBootstrap creates the first workspace and identity via anonymous headless bootstrap.
func (c *Client) HeadlessBootstrap(ctx context.Context, req *HeadlessBootstrapRequest) (*HeadlessBootstrapResponse, error) {
	if req.NamespaceSlug == "" {
		return nil, fmt.Errorf("aweb: namespace_slug is required for headless bootstrap")
	}
	if req.Alias == "" {
		return nil, fmt.Errorf("aweb: alias is required for headless bootstrap")
	}
	var out HeadlessBootstrapResponse
	if err := c.Post(ctx, "/api/v1/bootstrap/headless-agent", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
