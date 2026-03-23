package awid

import "context"

// IdentityView is returned by GET /v1/agents.
type IdentityView struct {
	AgentID       string `json:"agent_id"`
	Alias         string `json:"alias"`
	Name          string `json:"name,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type,omitempty"`
	Status        string `json:"status,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
	Online        bool   `json:"online"`
	AccessMode    string `json:"access_mode,omitempty"`
	AddressReachability string `json:"address_reachability,omitempty"`
	NamespaceSlug string `json:"namespace_slug,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
}

type ListIdentitiesResponse struct {
	ProjectID  string         `json:"project_id"`
	Identities []IdentityView `json:"identities,omitempty"`
	Agents     []IdentityView `json:"agents,omitempty"`
}

func (r *ListIdentitiesResponse) Items() []IdentityView {
	if r == nil {
		return nil
	}
	if len(r.Identities) > 0 {
		return r.Identities
	}
	return r.Agents
}

func (c *Client) ListIdentities(ctx context.Context) (*ListIdentitiesResponse, error) {
	var out ListIdentitiesResponse
	if err := c.Get(ctx, "/v1/agents", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type PatchIdentityRequest struct {
	AccessMode         string `json:"access_mode,omitempty"`
	AddressReachability string `json:"address_reachability,omitempty"`
}

type PatchIdentityResponse struct {
	AgentID            string `json:"agent_id"`
	AccessMode         string `json:"access_mode,omitempty"`
	AddressReachability string `json:"address_reachability,omitempty"`
}

func (c *Client) PatchIdentity(ctx context.Context, agentID string, req *PatchIdentityRequest) (*PatchIdentityResponse, error) {
	var out PatchIdentityResponse
	if err := c.Patch(ctx, "/v1/agents/"+urlPathEscape(agentID), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HeartbeatResponse is returned by POST /v1/agents/heartbeat.
type HeartbeatResponse struct {
	AgentID  string `json:"agent_id"`
	LastSeen string `json:"last_seen"`
	TTL      int    `json:"ttl_seconds"`
}

// Heartbeat reports agent liveness to the aweb server.
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.Post(ctx, "/v1/agents/heartbeat", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
