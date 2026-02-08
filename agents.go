package aweb

import "context"

// AgentView is returned by GET /v1/agents.
type AgentView struct {
	AgentID    string `json:"agent_id"`
	Alias      string `json:"alias"`
	HumanName  string `json:"human_name,omitempty"`
	AgentType  string `json:"agent_type,omitempty"`
	Status     string `json:"status,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
	Online     bool   `json:"online"`
	AccessMode string `json:"access_mode,omitempty"`
}

type ListAgentsResponse struct {
	ProjectID string     `json:"project_id"`
	Agents    []AgentView `json:"agents"`
}

func (c *Client) ListAgents(ctx context.Context) (*ListAgentsResponse, error) {
	var out ListAgentsResponse
	if err := c.get(ctx, "/v1/agents", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type PatchAgentRequest struct {
	AccessMode string `json:"access_mode"`
}

type PatchAgentResponse struct {
	AgentID    string `json:"agent_id"`
	AccessMode string `json:"access_mode"`
}

func (c *Client) PatchAgent(ctx context.Context, agentID string, req *PatchAgentRequest) (*PatchAgentResponse, error) {
	var out PatchAgentResponse
	if err := c.patch(ctx, "/v1/agents/"+agentID, req, &out); err != nil {
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
	if err := c.post(ctx, "/v1/agents/heartbeat", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

