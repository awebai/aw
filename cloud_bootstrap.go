package aweb

import "context"

// CloudBootstrapAgentRequest is sent to POST /api/v1/agents/bootstrap.
type CloudBootstrapAgentRequest struct {
	ProjectID *string `json:"project_id,omitempty"`
	Alias     *string `json:"alias,omitempty"`
	HumanName string  `json:"human_name,omitempty"`
	AgentType string  `json:"agent_type,omitempty"`
}

// CloudBootstrapAgentResponse is returned by POST /api/v1/agents/bootstrap.
type CloudBootstrapAgentResponse struct {
	OrgID             string `json:"org_id"`
	OrgSlug           string `json:"org_slug"`
	OrgName           string `json:"org_name"`
	ProjectID         string `json:"project_id"`
	ProjectSlug       string `json:"project_slug"`
	ProjectName       string `json:"project_name"`
	ServerURL         string `json:"server_url"`
	BootstrapEndpoint string `json:"bootstrap_endpoint"`
	APIKey            string `json:"api_key"`
	AgentID           string `json:"agent_id"`
	Alias             string `json:"alias"`
	Created           bool   `json:"created"`
}

// CloudBootstrapAgent bootstraps an agent through the aweb-cloud wrapper.
func (c *Client) CloudBootstrapAgent(ctx context.Context, req *CloudBootstrapAgentRequest) (*CloudBootstrapAgentResponse, error) {
	var out CloudBootstrapAgentResponse
	if err := c.post(ctx, "/api/v1/agents/bootstrap", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
