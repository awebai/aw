package awid

import "context"

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
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) NetworkDirectoryGet(ctx context.Context, orgSlug, alias string) (*NetworkDirectoryAgent, error) {
	var out NetworkDirectoryAgent
	if err := c.Get(ctx, "/v1/network/directory/"+urlPathEscape(orgSlug)+"/"+urlPathEscape(alias), &out); err != nil {
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
	if err := c.Post(ctx, "/v1/agents/publish", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) NetworkUnpublishAgent(ctx context.Context, alias string) error {
	return c.Delete(ctx, "/v1/agents/"+urlPathEscape(alias)+"/publish")
}
