package aweb

import "context"

// RegisterRequest is sent to POST /v1/auth/register.
//
// This endpoint lets agents self-onboard from the CLI.
// It does not require an API key.
type RegisterRequest struct {
	Email     string  `json:"email"`
	Username  *string `json:"username,omitempty"`
	Password  *string `json:"password,omitempty"`
	Alias     *string `json:"alias,omitempty"`
	HumanName string  `json:"human_name,omitempty"`
}

// RegisterResponse is returned by POST /v1/auth/register.
type RegisterResponse struct {
	APIKey               string `json:"api_key"`
	AgentID              string `json:"agent_id"`
	Alias                string `json:"alias"`
	Username             string `json:"username"`
	Email                string `json:"email"`
	ProjectSlug          string `json:"project_slug"`
	ProjectName          string `json:"project_name"`
	ServerURL            string `json:"server_url"`
	NamespaceSlug        string `json:"namespace_slug,omitempty"`
	VerificationRequired bool   `json:"verification_required"`
}

// Register creates a new account on the server.
func (c *Client) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	var out RegisterResponse
	if err := c.post(ctx, "/v1/auth/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
