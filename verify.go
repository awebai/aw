package aweb

import "context"

// VerifyCodeRequest is sent to POST /v1/auth/verify-code.
//
// This endpoint verifies email ownership using a 6-digit code.
// It does not require an API key.
type VerifyCodeRequest struct {
	Email         string `json:"email"`
	Code          string `json:"code"`
	Alias         string `json:"alias,omitempty"`
	NamespaceSlug string `json:"namespace_slug,omitempty"`
}

// VerifyCodeResponse is returned by POST /v1/auth/verify-code.
// When alias + namespace_slug are provided in the request, the server
// bootstraps the agent inline and returns credentials.
type VerifyCodeResponse struct {
	Verified           bool   `json:"verified"`
	Username           string `json:"username"`
	RegistrationSource string `json:"registration_source"`
	APIKey             string `json:"api_key,omitempty"`
	AgentID            string `json:"agent_id,omitempty"`
	Alias              string `json:"alias,omitempty"`
	NamespaceSlug      string `json:"namespace_slug,omitempty"`
}

// VerifyCode submits a verification code for email ownership.
func (c *Client) VerifyCode(ctx context.Context, req *VerifyCodeRequest) (*VerifyCodeResponse, error) {
	var out VerifyCodeResponse
	if err := c.post(ctx, "/v1/auth/verify-code", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
