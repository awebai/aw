package aweb

import (
	"context"
	"encoding/json"
)

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
	DID       string  `json:"did,omitempty"`
	PublicKey string  `json:"public_key,omitempty"`
	Custody   string  `json:"custody,omitempty"`
	Lifetime  string  `json:"lifetime,omitempty"`
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
	DID                  string `json:"did,omitempty"`
	Custody              string `json:"custody,omitempty"`
	Lifetime             string `json:"lifetime,omitempty"`
}

// ExistingAccountInfo is returned in a structured 409 body when the email
// is already registered. The server sends a verification code and lists
// the user's namespaces so the CLI can proceed with an existing account.
type ExistingAccountInfo struct {
	ExistingAccount      bool        `json:"existing_account"`
	VerificationRequired bool        `json:"verification_required"`
	Email                string      `json:"email"`
	Handle               string      `json:"handle"`
	Namespaces           []Namespace `json:"namespaces"`
}

// ParseExistingAccount attempts to parse an ExistingAccountInfo from an HTTP
// error body. Returns nil if the error is not a 409 with existing_account: true.
func ParseExistingAccount(err error) *ExistingAccountInfo {
	code, ok := HTTPStatusCode(err)
	if !ok || code != 409 {
		return nil
	}
	body, ok := HTTPErrorBody(err)
	if !ok {
		return nil
	}
	var info ExistingAccountInfo
	if json.Unmarshal([]byte(body), &info) != nil || !info.ExistingAccount {
		return nil
	}
	return &info
}

// Register creates a new account on the server.
func (c *Client) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	var out RegisterResponse
	if err := c.post(ctx, "/v1/auth/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
