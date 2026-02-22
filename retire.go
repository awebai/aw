package aweb

import (
	"context"
	"fmt"
)

// RetireAgentRequest is the input to Client.RetireAgent.
type RetireAgentRequest struct {
	SuccessorDID     string // did:key of the successor agent
	SuccessorAddress string // namespace/alias of the successor
}

// retireAgentWireRequest is the wire format sent to PUT /v1/agents/me/retire.
type retireAgentWireRequest struct {
	Status           string `json:"status"`
	SuccessorDID     string `json:"successor_did"`
	SuccessorAddress string `json:"successor_address"`
}

// RetireAgentResponse is returned by PUT /v1/agents/me/retire.
type RetireAgentResponse struct {
	DID              string `json:"did"`
	Status           string `json:"status"`
	SuccessorDID     string `json:"successor_did"`
	SuccessorAddress string `json:"successor_address"`
	RetiredAt        string `json:"retired_at"`
}

// RetireAgent sends a retirement request to the server.
// The client must have been created with NewWithIdentity (has a signing key).
func (c *Client) RetireAgent(ctx context.Context, req *RetireAgentRequest) (*RetireAgentResponse, error) {
	if c.signingKey == nil {
		return nil, fmt.Errorf("RetireAgent: client has no signing key")
	}

	wire := &retireAgentWireRequest{
		Status:           "retired",
		SuccessorDID:     req.SuccessorDID,
		SuccessorAddress: req.SuccessorAddress,
	}

	var resp RetireAgentResponse
	if err := c.put(ctx, "/v1/agents/me/retire", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
