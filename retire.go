package aweb

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RetireAgentRequest is the input to Client.RetireAgent.
type RetireAgentRequest struct {
	SuccessorAgentID string // UUID of the successor agent
	SuccessorDID     string // did:key of the successor (used in retirement proof)
	SuccessorAddress string // namespace/alias of the successor (used in retirement proof)
}

// retireAgentWireRequest is the wire format sent to PUT /v1/agents/me/retire.
type retireAgentWireRequest struct {
	SuccessorAgentID string `json:"successor_agent_id"`
	Timestamp        string `json:"timestamp"`
	RetirementProof  string `json:"retirement_proof"`
}

// RetireAgentResponse is returned by PUT /v1/agents/me/retire.
type RetireAgentResponse struct {
	Status           string `json:"status"`
	AgentID          string `json:"agent_id"`
	SuccessorAgentID string `json:"successor_agent_id"`
}

// RetireAgent sends a retirement request to the server.
// For self-custodial agents, a retirement_proof is computed by signing the
// canonical retirement payload with the current signing key.
func (c *Client) RetireAgent(ctx context.Context, req *RetireAgentRequest) (*RetireAgentResponse, error) {
	if c.signingKey == nil {
		return nil, fmt.Errorf("RetireAgent: client has no signing key")
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// Sign the retirement payload with the current key.
	payload := canonicalRetirementJSON(req.SuccessorAddress, req.SuccessorDID, ts)
	sig := ed25519.Sign(c.signingKey, []byte(payload))

	wire := &retireAgentWireRequest{
		SuccessorAgentID: req.SuccessorAgentID,
		Timestamp:        ts,
		RetirementProof:  base64.RawStdEncoding.EncodeToString(sig),
	}

	var resp RetireAgentResponse
	if err := c.put(ctx, "/v1/agents/me/retire", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// canonicalRetirementJSON builds the canonical JSON for retirement proof signing.
// Fields: operation, successor_address, successor_did, timestamp — sorted lexicographically.
func canonicalRetirementJSON(successorAddress, successorDID, timestamp string) string {
	type field struct {
		key   string
		value string
	}
	fields := []field{
		{"operation", "retire"},
		{"successor_address", successorAddress},
		{"successor_did", successorDID},
		{"timestamp", timestamp},
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].key < fields[j].key })

	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(f.key)
		b.WriteString(`":"`)
		b.WriteString(f.value) // addresses, DIDs, and timestamps need no escaping
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
