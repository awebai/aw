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

// RotateKeyRequest is the input to Client.RotateKey.
type RotateKeyRequest struct {
	NewDID       string            // did:key of the new key
	NewPublicKey ed25519.PublicKey  // raw new public key
	Custody      string            // "self" or "custodial"
}

// rotateKeyWireRequest is the wire format sent to PUT /v1/agents/me/rotate.
type rotateKeyWireRequest struct {
	NewDID            string `json:"new_did"`
	NewPublicKey      string `json:"new_public_key"`
	Custody           string `json:"custody"`
	RotationSignature string `json:"rotation_signature"`
	Timestamp         string `json:"timestamp"`
}

// RotateKeyResponse is returned by PUT /v1/agents/me/rotate.
type RotateKeyResponse struct {
	OldDID    string `json:"old_did"`
	NewDID    string `json:"new_did"`
	RotatedAt string `json:"rotated_at"`
}

// RotateKey sends a key rotation request to the server.
// The client must have been created with NewWithIdentity (has a signing key).
// The rotation_signature is computed by signing the canonical rotation payload
// with the current (old) key.
func (c *Client) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	if c.signingKey == nil {
		return nil, fmt.Errorf("RotateKey: client has no signing key")
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// Sign the rotation payload with the old (current) key.
	payload := canonicalRotationJSON(c.did, req.NewDID, ts)
	sig := ed25519.Sign(c.signingKey, []byte(payload))

	wire := &rotateKeyWireRequest{
		NewDID:            req.NewDID,
		NewPublicKey:      base64.RawStdEncoding.EncodeToString(req.NewPublicKey),
		Custody:           req.Custody,
		RotationSignature: base64.RawStdEncoding.EncodeToString(sig),
		Timestamp:         ts,
	}

	var resp RotateKeyResponse
	if err := c.put(ctx, "/v1/agents/me/rotate", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// canonicalRotationJSON builds the canonical JSON for rotation signing.
// Fields: new_did, old_did, timestamp — sorted lexicographically.
func canonicalRotationJSON(oldDID, newDID, timestamp string) string {
	type field struct {
		key   string
		value string
	}
	fields := []field{
		{"new_did", newDID},
		{"old_did", oldDID},
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
		b.WriteString(f.value) // DIDs and timestamps need no escaping
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// RotateKeyCustodialRequest is the input to Client.RotateKeyCustodial.
// Used for custodial-to-self graduation where the server holds the old key.
type RotateKeyCustodialRequest struct {
	NewDID       string           // did:key of the new key
	NewPublicKey ed25519.PublicKey // raw new public key
	Custody      string           // "self"
}

// rotateKeyCustodialWireRequest is the wire format for custodial graduation.
// No rotation_signature — the server signs on behalf.
type rotateKeyCustodialWireRequest struct {
	NewDID       string `json:"new_did"`
	NewPublicKey string `json:"new_public_key"`
	Custody      string `json:"custody"`
}

// RotateKeyCustodial sends a custodial-to-self rotation request.
// The server holds the old key and signs the rotation on behalf.
func (c *Client) RotateKeyCustodial(ctx context.Context, req *RotateKeyCustodialRequest) (*RotateKeyResponse, error) {
	wire := &rotateKeyCustodialWireRequest{
		NewDID:       req.NewDID,
		NewPublicKey: base64.RawStdEncoding.EncodeToString(req.NewPublicKey),
		Custody:      req.Custody,
	}
	var resp RotateKeyResponse
	if err := c.put(ctx, "/v1/agents/me/rotate", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyRotationSignature verifies a rotation_signature using the old public key.
func VerifyRotationSignature(oldPub ed25519.PublicKey, oldDID, newDID, timestamp, signature string) (bool, error) {
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("decode rotation signature: %w", err)
	}
	payload := canonicalRotationJSON(oldDID, newDID, timestamp)
	return ed25519.Verify(oldPub, []byte(payload), sig), nil
}
