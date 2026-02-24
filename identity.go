package aweb

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// AgentIdentity holds resolved identity information for an agent.
type AgentIdentity struct {
	DID         string
	AgentID     string // server-assigned UUID
	Address     string // namespace/alias
	Handle      string // @alice
	PublicKey   ed25519.PublicKey
	ServerURL   string
	Custody     string // "self" or "custodial"
	Lifetime    string // "persistent" or "ephemeral"
	ResolvedAt  time.Time
	ResolvedVia string // "did:key", "server", "clawdid", "pin"
}

// IdentityResolver resolves an identifier to an AgentIdentity.
type IdentityResolver interface {
	Resolve(ctx context.Context, identifier string) (*AgentIdentity, error)
}

// DIDKeyResolver extracts the public key from a did:key string.
// No network call required.
type DIDKeyResolver struct{}

func (r *DIDKeyResolver) Resolve(_ context.Context, identifier string) (*AgentIdentity, error) {
	pub, err := ExtractPublicKey(identifier)
	if err != nil {
		return nil, fmt.Errorf("DIDKeyResolver: %w", err)
	}
	return &AgentIdentity{
		DID:         identifier,
		PublicKey:   pub,
		ResolvedAt:  time.Now().UTC(),
		ResolvedVia: "did:key",
	}, nil
}

// serverResolveResponse is the wire format returned by
// GET /v1/agents/resolve/{namespace}/{alias}.
type serverResolveResponse struct {
	DID       string `json:"did"`
	AgentID   string `json:"agent_id"`
	Address   string `json:"address"`
	HumanName string `json:"human_name"`
	Handle    string `json:"handle"`
	Server    string `json:"server"`
	Custody   string `json:"custody"`
	Lifetime  string `json:"lifetime"`
	Status    string `json:"status"`
}

// ServerResolver resolves an agent address via the aweb server.
type ServerResolver struct {
	Client *Client
}

func (r *ServerResolver) Resolve(ctx context.Context, identifier string) (*AgentIdentity, error) {
	var resp serverResolveResponse
	path := "/v1/agents/resolve/" + identifier
	if err := r.Client.get(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("ServerResolver: %w", err)
	}
	return &AgentIdentity{
		DID:         resp.DID,
		AgentID:     resp.AgentID,
		Address:     resp.Address,
		Handle:      resp.Handle,
		ServerURL:   resp.Server,
		Custody:     resp.Custody,
		Lifetime:    resp.Lifetime,
		ResolvedAt:  time.Now().UTC(),
		ResolvedVia: "server",
	}, nil
}

// PinResolver looks up identity from the local TOFU pin store.
type PinResolver struct {
	Store *PinStore
}

func (r *PinResolver) Resolve(_ context.Context, identifier string) (*AgentIdentity, error) {
	// Try direct DID lookup.
	if pin, ok := r.Store.Pins[identifier]; ok {
		return &AgentIdentity{
			DID:         identifier,
			Address:     pin.Address,
			Handle:      pin.Handle,
			ServerURL:   pin.Server,
			ResolvedAt:  time.Now().UTC(),
			ResolvedVia: "pin",
		}, nil
	}
	// Try reverse lookup by address.
	if did, ok := r.Store.Addresses[identifier]; ok {
		pin, exists := r.Store.Pins[did]
		if !exists {
			return nil, fmt.Errorf("PinResolver: address %q maps to DID %q not in pins", identifier, did)
		}
		return &AgentIdentity{
			DID:         did,
			Address:     pin.Address,
			Handle:      pin.Handle,
			ServerURL:   pin.Server,
			ResolvedAt:  time.Now().UTC(),
			ResolvedVia: "pin",
		}, nil
	}
	return nil, fmt.Errorf("PinResolver: no pin for %q", identifier)
}

// ClaimIdentityRequest is sent to PUT /v1/agents/me/identity.
// This endpoint lets an agent bind a did:key to itself (one-time claim).
type ClaimIdentityRequest struct {
	DID       string `json:"did"`
	PublicKey string `json:"public_key"`
	Custody   string `json:"custody"`
	Lifetime  string `json:"lifetime"`
}

// ClaimIdentityResponse is returned by PUT /v1/agents/me/identity.
type ClaimIdentityResponse struct {
	Status  string `json:"status"`
	DID     string `json:"did"`
	Custody string `json:"custody"`
}

// ClaimIdentity binds a did:key + public key to the agent identified by the
// client's API key. The server returns 409 if the agent already has an identity.
func (c *Client) ClaimIdentity(ctx context.Context, req *ClaimIdentityRequest) (*ClaimIdentityResponse, error) {
	var out ClaimIdentityResponse
	if err := c.put(ctx, "/v1/agents/me/identity", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChainResolver dispatches resolution by identifier format.
// did:key identifiers use DIDKeyResolver; addresses use ServerResolver.
// After server resolution, the public key is cross-checked by extracting
// it from the server-reported DID.
type ChainResolver struct {
	DIDKey *DIDKeyResolver
	Server *ServerResolver
	Pin    *PinResolver
	// ClaWDID is a nil-safe Phase 2 slot.
	ClaWDID IdentityResolver
}

func (r *ChainResolver) Resolve(ctx context.Context, identifier string) (*AgentIdentity, error) {
	if strings.HasPrefix(identifier, didKeyPrefix) {
		identity, err := r.DIDKey.Resolve(ctx, identifier)
		if err != nil {
			return nil, err
		}
		// Supplement with pin metadata if available.
		if r.Pin != nil {
			if pinIdentity, pinErr := r.Pin.Resolve(ctx, identifier); pinErr == nil {
				identity.Address = pinIdentity.Address
				identity.Handle = pinIdentity.Handle
				identity.ServerURL = pinIdentity.ServerURL
			}
		}
		return identity, nil
	}

	// Address-based resolution: use server, then cross-check DID.
	if r.Server == nil {
		return nil, fmt.Errorf("ChainResolver: no server resolver for address %q", identifier)
	}
	identity, err := r.Server.Resolve(ctx, identifier)
	if err != nil {
		return nil, err
	}
	// Cross-check: extract public key from server-reported DID.
	if identity.DID != "" {
		pub, err := ExtractPublicKey(identity.DID)
		if err != nil {
			return nil, fmt.Errorf("ChainResolver: server-reported DID invalid: %w", err)
		}
		identity.PublicKey = pub
	}
	return identity, nil
}
