package aweb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// signedFields holds the identity fields attached to outgoing messages
// when the client has a signing key.
type signedFields struct {
	FromDID      string
	ToDID        string
	Signature    string
	SigningKeyID string
	Timestamp    string
	MessageID    string
}

// signEnvelope signs a MessageEnvelope and returns the fields to embed
// in the request. When the client has no signing key (legacy/custodial),
// returns a zero signedFields. Callers stamp the returned fields onto
// the request struct before posting.
func (c *Client) signEnvelope(ctx context.Context, env *MessageEnvelope) (signedFields, error) {
	if c.signingKey == nil {
		return signedFields{}, nil
	}
	env.From = c.address
	env.FromDID = c.did
	env.Timestamp = time.Now().UTC().Format(time.RFC3339)
	msgID, err := generateUUID4()
	if err != nil {
		return signedFields{}, err
	}
	env.MessageID = msgID

	// Resolve recipient DID for to_did binding (mail only).
	if c.resolver != nil && env.To != "" && env.ToDID == "" {
		if identity, err := c.resolver.Resolve(ctx, env.To); err == nil && identity.DID != "" {
			env.ToDID = identity.DID
		}
	}

	sig, err := SignMessage(c.signingKey, env)
	if err != nil {
		return signedFields{}, fmt.Errorf("sign message: %w", err)
	}
	return signedFields{
		FromDID:      c.did,
		ToDID:        env.ToDID,
		Signature:    sig,
		SigningKeyID: c.did,
		Timestamp:    env.Timestamp,
		MessageID:    env.MessageID,
	}, nil
}

const (
	// DefaultTimeout is the default HTTP timeout used by the client.
	DefaultTimeout = 10 * time.Second

	maxResponseSize = 10 * 1024 * 1024
)

// Client is an aweb HTTP client.
//
// It is designed to be easy to extract into a standalone repo and to be used by:
// - the `aw` CLI
// - the `bdh` CLI for `:mail/:chat/:lock` delegation
type Client struct {
	baseURL    string
	httpClient *http.Client
	sseClient  *http.Client // No response timeout; SSE connections are long-lived.
	apiKey     string
	signingKey ed25519.PrivateKey // nil for legacy/custodial
	did        string            // empty for legacy/custodial
	address      string            // namespace/alias, used in signed envelopes
	resolver     IdentityResolver  // optional; resolves recipient DID for to_did binding
	pinStore     *PinStore         // optional; TOFU pin store for sender identity verification
	pinStorePath string            // disk path for persisting pin store
}

// New creates a new client.
func New(baseURL string) (*Client, error) {
	if _, err := url.Parse(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		sseClient: &http.Client{},
	}, nil
}

// NewWithAPIKey creates a new client authenticated with a project API key.
// The client operates in legacy/custodial mode (no signing).
func NewWithAPIKey(baseURL, apiKey string) (*Client, error) {
	c, err := New(baseURL)
	if err != nil {
		return nil, err
	}
	c.apiKey = apiKey
	return c, nil
}

// NewWithIdentity creates an authenticated client with signing capability.
func NewWithIdentity(baseURL, apiKey string, signingKey ed25519.PrivateKey, did string) (*Client, error) {
	if signingKey == nil {
		return nil, fmt.Errorf("signingKey must not be nil")
	}
	if did == "" {
		return nil, fmt.Errorf("did must not be empty")
	}
	expected := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if did != expected {
		return nil, fmt.Errorf("did does not match signingKey")
	}
	c, err := NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		return nil, err
	}
	c.signingKey = signingKey
	c.did = did
	return c, nil
}

// SigningKey returns the client's signing key, or nil for legacy/custodial clients.
func (c *Client) SigningKey() ed25519.PrivateKey { return c.signingKey }

// DID returns the client's DID, or empty for legacy/custodial clients.
func (c *Client) DID() string { return c.did }

// SetAddress sets the client's agent address (namespace/alias) for use in
// signed message envelopes.
func (c *Client) SetAddress(address string) { c.address = address }

// SetResolver sets the identity resolver used to resolve recipient DIDs
// for to_did binding in signed envelopes.
func (c *Client) SetResolver(r IdentityResolver) { c.resolver = r }

// SetPinStore sets the TOFU pin store for sender identity verification.
// If path is non-empty, the store is persisted to disk after updates.
func (c *Client) SetPinStore(ps *PinStore, path string) {
	c.pinStore = ps
	c.pinStorePath = path
}

// CheckTOFUPin checks a verified message against the TOFU pin store.
// On first contact, creates a pin. On subsequent contact with matching DID,
// updates last_seen. On DID mismatch, returns IdentityMismatch.
// Returns the status unchanged if no pin store is set, the message is not
// verified, or from_did/from_alias is empty.
func (c *Client) CheckTOFUPin(status VerificationStatus, fromAlias, fromDID string) VerificationStatus {
	if c.pinStore == nil || (status != Verified && status != VerifiedCustodial) || fromDID == "" || fromAlias == "" {
		return status
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()

	result := c.pinStore.CheckPin(fromAlias, fromDID, LifetimePersistent)
	switch result {
	case PinNew:
		c.pinStore.StorePin(fromDID, fromAlias, "", "")
		c.savePinStore()
	case PinOK:
		c.pinStore.StorePin(fromDID, fromAlias, "", "")
		c.savePinStore()
	case PinMismatch:
		return IdentityMismatch
	case PinSkipped:
		// Ephemeral agent — no pin check.
	}
	return status
}

func (c *Client) savePinStore() {
	if c.pinStorePath != "" {
		// Best effort: atomic write via temp+rename. A failed save means
		// the next process loads a stale store and may re-pin.
		_ = c.pinStore.Save(c.pinStorePath)
	}
}

// checkRecipientBinding downgrades a Verified status to IdentityMismatch
// if the message's to_did doesn't match the client's own DID.
// Returns the status unchanged if to_did is empty, the client has no DID,
// or the DIDs match.
func (c *Client) checkRecipientBinding(status VerificationStatus, toDID string) VerificationStatus {
	if status != Verified || toDID == "" || c.did == "" {
		return status
	}
	if toDID != c.did {
		return IdentityMismatch
	}
	return status
}

type apiError struct {
	StatusCode int
	Body       string
}

func (e *apiError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("aweb: http %d", e.StatusCode)
	}
	return fmt.Sprintf("aweb: http %d: %s", e.StatusCode, e.Body)
}

// HTTPStatusCode returns the HTTP status code for API errors.
func HTTPStatusCode(err error) (int, bool) {
	var e *apiError
	if !errors.As(err, &e) {
		return 0, false
	}
	return e.StatusCode, true
}

// HTTPErrorBody returns the response body for API errors.
func HTTPErrorBody(err error) (string, bool) {
	var e *apiError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Body, true
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, in any, out any) error {
	return c.do(ctx, http.MethodPost, path, in, out)
}

func (c *Client) patch(ctx context.Context, path string, in any, out any) error {
	return c.do(ctx, http.MethodPatch, path, in, out)
}

func (c *Client) put(ctx context.Context, path string, in any, out any) error {
	return c.do(ctx, http.MethodPut, path, in, out)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	resp, err := c.doRaw(ctx, method, path, "application/json", in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path, accept string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", accept)
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
