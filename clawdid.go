package aweb

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// LogEntry represents a ClawDID audit log entry.
type LogEntry struct {
	AuthorizedBy   string
	DIDClaw        string
	NewDIDKey      string
	Operation      string
	PrevEntryHash  *string // nil for seq=1
	PreviousDIDKey *string // nil for create
	Seq            int
	StateHash      string
	Timestamp      string
}

// CanonicalJSON returns the canonical JSON representation of a log entry
// for hashing and signature verification. Fields are sorted lexicographically,
// compact separators, null values rendered as JSON null.
// Unlike MessageEnvelope's CanonicalJSON, all fields are always present (nullable ones emit null).
func (e *LogEntry) CanonicalJSON() string {
	type field struct {
		key string
		val string // pre-formatted JSON value (including quotes for strings)
	}

	jsonStr := func(s string) string {
		var b strings.Builder
		b.WriteByte('"')
		writeEscapedString(&b, s)
		b.WriteByte('"')
		return b.String()
	}
	jsonNullableStr := func(s *string) string {
		if s == nil {
			return "null"
		}
		return jsonStr(*s)
	}

	fields := []field{
		{"authorized_by", jsonStr(e.AuthorizedBy)},
		{"did_claw", jsonStr(e.DIDClaw)},
		{"new_did_key", jsonStr(e.NewDIDKey)},
		{"operation", jsonStr(e.Operation)},
		{"prev_entry_hash", jsonNullableStr(e.PrevEntryHash)},
		{"previous_did_key", jsonNullableStr(e.PreviousDIDKey)},
		{"seq", strconv.Itoa(e.Seq)},
		{"state_hash", jsonStr(e.StateHash)},
		{"timestamp", jsonStr(e.Timestamp)},
	}

	// Fields are already in lexicographic order.
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(f.key)
		b.WriteString(`":`)
		b.WriteString(f.val)
	}
	b.WriteByte('}')
	return b.String()
}

// VerifyLogEntrySignature verifies an Ed25519 signature over canonical log entry bytes.
// The signature is base64 (RFC 4648, no padding).
func VerifyLogEntrySignature(pub ed25519.PublicKey, signatureB64, canonicalPayload string) (bool, error) {
	sig, err := base64.RawStdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("decode log entry signature: %w", err)
	}
	return ed25519.Verify(pub, []byte(canonicalPayload), sig), nil
}

// --- ClawDID /key verifier ---

// ClawDIDVerificationStatus is the result of verifying a ClawDID /key response.
type ClawDIDVerificationStatus string

const (
	ClawDIDVerified  ClawDIDVerificationStatus = "ok_verified"
	ClawDIDDegraded  ClawDIDVerificationStatus = "ok_degraded"
	ClawDIDHardError ClawDIDVerificationStatus = "hard_error"
)

// ClawDIDVerificationResult holds the outcome of verifying a ClawDID /key response.
type ClawDIDVerificationResult struct {
	Status ClawDIDVerificationStatus
	Reason string
}

// ClawDIDKeyResponse is the wire format of GET /v1/did/{did_claw}/key.
type ClawDIDKeyResponse struct {
	DIDClaw       string          `json:"did_claw"`
	CurrentDIDKey string          `json:"current_did_key"`
	LogHead       *ClawDIDLogHead `json:"log_head"`
}

// ClawDIDLogHead is the log_head portion of the /key response.
type ClawDIDLogHead struct {
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	EntryHash      string  `json:"entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Signature      string  `json:"signature"`
	Timestamp      string  `json:"timestamp"`
}

// ClawDIDCache holds cached state for monotonicity checks across verifications.
type ClawDIDCache struct {
	Seq       int    `json:"seq" yaml:"seq"`
	EntryHash string `json:"entry_hash" yaml:"entry_hash"`
}

// VerifyClawDIDKeyResponse verifies a ClawDID /key response against its claimed
// did_claw and an optional local cache for monotonicity.
// Updates the cache on successful verification.
func VerifyClawDIDKeyResponse(didClaw string, resp *ClawDIDKeyResponse, cache *ClawDIDCache) ClawDIDVerificationResult {
	// 1. did_claw must match.
	if resp.DIDClaw != didClaw {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: fmt.Sprintf("did_claw mismatch: expected %s, got %s", didClaw, resp.DIDClaw),
		}
	}

	// 2. log_head missing → degraded.
	if resp.LogHead == nil {
		return ClawDIDVerificationResult{
			Status: ClawDIDDegraded,
			Reason: "log_head missing",
		}
	}

	head := resp.LogHead

	// 3. new_did_key must match current_did_key.
	if head.NewDIDKey != resp.CurrentDIDKey {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: fmt.Sprintf("new_did_key %s != current_did_key %s", head.NewDIDKey, resp.CurrentDIDKey),
		}
	}

	// 4. Reconstruct canonical payload and verify entry_hash.
	entry := LogEntry{
		AuthorizedBy:   head.AuthorizedBy,
		DIDClaw:        resp.DIDClaw,
		NewDIDKey:      head.NewDIDKey,
		Operation:      head.Operation,
		PrevEntryHash:  head.PrevEntryHash,
		PreviousDIDKey: head.PreviousDIDKey,
		Seq:            head.Seq,
		StateHash:      head.StateHash,
		Timestamp:      head.Timestamp,
	}
	canonical := entry.CanonicalJSON()
	hash := sha256.Sum256([]byte(canonical))
	computedHash := hex.EncodeToString(hash[:])
	if computedHash != head.EntryHash {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: fmt.Sprintf("entry_hash mismatch: computed %s, got %s", computedHash, head.EntryHash),
		}
	}

	// 5. Verify signature against authorized_by key.
	pub, err := ExtractPublicKey(head.AuthorizedBy)
	if err != nil {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: fmt.Sprintf("invalid authorized_by: %v", err),
		}
	}
	ok, err := VerifyLogEntrySignature(pub, head.Signature, canonical)
	if err != nil {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: fmt.Sprintf("signature decode: %v", err),
		}
	}
	if !ok {
		return ClawDIDVerificationResult{
			Status: ClawDIDHardError,
			Reason: "signature verification failed",
		}
	}

	// 6. Cache monotonicity checks.
	if cache != nil && cache.Seq > 0 {
		if head.Seq < cache.Seq {
			return ClawDIDVerificationResult{
				Status: ClawDIDHardError,
				Reason: fmt.Sprintf("seq regression: cached %d, got %d", cache.Seq, head.Seq),
			}
		}
		if head.Seq == cache.Seq && head.EntryHash != cache.EntryHash {
			return ClawDIDVerificationResult{
				Status: ClawDIDHardError,
				Reason: "split view: same seq, different entry_hash",
			}
		}
		if head.Seq == cache.Seq+1 {
			if head.PrevEntryHash == nil || *head.PrevEntryHash != cache.EntryHash {
				return ClawDIDVerificationResult{
					Status: ClawDIDHardError,
					Reason: "chain break: prev_entry_hash does not match cached entry_hash",
				}
			}
		}
		if head.Seq > cache.Seq+1 {
			oldSeq := cache.Seq
			// Update cache even though degraded — we verified the entry itself.
			cache.Seq = head.Seq
			cache.EntryHash = head.EntryHash
			return ClawDIDVerificationResult{
				Status: ClawDIDDegraded,
				Reason: fmt.Sprintf("seq gap: cached %d, got %d; fetch /log to resync", oldSeq, head.Seq),
			}
		}
	}

	// Update cache.
	if cache != nil {
		cache.Seq = head.Seq
		cache.EntryHash = head.EntryHash
	}

	return ClawDIDVerificationResult{Status: ClawDIDVerified}
}

// --- ClawDID HTTP client ---

// ClawDIDClient fetches key information from a ClawDID registry.
type ClawDIDClient struct {
	RegistryURL string // e.g. "https://api.clawdid.ai"
	HTTPClient  *http.Client
}

// FetchKey calls GET /v1/did/{did_claw}/key on the registry.
func (c *ClawDIDClient) FetchKey(ctx context.Context, didClaw string) (*ClawDIDKeyResponse, error) {
	if !strings.HasPrefix(didClaw, "did:claw:") && !strings.HasPrefix(didClaw, "did:aw:") {
		return nil, fmt.Errorf("clawdid: invalid did: %q", didClaw)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	url := c.RegistryURL + "/v1/did/" + didClaw + "/key"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("clawdid: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clawdid: fetch key: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("clawdid: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clawdid: http %d: %s", resp.StatusCode, string(body))
	}

	var result ClawDIDKeyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("clawdid: decode response: %w", err)
	}
	return &result, nil
}
