package aweb

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

type VerificationStatus string

const (
	Verified          VerificationStatus = "verified"
	VerifiedCustodial VerificationStatus = "verified_custodial"
	Unverified        VerificationStatus = "unverified"
	Failed            VerificationStatus = "failed"
	IdentityMismatch  VerificationStatus = "identity_mismatch"
)

// RotationAnnouncement is attached to messages after key rotation.
// The old key signs the transition to the new key.
type RotationAnnouncement struct {
	OldDID          string `json:"old_did"`
	NewDID          string `json:"new_did"`
	Timestamp       string `json:"timestamp"`
	OldKeySignature string `json:"old_key_signature"`
}

// MessageEnvelope holds the fields used for signing and verification.
// Transport-only fields (Signature, SigningKeyID) are not part of the
// signed payload but are carried here for convenience.
type MessageEnvelope struct {
	From         string `json:"from"`
	FromDID      string `json:"from_did"`
	To           string `json:"to"`
	ToDID        string `json:"to_did"`
	Type         string `json:"type"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Timestamp    string `json:"timestamp"`
	FromStableID string `json:"from_stable_id,omitempty"`
	ToStableID   string `json:"to_stable_id,omitempty"`
	MessageID    string `json:"message_id,omitempty"`

	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
}

// SignMessage signs the canonical JSON payload of an envelope.
// Returns the signature as base64 (RFC 4648, no padding).
func SignMessage(key ed25519.PrivateKey, env *MessageEnvelope) (string, error) {
	payload := canonicalJSON(env)
	sig := ed25519.Sign(key, []byte(payload))
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

// VerifyMessage checks the signature on a message envelope.
// Returns Unverified if DID or signature is missing (legacy message).
// Returns Failed if the DID is malformed, the signature doesn't verify,
// or SigningKeyID disagrees with FromDID.
// Returns Verified if the signature is valid.
// Does not check TOFU pins or custody — callers handle those.
func VerifyMessage(env *MessageEnvelope) (VerificationStatus, error) {
	if env.FromDID == "" || env.Signature == "" {
		return Unverified, nil
	}

	// If SigningKeyID is present, it must match FromDID.
	if env.SigningKeyID != "" && env.SigningKeyID != env.FromDID {
		return Failed, fmt.Errorf("signing_key_id %q does not match from_did %q", env.SigningKeyID, env.FromDID)
	}

	// SOT §7 step 2: invalid did:key format → Unverified (not a did:key identity).
	// SOT §7 step 3: valid prefix but decode failure → Failed (malformed identity).
	if !strings.HasPrefix(env.FromDID, "did:key:z") {
		return Unverified, nil
	}
	pub, err := ExtractPublicKey(env.FromDID)
	if err != nil {
		return Failed, fmt.Errorf("extract public key from from_did: %w", err)
	}

	sig, err := base64.RawStdEncoding.DecodeString(env.Signature)
	if err != nil {
		return Failed, fmt.Errorf("decode signature: %w", err)
	}

	payload := canonicalJSON(env)
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return Failed, nil
	}

	return Verified, nil
}

// canonicalJSON builds the canonical JSON payload for signing.
// Fields are sorted lexicographically, no whitespace, minimal escaping.
// This is a subset of RFC 8785 (JSON Canonicalization Scheme).
func canonicalJSON(env *MessageEnvelope) string {
	type field struct {
		key   string
		value string
	}

	// Always-present signed fields.
	fields := []field{
		{"body", env.Body},
		{"from", env.From},
		{"from_did", env.FromDID},
		{"subject", env.Subject},
		{"timestamp", env.Timestamp},
		{"to", env.To},
		{"to_did", env.ToDID},
		{"type", env.Type},
	}

	// Optional fields included when present.
	if env.FromStableID != "" {
		fields = append(fields, field{"from_stable_id", env.FromStableID})
	}
	if env.MessageID != "" {
		fields = append(fields, field{"message_id", env.MessageID})
	}
	if env.ToStableID != "" {
		fields = append(fields, field{"to_stable_id", env.ToStableID})
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
		writeEscapedString(&b, f.value)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// writeEscapedString writes a JSON-escaped string value (without surrounding quotes).
func writeEscapedString(b *strings.Builder, s string) {
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
}
