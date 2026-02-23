package aweb

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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
