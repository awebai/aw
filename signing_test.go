package aweb

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	// Signature should be valid base64 no-padding.
	if _, err := base64.RawStdEncoding.DecodeString(sig); err != nil {
		t.Fatalf("signature is not valid base64 no-padding: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
}

func TestSignVerifyWithStableIDs(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:         "mycompany/researcher",
		FromDID:      did,
		To:           "otherco/monitor",
		ToDID:        "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:         "mail",
		Subject:      "task complete",
		Body:         "results attached",
		Timestamp:    "2026-02-21T15:30:00Z",
		FromStableID: "did:claw:Qm9iJ3x",
		ToStableID:   "did:claw:Qm9iJ3y",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did
	env.Body = "tampered body"

	status, _ := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("status=%q, want %q", status, Failed)
	}
}

func TestVerifyMissingDID(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Unverified {
		t.Fatalf("status=%q, want %q", status, Unverified)
	}
}

func TestVerifyMissingSignature(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Unverified {
		t.Fatalf("status=%q, want %q", status, Unverified)
	}
}

func TestVerifyBadDIDFormat(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "not-a-did",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
		Signature: "AAAA",
	}

	status, err := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("status=%q, want %q", status, Failed)
	}
	if err == nil {
		t.Fatal("expected error for bad DID format")
	}
}

func TestVerifySigningKeyIDMismatch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP" // different DID

	status, err := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("status=%q, want %q", status, Failed)
	}
	if err == nil {
		t.Fatal("expected error for signing_key_id mismatch")
	}
}

func TestCanonicalJSONFieldOrder(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "did:key:z6MkhaXgBZD...",
		To:        "otherco/monitor",
		ToDID:     "did:key:z6MkrT4Jxd...",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	got := canonicalJSON(env)
	want := `{"body":"results attached","from":"mycompany/researcher","from_did":"did:key:z6MkhaXgBZD...","subject":"task complete","timestamp":"2026-02-21T15:30:00Z","to":"otherco/monitor","to_did":"did:key:z6MkrT4Jxd...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONWithStableIDs(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:         "a/b",
		FromDID:      "did:key:z6Mk...",
		To:           "c/d",
		ToDID:        "did:key:z6Mr...",
		Type:         "chat",
		Subject:      "",
		Body:         "hi",
		Timestamp:    "2026-01-01T00:00:00Z",
		FromStableID: "did:claw:abc",
		ToStableID:   "did:claw:def",
	}

	got := canonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","from_stable_id":"did:claw:abc","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","to_stable_id":"did:claw:def","type":"chat"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestSignVerifyWithMessageID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
		MessageID: "550e8400-e29b-41d4-a716-446655440000",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}

	// Tampering with message_id should break verification.
	env.MessageID = "tampered-id"
	status, _ = VerifyMessage(env)
	if status != Failed {
		t.Fatalf("tampered message_id: status=%q, want %q", status, Failed)
	}
}

func TestCanonicalJSONWithMessageID(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z6Mk...",
		To:        "c/d",
		ToDID:     "did:key:z6Mr...",
		Type:      "mail",
		Subject:   "",
		Body:      "hi",
		Timestamp: "2026-01-01T00:00:00Z",
		MessageID: "test-uuid-1234",
	}

	got := canonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","message_id":"test-uuid-1234","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONWithoutMessageID(t *testing.T) {
	t.Parallel()

	// Existing messages without message_id should produce unchanged canonical JSON.
	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z6Mk...",
		To:        "c/d",
		ToDID:     "did:key:z6Mr...",
		Type:      "mail",
		Subject:   "",
		Body:      "hi",
		Timestamp: "2026-01-01T00:00:00Z",
	}

	got := canonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONEscaping(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z",
		To:        "c/d",
		ToDID:     "did:key:y",
		Type:      "mail",
		Subject:   "",
		Body:      "hello \"world\"\nline2",
		Timestamp: "2026-01-01T00:00:00Z",
	}

	got := canonicalJSON(env)
	want := `{"body":"hello \"world\"\nline2","from":"a/b","from_did":"did:key:z","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:y","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}
