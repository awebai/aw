package aweb

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// buildLogHead constructs a ClawDIDLogHead from the clawdid-log-v1.json test vector.
func buildLogHead(t *testing.T) (ClawDIDKeyResponse, ed25519.PrivateKey) {
	t.Helper()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	key := ed25519.NewKeyFromSeed(seed)
	didKey := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	didClaw := ComputeStableID(key.Public().(ed25519.PublicKey), "claw")

	entry := LogEntry{
		AuthorizedBy:   didKey,
		DIDClaw:        didClaw,
		NewDIDKey:      didKey,
		Operation:      "create",
		PrevEntryHash:  nil,
		PreviousDIDKey: nil,
		Seq:            1,
		StateHash:      "e941011beb6cdf3a27c20f98fdd86dc2c50dca8dd6b5ff55cd3240172279a0f6",
		Timestamp:      "2026-02-22T10:00:00Z",
	}
	canonical := entry.CanonicalJSON()
	hash := sha256.Sum256([]byte(canonical))
	entryHash := hex.EncodeToString(hash[:])
	sig := ed25519.Sign(key, []byte(canonical))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	return ClawDIDKeyResponse{
		DIDClaw:       didClaw,
		CurrentDIDKey: didKey,
		LogHead: &ClawDIDLogHead{
			Seq:            1,
			Operation:      "create",
			PreviousDIDKey: nil,
			NewDIDKey:      didKey,
			PrevEntryHash:  nil,
			EntryHash:      entryHash,
			StateHash:      "e941011beb6cdf3a27c20f98fdd86dc2c50dca8dd6b5ff55cd3240172279a0f6",
			AuthorizedBy:   didKey,
			Signature:      sigB64,
			Timestamp:      "2026-02-22T10:00:00Z",
		},
	}, key
}

func TestVerifyClawDIDKeyResponseHappyPath(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	cache := &ClawDIDCache{}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDVerified {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDVerified)
	}

	// Cache should be updated.
	if cache.Seq != 1 {
		t.Errorf("cache seq: got %d, want 1", cache.Seq)
	}
	if cache.EntryHash != resp.LogHead.EntryHash {
		t.Errorf("cache entry_hash mismatch")
	}
}

func TestVerifyClawDIDKeyResponseDIDClawMismatch(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	cache := &ClawDIDCache{}

	result := VerifyClawDIDKeyResponse("did:claw:WRONG", &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s, want %s", result.Status, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseNoLogHead(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	resp.LogHead = nil
	cache := &ClawDIDCache{}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDDegraded {
		t.Fatalf("got %s, want %s", result.Status, ClawDIDDegraded)
	}
}

func TestVerifyClawDIDKeyResponseNewKeyMismatch(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	resp.CurrentDIDKey = "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2"
	cache := &ClawDIDCache{}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseSeqRegression(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	cache := &ClawDIDCache{Seq: 5, EntryHash: "something"}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseSplitView(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	cache := &ClawDIDCache{Seq: 1, EntryHash: "different_hash"}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseSeqGap(t *testing.T) {
	t.Parallel()

	resp, key := buildLogHead(t)
	resp.LogHead.Seq = 3
	// Reconstruct entry to make signature valid (seq changed).
	entry := LogEntry{
		AuthorizedBy:   resp.LogHead.AuthorizedBy,
		DIDClaw:        resp.DIDClaw,
		NewDIDKey:      resp.LogHead.NewDIDKey,
		Operation:      "create",
		PrevEntryHash:  nil,
		PreviousDIDKey: nil,
		Seq:            3,
		StateHash:      resp.LogHead.StateHash,
		Timestamp:      resp.LogHead.Timestamp,
	}
	canonical := entry.CanonicalJSON()
	hash := sha256.Sum256([]byte(canonical))
	resp.LogHead.EntryHash = hex.EncodeToString(hash[:])
	sig := ed25519.Sign(key, []byte(canonical))
	resp.LogHead.Signature = base64.RawStdEncoding.EncodeToString(sig)

	cache := &ClawDIDCache{Seq: 1, EntryHash: "prev_hash"}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDDegraded {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDDegraded)
	}
	if !strings.Contains(result.Reason, "cached 1") {
		t.Errorf("reason %q should mention cached seq 1", result.Reason)
	}
}

func TestVerifyClawDIDKeyResponseChainBreak(t *testing.T) {
	t.Parallel()

	resp, key := buildLogHead(t)
	// Make seq=2 with wrong prev_entry_hash.
	wrongPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	entry := LogEntry{
		AuthorizedBy:   resp.LogHead.AuthorizedBy,
		DIDClaw:        resp.DIDClaw,
		NewDIDKey:      resp.LogHead.NewDIDKey,
		Operation:      "create",
		PrevEntryHash:  &wrongPrev,
		PreviousDIDKey: nil,
		Seq:            2,
		StateHash:      resp.LogHead.StateHash,
		Timestamp:      resp.LogHead.Timestamp,
	}
	canonical := entry.CanonicalJSON()
	hash := sha256.Sum256([]byte(canonical))
	resp.LogHead.Seq = 2
	resp.LogHead.PrevEntryHash = &wrongPrev
	resp.LogHead.EntryHash = hex.EncodeToString(hash[:])
	sig := ed25519.Sign(key, []byte(canonical))
	resp.LogHead.Signature = base64.RawStdEncoding.EncodeToString(sig)

	cachedHash := "correct_prev_hash"
	cache := &ClawDIDCache{Seq: 1, EntryHash: cachedHash}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseBadSignature(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	resp.LogHead.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cache := &ClawDIDCache{}

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, cache)
	if result.Status != ClawDIDHardError {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDHardError)
	}
}

func TestVerifyClawDIDKeyResponseNilCache(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)

	result := VerifyClawDIDKeyResponse(resp.DIDClaw, &resp, nil)
	if result.Status != ClawDIDVerified {
		t.Fatalf("got %s (%s), want %s", result.Status, result.Reason, ClawDIDVerified)
	}
}

func TestClawDIDClientHappyPath(t *testing.T) {
	t.Parallel()

	resp, _ := buildLogHead(t)
	respJSON, _ := json.Marshal(resp)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/did/"+resp.DIDClaw+"/key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(respJSON)
	}))
	defer ts.Close()

	client := &ClawDIDClient{RegistryURL: ts.URL}
	got, err := client.FetchKey(context.Background(), resp.DIDClaw)
	if err != nil {
		t.Fatal(err)
	}
	if got.DIDClaw != resp.DIDClaw {
		t.Errorf("DIDClaw: got %s, want %s", got.DIDClaw, resp.DIDClaw)
	}
	if got.CurrentDIDKey != resp.CurrentDIDKey {
		t.Errorf("CurrentDIDKey: got %s, want %s", got.CurrentDIDKey, resp.CurrentDIDKey)
	}
}

func TestClawDIDClientNotFound(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer ts.Close()

	client := &ClawDIDClient{RegistryURL: ts.URL}
	_, err := client.FetchKey(context.Background(), "did:claw:nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestClawDIDRegisterHappyPath(t *testing.T) {
	t.Parallel()

	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	didKey := ComputeDIDKey(pub)
	didClaw := ComputeStableID(pub, "claw")

	serverURL := "https://app.claweb.ai/api"
	address := "myco/alice"
	timestamp := "2026-02-24T10:00:00Z"
	stateHash := ComputeStateHash(didClaw, didKey, serverURL, address, nil)

	// Build a real proof over the canonical log entry.
	entry := LogEntry{
		AuthorizedBy:   didKey,
		DIDClaw:        didClaw,
		NewDIDKey:      didKey,
		Operation:      "create",
		PrevEntryHash:  nil,
		PreviousDIDKey: nil,
		Seq:            1,
		StateHash:      stateHash,
		Timestamp:      timestamp,
	}
	canonical := entry.CanonicalJSON()
	sig := ed25519.Sign(priv, []byte(canonical))
	proof := base64.RawStdEncoding.EncodeToString(sig)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/did" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(405)
			return
		}

		var req ClawDIDRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.DIDClaw != didClaw {
			t.Errorf("did_claw=%q, want %q", req.DIDClaw, didClaw)
		}
		if req.DIDKey != didKey {
			t.Errorf("did_key=%q, want %q", req.DIDKey, didKey)
		}
		if req.Seq != 1 {
			t.Errorf("seq=%d, want 1", req.Seq)
		}
		if req.PrevEntryHash != nil {
			t.Errorf("prev_entry_hash should be nil for seq=1")
		}
		if req.StateHash == "" {
			t.Error("state_hash is empty")
		}

		// Verify the proof signature on the server side.
		reqPub, err := ExtractPublicKey(req.AuthorizedBy)
		if err != nil {
			t.Fatalf("extract pub from authorized_by: %v", err)
		}
		ok, err := VerifyLogEntrySignature(reqPub, req.Proof, canonical)
		if err != nil {
			t.Fatalf("verify proof: %v", err)
		}
		if !ok {
			t.Error("proof signature verification failed")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClawDIDRegisterResponse{
			DIDClaw: req.DIDClaw,
			Status:  "created",
		})
	}))
	t.Cleanup(ts.Close)

	client := &ClawDIDClient{RegistryURL: ts.URL}
	resp, err := client.Register(context.Background(), &ClawDIDRegisterRequest{
		DIDClaw:      didClaw,
		DIDKey:       didKey,
		Server:       serverURL,
		Address:      address,
		Seq:          1,
		StateHash:    stateHash,
		AuthorizedBy: didKey,
		Timestamp:    timestamp,
		Proof:        proof,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.Status != "created" {
		t.Errorf("status=%q, want created", resp.Status)
	}
	if resp.DIDClaw != didClaw {
		t.Errorf("did_claw=%q, want %q", resp.DIDClaw, didClaw)
	}
}

func TestClawDIDRegisterConflict(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"already registered"}`))
	}))
	t.Cleanup(ts.Close)

	client := &ClawDIDClient{RegistryURL: ts.URL}
	_, err := client.Register(context.Background(), &ClawDIDRegisterRequest{
		DIDClaw: "did:claw:test",
		DIDKey:  "did:key:z6Mktest",
	})
	if err == nil {
		t.Fatal("expected error for 409")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error should mention 409: %v", err)
	}
}

func TestClawDIDRegisterUnavailable(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	t.Cleanup(ts.Close)

	client := &ClawDIDClient{RegistryURL: ts.URL}
	_, err := client.Register(context.Background(), &ClawDIDRegisterRequest{
		DIDClaw: "did:claw:test",
		DIDKey:  "did:key:z6Mktest",
	})
	if err == nil {
		t.Fatal("expected error for 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention 503: %v", err)
	}
}

func TestComputeStateHash(t *testing.T) {
	t.Parallel()

	hash := ComputeStateHash("did:claw:abc", "did:key:z6Mk...", "https://app.claweb.ai/api", "myco/alice", nil)
	if hash == "" {
		t.Fatal("state hash should not be empty")
	}
	// Same inputs must produce the same hash.
	hash2 := ComputeStateHash("did:claw:abc", "did:key:z6Mk...", "https://app.claweb.ai/api", "myco/alice", nil)
	if hash != hash2 {
		t.Fatalf("hash mismatch: %s != %s", hash, hash2)
	}
	// Different inputs must produce different hashes.
	hash3 := ComputeStateHash("did:claw:xyz", "did:key:z6Mk...", "https://app.claweb.ai/api", "myco/alice", nil)
	if hash == hash3 {
		t.Fatal("different inputs should produce different hashes")
	}
	// nil handle vs non-nil empty handle must differ (null vs "").
	emptyHandle := ""
	hash4 := ComputeStateHash("did:claw:abc", "did:key:z6Mk...", "https://app.claweb.ai/api", "myco/alice", &emptyHandle)
	if hash == hash4 {
		t.Fatal("nil handle and empty-string handle should produce different hashes")
	}
}

func TestComputeStateHashGolden(t *testing.T) {
	t.Parallel()

	// Golden value: SHA-256 of canonical JSON with null handle.
	// {"address":"myco/alice","current_did_key":"did:key:z6Mk...","did_claw":"did:claw:abc","handle":null,"server":"https://app.claweb.ai/api"}
	hash := ComputeStateHash("did:claw:abc", "did:key:z6Mk...", "https://app.claweb.ai/api", "myco/alice", nil)

	// Compute expected hash manually.
	canonical := `{"address":"myco/alice","current_did_key":"did:key:z6Mk...","did_claw":"did:claw:abc","handle":null,"server":"https://app.claweb.ai/api"}`
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	if hash != expected {
		t.Fatalf("golden hash mismatch:\n  got:  %s\n  want: %s\n  canonical: %s", hash, expected, canonical)
	}
}
