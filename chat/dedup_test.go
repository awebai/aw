// ABOUTME: Tests for the message delivery dedup cache.

package chat

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFilterSeenRemovesDuplicates(t *testing.T) {
	t.Parallel()

	messages := []Event{
		{Type: "message", MessageID: "m1", Body: "hello"},
		{Type: "message", MessageID: "m2", Body: "world"},
		{Type: "message", MessageID: "m3", Body: "foo"},
	}
	seen := map[string]bool{"m1": true, "m3": true}

	filtered := FilterSeen(messages, seen)

	if len(filtered) != 1 {
		t.Fatalf("filtered=%d, want 1", len(filtered))
	}
	if filtered[0].MessageID != "m2" {
		t.Fatalf("message_id=%s, want m2", filtered[0].MessageID)
	}
}

func TestFilterSeenKeepsAllWhenNoneSeen(t *testing.T) {
	t.Parallel()

	messages := []Event{
		{Type: "message", MessageID: "m1", Body: "hello"},
		{Type: "message", MessageID: "m2", Body: "world"},
	}

	filtered := FilterSeen(messages, nil)

	if len(filtered) != 2 {
		t.Fatalf("filtered=%d, want 2", len(filtered))
	}
}

func TestFilterSeenKeepsEventsWithoutMessageID(t *testing.T) {
	t.Parallel()

	messages := []Event{
		{Type: "message", MessageID: "m1", Body: "hello"},
		{Type: "read_receipt", Body: "read"},
	}
	seen := map[string]bool{"m1": true}

	filtered := FilterSeen(messages, seen)

	if len(filtered) != 1 {
		t.Fatalf("filtered=%d, want 1", len(filtered))
	}
	if filtered[0].Type != "read_receipt" {
		t.Fatalf("type=%s, want read_receipt", filtered[0].Type)
	}
}

func TestDeliveredCacheRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sessionID := "test-session-1"

	// Initially empty.
	seen := LoadDeliveredIDs(dir, sessionID)
	if len(seen) != 0 {
		t.Fatalf("initial seen=%d, want 0", len(seen))
	}

	// Save some IDs.
	SaveDeliveredIDs(dir, sessionID, []string{"m1", "m2", "m3"})

	// Load them back.
	seen = LoadDeliveredIDs(dir, sessionID)
	if len(seen) != 3 {
		t.Fatalf("seen=%d, want 3", len(seen))
	}
	for _, id := range []string{"m1", "m2", "m3"} {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
}

func TestDeliveredCacheAppends(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sessionID := "test-session-2"

	SaveDeliveredIDs(dir, sessionID, []string{"m1", "m2"})
	SaveDeliveredIDs(dir, sessionID, []string{"m3"})

	seen := LoadDeliveredIDs(dir, sessionID)
	if len(seen) != 3 {
		t.Fatalf("seen=%d, want 3", len(seen))
	}
}

func TestDeliveredCacheIgnoresExpiredFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sessionID := "test-session-3"

	SaveDeliveredIDs(dir, sessionID, []string{"m1"})

	// Backdate the file past the TTL.
	path := deliveredCachePath(dir, sessionID)
	old := time.Now().Add(-deliveredCacheTTL - time.Minute)
	_ = os.Chtimes(path, old, old)

	seen := LoadDeliveredIDs(dir, sessionID)
	if len(seen) != 0 {
		t.Fatalf("seen=%d after expiry, want 0", len(seen))
	}
}

func TestDeliveredCacheSaveAfterExpiryPurgesOldIDs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sessionID := "test-session-purge"

	SaveDeliveredIDs(dir, sessionID, []string{"old1", "old2"})

	// Backdate the file past the TTL.
	path := deliveredCachePath(dir, sessionID)
	old := time.Now().Add(-deliveredCacheTTL - time.Minute)
	_ = os.Chtimes(path, old, old)

	// Save new IDs — old ones should be purged since the file is expired.
	SaveDeliveredIDs(dir, sessionID, []string{"new1"})

	seen := LoadDeliveredIDs(dir, sessionID)
	if len(seen) != 1 {
		t.Fatalf("seen=%d, want 1 (old IDs should be purged)", len(seen))
	}
	if !seen["new1"] {
		t.Fatal("missing new1")
	}
	if seen["old1"] || seen["old2"] {
		t.Fatal("old IDs should have been purged after TTL expiry")
	}
}

func TestDeliveredCachePathIsDeterministic(t *testing.T) {
	t.Parallel()

	p1 := deliveredCachePath("/tmp/test", "session-abc")
	p2 := deliveredCachePath("/tmp/test", "session-abc")
	if p1 != p2 {
		t.Fatalf("paths differ: %s vs %s", p1, p2)
	}
	if filepath.Dir(p1) != "/tmp/test" {
		t.Fatalf("unexpected dir: %s", filepath.Dir(p1))
	}
}
