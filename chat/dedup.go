// ABOUTME: Defense-in-depth dedup for chat message delivery.
// ABOUTME: Prevents echo/replay when mark-read fails by tracking delivered message IDs.

package chat

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const deliveredCacheTTL = 10 * time.Minute

// FilterSeen removes events whose MessageID is in the seen set.
// Events without a MessageID are kept.
func FilterSeen(messages []Event, seen map[string]bool) []Event {
	if len(seen) == 0 {
		return messages
	}
	filtered := make([]Event, 0, len(messages))
	for _, m := range messages {
		if m.MessageID != "" && seen[m.MessageID] {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

// deliveredCachePath returns the file path for a session's delivered-IDs cache.
func deliveredCachePath(dir, sessionID string) string {
	h := sha256.Sum256([]byte(sessionID))
	return filepath.Join(dir, "aw-delivered-"+hex.EncodeToString(h[:8]))
}

// LoadDeliveredIDs loads recently-delivered message IDs for a session.
// Returns an empty map if the cache file is missing or expired.
func LoadDeliveredIDs(dir, sessionID string) map[string]bool {
	path := deliveredCachePath(dir, sessionID)
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(info.ModTime()) > deliveredCacheTTL {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id != "" {
			seen[id] = true
		}
	}
	return seen
}

// SaveDeliveredIDs writes message IDs to the session's delivered-IDs cache,
// merging with any existing IDs that are still within the TTL.
func SaveDeliveredIDs(dir, sessionID string, ids []string) {
	if len(ids) == 0 {
		return
	}
	// Merge with existing cache to preserve previously-seen IDs.
	existing := LoadDeliveredIDs(dir, sessionID)
	merged := make(map[string]bool, len(existing)+len(ids))
	for id := range existing {
		merged[id] = true
	}
	for _, id := range ids {
		merged[id] = true
	}
	var sb strings.Builder
	for id := range merged {
		sb.WriteString(id)
		sb.WriteByte('\n')
	}
	path := deliveredCachePath(dir, sessionID)
	_ = os.WriteFile(path, []byte(sb.String()), 0600)
}
