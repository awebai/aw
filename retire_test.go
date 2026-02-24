package aweb

import (
	"encoding/json"
	"testing"
)

func TestCanonicalRetirementJSON_EscapesStrings(t *testing.T) {
	successorAddress := "ns/ali\"ce\\\\agent\nline2"
	successorDID := "did:key:z6Mkp\"\\\\\n"
	timestamp := "2026-02-24T10:51:58Z"

	got := canonicalRetirementJSON(successorAddress, successorDID, timestamp)
	want := `{"operation":"retire","successor_address":"ns/ali\"ce\\\\agent\nline2","successor_did":"did:key:z6Mkp\"\\\\\n","timestamp":"2026-02-24T10:51:58Z"}`
	if got != want {
		t.Fatalf("canonicalRetirementJSON mismatch:\n got: %s\nwant: %s", got, want)
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("canonicalRetirementJSON produced invalid JSON: %v\njson: %s", err, got)
	}
	if parsed["successor_address"] != successorAddress {
		t.Fatalf("successor_address round-trip mismatch:\n got: %q\nwant: %q", parsed["successor_address"], successorAddress)
	}
	if parsed["successor_did"] != successorDID {
		t.Fatalf("successor_did round-trip mismatch:\n got: %q\nwant: %q", parsed["successor_did"], successorDID)
	}
	if parsed["timestamp"] != timestamp {
		t.Fatalf("timestamp round-trip mismatch:\n got: %q\nwant: %q", parsed["timestamp"], timestamp)
	}
	if parsed["operation"] != "retire" {
		t.Fatalf("operation mismatch: %q", parsed["operation"])
	}
}
