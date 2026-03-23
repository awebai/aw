package main

import (
	"strings"
	"testing"
)

func TestPromptIndexedChoiceDefaultsToFirstOption(t *testing.T) {
	t.Parallel()

	in := strings.NewReader("\n")
	var out strings.Builder

	got, err := promptIndexedChoice("Role", []string{"coordinator", "developer"}, 0, in, &out)
	if err != nil {
		t.Fatalf("promptIndexedChoice: %v", err)
	}
	if got != "coordinator" {
		t.Fatalf("got %q, want coordinator", got)
	}
	text := out.String()
	if !strings.Contains(text, "1. coordinator") || !strings.Contains(text, "2. developer") {
		t.Fatalf("missing numbered role list:\n%s", text)
	}
	if !strings.Contains(text, "Role number [1]:") {
		t.Fatalf("missing numbered prompt:\n%s", text)
	}
}

func TestPromptIndexedChoiceRetriesUntilValidNumber(t *testing.T) {
	t.Parallel()

	in := strings.NewReader("x\n2\n")
	var out strings.Builder

	got, err := promptIndexedChoice("Role", []string{"coordinator", "developer"}, 0, in, &out)
	if err != nil {
		t.Fatalf("promptIndexedChoice: %v", err)
	}
	if got != "developer" {
		t.Fatalf("got %q, want developer", got)
	}
	if !strings.Contains(out.String(), "Enter a number between 1 and 2.") {
		t.Fatalf("missing retry hint:\n%s", out.String())
	}
}
