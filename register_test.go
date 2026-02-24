package aweb

import (
	"testing"
)

func TestParseExistingAccountFromHTTPError(t *testing.T) {
	t.Parallel()

	body := `{"existing_account":true,"verification_required":true,"email":"juan@example.com","handle":"juan","namespaces":[{"slug":"juan","tier":"free"},{"slug":"mycompany","tier":"paid"}]}`

	err := &apiError{StatusCode: 409, Body: body}
	info := ParseExistingAccount(err)
	if info == nil {
		t.Fatal("expected ExistingAccountInfo, got nil")
	}
	if !info.ExistingAccount {
		t.Fatal("existing_account=false")
	}
	if !info.VerificationRequired {
		t.Fatal("verification_required=false")
	}
	if info.Email != "juan@example.com" {
		t.Fatalf("email=%q", info.Email)
	}
	if info.Handle != "juan" {
		t.Fatalf("handle=%q", info.Handle)
	}
	if len(info.Namespaces) != 2 {
		t.Fatalf("got %d namespaces, want 2", len(info.Namespaces))
	}
	if info.Namespaces[0].Slug != "juan" || info.Namespaces[0].Tier != "free" {
		t.Fatalf("ns[0]=%+v", info.Namespaces[0])
	}
	if info.Namespaces[1].Slug != "mycompany" || info.Namespaces[1].Tier != "paid" {
		t.Fatalf("ns[1]=%+v", info.Namespaces[1])
	}
}

func TestParseExistingAccountNon409(t *testing.T) {
	t.Parallel()

	err := &apiError{StatusCode: 400, Body: `{"error":"bad request"}`}
	if info := ParseExistingAccount(err); info != nil {
		t.Fatalf("expected nil for 400, got %+v", info)
	}
}

func TestParseExistingAccountOldFormat(t *testing.T) {
	t.Parallel()

	// Old-style 409 body without existing_account field — should return nil.
	err := &apiError{StatusCode: 409, Body: `{"error":{"code":"USERNAME_TAKEN","message":"username taken"}}`}
	if info := ParseExistingAccount(err); info != nil {
		t.Fatalf("expected nil for old-style 409, got %+v", info)
	}
}
