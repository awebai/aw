package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAwInviteCreateOmitsDefaultServerFlag(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/invites/cli":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":    "inv-1",
				"token":        "aw_inv_7f3k9x2m",
				"token_prefix": "7f3k9x2m",
				"alias_hint":   "reviewer",
				"access_mode":  "open",
				"max_uses":     1,
				"expires_at":   "2026-03-21T18:00:00Z",
				"namespace":    "myteam.aweb.ai",
				"server_url":   "https://app.aweb.ai/api",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "invite", "--alias", "reviewer")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "aw init --invite aw_inv_7f3k9x2m --alias reviewer") {
		t.Fatalf("missing invite command:\n%s", text)
	}
	if strings.Contains(text, "--server ") {
		t.Fatalf("default hosted server should be omitted:\n%s", text)
	}
}

func TestAwInviteCreateIncludesSelfHostedServerFlag(t *testing.T) {
	t.Parallel()

	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/invites/cli":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":    "inv-1",
				"token":        "aw_inv_7f3k9x2m",
				"token_prefix": "7f3k9x2m",
				"access_mode":  "open",
				"max_uses":     1,
				"expires_at":   "2026-03-21T18:00:00Z",
				"namespace":    "myteam.example",
				"server_url":   serverURL + "/api",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "invite")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "--server "+server.URL) {
		t.Fatalf("self-hosted invite command should include --server:\n%s", text)
	}
	if !strings.Contains(text, "--alias <choose-an-alias>") {
		t.Fatalf("missing alias placeholder:\n%s", text)
	}
}

func TestAwInviteListAndRevoke(t *testing.T) {
	t.Parallel()

	var gotDeletePath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/invites/cli":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invites": []map[string]any{
					{
						"invite_id":    "inv-1",
						"token_prefix": "7f3k9x2m",
						"alias_hint":   "reviewer",
						"access_mode":  "open",
						"max_uses":     5,
						"current_uses": 2,
						"expires_at":   "2026-03-27T18:00:00Z",
						"created_at":   "2026-03-20T18:00:00Z",
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/invites/cli/inv-1":
			gotDeletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	listCmd := exec.CommandContext(ctx, bin, "invite", "list")
	listCmd.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	listCmd.Dir = tmp
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("invite list failed: %v\n%s", err, string(listOut))
	}
	if !strings.Contains(string(listOut), "7f3k9x2m") || !strings.Contains(string(listOut), "reviewer") {
		t.Fatalf("unexpected list output:\n%s", string(listOut))
	}

	revokeCmd := exec.CommandContext(ctx, bin, "invite", "revoke", "7f3k9x")
	revokeCmd.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	revokeCmd.Dir = tmp
	revokeOut, err := revokeCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("invite revoke failed: %v\n%s", err, string(revokeOut))
	}
	if gotDeletePath != "/api/v1/invites/cli/inv-1" {
		t.Fatalf("delete path=%q", gotDeletePath)
	}
	if !strings.Contains(string(revokeOut), "Invite 7f3k9x revoked") {
		t.Fatalf("unexpected revoke output:\n%s", string(revokeOut))
	}
}
