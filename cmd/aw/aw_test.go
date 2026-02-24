package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
)

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// aw probes for aweb by calling GET /v1/agents/heartbeat on candidate bases.
		// Return any non-404 to indicate "endpoint exists" without side effects.
		// Only intercept GET; POST is the actual heartbeat and should reach the inner handler.
		if r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat") {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: wrapped},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// extractJSON finds the first JSON object in mixed output (e.g. from
// CombinedOutput where stderr warnings precede stdout JSON).
func extractJSON(t *testing.T, out []byte) []byte {
	t.Helper()
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		t.Fatalf("no JSON object in output:\n%s", string(out))
	}
	return out[idx:]
}

func TestAwIntrospect(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
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

	run := exec.CommandContext(ctx, bin, "introspect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwIntrospectIncludesIdentityFields(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
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
    did: "did:key:z6MkTestKey123"
    custody: "self"
    lifetime: "persistent"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	if got["did"] != "did:key:z6MkTestKey123" {
		t.Fatalf("did=%v", got["did"])
	}
	if got["custody"] != "self" {
		t.Fatalf("custody=%v", got["custody"])
	}
	if got["lifetime"] != "persistent" {
		t.Fatalf("lifetime=%v", got["lifetime"])
	}
	if _, ok := got["public_key"]; ok {
		t.Fatal("public_key should not be present in introspect output")
	}
}

func TestAwIntrospectServerFlagSelectsConfiguredServer(t *testing.T) {
	t.Parallel()

	serverA := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_a" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-a"})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	serverB := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_b" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-b"})
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  a:
    url: `+serverA.URL+`
  b:
    url: `+serverB.URL+`
accounts:
  acct_a:
    server: a
    api_key: aw_sk_a
  acct_b:
    server: b
    api_key: aw_sk_b
default_account: acct_a
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".aw", "context"), []byte(strings.TrimSpace(`
default_account: acct_a
server_accounts:
  b: acct_b
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect", "--server-name", "b")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-b" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwIntrospectEnvOverridesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_env" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"project_id": "proj-123"})
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
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
    api_key: aw_sk_config
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "introspect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_API_KEY=aw_sk_env",
		"AWEB_URL=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
}

func TestAwInitRetriesWhenSuggestedAliasAlreadyExists(t *testing.T) {
	t.Parallel()

	var initCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
			return
		case "/v1/init":
			initCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_, hasAuth := r.Header["Authorization"]
			if hasAuth {
				t.Fatalf("unexpected auth header on init")
			}

			switch initCalls {
			case 1:
				if payload["alias"] != "alice" {
					t.Fatalf("first alias=%v", payload["alias"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"created_at":   "now",
					"project_id":   "proj-1",
					"project_slug": "demo",
					"agent_id":     "agent-alice",
					"alias":        "alice",
					"api_key":      "aw_sk_alice",
					"created":      false,
				})
				return
			case 2:
				if _, ok := payload["alias"]; ok {
					t.Fatalf("expected alias omitted on retry, got %v", payload["alias"])
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"created_at":   "now",
					"project_id":   "proj-1",
					"project_slug": "demo",
					"agent_id":     "agent-bob",
					"alias":        "bob",
					"api_key":      "aw_sk_bob",
					"created":      true,
				})
				return
			default:
				t.Fatalf("unexpected init call %d", initCalls)
			}
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--namespace", "demo", "--print-exports=false", "--write-context=false")
	// Ensure non-TTY mode so aw init doesn't prompt during tests.
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["alias"] != "bob" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if initCalls != 2 {
		t.Fatalf("initCalls=%d", initCalls)
	}
}

func TestAwAgents(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agents": []map[string]any{
					{
						"agent_id":   "agent-1",
						"alias":      "alice",
						"human_name": "Alice",
						"agent_type": "agent",
						"status":     "active",
						"last_seen":  "2026-02-04T10:00:00Z",
						"online":     true,
					},
					{
						"agent_id":   "agent-2",
						"alias":      "bob",
						"human_name": "Bob",
						"agent_type": "agent",
						"status":     nil,
						"last_seen":  nil,
						"online":     false,
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "agents")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	agents, ok := got["agents"].([]any)
	if !ok || len(agents) != 2 {
		t.Fatalf("agents=%v", got["agents"])
	}
	first := agents[0].(map[string]any)
	if first["alias"] != "alice" {
		t.Fatalf("first alias=%v", first["alias"])
	}
	if first["online"] != true {
		t.Fatalf("first online=%v", first["online"])
	}
}

func TestAwMailAck(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/msg-42/ack":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":      "msg-42",
				"acknowledged_at": "2026-02-04T10:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "mail", "ack", "--message-id", "msg-42")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["message_id"] != "msg-42" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
}

func TestAwLockRenew(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/renew":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["resource_key"] != "my-lock" {
				t.Fatalf("resource_key=%v", payload["resource_key"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "renewed",
				"resource_key": "my-lock",
				"expires_at":   "2026-02-04T11:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "lock", "renew", "--resource-key", "my-lock", "--ttl-seconds", "3600")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["resource_key"] != "my-lock" {
		t.Fatalf("resource_key=%v", got["resource_key"])
	}
	if got["status"] != "renewed" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAwNamespace(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projects/current":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"project_id": "proj-abc",
				"slug":       "my-project",
				"name":       "My Project",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "namespace")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-abc" {
		t.Fatalf("project_id=%v", got["project_id"])
	}
	if got["slug"] != "my-project" {
		t.Fatalf("slug=%v", got["slug"])
	}
}

func TestAwLockRevoke(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/revoke":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["prefix"] != "test-" {
				t.Fatalf("prefix=%v", payload["prefix"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"revoked_count": 2,
				"revoked_keys":  []string{"test-lock-1", "test-lock-2"},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "lock", "revoke", "--prefix", "test-")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["revoked_count"] != float64(2) {
		t.Fatalf("revoked_count=%v", got["revoked_count"])
	}
}

func TestAwChatSendAndLeavePositionalArgs(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
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
    agent_alias: eve
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	// Verify the API request used the positional alias and message
	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestAwChatSendAndWaitMissingArgs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	// No positional args at all
	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH=/nonexistent")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwChatSendAndWaitExtraArgsRejected(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait", "bob", "hello", "extra-arg")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH=/nonexistent")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for extra args, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwInitWritesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
			return
		case "/v1/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"created_at":   "now",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"agent_id":     "agent-alice",
				"alias":        "alice",
				"api_key":      "aw_sk_alice",
				"created":      true,
			})
			return
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	// Mock ClawDID registry to verify stable_id registration.
	clawDIDServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"did_claw": "did:claw:test", "status": "created"})
	}))
	t.Cleanup(clawDIDServer.Close)

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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--namespace", "demo", "--server-name", "local", "--server-url", server.URL, "--account", "acct", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"CLAWDID_REGISTRY_URL="+clawDIDServer.URL,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_alice" {
		t.Fatalf("api_key=%v", got["api_key"])
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers        map[string]map[string]any `yaml:"servers"`
		Accounts       map[string]map[string]any `yaml:"accounts"`
		DefaultAccount string                    `yaml:"default_account"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if cfg.DefaultAccount != "acct" {
		t.Fatalf("default_account=%q", cfg.DefaultAccount)
	}
	localSrv, ok := cfg.Servers["local"]
	if !ok {
		t.Fatalf("missing servers.local")
	}
	if localSrv["url"] != server.URL {
		t.Fatalf("servers.local.url=%v", localSrv["url"])
	}
	acct, ok := cfg.Accounts["acct"]
	if !ok {
		t.Fatalf("missing accounts.acct")
	}
	if acct["server"] != "local" {
		t.Fatalf("accounts.acct.server=%v", acct["server"])
	}
	if acct["api_key"] != "aw_sk_alice" {
		t.Fatalf("accounts.acct.api_key=%v", acct["api_key"])
	}
	if acct["namespace_slug"] != "demo" {
		t.Fatalf("accounts.acct.namespace_slug=%v", acct["namespace_slug"])
	}
	if acct["agent_id"] != "agent-alice" {
		t.Fatalf("accounts.acct.agent_id=%v", acct["agent_id"])
	}
	if acct["agent_alias"] != "alice" {
		t.Fatalf("accounts.acct.agent_alias=%v", acct["agent_alias"])
	}
	stableID, _ := acct["stable_id"].(string)
	if !strings.HasPrefix(stableID, "did:claw:") {
		t.Fatalf("accounts.acct.stable_id=%v, want did:claw: prefix", acct["stable_id"])
	}
}

func TestAwInitCloudModeRequiresCloudToken(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/init":
			http.NotFound(w, r)
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--cloud", "--namespace", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "cloud-token") {
		t.Fatalf("expected cloud token guidance, got: %s", string(out))
	}
}

func TestAwInitCloudModeSkipsInitProbe(t *testing.T) {
	t.Parallel()

	var initCalls int
	var cloudCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/init":
			initCalls++
			t.Fatalf("unexpected /v1/init probe in --cloud mode")
		case "/api/v1/agents/bootstrap":
			cloudCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer cloud_jwt_token" {
				t.Fatalf("auth=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":             "org-1",
				"org_slug":           "juan",
				"org_name":           "Juan",
				"project_id":         "proj-cloud",
				"project_slug":       "default",
				"project_name":       "Default",
				"server_url":         "https://app.aweb.ai",
				"bootstrap_endpoint": "/api/v1/agents/bootstrap",
				"api_key":            "aw_sk_cloud",
				"agent_id":           "agent-researcher",
				"alias":              "researcher",
				"created":            true,
			})
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

	run := exec.CommandContext(ctx, bin, "init", "--cloud", "--namespace", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false", "--server-url", server.URL)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=cloud_jwt_token",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_cloud" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if initCalls != 0 {
		t.Fatalf("initCalls=%d", initCalls)
	}
	if cloudCalls != 1 {
		t.Fatalf("cloudCalls=%d", cloudCalls)
	}
}

func TestAwInitAcceptsAPIV1BaseURL(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/heartbeat":
			// Probe path (GET) - any non-404 response is treated as "exists".
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/api/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
		case "/api/v1/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"created_at":   "now",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"agent_id":     "agent-alice",
				"alias":        "alice",
				"api_key":      "aw_sk_alice",
				"created":      true,
			})
		default:
			http.NotFound(w, r)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--namespace", "demo", "--print-exports=false", "--write-context=false", "--server-url", server.URL+"/api/v1")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_alice" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
}

func TestAwInitAllowsCustomMountRoot(t *testing.T) {
	t.Parallel()

	var gotInitPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom/v1/agents/heartbeat":
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/custom/v1/init":
			gotInitPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"created_at":   "now",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"agent_id":     "agent-alice",
				"alias":        "alice",
				"api_key":      "aw_sk_alice",
				"created":      true,
			})
		case "/custom/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--namespace", "demo", "--print-exports=false", "--write-context=false", "--server-url", server.URL+"/custom")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_alice" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if gotInitPath != "/custom/v1/init" {
		t.Fatalf("gotInitPath=%q", gotInitPath)
	}
}

func TestAwInitCloudTokenResolutionFromConfiguredServerKey(t *testing.T) {
	t.Parallel()

	var cloudCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/init":
			http.NotFound(w, r)
		case "/api/v1/agents/bootstrap":
			cloudCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer cloud_jwt_config" {
				t.Fatalf("auth=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":             "org-1",
				"org_slug":           "juan",
				"org_name":           "Juan",
				"project_id":         "proj-cloud",
				"project_slug":       "default",
				"project_name":       "Default",
				"server_url":         "https://app.aweb.ai",
				"bootstrap_endpoint": "/api/v1/agents/bootstrap",
				"api_key":            "aw_sk_cloud",
				"agent_id":           "agent-researcher",
				"alias":              "researcher",
				"created":            true,
			})
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
  prod:
    url: `+server.URL+`
accounts:
  cloud-acct:
    server: prod
    api_key: cloud_jwt_config
default_account: cloud-acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--cloud", "--namespace", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false", "--server-url", server.URL)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_cloud" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if cloudCalls != 1 {
		t.Fatalf("cloudCalls=%d", cloudCalls)
	}
}

func TestAwInitCloudWithExistingAPIKey(t *testing.T) {
	t.Parallel()

	var cloudCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/bootstrap":
			cloudCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_existing" {
				t.Fatalf("auth=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":             "org-1",
				"org_slug":           "juan",
				"org_name":           "Juan",
				"project_id":         "proj-1",
				"project_slug":       "default",
				"project_name":       "Default",
				"server_url":         "https://app.aweb.ai",
				"bootstrap_endpoint": "/api/v1/agents/bootstrap",
				"api_key":            "aw_sk_newagent",
				"agent_id":           "agent-bob",
				"alias":              "bob",
				"created":            true,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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
  prod:
    url: `+server.URL+`
accounts:
  existing-acct:
    server: prod
    api_key: aw_sk_existing
default_account: existing-acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--cloud", "--namespace", "demo",
		"--alias", "bob", "--print-exports=false", "--write-context=false", "--server-url", server.URL)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_newagent" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if cloudCalls != 1 {
		t.Fatalf("cloudCalls=%d", cloudCalls)
	}
}

func TestAwInitCloudWithAPIKeyRequiresAlias(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/bootstrap":
			t.Fatal("bootstrap should not be called when alias is missing")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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
  prod:
    url: `+server.URL+`
accounts:
  existing-acct:
    server: prod
    api_key: aw_sk_existing
default_account: existing-acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--cloud", "--namespace", "demo",
		"--print-exports=false", "--write-context=false", "--server-url", server.URL)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_ALIAS=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "--alias") {
		t.Fatalf("expected '--alias' hint in error, got: %s", outStr)
	}
}

func TestAwChatSendAndLeavePositionalArgsOrder(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
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
    agent_alias: eve
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "version")
	run.Env = append(os.Environ(), "AWEB_URL=", "AWEB_API_KEY=")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !strings.HasPrefix(string(out), "aw ") {
		t.Fatalf("unexpected version output: %s", string(out))
	}
}

func TestAwContactsList(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{
						"contact_id":      "ct-1",
						"contact_address": "alice@example.com",
						"label":           "Alice",
						"created_at":      "2026-02-08T10:00:00Z",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "contacts", "list")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	contacts, ok := got["contacts"].([]any)
	if !ok || len(contacts) != 1 {
		t.Fatalf("contacts=%v", got["contacts"])
	}
	first := contacts[0].(map[string]any)
	if first["contact_address"] != "alice@example.com" {
		t.Fatalf("contact_address=%v", first["contact_address"])
	}
}

func TestAwContactsAdd(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contact_id":      "ct-1",
				"contact_address": gotBody["contact_address"],
				"label":           gotBody["label"],
				"created_at":      "2026-02-08T10:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "contacts", "add", "bob@example.com", "--label", "Bob")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["contact_id"] != "ct-1" {
		t.Fatalf("contact_id=%v", got["contact_id"])
	}
	if got["contact_address"] != "bob@example.com" {
		t.Fatalf("contact_address=%v", got["contact_address"])
	}
	if gotBody["contact_address"] != "bob@example.com" {
		t.Fatalf("req contact_address=%v", gotBody["contact_address"])
	}
	if gotBody["label"] != "Bob" {
		t.Fatalf("req label=%v", gotBody["label"])
	}
}

func TestAwContactsRemove(t *testing.T) {
	t.Parallel()

	var deletePath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/contacts" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{"contact_id": "ct-1", "contact_address": "alice@example.com", "created_at": "2026-02-08T10:00:00Z"},
					{"contact_id": "ct-2", "contact_address": "bob@example.com", "created_at": "2026-02-08T11:00:00Z"},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/contacts/") && r.Method == http.MethodDelete:
			deletePath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
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

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "bob@example.com")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["deleted"] != true {
		t.Fatalf("deleted=%v", got["deleted"])
	}
	if deletePath != "/v1/contacts/ct-2" {
		t.Fatalf("delete path=%s (expected /v1/contacts/ct-2)", deletePath)
	}
}

func TestAwContactsRemoveNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "nobody@example.com")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "contact not found") {
		t.Fatalf("expected 'contact not found' error, got: %s", string(out))
	}
}

func TestAwAgentAccessModeGet(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agents": []map[string]any{
					{
						"agent_id":    "agent-1",
						"alias":       "alice",
						"online":      true,
						"access_mode": "contacts_only",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "agent", "access-mode")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["access_mode"] != "contacts_only" {
		t.Fatalf("access_mode=%v", got["access_mode"])
	}
}

func TestAwAgentAccessModeSet(t *testing.T) {
	t.Parallel()

	var patchBody map[string]any
	var patchPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/agents/") && r.Method == http.MethodPatch:
			patchPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&patchBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":    "agent-1",
				"access_mode": patchBody["access_mode"],
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
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

	run := exec.CommandContext(ctx, bin, "agent", "access-mode", "open")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["access_mode"] != "open" {
		t.Fatalf("access_mode=%v", got["access_mode"])
	}
	if patchPath != "/v1/agents/agent-1" {
		t.Fatalf("patch path=%s", patchPath)
	}
	if patchBody["access_mode"] != "open" {
		t.Fatalf("patch access_mode=%v", patchBody["access_mode"])
	}
}

func TestAwRegisterMissingEmail(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-TTY (no stdin) + no --email flag → should fail with usage error.
	run := exec.CommandContext(ctx, bin, "register", "--server-url", server.URL,
		"--username", "testuser", "--alias", "alice")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "email") {
		t.Fatalf("expected email-related error, got: %s", string(out))
	}
}

func TestAwRegisterInvalidEmail(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register", "--server-url", server.URL, "--email", "not-an-email",
		"--username", "testuser", "--alias", "alice")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "invalid email") {
		t.Fatalf("expected 'invalid email' error, got: %s", string(out))
	}
}

func TestAwRegisterSuccess(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			// Should be unauthenticated.
			if auth := r.Header.Get("Authorization"); auth != "" {
				t.Fatalf("unexpected auth header: %q", auth)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["email"] != "test@example.com" {
				t.Fatalf("email=%v", payload["email"])
			}
			if payload["username"] != "testuser" {
				t.Fatalf("username=%v", payload["username"])
			}
			if payload["alias"] != "alice" {
				t.Fatalf("alias=%v", payload["alias"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":               "aw_sk_register_test",
				"agent_id":              "agent-reg-1",
				"alias":                 "alice",
				"username":              "testuser",
				"project_slug":          "default",
				"project_name":          "Default",
				"server_url":            "http://localhost:9999",
				"verification_required": true,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	if err := run.Run(); err != nil {
		t.Fatalf("run failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, stdout.String())
	}
	if got["api_key"] != "aw_sk_register_test" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if got["agent_id"] != "agent-reg-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["username"] != "testuser" {
		t.Fatalf("username=%v", got["username"])
	}
	if got["verification_required"] != true {
		t.Fatalf("verification_required=%v", got["verification_required"])
	}
	// Non-TTY: should print verification instructions on stderr.
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "aw verify") {
		t.Fatalf("expected 'aw verify' in stderr, got: %s", stderrStr)
	}
}

func TestAwRegisterServerNotSupported(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "does not support cli registration") {
		t.Fatalf("expected 'does not support CLI registration' error, got: %s", string(out))
	}
}

func TestAwRegisterEmailTaken(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"detail": "email already registered",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "taken@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "already registered") {
		t.Fatalf("expected 'already registered' error, got: %s", string(out))
	}
}

func TestAwRegisterExistingAccountFlow(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			// Return structured 409 with existing_account.
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"existing_account":      true,
				"verification_required": true,
				"email":                 "existing@example.com",
				"handle":                "existinguser",
				"namespaces": []map[string]any{
					{"slug": "existinguser", "tier": "free"},
				},
			})
		case "/v1/auth/verify-code":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "123456" {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid code"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "existinguser",
				"registration_source": "cli",
				"api_key":             "aw_sk_new_agent",
				"agent_id":            "agent-existing-42",
				"alias":               "researcher",
				"namespace_slug":      "existinguser",
			})
		case "/v1/agents/me/identity":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     body["did"],
				"custody": "self",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	clawDIDServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "existing@example.com",
		"--username", "existinguser",
		"--alias", "researcher",
		"--namespace", "existinguser",
	)
	// Provide verification code via stdin.
	run.Stdin = strings.NewReader("123456\n")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"HOME="+tmp,
		"XDG_CONFIG_HOME="+filepath.Join(tmp, ".config"),
		"CLAWDID_REGISTRY_URL="+clawDIDServer.URL,
	)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("register failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	// Verify JSON output contains bootstrap credentials.
	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("parsing JSON: %v\nstdout: %s", err, stdout.String())
	}
	if resp["api_key"] != "aw_sk_new_agent" {
		t.Fatalf("api_key=%v", resp["api_key"])
	}
	if resp["agent_id"] != "agent-existing-42" {
		t.Fatalf("agent_id=%v", resp["agent_id"])
	}

	// Verify stderr has expected messages.
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "Account already exists") {
		t.Fatalf("missing 'Account already exists' in stderr:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "Verified!") {
		t.Fatalf("missing 'Verified!' in stderr:\n%s", stderrStr)
	}

	// Verify config was written.
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfgStr := string(cfgData)
	if !strings.Contains(cfgStr, "aw_sk_new_agent") {
		t.Fatalf("config missing api_key:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "researcher") {
		t.Fatalf("config missing alias:\n%s", cfgStr)
	}
}

func TestAwRegisterExistingAccountAutoSelectNamespace(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"existing_account":      true,
				"verification_required": true,
				"email":                 "auto@example.com",
				"handle":                "autouser",
				"namespaces": []map[string]any{
					{"slug": "autouser", "tier": "free"},
				},
			})
		case "/v1/auth/verify-code":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "autouser",
				"registration_source": "cli",
				"api_key":             "aw_sk_auto",
				"agent_id":            "agent-auto",
				"alias":               "bot",
				"namespace_slug":      "autouser",
			})
		case "/v1/agents/me/identity":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     body["did"],
				"custody": "self",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	clawDIDServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// No --namespace flag; single namespace should be auto-selected.
	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "auto@example.com",
		"--username", "autouser",
		"--alias", "bot",
	)
	run.Stdin = strings.NewReader("999999\n")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"HOME="+tmp,
		"XDG_CONFIG_HOME="+filepath.Join(tmp, ".config"),
		"CLAWDID_REGISTRY_URL="+clawDIDServer.URL,
	)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("register failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	// Should auto-select the single namespace.
	if !strings.Contains(stderr.String(), "Using namespace: autouser") {
		t.Fatalf("expected auto-selection message, stderr:\n%s", stderr.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("parsing JSON: %v\nstdout: %s", err, stdout.String())
	}
	if resp["api_key"] != "aw_sk_auto" {
		t.Fatalf("api_key=%v", resp["api_key"])
	}
}

func TestAwRegisterUsernameTaken(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "USERNAME_TAKEN",
					"message": "Username \"alice\" is already taken.",
					"details": map[string]any{
						"attempted_username": "alice",
						"source":             "explicit",
					},
				},
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "alice",
		"--alias", "myalias",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := string(out)
	// Should show a clean message, not a raw JSON dump.
	if strings.Contains(outStr, "USERNAME_TAKEN") {
		t.Fatalf("expected parsed error, not raw JSON dump: %s", outStr)
	}
	if !strings.Contains(outStr, "alice") {
		t.Fatalf("expected username 'alice' in error, got: %s", outStr)
	}
	if !strings.Contains(outStr, "--username") {
		t.Fatalf("expected '--username' hint in error, got: %s", outStr)
	}
}

func TestAwRegisterAliasTaken(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "ALIAS_TAKEN",
					"message": "Alias \"bob\" is already taken.",
					"details": map[string]any{
						"attempted_alias": "bob",
					},
				},
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "bob",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := string(out)
	// Should show a clean message, not a raw JSON dump.
	if strings.Contains(outStr, "ALIAS_TAKEN") {
		t.Fatalf("expected parsed error, not raw JSON dump: %s", outStr)
	}
	if !strings.Contains(outStr, "bob") {
		t.Fatalf("expected alias 'bob' in error, got: %s", outStr)
	}
	if !strings.Contains(outStr, "--alias") {
		t.Fatalf("expected '--alias' hint in error, got: %s", outStr)
	}
}

func TestAwRegisterExistingAccountNamespaceNotOwned(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"existing_account":      true,
				"verification_required": true,
				"email":                 "ns@example.com",
				"handle":                "nsuser",
				"namespaces": []map[string]any{
					{"slug": "nsuser", "tier": "free"},
					{"slug": "ownedco", "tier": "paid"},
				},
			})
		case "/v1/auth/verify-code":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not authorized"})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "ns@example.com",
		"--username", "nsuser",
		"--alias", "bot",
		"--namespace", "notmine",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("123456\n")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"HOME="+tmp,
		"XDG_CONFIG_HOME="+filepath.Join(tmp, ".config"),
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "don't have access") {
		t.Fatalf("expected 'don't have access' error, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "nsuser") || !strings.Contains(outStr, "ownedco") {
		t.Fatalf("expected namespace list in error, got:\n%s", outStr)
	}
}

func TestAwRegisterExistingAccountMultipleNamespacesNonTTY(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"existing_account":      true,
				"verification_required": true,
				"email":                 "multi@example.com",
				"handle":                "multiuser",
				"namespaces": []map[string]any{
					{"slug": "multiuser", "tier": "free"},
					{"slug": "bigcorp", "tier": "paid"},
				},
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// No --namespace, multiple namespaces, non-TTY → should fail.
	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "multi@example.com",
		"--username", "multiuser",
		"--alias", "bot",
		"--save-config=false",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"HOME="+tmp,
		"XDG_CONFIG_HOME="+filepath.Join(tmp, ".config"),
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "--namespace") {
		t.Fatalf("expected '--namespace' hint, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "multiuser") || !strings.Contains(outStr, "bigcorp") {
		t.Fatalf("expected namespace list, got:\n%s", outStr)
	}
}

func TestAwRegisterExistingAccountClaimsIdentity(t *testing.T) {
	t.Parallel()

	var identityClaimed bool
	var claimBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"existing_account":      true,
				"verification_required": true,
				"email":                 "claim@example.com",
				"handle":                "claimuser",
				"namespaces": []map[string]any{
					{"slug": "claimuser", "tier": "free"},
				},
			})
		case "/v1/auth/verify-code":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "claimuser",
				"registration_source": "cli",
				"api_key":             "aw_sk_claim_test",
				"agent_id":            "agent-claim-1",
				"alias":               "researcher",
				"namespace_slug":      "claimuser",
			})
		case "/v1/agents/me/identity":
			if r.Method != http.MethodPut {
				t.Fatalf("identity method=%s, want PUT", r.Method)
			}
			identityClaimed = true
			_ = json.NewDecoder(r.Body).Decode(&claimBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     claimBody["did"],
				"custody": "self",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	clawDIDServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "claim@example.com",
		"--username", "claimuser",
		"--alias", "researcher",
		"--namespace", "claimuser",
	)
	run.Stdin = strings.NewReader("123456\n")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"HOME="+tmp,
		"XDG_CONFIG_HOME="+filepath.Join(tmp, ".config"),
		"CLAWDID_REGISTRY_URL="+clawDIDServer.URL,
	)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("register failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	// ClaimIdentity must have been called with a valid DID and public key.
	if !identityClaimed {
		t.Fatal("ClaimIdentity was not called after existing-account verify")
	}
	did, _ := claimBody["did"].(string)
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("ClaimIdentity did=%q, want did:key:z6Mk... prefix", did)
	}
	if claimBody["public_key"] == nil || claimBody["public_key"] == "" {
		t.Fatal("ClaimIdentity public_key is empty")
	}
	if claimBody["custody"] != "self" {
		t.Fatalf("ClaimIdentity custody=%v", claimBody["custody"])
	}
}

func TestAwRegisterWritesConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":               "aw_sk_reg",
				"agent_id":              "agent-reg-1",
				"alias":                 "alice",
				"username":              "testuser",
				"email":                 "test@example.com",
				"project_slug":          "myproject",
				"project_name":          "My Project",
				"server_url":            "http://localhost:9999",
				"verification_required": false,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	// Mock ClawDID registry to verify stable_id registration.
	clawDIDServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"did_claw": "did:claw:test", "status": "created"})
	}))
	t.Cleanup(clawDIDServer.Close)

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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL="+clawDIDServer.URL,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_reg" {
		t.Fatalf("api_key=%v", got["api_key"])
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers        map[string]map[string]any `yaml:"servers"`
		Accounts       map[string]map[string]any `yaml:"accounts"`
		DefaultAccount string                    `yaml:"default_account"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	// Should have set a default account since config was empty.
	if cfg.DefaultAccount == "" {
		t.Fatalf("default_account is empty")
	}
	// Find the account entry and verify fields.
	var found bool
	for name, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_reg" {
			found = true
			if acct["agent_id"] != "agent-reg-1" {
				t.Fatalf("accounts.%s.agent_id=%v", name, acct["agent_id"])
			}
			if acct["agent_alias"] != "alice" {
				t.Fatalf("accounts.%s.agent_alias=%v", name, acct["agent_alias"])
			}
			if acct["namespace_slug"] != "myproject" {
				t.Fatalf("accounts.%s.namespace_slug=%v", name, acct["namespace_slug"])
			}
			if acct["email"] != "test@example.com" {
				t.Fatalf("accounts.%s.email=%v", name, acct["email"])
			}
			stableID, _ := acct["stable_id"].(string)
			if !strings.HasPrefix(stableID, "did:claw:") {
				t.Fatalf("accounts.%s.stable_id=%v, want did:claw: prefix", name, acct["stable_id"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_reg in config:\n%s", string(data))
	}
	// Should have a server entry with the test server URL.
	var serverFound bool
	for _, srv := range cfg.Servers {
		if srv["url"] == server.URL {
			serverFound = true
			break
		}
	}
	if !serverFound {
		t.Fatalf("no server with url=%s in config:\n%s", server.URL, string(data))
	}
}

func TestAwRegisterMissingUsername(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--alias", "alice",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "username") {
		t.Fatalf("expected username-related error, got: %s", string(out))
	}
}

func TestAwRegisterMissingAlias(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "alias") {
		t.Fatalf("expected alias-related error, got: %s", string(out))
	}
}

func TestAwIntrospectVerificationRequired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		maskedEmail string
		wantEmail   bool
	}{
		{"with_masked_email", "t***@example.com", true},
		{"without_masked_email", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			details := map[string]any{}
			if tc.maskedEmail != "" {
				details["masked_email"] = tc.maskedEmail
			}

			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/introspect":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{
							"code":    "EMAIL_VERIFICATION_REQUIRED",
							"message": "Email verification pending.",
							"details": details,
						},
					})
				default:
					// Accept heartbeat probes.
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
    email: test@example.com
default_account: acct
`)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			run := exec.CommandContext(ctx, bin, "introspect")
			run.Env = append(os.Environ(),
				"AW_CONFIG_PATH="+cfgPath,
				"AWEB_URL=",
				"AWEB_API_KEY=",
			)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected failure, got success:\n%s", string(out))
			}
			outStr := string(out)
			if !strings.Contains(outStr, "aw verify") {
				t.Fatalf("expected 'aw verify' hint in error, got: %s", outStr)
			}
			if tc.wantEmail {
				if !strings.Contains(outStr, tc.maskedEmail) {
					t.Fatalf("expected masked email %q in output, got: %s", tc.maskedEmail, outStr)
				}
			} else {
				if strings.Contains(outStr, "(") {
					t.Fatalf("expected no parenthetical email in output, got: %s", outStr)
				}
			}
			// Should NOT show the raw error code.
			if strings.Contains(outStr, "EMAIL_VERIFICATION_REQUIRED") {
				t.Fatalf("expected parsed error, not raw code: %s", outStr)
			}
		})
	}
}

func TestAwVerifySuccess(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/verify-code":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			// Should be unauthenticated.
			if auth := r.Header.Get("Authorization"); auth != "" {
				t.Fatalf("unexpected auth header: %q", auth)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["email"] != "test@example.com" {
				t.Fatalf("email=%s", body["email"])
			}
			if body["code"] != "123456" {
				t.Fatalf("code=%s", body["code"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "testuser",
				"registration_source": "cli",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "verify",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--code", "123456",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	outStr := strings.ToLower(string(out))
	if !strings.Contains(outStr, "verified") {
		t.Fatalf("expected 'verified' in output, got: %s", string(out))
	}
}

func TestAwVerifyHeartbeatAfterSuccess(t *testing.T) {
	t.Parallel()

	var heartbeatReceived int32

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/verify-code" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "testuser",
				"registration_source": "cli",
			})
		case r.URL.Path == "/v1/agents/heartbeat" && r.Method == http.MethodPost:
			atomic.AddInt32(&heartbeatReceived, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "ag_test",
				"alias":    "tester",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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
    api_key: aw_sk_testapikey
    email: test@example.com
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "verify",
		"--code", "123456",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	outStr := string(out)
	if !strings.Contains(strings.ToLower(outStr), "verified") {
		t.Fatalf("expected 'verified' in output, got: %s", outStr)
	}
	if !strings.Contains(strings.ToLower(outStr), "active") {
		t.Fatalf("expected 'active' in output, got: %s", outStr)
	}
	if atomic.LoadInt32(&heartbeatReceived) == 0 {
		t.Fatal("expected heartbeat POST after verify, but server did not receive one")
	}
}

func TestAwVerifyInvalidCode(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/verify-code":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "INVALID_CODE",
					"message": "Invalid or expired verification code.",
				},
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "verify",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--code", "000000",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	outStr := strings.ToLower(string(out))
	if !strings.Contains(outStr, "invalid") && !strings.Contains(outStr, "expired") {
		t.Fatalf("expected 'invalid' or 'expired' in error, got: %s", string(out))
	}
}

func TestAwVerifyResolvesEmailFromConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/verify-code":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["email"] != "config@example.com" {
				t.Fatalf("email=%s, expected config@example.com", body["email"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "testuser",
				"registration_source": "cli",
			})
		case "/v1/agents/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "ag_test",
				"alias":    "tester",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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
    email: config@example.com
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No --email flag; should resolve from config.
	run := exec.CommandContext(ctx, bin, "verify",
		"--code", "123456",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "verified") {
		t.Fatalf("expected 'verified' in output, got: %s", string(out))
	}
}

func TestAwVerifyClaimsIdentity(t *testing.T) {
	t.Parallel()

	var identityClaimed bool
	var claimBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/verify-code" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "testuser",
				"registration_source": "cli",
			})
		case r.URL.Path == "/v1/agents/heartbeat" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "ag_verify",
				"alias":    "researcher",
			})
		case r.URL.Path == "/v1/agents/me/identity" && r.Method == http.MethodPut:
			identityClaimed = true
			_ = json.NewDecoder(r.Body).Decode(&claimBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     claimBody["did"],
				"custody": "self",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Config with API key and alias but no DID — verify should provision identity.
	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_verify_test
    email: test@example.com
    agent_alias: researcher
    namespace_slug: myco
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "verify",
		"--code", "123456",
	)
	run.Stdin = strings.NewReader("")
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	if err := run.Run(); err != nil {
		t.Fatalf("run failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	// ClaimIdentity must have been called.
	if !identityClaimed {
		t.Fatal("ClaimIdentity was not called after verify")
	}
	did, _ := claimBody["did"].(string)
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("ClaimIdentity did=%q, want did:key:z6Mk... prefix", did)
	}
	if claimBody["public_key"] == nil || claimBody["public_key"] == "" {
		t.Fatal("ClaimIdentity public_key is empty")
	}
	if claimBody["custody"] != "self" {
		t.Fatalf("ClaimIdentity custody=%v", claimBody["custody"])
	}

	// Config should now have DID and signing_key.
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(cfgData))
	}
	acct := cfg.Accounts["acct"]
	if acct["did"] == nil || acct["did"] == "" {
		t.Fatalf("config did is empty after verify:\n%s", string(cfgData))
	}
	if acct["signing_key"] == nil || acct["signing_key"] == "" {
		t.Fatalf("config signing_key is empty after verify:\n%s", string(cfgData))
	}
	if acct["custody"] != "self" {
		t.Fatalf("config custody=%v, want self", acct["custody"])
	}

	// Signing key file should exist on disk.
	keyPath, _ := acct["signing_key"].(string)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("signing key file not found at %s", keyPath)
	}

	// Stderr should mention the identity.
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "Identity:") {
		t.Fatalf("expected 'Identity:' in stderr, got: %s", stderrStr)
	}
}

func TestAwVerifyResolvesServerFromName(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/verify-code":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["email"] != "alice@example.com" {
				t.Fatalf("email=%s, expected alice@example.com", body["email"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verified":            true,
				"username":            "alice",
				"registration_source": "cli",
			})
		case "/v1/agents/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "ag_alice",
				"alias":    "alice",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Config with two servers; default_account points to "other" (wrong server).
	// Passing --server-name=target should select the target server's account.
	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  target:
    url: `+server.URL+`
  other:
    url: http://localhost:1
accounts:
  acct-target:
    server: target
    api_key: aw_sk_target
    email: alice@example.com
  acct-other:
    server: other
    api_key: aw_sk_other
    email: other@example.com
default_account: acct-other
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write .aw/context to map server name to account.
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "context"), []byte(strings.TrimSpace(`
default_account: acct-target
server_accounts:
  target: acct-target
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No --server-url; should resolve URL from config via --server-name.
	run := exec.CommandContext(ctx, bin, "verify",
		"--server-name", "target",
		"--code", "123456",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(strings.ToLower(string(out)), "verified") {
		t.Fatalf("expected 'verified' in output, got: %s", string(out))
	}
}

func TestAwRegisterNamespaceSlugStoredInConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":               "aw_sk_ns",
				"agent_id":              "agent-ns-1",
				"alias":                 "alice",
				"username":              "testuser",
				"email":                 "test@example.com",
				"project_slug":          "myproject",
				"project_name":          "My Project",
				"server_url":            "http://localhost:9999",
				"namespace_slug":        "mycompany",
				"verification_required": false,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	var found bool
	for name, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_ns" {
			found = true
			if acct["namespace_slug"] != "mycompany" {
				t.Fatalf("accounts.%s.namespace_slug=%v, want mycompany", name, acct["namespace_slug"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_ns in config:\n%s", string(data))
	}
}

func TestAwRegisterSendsIdentityFields(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/register":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":               "aw_sk_identity",
				"agent_id":              "agent-id-1",
				"alias":                 "alice",
				"username":              "testuser",
				"email":                 "test@example.com",
				"project_slug":          "myproject",
				"project_name":          "My Project",
				"server_url":            "http://localhost:9999",
				"verification_required": false,
				"did":                   gotBody["did"],
				"custody":               "self",
				"lifetime":              "persistent",
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "register",
		"--server-url", server.URL,
		"--email", "test@example.com",
		"--username", "testuser",
		"--alias", "alice",
		"--write-context=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify request included identity fields.
	did, _ := gotBody["did"].(string)
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("request did=%q, want did:key:z6Mk... prefix", did)
	}
	pubKey, _ := gotBody["public_key"].(string)
	if pubKey == "" {
		t.Fatal("request public_key is empty")
	}
	if gotBody["custody"] != "self" {
		t.Fatalf("request custody=%v", gotBody["custody"])
	}
	if gotBody["lifetime"] != "persistent" {
		t.Fatalf("request lifetime=%v", gotBody["lifetime"])
	}
	// ClaWeb expects handle alongside username.
	if gotBody["handle"] != "testuser" {
		t.Fatalf("request handle=%v, want testuser", gotBody["handle"])
	}

	// Verify config stores identity fields.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	var found bool
	for name, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_identity" {
			found = true
			if acct["did"] == nil || acct["did"] == "" {
				t.Fatalf("accounts.%s.did is empty", name)
			}
			if acct["signing_key"] == nil || acct["signing_key"] == "" {
				t.Fatalf("accounts.%s.signing_key is empty", name)
			}
			if acct["custody"] != "self" {
				t.Fatalf("accounts.%s.custody=%v, want self", name, acct["custody"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("accounts.%s.lifetime=%v, want persistent", name, acct["lifetime"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_identity in config:\n%s", string(data))
	}

	// Verify key files were created.
	keysDir := filepath.Join(tmp, "keys")
	keyFiles, _ := filepath.Glob(filepath.Join(keysDir, "*.signing.key"))
	if len(keyFiles) == 0 {
		t.Fatal("no signing key files created in keys directory")
	}
	pubFiles, _ := filepath.Glob(filepath.Join(keysDir, "*.signing.pub"))
	if len(pubFiles) == 0 {
		t.Fatal("no public key files created in keys directory")
	}
}

func TestAwAgentPrivacyGet(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agents": []map[string]any{
					{
						"agent_id": "agent-1",
						"alias":    "alice",
						"online":   true,
						"privacy":  "private",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "agent", "privacy")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["privacy"] != "private" {
		t.Fatalf("privacy=%v", got["privacy"])
	}
}

func TestAwAgentPrivacySet(t *testing.T) {
	t.Parallel()

	var patchBody map[string]any
	var patchPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1",
				"agent_id":   "agent-1",
				"alias":      "alice",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/agents/") && r.Method == http.MethodPatch:
			patchPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&patchBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "agent-1",
				"privacy":  patchBody["privacy"],
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
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

	run := exec.CommandContext(ctx, bin, "agent", "privacy", "private")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["agent_id"] != "agent-1" {
		t.Fatalf("agent_id=%v", got["agent_id"])
	}
	if got["privacy"] != "private" {
		t.Fatalf("privacy=%v", got["privacy"])
	}
	if patchPath != "/v1/agents/agent-1" {
		t.Fatalf("patch path=%s", patchPath)
	}
	if patchBody["privacy"] != "private" {
		t.Fatalf("patch privacy=%v", patchBody["privacy"])
	}
	// Verify access_mode is NOT sent (omitempty should suppress it).
	if _, hasAccessMode := patchBody["access_mode"]; hasAccessMode {
		t.Fatalf("access_mode should not be in patch body when only setting privacy, got: %v", patchBody)
	}
}

func TestAwMailSendHandleRoutesToDMEndpoint(t *testing.T) {
	t.Parallel()

	var dmBody map[string]any
	var dmPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/network/dm":
			dmPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&dmBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "msg-dm-1",
				"status":       "delivered",
				"delivered_at": "2026-02-21T12:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-alias", "@juanre",
		"--body", "hello from DM",
		"--subject", "test DM",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["message_id"] != "msg-dm-1" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
	if dmPath != "/v1/network/dm" {
		t.Fatalf("dm path=%s", dmPath)
	}
	if dmBody["to_handle"] != "juanre" {
		t.Fatalf("to_handle=%v, want juanre", dmBody["to_handle"])
	}
	if dmBody["body"] != "hello from DM" {
		t.Fatalf("body=%v", dmBody["body"])
	}
	if dmBody["subject"] != "test DM" {
		t.Fatalf("subject=%v", dmBody["subject"])
	}
}

func TestAwMailSendHandleEmpty(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-alias", "@",
		"--body", "hello",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for empty handle @, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "empty") || !strings.Contains(string(out), "handle") {
		t.Fatalf("expected error about empty handle, got: %s", string(out))
	}
}

func TestAwBlockNamespace(t *testing.T) {
	t.Parallel()

	var postBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/network/blocked" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&postBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address":    postBody["address"],
				"blocked_at": "2026-02-21T12:00:00Z",
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "block", "spammerco")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["address"] != "spammerco" {
		t.Fatalf("address=%v", got["address"])
	}
	if postBody["address"] != "spammerco" {
		t.Fatalf("post address=%v", postBody["address"])
	}
}

func TestAwUnblockNamespace(t *testing.T) {
	t.Parallel()

	var deletePath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/network/blocked/") && r.Method == http.MethodDelete:
			deletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "unblock", "spammerco")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletePath != "/v1/network/blocked/spammerco" {
		t.Fatalf("delete path=%s", deletePath)
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["address"] != "spammerco" {
		t.Fatalf("address=%v", got["address"])
	}
	if got["status"] != "unblocked" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAwBlockList(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/network/blocked" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blocked": []map[string]any{
					{"address": "spammerco", "blocked_at": "2026-02-21T12:00:00Z"},
					{"address": "spammerco/marketer", "blocked_at": "2026-02-21T13:00:00Z"},
				},
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "block", "list")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	blocked, ok := got["blocked"].([]any)
	if !ok || len(blocked) != 2 {
		t.Fatalf("blocked=%v", got["blocked"])
	}
}

func TestAwBlockAgentLevel(t *testing.T) {
	t.Parallel()

	var postBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/network/blocked" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&postBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address":    postBody["address"],
				"blocked_at": "2026-02-21T12:00:00Z",
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	run := exec.CommandContext(ctx, bin, "block", "spammerco/marketer")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["address"] != "spammerco/marketer" {
		t.Fatalf("address=%v", got["address"])
	}
	if postBody["address"] != "spammerco/marketer" {
		t.Fatalf("post address=%v", postBody["address"])
	}
}

func TestAwInitNamespaceRequiresAlias(t *testing.T) {
	t.Parallel()

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
    url: http://localhost:9999
accounts:
  acct:
    server: local
    api_key: cloudtoken123
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", "http://localhost:9999",
		"--target-namespace", "mycomp",
		"--namespace", "demo",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error without --alias, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "--alias") {
		t.Fatalf("expected error about --alias, got: %s", string(out))
	}
}

func TestAwInitNamespaceForcesCloudMode(t *testing.T) {
	t.Parallel()

	var bootstrapBody map[string]any
	var bootstrapCalled atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/bootstrap":
			bootstrapCalled.Store(true)
			if err := json.NewDecoder(r.Body).Decode(&bootstrapBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":       "org-1",
				"org_slug":     "mycomp",
				"org_name":     "My Company",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"project_name": "Demo",
				"server_url":   "http://localhost:9999",
				"api_key":      "aw_sk_new",
				"agent_id":     "agent-new",
				"alias":        "billing",
				"created":      true,
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"name_prefix":  "alice",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--target-namespace", "mycomp",
		"--alias", "billing",
		"--namespace", "demo",
		"--cloud-token", "jwt_token_123",
		"--write-context=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !bootstrapCalled.Load() {
		t.Fatal("expected cloud bootstrap to be called")
	}
	if bootstrapBody["namespace_slug"] != "mycomp" {
		t.Fatalf("namespace_slug=%v, want mycomp", bootstrapBody["namespace_slug"])
	}
}

func TestAwInitNamespaceStoresInConfig(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/bootstrap":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":       "org-1",
				"org_slug":     "mycomp",
				"org_name":     "My Company",
				"project_id":   "proj-1",
				"project_slug": "demo",
				"project_name": "Demo",
				"server_url":   "http://localhost:9999",
				"api_key":      "aw_sk_new",
				"agent_id":     "agent-new",
				"alias":        "billing",
				"created":      true,
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"name_prefix":  "alice",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--target-namespace", "mycomp",
		"--alias", "billing",
		"--namespace", "demo",
		"--cloud-token", "jwt_token_123",
		"--write-context=false",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	var found bool
	for name, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_new" {
			found = true
			if acct["namespace_slug"] != "mycomp" {
				t.Fatalf("accounts.%s.namespace_slug=%v, want mycomp", name, acct["namespace_slug"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_new in config:\n%s", string(data))
	}
}

func TestAwMailSendSignsWithIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := aweb.ComputeDIDKey(pub)

	// Generate a recipient key so the resolver can return a DID.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := aweb.ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/resolve/monitor", "/v1/agents/resolve/myco/monitor":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did":     recipientDID,
				"address": "myco/monitor",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	keysDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

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

	// Save the signing key to disk.
	address := "myco/agent"
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		t.Fatal(err)
	}
	keyPath := awconfig.SigningKeyPath(keysDir, address)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    did: "`+did+`"
    signing_key: "`+keyPath+`"
    custody: "self"
    default_project: "myco"
    agent_alias: "agent"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-alias", "monitor",
		"--body", "hello from identity",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify the request carries identity fields.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did on wire=%v, want %s", gotBody["to_did"], recipientDID)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing or empty")
	}
	msgID, ok := gotBody["message_id"].(string)
	if !ok || msgID == "" {
		t.Fatal("message_id missing or empty")
	}

	// Verify the signature covers canonical to address (myco/monitor),
	// matching what aweb returns in to_address on the inbox side.
	var fromStableID string
	if v, ok := gotBody["from_stable_id"].(string); ok {
		fromStableID = v
	}
	env := &aweb.MessageEnvelope{
		From:         "myco/agent",
		FromDID:      did,
		To:           "myco/monitor",
		ToDID:        recipientDID,
		Type:         "mail",
		Body:         "hello from identity",
		Timestamp:    gotBody["timestamp"].(string),
		MessageID:    msgID,
		FromStableID: fromStableID,
		Signature:    sig,
	}
	status, verifyErr := aweb.VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != aweb.Verified {
		t.Fatalf("status=%s, want verified", status)
	}
}

func TestAwMailSendSignsWithIdentityNamespace(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := aweb.ComputeDIDKey(pub)

	// Generate a recipient key so the resolver can return a DID.
	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := aweb.ComputeDIDKey(recipientPub)

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/resolve/monitor", "/v1/agents/resolve/acme/monitor":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did":     recipientDID,
				"address": "acme/monitor",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	keysDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

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

	// namespace_slug takes priority over default_project in deriveAgentAddress.
	address := "acme/bot"
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		t.Fatal(err)
	}
	keyPath := awconfig.SigningKeyPath(keysDir, address)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    did: "`+did+`"
    signing_key: "`+keyPath+`"
    custody: "self"
    namespace_slug: "acme"
    default_project: "fallback"
    agent_alias: "bot"
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-alias", "monitor",
		"--body", "hello from namespace",
	)
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify From address uses namespace_slug (not default_project).
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_did"] != recipientDID {
		t.Fatalf("to_did on wire=%v, want %s", gotBody["to_did"], recipientDID)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing")
	}

	// Verify the signature covers canonical to address (acme/monitor),
	// matching what aweb returns in to_address on the inbox side.
	var fromStableID string
	if v, ok := gotBody["from_stable_id"].(string); ok {
		fromStableID = v
	}
	env := &aweb.MessageEnvelope{
		From:         "acme/bot",
		FromDID:      did,
		To:           "acme/monitor",
		ToDID:        recipientDID,
		Type:         "mail",
		Body:         "hello from namespace",
		Timestamp:    gotBody["timestamp"].(string),
		MessageID:    gotBody["message_id"].(string),
		FromStableID: fromStableID,
		Signature:    sig,
	}
	status, verifyErr := aweb.VerifyMessage(env)
	if verifyErr != nil {
		t.Fatalf("VerifyMessage: %v", verifyErr)
	}
	if status != aweb.Verified {
		t.Fatalf("status=%s, want verified (namespace_slug should be used for From address)", status)
	}
}

func TestAwConnect(t *testing.T) {
	t.Parallel()

	var identityClaimed atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"human_name": "Alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
				"name":       "My Company",
			})
		case "/v1/agents/me/identity":
			if r.Method != http.MethodPut {
				t.Fatalf("identity endpoint: method=%s, want PUT", r.Method)
			}
			identityClaimed.Store(true)
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     req["did"],
				"custody": "self",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Write empty config — no accounts configured.
	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1", // unreachable — forces best-effort failure
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !identityClaimed.Load() {
		t.Fatal("expected /v1/agents/me/identity to be called")
	}

	// Verify config was written with identity fields.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Servers        map[string]map[string]any `yaml:"servers"`
		Accounts       map[string]map[string]any `yaml:"accounts"`
		DefaultAccount string                    `yaml:"default_account"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if cfg.DefaultAccount == "" {
		t.Fatal("default_account not set")
	}
	// Find the account with our API key.
	var found bool
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			found = true
			if acct["agent_id"] != "agent-1" {
				t.Fatalf("agent_id=%v", acct["agent_id"])
			}
			if acct["agent_alias"] != "alice" {
				t.Fatalf("agent_alias=%v", acct["agent_alias"])
			}
			if acct["namespace_slug"] != "myco" {
				t.Fatalf("namespace_slug=%v, want myco", acct["namespace_slug"])
			}
			// Verify identity fields are populated.
			did, _ := acct["did"].(string)
			if did == "" || !strings.HasPrefix(did, "did:key:z") {
				t.Fatalf("did=%v, want did:key:z...", acct["did"])
			}
			signingKey, _ := acct["signing_key"].(string)
			if signingKey == "" {
				t.Fatal("signing_key not set")
			}
			if acct["custody"] != "self" {
				t.Fatalf("custody=%v, want self", acct["custody"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("lifetime=%v, want persistent", acct["lifetime"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("no account with api_key=aw_sk_test in config:\n%s", string(data))
	}
	// Verify server entry exists.
	if len(cfg.Servers) == 0 {
		t.Fatal("no servers in config")
	}

	// Verify .aw/context was written.
	ctxPath := filepath.Join(tmp, ".aw", "context")
	if _, err := os.Stat(ctxPath); os.IsNotExist(err) {
		t.Fatal(".aw/context not written")
	}
}

func TestAwConnectPreservesExistingIdentity(t *testing.T) {
	t.Parallel()

	var identityCalled atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			identityCalled.Store(true)
			w.WriteHeader(200)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Pre-populate config with existing identity.
	pub, priv, _ := ed25519.GenerateKey(nil)
	did := aweb.ComputeDIDKey(pub)
	keysDir := filepath.Join(tmp, "keys")
	_ = os.MkdirAll(keysDir, 0o700)
	_ = awconfig.SaveKeypair(keysDir, "myco/alice", pub, priv)
	keyPath := awconfig.SigningKeyPath(keysDir, "myco/alice")

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  `+server.Listener.Addr().String()+`:
    url: `+server.URL+`
accounts:
  acct-`+server.Listener.Addr().String()+`__agent-1:
    server: `+server.Listener.Addr().String()+`
    api_key: aw_sk_test
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    did: "`+did+`"
    signing_key: "`+keyPath+`"
    custody: self
    lifetime: persistent
    stable_id: "did:claw:existing"
default_account: acct-`+server.Listener.Addr().String()+`__agent-1
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Should NOT call /v1/agents/me/identity when identity exists.
	if identityCalled.Load() {
		t.Fatal("/v1/agents/me/identity should not be called when identity already exists")
	}

	// Verify existing identity is preserved.
	data, _ := os.ReadFile(cfgPath)
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	_ = yaml.Unmarshal(data, &cfg)
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			if acct["did"] != did {
				t.Fatalf("did=%v, want %s (preserved)", acct["did"], did)
			}
			if acct["stable_id"] != "did:claw:existing" {
				t.Fatalf("stable_id=%v, want did:claw:existing (preserved)", acct["stable_id"])
			}
			break
		}
	}
}

func TestAwConnectIdentityAlreadySetNoLocalKey(t *testing.T) {
	t.Parallel()

	// Pre-create a keypair that the server will report as the agent's identity,
	// but do NOT save it to the test's keysDir — simulating key loss.
	// provisionIdentity will generate and save a different key, which won't
	// match the server's DID, triggering the "no matching key" error.
	pub, _, err := awconfig.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverDID := aweb.ComputeDIDKey(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "IDENTITY_ALREADY_SET",
					"message": "identity already bound",
				},
			})
		case "/v1/agents/resolve/myco/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":      serverDID,
				"agent_id": "agent-1",
				"address":  "myco/alice",
				"custody":  "self",
				"lifetime": "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr == nil {
		t.Fatalf("expected error for 409 with no local key, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "no matching signing key found locally") {
		t.Fatalf("expected 'no matching signing key found locally', got: %s", string(out))
	}
	if !strings.Contains(string(out), "aw reset --remote --confirm") {
		t.Fatalf("expected recovery suggestion with 'aw reset --remote --confirm', got: %s", string(out))
	}
}

func TestAwConnectRecoverWith409AndLocalKey(t *testing.T) {
	t.Parallel()

	// Pre-create a keypair that the server will report as the agent's identity.
	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverDID := aweb.ComputeDIDKey(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "IDENTITY_ALREADY_SET",
					"message": "identity already bound",
				},
			})
		case "/v1/agents/resolve/myco/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":      serverDID,
				"agent_id": "agent-1",
				"address":  "myco/alice",
				"custody":  "self",
				"lifetime": "persistent",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	// Save the keypair to the keys directory so recovery can find it.
	keysDir := filepath.Join(filepath.Dir(cfgPath), "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveKeypair(keysDir, "myco/alice", pub, priv); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1", // unreachable — best-effort
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Fatalf("expected 409 recovery to succeed, got error: %v\n%s", runErr, string(out))
	}

	// Verify config was written with recovered identity fields.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			did, _ := acct["did"].(string)
			if did != serverDID {
				t.Fatalf("did=%q, want %q", did, serverDID)
			}
			signingKey, _ := acct["signing_key"].(string)
			if signingKey == "" {
				t.Fatal("signing_key not set after recovery")
			}
			if acct["custody"] != "self" {
				t.Fatalf("custody=%v, want self", acct["custody"])
			}
			if acct["lifetime"] != "persistent" {
				t.Fatalf("lifetime=%v, want persistent", acct["lifetime"])
			}
			return
		}
	}
	t.Fatalf("no account with api_key=aw_sk_test in config:\n%s", string(data))
}

func TestAwConnectClawDIDBestEffort(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"agent_type": "agent",
			})
		case "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})
		case "/v1/agents/me/identity":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     req["did"],
				"custody": "self",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1", // unreachable
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed (should succeed despite ClawDID failure): %v\n%s", err, string(out))
	}

	// Connect should succeed with identity but no stable_id.
	data, _ := os.ReadFile(cfgPath)
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	_ = yaml.Unmarshal(data, &cfg)
	for _, acct := range cfg.Accounts {
		if acct["api_key"] == "aw_sk_test" {
			did, _ := acct["did"].(string)
			if did == "" || !strings.HasPrefix(did, "did:key:z") {
				t.Fatalf("did=%v, want did:key:z...", acct["did"])
			}
			// StableID should be empty when ClawDID is unreachable.
			if acct["stable_id"] != nil && acct["stable_id"] != "" {
				t.Fatalf("stable_id=%v, want empty (ClawDID unreachable)", acct["stable_id"])
			}
			break
		}
	}

	// Verify stderr warns about ClawDID failure.
	if !strings.Contains(string(out), "ClawDID registration failed") {
		t.Fatalf("expected warning about ClawDID failure in output: %s", string(out))
	}
}

func TestAwConnectMissingEnvVars(t *testing.T) {
	t.Parallel()

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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// No AWEB_URL or AWEB_API_KEY — should fail.
	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "AWEB_URL") {
		t.Fatalf("expected error mentioning AWEB_URL, got: %s", string(out))
	}
}

func TestAwConnectNoAgentID(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/introspect":
			// User-scoped key: no agent_id.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"user_id":    "user-1",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
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

	if err := os.WriteFile(cfgPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "connect")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_test",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for user-scoped key, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "agent-scoped") {
		t.Fatalf("expected error about agent-scoped key, got: %s", string(out))
	}
}

func TestAwResetLocal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	// Create .aw/context.
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctxPath := filepath.Join(awDir, "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "reset")
	run.Dir = tmp
	run.Env = os.Environ()
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw reset failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Removed") {
		t.Fatalf("expected 'Removed' message, got: %s", string(out))
	}
	if _, err := os.Stat(ctxPath); !os.IsNotExist(err) {
		t.Fatal(".aw/context still exists after reset")
	}
	if _, err := os.Stat(awDir); !os.IsNotExist(err) {
		t.Fatal(".aw directory still exists after reset (should be cleaned up when empty)")
	}
}

func TestAwResetRemoteNoConfirm(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

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

	run := exec.CommandContext(ctx, bin, "reset", "--remote")
	run.Dir = tmp
	run.Env = os.Environ()
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error without --confirm, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "--confirm") {
		t.Fatalf("expected --confirm guidance, got: %s", string(out))
	}
}

func TestAwResetRemote(t *testing.T) {
	t.Parallel()

	var (
		resetCalled atomic.Bool
		claimCalled atomic.Bool
	)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/me/identity/reset" && r.Method == http.MethodPost:
			resetCalled.Store(true)
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["confirm"] != true {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})

		case r.URL.Path == "/v1/agents/me/identity" && r.Method == http.MethodPut:
			claimCalled.Store(true)
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"did":     req["did"],
				"custody": "self",
			})

		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"agent_id":   "agent-1",
				"alias":      "alice",
				"agent_type": "agent",
			})

		case r.URL.Path == "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123",
				"slug":       "myco",
			})

		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
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

	// Create a pre-existing config with an old identity.
	serverName := strings.TrimPrefix(server.URL, "http://")
	cfgContent := fmt.Sprintf(`servers:
  %s:
    url: %s
accounts:
  test-acct:
    server: %s
    api_key: aw_sk_test
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    did: did:key:z6Mkold
    signing_key: /nonexistent/old.signing.key
    custody: self
    lifetime: persistent
default_account: test-acct
`, serverName, server.URL, serverName)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "reset", "--remote", "--confirm")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1", // unreachable — best-effort
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Fatalf("aw reset --remote --confirm failed: %v\n%s", runErr, string(out))
	}

	if !resetCalled.Load() {
		t.Fatal("expected POST /v1/agents/me/identity/reset to be called")
	}
	if !claimCalled.Load() {
		t.Fatal("expected PUT /v1/agents/me/identity to be called")
	}

	// Verify config was updated with new identity.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	acct, ok := cfg.Accounts["test-acct"]
	if !ok {
		t.Fatalf("test-acct not found in config:\n%s", string(data))
	}
	did, _ := acct["did"].(string)
	if did == "" || did == "did:key:z6Mkold" {
		t.Fatalf("DID not updated: %q", did)
	}
	if !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("DID format wrong: %q", did)
	}
	signingKey, _ := acct["signing_key"].(string)
	if signingKey == "" || signingKey == "/nonexistent/old.signing.key" {
		t.Fatalf("signing_key not updated: %q", signingKey)
	}
	if acct["custody"] != "self" {
		t.Fatalf("custody=%v", acct["custody"])
	}
	if acct["lifetime"] != "persistent" {
		t.Fatalf("lifetime=%v", acct["lifetime"])
	}
}

func TestAwResetRemoteWipeKeys(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/me/identity/reset" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case r.URL.Path == "/v1/agents/me/identity" && r.Method == http.MethodPut:
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok", "did": req["did"], "custody": "self",
			})
		case r.URL.Path == "/v1/auth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123", "agent_id": "agent-1",
				"alias": "alice", "agent_type": "agent",
			})
		case r.URL.Path == "/v1/projects/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-123", "slug": "myco",
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	keysDir := filepath.Join(tmp, "keys")

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

	// Create an old keypair to be wiped.
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldPub, oldPriv, err := awconfig.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveKeypair(keysDir, "myco/alice", oldPub, oldPriv); err != nil {
		t.Fatal(err)
	}
	oldKeyPath := awconfig.SigningKeyPath(keysDir, "myco/alice")

	// Verify old files exist.
	if _, err := os.Stat(oldKeyPath); err != nil {
		t.Fatalf("old key not created: %v", err)
	}

	serverName := strings.TrimPrefix(server.URL, "http://")
	cfgContent := fmt.Sprintf(`servers:
  %s:
    url: %s
accounts:
  test-acct:
    server: %s
    api_key: aw_sk_test
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    did: did:key:z6Mkold
    signing_key: %s
    custody: self
    lifetime: persistent
default_account: test-acct
`, serverName, server.URL, serverName, oldKeyPath)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "reset", "--remote", "--confirm", "--wipe-keys")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"CLAWDID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Fatalf("aw reset --remote --confirm --wipe-keys failed: %v\n%s", runErr, string(out))
	}

	// With the same address, SaveKeypair overwrites the old key in-place.
	// --wipe-keys is a no-op here since sel.SigningKey == signingKeyPath.
	// Verify the key file exists with new content.
	newKeyPath := awconfig.SigningKeyPath(keysDir, "myco/alice")
	if _, err := os.Stat(newKeyPath); err != nil {
		t.Fatalf("new key not created: %v", err)
	}
	// Verify the key on disk differs from the old one.
	newPriv, err := awconfig.LoadSigningKey(newKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	newPub := newPriv.Public().(ed25519.PublicKey)
	if newPub.Equal(oldPub) {
		t.Fatal("key was not regenerated")
	}

	// Verify config updated.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	acct := cfg.Accounts["test-acct"]
	did, _ := acct["did"].(string)
	if did == "did:key:z6Mkold" || did == "" {
		t.Fatalf("DID not updated: %q", did)
	}
}
