package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
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
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["project_id"] != "proj-123" {
		t.Fatalf("project_id=%v", got["project_id"])
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

	run := exec.CommandContext(ctx, bin, "introspect", "--server", "b")
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
	if err := json.Unmarshal(out, &got); err != nil {
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
	if err := json.Unmarshal(out, &got); err != nil {
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

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--print-exports=false", "--write-context=false")
	// Ensure non-TTY mode so aw init doesn't prompt during tests.
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
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
	if err := json.Unmarshal(out, &got); err != nil {
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
	if err := json.Unmarshal(out, &got); err != nil {
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
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["resource_key"] != "my-lock" {
		t.Fatalf("resource_key=%v", got["resource_key"])
	}
	if got["status"] != "renewed" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAwProject(t *testing.T) {
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

	run := exec.CommandContext(ctx, bin, "project")
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
	if err := json.Unmarshal(out, &got); err != nil {
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
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["revoked_count"] != float64(2) {
		t.Fatalf("revoked_count=%v", got["revoked_count"])
	}
}

func TestAwChatSendPositionalArgs(t *testing.T) {
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

	run := exec.CommandContext(ctx, bin, "chat", "send", "--leave-conversation", "bob", "hello there")
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
	if err := json.Unmarshal(out, &got); err != nil {
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

func TestAwChatSendMissingArgs(t *testing.T) {
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
	run := exec.CommandContext(ctx, bin, "chat", "send")
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

func TestAwChatSendExtraArgsRejected(t *testing.T) {
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

	run := exec.CommandContext(ctx, bin, "chat", "send", "bob", "hello", "extra-arg")
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

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--server", "local", "--url", server.URL, "--account", "acct", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
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
	if acct["default_project"] != "demo" {
		t.Fatalf("accounts.acct.default_project=%v", acct["default_project"])
	}
	if acct["agent_id"] != "agent-alice" {
		t.Fatalf("accounts.acct.agent_id=%v", acct["agent_id"])
	}
	if acct["agent_alias"] != "alice" {
		t.Fatalf("accounts.acct.agent_alias=%v", acct["agent_alias"])
	}
}

func TestAwInitFallsBackToCloudBootstrap(t *testing.T) {
	t.Parallel()

	var initCalls int
	var cloudBootstrapCalls int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/init":
			initCalls++
			http.NotFound(w, r)
		case "/api/v1/agents/bootstrap":
			cloudBootstrapCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer cloud_jwt_token" {
				t.Fatalf("auth=%q", got)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["alias"] != "researcher" {
				t.Fatalf("alias=%v", payload["alias"])
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=cloud_jwt_token",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_cloud" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if got["project_slug"] != "default" {
		t.Fatalf("project_slug=%v", got["project_slug"])
	}
	if initCalls != 1 {
		t.Fatalf("initCalls=%d", initCalls)
	}
	if cloudBootstrapCalls != 1 {
		t.Fatalf("cloudBootstrapCalls=%d", cloudBootstrapCalls)
	}
}

func TestAwInitCloudFallbackNormalizesAPIPrefixedBaseURL(t *testing.T) {
	t.Parallel()

	var gotInitPath string
	var gotCloudPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init":
			gotInitPath = r.URL.Path
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Endpoint not available in Cloud mode"})
		case "/api/v1/agents/bootstrap":
			gotCloudPath = r.URL.Path
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
				"created":            false,
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
	build.Dir = filepath.Clean(filepath.Join(wd, "..", "..")) // module root (aweb-go)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false", "--url", server.URL+"/api")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=cloud_jwt_token",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["api_key"] != "aw_sk_cloud" {
		t.Fatalf("api_key=%v", got["api_key"])
	}
	if gotInitPath != "/api/v1/init" {
		t.Fatalf("gotInitPath=%q", gotInitPath)
	}
	if gotCloudPath != "/api/v1/agents/bootstrap" {
		t.Fatalf("gotCloudPath=%q", gotCloudPath)
	}
}

func TestAwInitCloudFallbackRequiresCloudToken(t *testing.T) {
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

	run := exec.CommandContext(ctx, bin, "init", "--project-slug", "demo", "--alias", "researcher", "--print-exports=false", "--write-context=false")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
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

func TestAwChatSendFlagsAfterPositionalArgs(t *testing.T) {
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

	// Flags AFTER positional args — the main reason for the cobra migration.
	run := exec.CommandContext(ctx, bin, "chat", "send", "bob", "hello there", "--leave-conversation")
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
	if err := json.Unmarshal(out, &got); err != nil {
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
