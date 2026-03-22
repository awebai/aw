package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/awebai/aw/awconfig"
)

func TestAwInitHeadlessBootstrapAgainstHosted(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	var gotAuth string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "deploy-bot", "roles": []string{}})
		case "/api/v1/bootstrap/headless-agent":
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":       "org-1",
				"org_slug":     "myteam",
				"project_id":   "proj-1",
				"project_slug": "default",
				"namespace":    "myteam.aweb.ai",
				"agent_id":     "agent-1",
				"alias":        "deploy-bot",
				"address":      "myteam.aweb.ai/deploy-bot",
				"api_key":      "aw_sk_headless_test",
				"did":          "did:key:z6MkTest",
				"stable_id":    "stable-1",
				"custody":      "self",
				"lifetime":     "persistent",
				"created":      true,
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

	// No config, no tokens, no API key — headless path.
	run := exec.CommandContext(ctx, bin, "init",
		"--namespace", "myteam",
		"--alias", "deploy-bot",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_NAMESPACE=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Should have hit the headless endpoint.
	if gotPath != "/api/v1/bootstrap/headless-agent" {
		t.Fatalf("expected headless endpoint, got path=%q", gotPath)
	}

	// Should be unauthenticated.
	if gotAuth != "" {
		t.Fatalf("expected no auth header, got %q", gotAuth)
	}

	// Verify request body.
	if gotBody["namespace_slug"] != "myteam" {
		t.Fatalf("namespace_slug=%v", gotBody["namespace_slug"])
	}
	if gotBody["alias"] != "deploy-bot" {
		t.Fatalf("alias=%v", gotBody["alias"])
	}
	if _, ok := gotBody["did"]; !ok {
		t.Fatal("missing did in request")
	}
	if _, ok := gotBody["public_key"]; !ok {
		t.Fatal("missing public_key in request")
	}

	// Verify JSON response.
	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["alias"] != "deploy-bot" {
		t.Fatalf("alias=%v", resp["alias"])
	}
	if resp["api_key"] != "aw_sk_headless_test" {
		t.Fatalf("api_key=%v", resp["api_key"])
	}

	// Verify config was written.
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg awconfig.GlobalConfig
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// Should have an account with the headless API key.
	found := false
	for _, acct := range cfg.Accounts {
		if acct.APIKey == "aw_sk_headless_test" {
			found = true
			if acct.AgentAlias != "deploy-bot" {
				t.Fatalf("agent_alias=%q", acct.AgentAlias)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected account with headless API key in config:\n%s", string(cfgData))
	}
}

func TestAwInitIgnoresExistingConfigKeys(t *testing.T) {
	t.Parallel()

	// Init should NOT use existing aw_sk_ keys from config to bootstrap.
	// It should try headless first, even when config has keys.
	var gotPath string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "reviewer", "roles": []string{}})
		case "/api/v1/bootstrap/headless-agent":
			gotPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id":       "org-1",
				"org_slug":     "myteam",
				"project_id":   "proj-1",
				"project_slug": "default",
				"namespace":    "myteam.aweb.ai",
				"agent_id":     "agent-2",
				"alias":        "reviewer",
				"address":      "myteam.aweb.ai/reviewer",
				"api_key":      "aw_sk_new_agent",
				"did":          "did:key:z6MkTest2",
				"stable_id":    "stable-2",
				"custody":      "self",
				"lifetime":     "persistent",
				"created":      true,
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

	// Config has an existing aw_sk_ key — init should ignore it.
	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  existing:
    server: local
    api_key: aw_sk_existing
default_account: existing
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "init",
		"--namespace", "myteam",
		"--alias", "reviewer",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_NAMESPACE=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Should have used headless, NOT /v1/init with existing key.
	if gotPath != "/api/v1/bootstrap/headless-agent" {
		t.Fatalf("expected headless bootstrap, got path=%q", gotPath)
	}
}

func TestAwInitSelfHostedStillUsesV1Init(t *testing.T) {
	t.Parallel()

	var gotPath string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "deploy-bot", "roles": []string{}})
		case "/api/v1/bootstrap/headless-agent":
			// Self-hosted server doesn't have this endpoint.
			http.NotFound(w, r)
		case "/v1/init":
			gotPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"project_id":   "proj-1",
				"project_slug": "default",
				"agent_id":     "agent-1",
				"alias":        "deploy-bot",
				"api_key":      "aw_sk_selfhost",
				"created":      true,
				"did":          "did:key:z6MkTest3",
				"custody":      "self",
				"lifetime":     "persistent",
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

	// Explicit --server-url to non-hosted server, no config → self-hosted /v1/init.
	run := exec.CommandContext(ctx, bin, "init",
		"--server-url", server.URL,
		"--namespace", "myteam",
		"--alias", "deploy-bot",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_NAMESPACE=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotPath != "/v1/init" {
		t.Fatalf("expected /v1/init, got path=%q", gotPath)
	}
}

func TestAwInitHeadlessRetryOnAliasCollision(t *testing.T) {
	t.Parallel()

	// On a hosted server: headless bootstrap succeeds for the first call
	// with a suggested alias, but the alias is already taken (created=false
	// shouldn't happen with headless — it would 409 — but the retry logic
	// must still handle the self-hosted fallback case where /v1/init returns
	// created=false). The retry should go directly to /v1/init with nil alias.
	initCalls := 0

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/bootstrap/headless-agent":
			http.NotFound(w, r)
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "myteam",
				"project_id":   nil,
				"name_prefix":  "alice",
			})
		case "/v1/init":
			initCalls++
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)

			if payload["alias"] != nil {
				// First call: alias "alice" collides.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"project_id":   "proj-1",
					"project_slug": "myteam",
					"agent_id":     "agent-1",
					"alias":        "alice",
					"api_key":      "aw_sk_test",
					"created":      false,
					"did":          "did:key:z6MkTest",
					"custody":      "self",
					"lifetime":     "persistent",
				})
			} else {
				// Retry: server allocates alias.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       "ok",
					"project_id":   "proj-1",
					"project_slug": "myteam",
					"agent_id":     "agent-2",
					"alias":        "alice-2",
					"api_key":      "aw_sk_retry",
					"created":      true,
					"did":          "did:key:z6MkTest2",
					"custody":      "self",
					"lifetime":     "persistent",
				})
			}
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

	// No --alias, no API key → headless 404s → /v1/init with suggested alias → collision → retry.
	run := exec.CommandContext(ctx, bin, "init",
		"--namespace", "myteam",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_NAMESPACE=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if initCalls != 2 {
		t.Fatalf("expected 2 /v1/init calls (first + retry), got %d", initCalls)
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["alias"] != "alice-2" {
		t.Fatalf("alias=%v, want alice-2 (server-allocated)", resp["alias"])
	}
}

func TestAwInitHeadlessWithAPIMount(t *testing.T) {
	t.Parallel()

	// Server where the aweb API is mounted at /api. resolveWorkingBaseURL
	// will resolve to server.URL+"/api". The headless endpoint must not
	// double the /api prefix.
	var gotPath string

	// Use raw httptest.Server to avoid the newLocalHTTPServer heartbeat
	// wrapper that responds on /v1/agents/heartbeat (we need the root
	// heartbeat to 404 so the resolver picks /api as the base).
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("/api/v1/bootstrap/headless-agent", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"org_id":       "org-1",
			"org_slug":     "myteam",
			"project_id":   "proj-1",
			"project_slug": "default",
			"namespace":    "myteam.aweb.ai",
			"agent_id":     "agent-1",
			"alias":        "deploy-bot",
			"address":      "myteam.aweb.ai/deploy-bot",
			"api_key":      "aw_sk_api_mount",
			"did":          "did:key:z6MkTest4",
			"stable_id":    "stable-4",
			"custody":      "self",
			"lifetime":     "persistent",
			"created":      true,
		})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

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

	// AWEB_URL will trigger resolveWorkingBaseURL which probes /api
	// and resolves to server.URL+"/api".
	run := exec.CommandContext(ctx, bin, "init",
		"--namespace", "myteam",
		"--alias", "deploy-bot",
		"--json",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AWEB_CLOUD_TOKEN=",
		"AWEB_API_KEY=",
		"AWEB_NAMESPACE=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotPath != "/api/v1/bootstrap/headless-agent" {
		t.Fatalf("expected /api/v1/bootstrap/headless-agent, got path=%q", gotPath)
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["api_key"] != "aw_sk_api_mount" {
		t.Fatalf("api_key=%v", resp["api_key"])
	}
}
