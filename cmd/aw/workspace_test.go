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

	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
)

func buildAwBinary(t *testing.T, ctx context.Context, outPath string) {
	t.Helper()
	build := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}
}

func initGitRepoWithOrigin(t *testing.T, dir, origin string) {
	t.Helper()
	commands := [][]string{
		{"git", "init"},
		{"git", "remote", "add", "origin", origin},
	}
	for _, argv := range commands {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(argv, " "), err, string(out))
		}
	}
}

func TestAwWorkspaceInitWritesWorkspaceState(t *testing.T) {
	t.Parallel()

	const workspaceID = "11111111-1111-1111-1111-111111111111"
	const projectID = "22222222-2222-2222-2222-222222222222"
	const repoID = "33333333-3333-3333-3333-333333333333"
	const origin = "https://github.com/acme/repo.git"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces/register":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			if req["role"] != "developer" {
				t.Fatalf("role=%v", req["role"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     workspaceID,
				"project_id":       projectID,
				"project_slug":     "demo",
				"repo_id":          repoID,
				"canonical_origin": "github.com/acme/repo",
				"alias":            "alice",
				"human_name":       "Alice",
				"created":          true,
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
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    agent_id: `+workspaceID+`
    agent_alias: alice
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "init", "--role", "developer")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Registered workspace alice") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}

	data, err := os.ReadFile(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.WorkspaceID != workspaceID {
		t.Fatalf("workspace_id=%s", state.WorkspaceID)
	}
	if state.ProjectID != projectID {
		t.Fatalf("project_id=%s", state.ProjectID)
	}
	if state.Alias != "alice" {
		t.Fatalf("alias=%s", state.Alias)
	}
	if state.Role != "developer" {
		t.Fatalf("role=%s", state.Role)
	}
	if state.CanonicalOrigin != "github.com/acme/repo" {
		t.Fatalf("canonical_origin=%s", state.CanonicalOrigin)
	}
}

func TestAwInitAutoAttachesRepoContext(t *testing.T) {
	t.Parallel()

	const workspaceID = "11111111-1111-1111-1111-111111111111"
	const projectID = "22222222-2222-2222-2222-222222222222"
	const repoID = "33333333-3333-3333-3333-333333333333"
	const origin = "https://github.com/acme/repo.git"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/bootstrap/headless-agent":
			http.NotFound(w, r)
		case "/v1/init":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "2026-03-10T10:00:00Z",
				"project_id":     projectID,
				"project_slug":   "demo",
				"agent_id":       workspaceID,
				"alias":          "alice",
				"api_key":        "aw_sk_test",
				"namespace_slug": "demo",
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "persistent",
			})
		case "/v1/workspaces/register":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     workspaceID,
				"project_id":       projectID,
				"project_slug":     "demo",
				"repo_id":          repoID,
				"canonical_origin": "github.com/acme/repo",
				"alias":            "alice",
				"human_name":       "Alice",
				"created":          true,
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
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init", "--namespace", "demo", "--alias", "alice")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL="+server.URL,
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "Context:    attached github.com/acme/repo") {
		t.Fatalf("expected repo attachment summary:\n%s", text)
	}

	if _, err := os.Stat(filepath.Join(repo, ".aw", "context")); err != nil {
		t.Fatalf("expected .aw/context: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.WorkspaceID != workspaceID {
		t.Fatalf("workspace_id=%s", state.WorkspaceID)
	}
	if state.CanonicalOrigin != "github.com/acme/repo" {
		t.Fatalf("canonical_origin=%s", state.CanonicalOrigin)
	}
}

func TestAwWorkspaceStatusShowsTeamState(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   selfID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"hostname":       "devbox",
						"workspace_path": "/tmp/repo",
						"repo":           "github.com/acme/repo",
						"branch":         "main",
						"claims": []map[string]any{
							{"bead_id": "TASK-001", "title": "Own task", "claimed_at": "2026-03-10T10:00:00Z"},
						},
					},
					{
						"workspace_id": peerID,
						"alias":        "bob",
						"role":         "reviewer",
						"status":       "idle",
						"last_seen":    "2026-03-10T10:05:00Z",
						"claims": []map[string]any{
							{"bead_id": "TASK-002", "title": "Peer task", "claimed_at": "2026-03-10T10:01:00Z"},
						},
					},
				},
				"has_more": false,
			})
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{
					{
						"project_id":      "proj-1",
						"resource_key":    "src/main.go",
						"holder_agent_id": selfID,
						"holder_alias":    "alice",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
					{
						"project_id":      "proj-1",
						"resource_key":    "src/review.go",
						"holder_agent_id": peerID,
						"holder_alias":    "bob",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
				},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{{"bead_id": "TASK-002", "claimants": []map[string]any{{"alias": "bob", "workspace_id": peerID}}}},
				"escalations_pending": 2,
				"timestamp":           "2026-03-10T10:10:00Z",
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
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    agent_id: `+selfID+`
    agent_alias: alice
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	state := awconfig.WorktreeWorkspace{
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
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
	text := string(out)
	for _, want := range []string{
		"## Self",
		"- Alias: alice",
		"- Context: repo_worktree",
		"## Claims",
		"TASK-001",
		"## Locks",
		"src/main.go",
		"## Team",
		"bob (reviewer) — idle, 1 claim(s)",
		"TASK-002",
		"lock src/review.go",
		"Escalations pending: 2",
		"Claim conflicts: 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestAwWorkspaceStatusWithoutLocalWorkspaceShowsAgentContext(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/workspaces/team":
			if got := r.URL.Query().Get("always_include_workspace_id"); got != selfID {
				t.Fatalf("always_include_workspace_id=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id": peerID,
						"alias":        "reviewer-jane",
						"role":         "coordinator",
						"status":       "active",
						"claims": []map[string]any{
							{"bead_id": "TASK-100", "title": "Coordinate release", "claimed_at": "2026-03-10T10:01:00Z"},
						},
					},
				},
				"has_more": false,
			})
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 1},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 1,
				"timestamp":           "2026-03-10T10:10:00Z",
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
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    agent_id: `+selfID+`
    agent_alias: coordinator
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
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
	text := string(out)
	for _, want := range []string{
		"## Self",
		"- Alias: coordinator",
		"- Context: none",
		"- Status: offline",
		"## Team",
		"reviewer-jane (coordinator) — active, 1 claim(s)",
		"TASK-100",
		"Escalations pending: 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}
