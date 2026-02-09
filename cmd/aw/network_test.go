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

func TestMailSendNetworkAddressRoutesToCloudEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/mail":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "net-msg-1",
				"status":       "sent",
				"delivered_at": "2026-02-06T00:00:00Z",
				"from_address": "myorg/me",
				"to_address":   "acme/researcher",
			})
			case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`/api
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--to-alias", "acme/researcher", "--body", "hello network")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/network/mail" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotBody["to_address"] != "acme/researcher" {
		t.Fatalf("to_address=%v", gotBody["to_address"])
	}
	if gotBody["body"] != "hello network" {
		t.Fatalf("body=%v", gotBody["body"])
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["message_id"] != "net-msg-1" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
}

func TestMailSendPlainAliasRoutesToOSSEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			gotPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "oss-msg-1",
				"status":       "sent",
				"delivered_at": "2026-02-06T00:00:00Z",
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
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
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--to-alias", "bob", "--body", "hello local")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/v1/messages" {
		t.Fatalf("path=%s", gotPath)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["message_id"] != "oss-msg-1" {
		t.Fatalf("message_id=%v", got["message_id"])
	}
}

func TestChatSendNetworkAddressRoutesToCloudEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/chat":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "net-sess-1",
				"message_id":        "net-msg-1",
				"participants":      []string{"myorg/me", "acme/bot"},
				"sse_url":           "/api/v1/network/chat/net-sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
			case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`/api
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    agent_alias: eve
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "acme/bot", "hello network")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if gotPath != "/api/v1/network/chat" {
		t.Fatalf("path=%s", gotPath)
	}
	addrs, ok := gotBody["to_addresses"].([]any)
	if !ok || len(addrs) != 1 || addrs[0] != "acme/bot" {
		t.Fatalf("to_addresses=%v", gotBody["to_addresses"])
	}
	if gotBody["message"] != "hello network" {
		t.Fatalf("message=%v", gotBody["message"])
	}
	if gotBody["leaving"] != true {
		t.Fatalf("leaving=%v", gotBody["leaving"])
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["session_id"] != "net-sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}
}

func TestDirectorySearch(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/directory":
			if r.URL.Query().Get("capability") != "translate" {
				t.Fatalf("capability=%s", r.URL.Query().Get("capability"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agents": []map[string]any{{
					"org_slug":     "acme",
					"org_name":     "Acme Corp",
					"alias":        "translator",
					"capabilities": []string{"translate"},
					"description":  "Translates things",
				}},
				"total": 1,
			})
			case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`/api
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "directory", "--capability", "translate")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["total"] != float64(1) {
		t.Fatalf("total=%v", got["total"])
	}
	agents := got["agents"].([]any)
	first := agents[0].(map[string]any)
	if first["alias"] != "translator" {
		t.Fatalf("alias=%v", first["alias"])
	}
}

func TestDirectoryGetByAddress(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/network/directory/acme/researcher":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_slug":     "acme",
				"org_name":     "Acme Corp",
				"alias":        "researcher",
				"capabilities": []string{"research"},
				"description":  "Research agent",
			})
			case "/api/v1/agents/heartbeat":
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
	wd, _ := os.Getwd()
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`/api
accounts:
  acct:
    server: local
    api_key: aw_sk_test
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "directory", "acme/researcher")
	run.Env = append(os.Environ(), "AW_CONFIG_PATH="+cfgPath, "AWEB_URL=", "AWEB_API_KEY=")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got["alias"] != "researcher" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["org_slug"] != "acme" {
		t.Fatalf("org_slug=%v", got["org_slug"])
	}
}
