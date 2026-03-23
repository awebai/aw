package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

func TestAwIdentityDecommissionEphemeral(t *testing.T) {
	t.Parallel()

	var deregisterCalled atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/me" && r.Method == http.MethodDelete:
			deregisterCalled.Store(true)
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
	buildAwBinary(t, ctx, bin)

	cfg := strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_ephemeral
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    custody: managed
    lifetime: ephemeral
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "context"), []byte(strings.TrimSpace(`
default_account: acct
server_accounts:
  local: acct
client_default_accounts:
  aw: acct
`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "decommission", "--confirm")
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
	if !deregisterCalled.Load() {
		t.Fatal("expected DELETE /v1/agents/me")
	}
	if !strings.Contains(string(out), "Identity decommissioned.") {
		t.Fatalf("expected decommission output, got: %s", string(out))
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfgOut struct {
		Accounts map[string]map[string]any `yaml:"accounts"`
	}
	if err := yaml.Unmarshal(data, &cfgOut); err != nil {
		t.Fatalf("yaml: %v\n%s", err, string(data))
	}
	if len(cfgOut.Accounts) != 0 {
		t.Fatalf("expected account removal after decommission:\n%s", string(data))
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "context")); !os.IsNotExist(err) {
		t.Fatalf("expected .aw/context removal, err=%v", err)
	}
}

func TestAwIdentityDecommissionRejectsPermanent(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	cfg := strings.TrimSpace(`
servers:
  local:
    url: http://localhost:9999
accounts:
  acct:
    server: local
    api_key: aw_sk_permanent
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    custody: self
    lifetime: persistent
    did: did:key:z6MkPermanent
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "decommission", "--confirm")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "aw identity replace --successor") {
		t.Fatalf("expected permanent-identity guidance, got: %s", string(out))
	}
}

func TestAwIdentityReplace(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	var replaceCalled atomic.Bool
	var replaceBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/resolve/acme/successor" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": "successor-1",
				"did":      "did:key:z6MkSuccessor",
				"address":  "acme/successor",
			})
		case r.URL.Path == "/v1/agents/me/retire" && r.Method == http.MethodPut:
			replaceCalled.Store(true)
			if err := json.NewDecoder(r.Body).Decode(&replaceBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":             "retired",
				"agent_id":           "agent-1",
				"successor_agent_id": "successor-1",
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
	buildAwBinary(t, ctx, bin)

	keysDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveKeypair(keysDir, "myco/alice", pub, priv); err != nil {
		t.Fatal(err)
	}
	keyPath := awid.SigningKeyPath(keysDir, "myco/alice")

	cfg := strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_permanent
    agent_id: agent-1
    agent_alias: alice
    namespace_slug: myco
    custody: self
    lifetime: persistent
    did: `+did+`
    signing_key: `+keyPath+`
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "identity", "replace", "--successor", "acme/successor")
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
	if !replaceCalled.Load() {
		t.Fatal("expected PUT /v1/agents/me/retire")
	}
	if replaceBody["successor_agent_id"] != "successor-1" {
		t.Fatalf("successor_agent_id=%v", replaceBody["successor_agent_id"])
	}
	if !strings.Contains(string(out), "Identity replaced.") {
		t.Fatalf("expected replace output, got: %s", string(out))
	}
}
