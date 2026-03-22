package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindWorktreeContextPathWalksUp(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	root := filepath.Join(tmp, "repo")
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	ctxPath := filepath.Join(root, ".aw", "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: alice\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := FindWorktreeContextPath(nested)
	if err != nil {
		t.Fatalf("FindWorktreeContextPath: %v", err)
	}
	if got != ctxPath {
		t.Fatalf("path=%q want %q", got, ctxPath)
	}
}

func TestFindWorktreeContextPathStopsAtAwBoundary(t *testing.T) {
	t.Parallel()

	// Simulate two sibling worktrees under a parent:
	//   parent/
	//     project-bob/.aw/context  (bob's identity)
	//     project-alice/.aw/workspace.yaml  (alice, but NO .aw/context)
	//
	// When searching from project-alice, we must NOT walk up and
	// find project-bob's context. We should find project-alice's .aw/
	// directory (which has workspace.yaml but no context) and stop.
	tmp := t.TempDir()

	bobDir := filepath.Join(tmp, "project-bob")
	if err := os.MkdirAll(filepath.Join(bobDir, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bobDir, ".aw", "context"), []byte("default_account: bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	aliceDir := filepath.Join(tmp, "project-alice")
	if err := os.MkdirAll(filepath.Join(aliceDir, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(aliceDir, ".aw", "workspace.yaml"), []byte("alias: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Searching from alice's dir should NOT find bob's context
	_, err := FindWorktreeContextPath(aliceDir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected ErrNotExist (alice has .aw/ but no context), got err=%v", err)
	}
}

func TestFindWorktreeContextPathStopsAtParentAwDir(t *testing.T) {
	t.Parallel()

	// parent/.aw/context exists, but child also has .aw/ (without context).
	// Should NOT cross the child's .aw/ boundary to find parent's.
	tmp := t.TempDir()

	parentDir := filepath.Join(tmp, "parent")
	if err := os.MkdirAll(filepath.Join(parentDir, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parentDir, ".aw", "context"), []byte("default_account: parent\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	childDir := filepath.Join(parentDir, "child-worktree")
	if err := os.MkdirAll(filepath.Join(childDir, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := FindWorktreeContextPath(childDir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("should not cross .aw/ boundary to parent, got err=%v", err)
	}
}

func TestFindWorktreeContextPathMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	_, err := FindWorktreeContextPath(tmp)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v, want os.ErrNotExist", err)
	}
}

func TestSaveWorktreeContextToWrites0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "context")

	ctx := &WorktreeContext{
		DefaultAccount: "alice",
		ServerAccounts: map[string]string{"prod": "bob"},
	}
	if err := SaveWorktreeContextTo(path, ctx); err != nil {
		t.Fatalf("SaveWorktreeContextTo: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%o, want 600", got)
	}
}

func TestSaveWorktreeContextToRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "context")

	ctx := &WorktreeContext{
		DefaultAccount: "alice",
		ServerAccounts: map[string]string{"prod": "bob"},
		HumanAccount:   "human",
	}
	if err := SaveWorktreeContextTo(path, ctx); err != nil {
		t.Fatalf("SaveWorktreeContextTo: %v", err)
	}

	loaded, err := LoadWorktreeContextFrom(path)
	if err != nil {
		t.Fatalf("LoadWorktreeContextFrom: %v", err)
	}
	if loaded.DefaultAccount != "alice" {
		t.Fatalf("default_account=%s", loaded.DefaultAccount)
	}
	if loaded.ServerAccounts["prod"] != "bob" {
		t.Fatalf("server_accounts[prod]=%s", loaded.ServerAccounts["prod"])
	}
	if loaded.HumanAccount != "human" {
		t.Fatalf("human_account=%s", loaded.HumanAccount)
	}
}

func TestSaveWorktreeContextToReplacesExisting(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "context")

	ctx1 := &WorktreeContext{DefaultAccount: "alice"}
	if err := SaveWorktreeContextTo(path, ctx1); err != nil {
		t.Fatalf("first save: %v", err)
	}

	ctx2 := &WorktreeContext{DefaultAccount: "bob"}
	if err := SaveWorktreeContextTo(path, ctx2); err != nil {
		t.Fatalf("second save: %v", err)
	}

	loaded, err := LoadWorktreeContextFrom(path)
	if err != nil {
		t.Fatalf("LoadWorktreeContextFrom: %v", err)
	}
	if loaded.DefaultAccount != "bob" {
		t.Fatalf("default_account=%s, want bob", loaded.DefaultAccount)
	}
}

func TestSaveWorktreeContextToSingleTrailingNewline(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "context")

	ctx := &WorktreeContext{DefaultAccount: "alice"}
	if err := SaveWorktreeContextTo(path, ctx); err != nil {
		t.Fatalf("SaveWorktreeContextTo: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		t.Fatal("missing trailing newline")
	}
	if strings.HasSuffix(s, "\n\n") {
		t.Fatal("double trailing newline")
	}
}

func TestSaveWorktreeContextToNoTempFileLeftBehind(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, ".aw")
	path := filepath.Join(dir, "context")

	ctx := &WorktreeContext{DefaultAccount: "alice"}
	if err := SaveWorktreeContextTo(path, ctx); err != nil {
		t.Fatalf("SaveWorktreeContextTo: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp.") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}
