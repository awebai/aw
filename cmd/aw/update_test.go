package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.7.0", -1},
		{"0.7.0", "0.7.0", 0},
		{"1.0.0", "0.9.0", 1},
		{"0.6.0", "0.10.0", -1},
		{"1.2.3", "1.2.3", 0},
		{"2.0.0", "1.99.99", 1},
		{"0.0.1", "0.0.2", -1},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.a, tt.b), func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFetchLatestRelease(t *testing.T) {
	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets": []map[string]interface{}{
			{"name": "aw_0.7.0_darwin_arm64.tar.gz", "browser_download_url": "https://example.com/aw_0.7.0_darwin_arm64.tar.gz"},
			{"name": "aw_0.7.0_linux_amd64.tar.gz", "browser_download_url": "https://example.com/aw_0.7.0_linux_amd64.tar.gz"},
			{"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/awebai/aw/releases/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	info, err := fetchLatestRelease(3, server.URL)
	if err != nil {
		t.Fatalf("fetchLatestRelease failed: %v", err)
	}

	if info.TagName != "v0.7.0" {
		t.Errorf("TagName = %q, want %q", info.TagName, "v0.7.0")
	}
	if len(info.Assets) != 3 {
		t.Errorf("got %d assets, want 3", len(info.Assets))
	}
	if info.Assets[0].Name != "aw_0.7.0_darwin_arm64.tar.gz" {
		t.Errorf("first asset name = %q, want %q", info.Assets[0].Name, "aw_0.7.0_darwin_arm64.tar.gz")
	}
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile")
	content := []byte("hello world")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(content)
	correctChecksum := fmt.Sprintf("%x", hash)

	t.Run("correct checksum passes", func(t *testing.T) {
		if err := verifyChecksum(filePath, correctChecksum); err != nil {
			t.Errorf("verifyChecksum with correct checksum failed: %v", err)
		}
	})

	t.Run("wrong checksum fails", func(t *testing.T) {
		err := verifyChecksum(filePath, "0000000000000000000000000000000000000000000000000000000000000000")
		if err == nil {
			t.Error("verifyChecksum with wrong checksum should fail")
		}
		if !strings.Contains(err.Error(), "checksum mismatch") {
			t.Errorf("error should mention checksum mismatch, got: %v", err)
		}
	})
}

func TestExtractBinary(t *testing.T) {
	binaryContent := []byte("#!/bin/bash\necho hello\n")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "aw",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	dir := t.TempDir()
	archivePath := filepath.Join(dir, "aw_0.7.0_linux_amd64.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := extractBinary(archivePath, "aw", destDir); err != nil {
		t.Fatalf("extractBinary failed: %v", err)
	}

	extracted, err := os.ReadFile(filepath.Join(destDir, "aw"))
	if err != nil {
		t.Fatalf("reading extracted binary: %v", err)
	}
	if !bytes.Equal(extracted, binaryContent) {
		t.Error("extracted binary content does not match original")
	}
}

func TestSelfUpdate_DevVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "dev"

	var buf bytes.Buffer
	err := selfUpdate(&buf, "")
	if err != nil {
		t.Fatalf("selfUpdate returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "dev build") {
		t.Errorf("expected dev build warning, got: %s", output)
	}
}

func TestSelfUpdate_AlreadyCurrent(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.7.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	err := selfUpdate(&buf, server.URL)
	if err != nil {
		t.Fatalf("selfUpdate returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "already the latest") {
		t.Errorf("expected 'already the latest', got: %s", output)
	}
}

func TestCheckLatestVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.6.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	checkLatestVersion(&buf, server.URL)

	output := buf.String()
	if !strings.Contains(output, "Update available") {
		t.Errorf("expected update hint, got: %s", output)
	}
	if !strings.Contains(output, "0.6.0") || !strings.Contains(output, "0.7.0") {
		t.Errorf("expected both versions in output, got: %s", output)
	}
}

func TestCheckLatestVersion_AlreadyCurrent(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "0.7.0"

	release := map[string]interface{}{
		"tag_name": "v0.7.0",
		"assets":   []map[string]interface{}{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	var buf bytes.Buffer
	checkLatestVersion(&buf, server.URL)

	output := buf.String()
	if output != "" {
		t.Errorf("expected no output when current, got: %s", output)
	}
}

func TestCheckLatestVersion_DevVersion(t *testing.T) {
	oldVersion := version
	defer func() { version = oldVersion }()
	version = "dev"

	var buf bytes.Buffer
	checkLatestVersion(&buf, "http://localhost:0")

	output := buf.String()
	if output != "" {
		t.Errorf("expected no output for dev version, got: %s", output)
	}
}
