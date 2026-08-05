#!/usr/bin/env bash
# Self-test for the release lane scripts, no network required.
#
# Builds a derived fixture repository (module github.com/awebai/aw, local
# unpushed tag - the same mechanism the stage lane uses), produces the six
# archives + checksums.txt + seven tgz + manifest.json, then asserts:
#   green: inspect-staged.sh accepts the coherent staged set
#   reds:  corrupt archive bytes, wrong manifest digest, wrong source SHA,
#          wrong version, missing file, tgz without an executable platform
#          binary, wrong checksums.txt digest, adoption mismatch
# Every red must refuse naming the item; the green run must report 12/12.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="0.0.1"
PASS=0

fail() { printf 'SELFTEST FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ── fixture source repository with a local unpushed tag ─────────────
fixture="$tmp/src"
mkdir -p "$fixture/cmd/aw" "$fixture/cmd/aweb-a2a-gw"
cat > "$fixture/go.mod" <<EOF
module github.com/awebai/aw

go 1.24
EOF
for name in aw aweb-a2a-gw; do
  cat > "$fixture/cmd/$name/main.go" <<EOF
package main

import "fmt"

func main() { fmt.Println("$name selftest fixture") }
EOF
done
git -C "$fixture" init -q -b main
git -C "$fixture" config user.email selftest@example.invalid
git -C "$fixture" config user.name selftest
git -C "$fixture" add -A
git -C "$fixture" commit -qm fixture
git -C "$fixture" tag "v$VERSION"
SOURCE_SHA="$(git -C "$fixture" rev-parse HEAD)"

# ── build 12 binaries and assemble the six archives ─────────────────
dist="$tmp/dist"
mkdir -p "$dist"
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
  goos="${platform%%_*}"; goarch="${platform##*_}"
  ext=tar.gz; [[ "$goos" == windows ]] && ext=zip
  stage="$tmp/build/$platform"
  mkdir -p "$stage"
  for name in aw aweb-a2a-gw; do
    out="$name"; [[ "$goos" == windows ]] && out="$name.exe"
    (cd "$fixture" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      GOCACHE="$tmp/go-cache" GOFLAGS=-buildvcs=true \
      go build -o "$stage/$out" "./cmd/$name")
  done
  if [[ "$ext" == "tar.gz" ]]; then
    tar -czf "$dist/aw_${VERSION}_${platform}.tar.gz" -C "$stage" .
  else
    (cd "$stage" && zip -q "$dist/aw_${VERSION}_${platform}.zip" ./*)
  fi
done
(cd "$dist" && for f in aw_*; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done > checksums.txt)

# ── stage the seven npm tgz from the staged archives ────────────────
tgz="$tmp/tgz"
"$SCRIPT_DIR/stage-npm.sh" --dist "$dist" --out "$tgz" --version "$VERSION" --source-root "$REPO_ROOT" >/dev/null \
  || fail "stage-npm.sh refused a coherent staged set"
ok "stage-npm produced 7 tgz from staged archives"

# ── manifest over the 14 payload files ──────────────────────────────
manifest="$tmp/manifest.json"
python3 - "$dist" "$tgz" "$manifest" "$VERSION" "$SOURCE_SHA" <<'PY'
import hashlib, json, os, sys
dist, tgz, out, version, sha = sys.argv[1:6]
files = {}
for d in (dist, tgz):
    for name in sorted(os.listdir(d)):
        with open(os.path.join(d, name), "rb") as f:
            files[name] = hashlib.sha256(f.read()).hexdigest()
canonical = hashlib.sha256(
    json.dumps(files, sort_keys=True).encode()
).hexdigest()
with open(out, "w") as f:
    json.dump({
        "mode": "stage-only",
        "tag": f"v{version}",
        "candidate_version": version,
        "source_sha": sha,
        "files": files,
        "canonical_set_digest": canonical,
    }, f, indent=2, sort_keys=True)
PY

inspect() {
  "$SCRIPT_DIR/inspect-staged.sh" \
    --dist "$1" --npm "$2" --manifest "$3" \
    --source-sha "$4" --version "$5" 2>&1
}

# ── green: the coherent set passes and reports 12/12 ────────────────
out="$(inspect "$dist" "$tgz" "$manifest" "$SOURCE_SHA" "$VERSION")" \
  || fail "inspect refused the coherent staged set: $out"
grep -q "12/12" <<<"$out" || fail "inspect did not report 12/12 stamps: $out"
ok "inspect accepts the coherent set with 12/12 stamps"

expect_refusal() {
  local label="$1" needle="$2"; shift 2
  local out
  if out="$(inspect "$@")"; then
    fail "$label: inspect accepted what it must refuse"
  fi
  grep -qi "$needle" <<<"$out" \
    || fail "$label: refusal does not name the item ($needle): $out"
  ok "$label refused, naming: $needle"
}

clone_set() {
  rm -rf "$tmp/mut"; mkdir -p "$tmp/mut"
  cp -R "$dist" "$tmp/mut/dist"; cp -R "$tgz" "$tmp/mut/tgz"
  cp "$manifest" "$tmp/mut/manifest.json"
}

# ── red: corrupted archive bytes ────────────────────────────────────
clone_set
printf 'x' >> "$tmp/mut/dist/aw_${VERSION}_linux_amd64.tar.gz"
expect_refusal "corrupt archive" "linux_amd64" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: corrupted tgz bytes ────────────────────────────────────────
clone_set
tgz_file="$(ls "$tmp/mut/tgz"/awebai-aw-[0-9]*.tgz)"
printf 'x' >> "$tgz_file"
expect_refusal "corrupt tgz" "$(basename "$tgz_file")" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: manifest digest entry wrong ────────────────────────────────
clone_set
python3 - "$tmp/mut/manifest.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    m = json.load(f)
name = sorted(m["files"])[0]
m["files"][name] = "0" * 64
with open(path, "w") as f:
    json.dump(m, f)
PY
expect_refusal "wrong manifest digest" "digest" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: wrong source SHA ───────────────────────────────────────────
clone_set
expect_refusal "wrong source sha" "source" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" \
  "0000000000000000000000000000000000000000" "$VERSION"

# ── red: wrong version ──────────────────────────────────────────────
clone_set
expect_refusal "wrong version" "version" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "9.9.9"

# ── red: missing payload file ───────────────────────────────────────
clone_set
rm "$tmp/mut/dist/checksums.txt"
expect_refusal "missing file" "checksums.txt" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: platform tgz without an executable binary ──────────────────
clone_set
plat_tgz="$(ls "$tmp/mut/tgz"/awebai-aw-linux-x64-*.tgz)"
rework="$tmp/mut/rework"; mkdir -p "$rework"
tar -xzf "$plat_tgz" -C "$rework"
rm "$rework/package/bin/aw"
rm "$plat_tgz"
tar -czf "$plat_tgz" -C "$rework" package
python3 - "$tmp/mut/manifest.json" "$plat_tgz" <<'PY'
import hashlib, json, os, sys
path, tgz = sys.argv[1], sys.argv[2]
with open(path) as f:
    m = json.load(f)
with open(tgz, "rb") as f:
    m["files"][os.path.basename(tgz)] = hashlib.sha256(f.read()).hexdigest()
m["canonical_set_digest"] = hashlib.sha256(
    json.dumps(m["files"], sort_keys=True).encode()
).hexdigest()
with open(path, "w") as f:
    json.dump(m, f)
PY
expect_refusal "tgz missing executable binary" "bin/aw" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: checksums.txt digest mismatch ──────────────────────────────
clone_set
python3 - "$tmp/mut/dist/checksums.txt" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines()
first = lines[0].split()
lines[0] = "0" * 64 + "  " + first[1]
open(path, "w").write("\n".join(lines) + "\n")
PY
python3 - "$tmp/mut/manifest.json" "$tmp/mut/dist/checksums.txt" <<'PY'
import hashlib, json, sys
path, cks = sys.argv[1], sys.argv[2]
with open(path) as f:
    m = json.load(f)
with open(cks, "rb") as f:
    m["files"]["checksums.txt"] = hashlib.sha256(f.read()).hexdigest()
m["canonical_set_digest"] = hashlib.sha256(
    json.dumps(m["files"], sort_keys=True).encode()
).hexdigest()
with open(path, "w") as f:
    json.dump(m, f)
PY
expect_refusal "checksums.txt mismatch" "checksums.txt" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── red: canonical set digest mismatch ──────────────────────────────
clone_set
python3 - "$tmp/mut/manifest.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    m = json.load(f)
m["canonical_set_digest"] = "0" * 64
with open(path, "w") as f:
    json.dump(m, f)
PY
expect_refusal "canonical set digest mismatch" "canonical" \
  "$tmp/mut/dist" "$tmp/mut/tgz" "$tmp/mut/manifest.json" "$SOURCE_SHA" "$VERSION"

# ── publishability: stage-only manifests publish, others never ──────
"$SCRIPT_DIR/continue-publish.sh" --require-publishable "$manifest" \
  || fail "a stage-only manifest was refused publication"
ok "stage-only manifest is publishable"
clone_set
python3 - "$tmp/mut/manifest.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    m = json.load(f)
m["mode"] = "verify-only"
with open(path, "w") as f:
    json.dump(m, f)
PY
if "$SCRIPT_DIR/continue-publish.sh" --require-publishable "$tmp/mut/manifest.json" 2>/dev/null; then
  fail "a verify-only manifest was accepted for publication"
fi
ok "verify-only manifest refused for publication"

# ── input literals: well-formed accepted, malformed refused ─────────
"$SCRIPT_DIR/validate-inputs.sh" \
  --sha "$SOURCE_SHA" --version "$VERSION" \
  --digest "sha256:$(sha256 "$manifest")" --run-id 12345 --artifact-id 678 \
  || fail "well-formed input literals were refused"
ok "well-formed input literals accepted"
for bad in \
  "--sha not-a-sha" \
  "--sha ${SOURCE_SHA:0:39}" \
  "--version 1.2" \
  "--version v1.2.3" \
  "--digest $(sha256 "$manifest")" \
  "--digest sha256:short" \
  "--run-id 12x45" \
  "--artifact-id ''"; do
  # shellcheck disable=SC2086
  if "$SCRIPT_DIR/validate-inputs.sh" $bad 2>/dev/null; then
    fail "malformed input accepted: $bad"
  fi
done
ok "malformed input literals refused (8 forms)"

# ── adoption: exact bytes adopt, different bytes refuse ─────────────
staged_file="$dist/aw_${VERSION}_linux_amd64.tar.gz"
cp "$staged_file" "$tmp/observed-equal"
"$SCRIPT_DIR/continue-publish.sh" --check-adopt "$staged_file" "$tmp/observed-equal" \
  || fail "adoption refused byte-identical remote state"
ok "adoption accepts byte-identical remote state"
printf 'x' >> "$tmp/observed-equal"
if "$SCRIPT_DIR/continue-publish.sh" --check-adopt "$staged_file" "$tmp/observed-equal" 2>/dev/null; then
  fail "adoption accepted mismatched remote bytes"
fi
ok "adoption refuses mismatched remote bytes"

printf 'SELFTEST OK: %d assertions\n' "$PASS"
