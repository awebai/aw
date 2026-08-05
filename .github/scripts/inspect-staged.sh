#!/usr/bin/env bash
# Inspect a staged release set before anything is published.
#
#   inspect-staged.sh --dist <dir> --npm <dir> --manifest <manifest.json> \
#                     --source-sha <sha> --version <X.Y.Z>
#
# Refuses, naming the item, unless ALL of the following hold:
#   - the manifest binds exactly the declared source SHA and version
#   - the payload file set is exactly the manifest's 14 files
#     (6 archives + checksums.txt + 7 npm tgz), each matching its digest
#   - checksums.txt names exactly the six archives and all six match
#   - all 12 binaries (2 per archive) stamp module github.com/awebai/aw
#     at v<version>, vcs.revision == source SHA, vcs.modified false
#     (read via `go version -m`, no binary is executed)
#   - every tgz declares version <X.Y.Z>; the main package pins its six
#     platform optionalDependencies at exactly <X.Y.Z>; every platform
#     tgz carries its two expected binaries, executable, under package/bin/

set -euo pipefail

# Matching helper, exposed for the selftest: reads `go version -m` output on
# stdin and succeeds iff the main-module line carries exactly the expected
# version. Fixed-string tab-delimited match (the check-cli-release-vcs-stamps
# form) - no regex, so BSD and GNU grep behave identically.
if [[ "${1:-}" == "--match-module-version" ]]; then
  expected="${2:?expected version required}"
  info="$(cat)"
  if grep -Fq $'\tmod\tgithub.com/awebai/aw\t'"v${expected}"$'\t' <<<"$info"; then
    exit 0
  fi
  found="$(grep -F $'\tmod\tgithub.com/awebai/aw\t' <<<"$info" | head -1)"
  printf 'REFUSE: wrong module version, expected v%s; found: %s\n' \
    "$expected" "${found:-absent}" >&2
  exit 1
fi

DIST='' NPM='' MANIFEST='' SOURCE_SHA='' VERSION=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) DIST="$2"; shift 2 ;;
    --npm) NPM="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --source-sha) SOURCE_SHA="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "inspect-staged: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DIST" && -n "$NPM" && -n "$MANIFEST" && -n "$SOURCE_SHA" && -n "$VERSION" ]] \
  || { echo "inspect-staged: all of --dist --npm --manifest --source-sha --version are required" >&2; exit 2; }

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ── manifest binds the declared identity ────────────────────────────
read -r M_SHA M_VER < <(python3 - "$MANIFEST" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(m.get("source_sha", ""), m.get("candidate_version", ""))
PY
)
[[ "$M_SHA" == "$SOURCE_SHA" ]] \
  || fail "manifest source_sha $M_SHA does not equal declared source $SOURCE_SHA"
[[ "$M_VER" == "$VERSION" ]] \
  || fail "manifest candidate_version $M_VER does not equal declared version $VERSION"

# ── canonical set digest is the digest of the files map ─────────────
python3 - "$MANIFEST" <<'PY'
import hashlib, json, sys
m = json.load(open(sys.argv[1]))
recomputed = hashlib.sha256(
    json.dumps(m.get("files", {}), sort_keys=True).encode()
).hexdigest()
declared = m.get("canonical_set_digest")
if declared != recomputed:
    sys.exit(f"REFUSE: canonical set digest {declared} does not equal the "
             f"recomputed digest of the files map {recomputed}")
PY

# ── exact file set and per-file digests ─────────────────────────────
expected_files() { python3 -c 'import json,sys; [print(k) for k in sorted(json.load(open(sys.argv[1]))["files"])]' "$MANIFEST"; }
manifest_digest() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["files"][sys.argv[2]])' "$MANIFEST" "$1"; }

locate() {
  if [[ -f "$DIST/$1" ]]; then printf '%s' "$DIST/$1";
  elif [[ -f "$NPM/$1" ]]; then printf '%s' "$NPM/$1";
  else return 1; fi
}

count=0
while IFS= read -r name; do
  path="$(locate "$name")" || fail "manifest file $name is missing from the staged set"
  actual="$(sha256 "$path")"
  [[ "$actual" == "$(manifest_digest "$name")" ]] \
    || fail "digest mismatch for $name: staged $actual does not equal the manifest"
  count=$((count + 1))
done < <(expected_files)

on_disk="$( (cd "$DIST" && ls) ; (cd "$NPM" && ls) )"
while IFS= read -r name; do
  expected_files | grep -Fxq "$name" \
    || fail "unexpected file $name is not in the manifest"
done <<<"$on_disk"
[[ "$count" -eq 14 ]] || fail "manifest binds $count files, expected exactly 14"

# ── checksums.txt: exactly six archives, all matching ───────────────
archives=()
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
  ext=tar.gz; [[ "$platform" == windows_* ]] && ext=zip
  archives+=("aw_${VERSION}_${platform}.${ext}")
done
lines="$(wc -l < "$DIST/checksums.txt" | tr -d ' ')"
[[ "$lines" == "6" ]] || fail "checksums.txt has $lines lines, expected exactly the 6 archives"
for archive in "${archives[@]}"; do
  entry="$(grep -F "  $archive" "$DIST/checksums.txt" | awk '{print $1}')" \
    || fail "checksums.txt does not name $archive"
  [[ "$entry" == "$(sha256 "$DIST/$archive")" ]] \
    || fail "checksums.txt digest for $archive does not match the staged bytes"
done

# ── 12/12 binary stamps, read without execution ─────────────────────
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stamps=0
for archive in "${archives[@]}"; do
  platform="${archive#aw_${VERSION}_}"; platform="${platform%.*}"; platform="${platform%.tar}"
  extract="$work/$platform"
  mkdir -p "$extract"
  if [[ "$archive" == *.tar.gz ]]; then
    tar -xzf "$DIST/$archive" -C "$extract"
  else
    unzip -q "$DIST/$archive" -d "$extract"
  fi
  for name in aw aweb-a2a-gw; do
    bin="$name"; [[ "$platform" == windows_* ]] && bin="$name.exe"
    [[ -f "$extract/$bin" ]] || fail "$archive lacks binary $bin"
    info="$(go version -m "$extract/$bin")"
    if ! err="$("${BASH_SOURCE[0]}" --match-module-version "$VERSION" <<<"$info" 2>&1)"; then
      fail "$archive $bin: ${err#REFUSE: }"
    fi
    grep -Fq $'\tbuild\tvcs.revision='"$SOURCE_SHA" <<<"$info" \
      || fail "$archive $bin stamps the wrong source revision, expected $SOURCE_SHA"
    grep -Fq $'\tbuild\tvcs.modified=false' <<<"$info" \
      || fail "$archive $bin is stamped vcs.modified"
    stamps=$((stamps + 1))
  done
done
[[ "$stamps" -eq 12 ]] || fail "verified $stamps binary stamps, expected 12"

# ── tgz contracts ───────────────────────────────────────────────────
tgz_version() {
  python3 - "$1" <<'PY'
import json, sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    pkg = json.load(t.extractfile("package/package.json"))
print(pkg["version"])
PY
}

for entry in \
  "aw-linux-x64:aw:aweb-a2a-gw" "aw-linux-arm64:aw:aweb-a2a-gw" \
  "aw-darwin-x64:aw:aweb-a2a-gw" "aw-darwin-arm64:aw:aweb-a2a-gw" \
  "aw-windows-x64:aw.exe:aweb-a2a-gw.exe" "aw-windows-arm64:aw.exe:aweb-a2a-gw.exe"; do
  IFS=':' read -r pkg aw_bin gw_bin <<<"$entry"
  file="$NPM/awebai-${pkg}-${VERSION}.tgz"
  [[ -f "$file" ]] || fail "platform package awebai-${pkg}-${VERSION}.tgz is missing"
  ver="$(tgz_version "$file")"
  [[ "$ver" == "$VERSION" ]] \
    || fail "awebai-${pkg} declares version $ver, expected $VERSION"
  listing="$(tar -tvzf "$file")"
  for bin in "$aw_bin" "$gw_bin"; do
    # Exact-path match on the tar listing's final field: a substring match
    # would let bin/aweb-a2a-gw satisfy a check for bin/aw.
    line="$(awk -v p="package/bin/$bin" '$NF == p' <<<"$listing" | head -1)"
    [[ -n "$line" ]] || fail "awebai-${pkg} lacks binary package/bin/$bin"
    [[ "$line" == -rwx* ]] \
      || fail "awebai-${pkg} binary package/bin/$bin is not executable"
  done
done

main_tgz="$NPM/awebai-aw-${VERSION}.tgz"
[[ -f "$main_tgz" ]] || fail "main package awebai-aw-${VERSION}.tgz is missing"
ver="$(tgz_version "$main_tgz")"
[[ "$ver" == "$VERSION" ]] || fail "main package declares version $ver, expected $VERSION"
python3 - "$main_tgz" "$VERSION" <<'PY'
import json, sys, tarfile
path, version = sys.argv[1], sys.argv[2]
with tarfile.open(path) as t:
    pkg = json.load(t.extractfile("package/package.json"))
deps = pkg.get("optionalDependencies", {})
expected = {
    f"@awebai/aw-{p}" for p in
    ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64",
     "windows-x64", "windows-arm64")
}
if set(deps) != expected:
    sys.exit(f"REFUSE: main package optionalDependencies are {sorted(deps)}, "
             f"expected exactly {sorted(expected)}")
bad = {k: v for k, v in deps.items() if v != version}
if bad:
    sys.exit(f"REFUSE: optionalDependencies not pinned at exactly {version}: {bad}")
PY

echo "INSPECT OK: 12/12 stamps at v$VERSION/$SOURCE_SHA; 14/14 digests; checksums.txt 6/6; 7 tgz coherent"
