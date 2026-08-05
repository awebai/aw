#!/usr/bin/env bash
# Pack the seven npm packages from already-staged release archives.
#
# Inputs are the staged goreleaser archives; outputs are the exact tgz files
# that publication ships. Nothing here talks to a registry.
#
#   stage-npm.sh --dist <dir-with-6-archives> --out <tgz-dir> --version <X.Y.Z> \
#                --source-root <checkout-of-the-exact-source>
#
# The npm/ package sources come from the EXACT SOURCE checkout (they are
# versioned with the source being released, not with the tooling running
# this script), are copied to a working area, binaries are extracted from
# the staged archives, versions are set, and npm pack runs once per
# package. The source npm/ tree is never modified.

set -euo pipefail

DIST='' OUT='' VERSION='' SOURCE_ROOT=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) DIST="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --source-root) SOURCE_ROOT="$2"; shift 2 ;;
    *) echo "stage-npm: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DIST" && -n "$OUT" && -n "$VERSION" && -n "$SOURCE_ROOT" ]] \
  || { echo "stage-npm: --dist, --out, --version and --source-root are required" >&2; exit 2; }

NPM_SRC="$SOURCE_ROOT/npm"
[[ -d "$NPM_SRC" ]] || { echo "stage-npm: $NPM_SRC does not exist in the source root" >&2; exit 1; }

# platform -> npm package dir : archive extension : binary names
PLATFORMS=(
  "linux_amd64:aw-linux-x64:tar.gz:aw:aweb-a2a-gw"
  "linux_arm64:aw-linux-arm64:tar.gz:aw:aweb-a2a-gw"
  "darwin_amd64:aw-darwin-x64:tar.gz:aw:aweb-a2a-gw"
  "darwin_arm64:aw-darwin-arm64:tar.gz:aw:aweb-a2a-gw"
  "windows_amd64:aw-windows-x64:zip:aw.exe:aweb-a2a-gw.exe"
  "windows_arm64:aw-windows-arm64:zip:aw.exe:aweb-a2a-gw.exe"
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$OUT"
# Absolutize before any per-package subshell changes directory: npm pack
# resolves a relative destination against its cwd, not the caller's.
OUT="$(cd "$OUT" && pwd)"

set_version() {
  # Set package version (and, for the main package, pin every
  # optionalDependency to the same exact version) without sed portability
  # hazards.
  python3 - "$1" "$VERSION" <<'PY'
import json, sys
path, version = sys.argv[1], sys.argv[2]
with open(path) as f:
    pkg = json.load(f)
pkg["version"] = version
for name in list(pkg.get("optionalDependencies", {})):
    pkg["optionalDependencies"][name] = version
with open(path, "w") as f:
    json.dump(pkg, f, indent=2)
    f.write("\n")
PY
}

for entry in "${PLATFORMS[@]}"; do
  IFS=':' read -r platform pkg_dir ext aw_bin gw_bin <<<"$entry"
  archive="$DIST/aw_${VERSION}_${platform}.${ext}"
  [[ -f "$archive" ]] || { echo "stage-npm: missing staged archive $archive" >&2; exit 1; }

  cp -R "$NPM_SRC/$pkg_dir" "$work/$pkg_dir"
  mkdir -p "$work/$pkg_dir/bin" "$work/extract-$platform"
  if [[ "$ext" == "tar.gz" ]]; then
    tar -xzf "$archive" -C "$work/extract-$platform"
  else
    unzip -q "$archive" -d "$work/extract-$platform"
  fi
  for bin in "$aw_bin" "$gw_bin"; do
    [[ -f "$work/extract-$platform/$bin" ]] \
      || { echo "stage-npm: archive $archive lacks binary $bin" >&2; exit 1; }
    cp "$work/extract-$platform/$bin" "$work/$pkg_dir/bin/$bin"
    chmod +x "$work/$pkg_dir/bin/$bin"
  done
  set_version "$work/$pkg_dir/package.json"
  (cd "$work/$pkg_dir" && npm pack --pack-destination "$OUT" >/dev/null)
done

cp -R "$NPM_SRC/aw" "$work/aw"
set_version "$work/aw/package.json"
(cd "$work/aw" && npm pack --pack-destination "$OUT" >/dev/null)

count="$(ls "$OUT"/*.tgz | wc -l | tr -d ' ')"
[[ "$count" == "7" ]] || { echo "stage-npm: expected 7 tgz, produced $count" >&2; exit 1; }
echo "stage-npm: staged 7 npm packages at version $VERSION in $OUT"
