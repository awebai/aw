#!/usr/bin/env bash
# Byte-identity decisions for publish continuation.
#
#   continue-publish.sh --check-adopt <staged-file> <observed-file>
#
# Exit 0: the observed remote bytes are identical to the staged bytes and
# may be ADOPTED (the item was already published correctly; continuation
# uploads nothing for it). Exit 1: any difference - continuation must
# REFUSE rather than overwrite or republish.
#
# The workflow downloads remote state (release asset, npm tarball) to a
# file and asks this one question. Absent remote state never reaches this
# script: absent items are created from the staged bytes directly.

set -euo pipefail

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

case "${1:-}" in
  --require-publishable)
    # Only a stage-only artifact may continue to publication. A verify-only
    # run stages real bytes for inspection, and its artifact must never
    # become publishable evidence.
    manifest="${2:?manifest path required}"
    mode="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("mode",""))' "$manifest")"
    if [[ "$mode" == "stage-only" ]]; then
      echo "PUBLISHABLE: manifest mode is stage-only"
    else
      echo "REFUSE: manifest mode is ${mode:-absent}; only stage-only artifacts publish" >&2
      exit 1
    fi
    ;;
  --check-adopt)
    staged="${2:?staged file required}"
    observed="${3:?observed file required}"
    [[ -f "$staged" ]] || { echo "REFUSE: staged file $staged does not exist" >&2; exit 1; }
    [[ -f "$observed" ]] || { echo "REFUSE: observed file $observed does not exist" >&2; exit 1; }
    s="$(sha256 "$staged")"
    o="$(sha256 "$observed")"
    if [[ "$s" == "$o" ]]; then
      echo "ADOPT: $(basename "$staged") already published with identical bytes ($s)"
    else
      echo "REFUSE: $(basename "$staged") remote bytes $o do not equal staged bytes $s" >&2
      exit 1
    fi
    ;;
  *)
    echo "continue-publish: unknown or missing mode (expected --check-adopt)" >&2
    exit 2
    ;;
esac
