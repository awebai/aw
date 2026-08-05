#!/usr/bin/env bash
# Literal-format validation for workflow dispatch inputs.
#
#   validate-inputs.sh [--sha <40-hex>] [--version <X.Y.Z>]
#                      [--digest sha256:<64-hex>] [--run-id <digits>]
#                      [--artifact-id <digits>]
#
# Each provided value must match its exact literal format; anything else
# refuses naming the field. This is endpoint value handling for accidental
# malformed input - inputs are passed through the environment and only ever
# referenced as quoted shell variables after this check.

set -euo pipefail

fail() { printf 'REFUSE: %s\n' "$1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      [[ "$2" =~ ^[0-9a-f]{40}$ ]] \
        || fail "sha must be exactly 40 lowercase hex characters, got: $2"
      shift 2 ;;
    --version)
      [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || fail "version must be strict X.Y.Z with no prefix, got: $2"
      shift 2 ;;
    --digest)
      [[ "$2" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail "digest must be sha256:<64 lowercase hex>, got: $2"
      shift 2 ;;
    --run-id)
      [[ "$2" =~ ^[0-9]+$ ]] \
        || fail "run-id must be numeric, got: $2"
      shift 2 ;;
    --artifact-id)
      [[ "$2" =~ ^[0-9]+$ ]] \
        || fail "artifact-id must be numeric, got: $2"
      shift 2 ;;
    *)
      echo "validate-inputs: unknown argument $1" >&2; exit 2 ;;
  esac
done
echo "inputs well-formed"
