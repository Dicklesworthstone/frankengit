#!/usr/bin/env bash
# e2e: stock Git over fg serve-http, SHA-1 and SHA-256, protocols v0/v1/v2.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 5: the smart HTTP smoke
# runs in a lane). Executes the real fg binary; not a cargo-test wrapper.
#
# scripts/e2e/smart_http_smoke.py: unauthenticated and forged-identity
# refusals, initial and incremental pushes, clones over every protocol with
# fsck --strict, incremental fetches, a shallow clone, annotated tag push,
# peel and deletion, and a drained server receipt, for each object format.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init smart-http-smoke
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'The installed Git client, one loopback server per format; not a pinned-version differential or a throughput claim.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd HTTP-SMOKE-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
fge_capture smoke python3 "$E2E_ROOT/smart_http_smoke.py" --fg "$FG_BIN" \
  --git "${GIT_ORACLE_BIN:-git}" || true
RC=$FGE_LAST_EXIT
OUTPUT=$FGE_LAST_STDOUT

fge_phase assert
fge_assert_eq HTTP-SMOKE-002 0 "$RC" 'the stock Git smoke campaign completed with every server drained'
fge_assert_contains HTTP-SMOKE-003 "$OUTPUT" '"type": "smart_http_smoke_passed", "format": "sha1"' \
  'SHA-1: pushes, v0/v1/v2 clones, fetches, shallow clone and tags pass'
fge_assert_contains HTTP-SMOKE-004 "$OUTPUT" '"type": "smart_http_smoke_passed", "format": "sha256"' \
  'SHA-256: pushes, v0/v1/v2 clones, fetches, shallow clone and tags pass'

fge_phase teardown
