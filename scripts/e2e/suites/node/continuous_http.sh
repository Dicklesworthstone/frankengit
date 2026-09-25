#!/usr/bin/env bash
# e2e: continuous native HTTP serving, explicit stop and accepted-child drain.
# Owning bead: frankengit-root-doctrine-x2mv.4.8. Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init continuous-http
fge_phase setup
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
  fge_unsupported FG-HTTP-CONTINUOUS-001 'an explicitly supplied, already-built FG_BIN is required'
  exit 1
fi
fge_phase action
fge_run_timeout 1200 continuous-http python3 "$E2E_ROOT/continuous_http_smoke.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" || true
rc=$FGE_LAST_EXIT
fge_phase assert
fge_assert_eq FG-HTTP-CONTINUOUS-002 0 "$rc" \
  'native SHA-1/SHA-256 service survives 1024 requests, reloads credentials and drains accepted work'
