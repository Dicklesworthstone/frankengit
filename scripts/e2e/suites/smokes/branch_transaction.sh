#!/usr/bin/env bash
# e2e: atomic multi-branch transactions through the real prebuilt fg binary.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.26
fge_context campaign scripts/e2e/branch_transaction_smoke.py
fge_context non_claim 'Real native CLI campaign; not a Cargo wrapper, full fast, upstream Git or release qualification.'
fge_phase setup
fg=${FG_BIN:-}
fge_assert_cmd SMOKE-BRANCH-TRANSACTION-BIN 'FG_BIN names a prebuilt fg binary' test -n "$fg"
[ -x "$fg" ] || fge_die 'FG_BIN must name a prebuilt executable'
fge_phase action
fge_run_timeout "${FGE_SMOKE_TIMEOUT:-1500}" branch-transaction \
  python3 "$E2E_ROOT/branch_transaction_smoke.py" --fg "$fg" || true
fge_phase assert
fge_assert_exit SMOKE-BRANCH-TRANSACTION 0 "$FGE_LAST_EXIT" \
  'Atomic multi-branch transactions preserve net effects, exact replay and refusal boundaries in both hash formats'
fge_phase teardown
