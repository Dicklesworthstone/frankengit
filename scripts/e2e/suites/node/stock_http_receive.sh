#!/usr/bin/env bash
# e2e: stock Git HTTP push, authenticated attempt URLs, and canonical replay.
# Executes the real fg binary; this is not a cargo-test wrapper or substitute server.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init stock-http-receive
fge_phase setup
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
[[ "$TARGET_DIR" = /* ]] || TARGET_DIR="$REPO_ROOT/$TARGET_DIR"
FG_BIN="${FG_BIN:-$TARGET_DIR/debug/fg}"
fge_assert_cmd FG-HTTP-STOCK-001 'an already-built fg binary is executable' test -x "$FG_BIN"
[[ -x "$FG_BIN" ]] || fge_die 'stock HTTP receive requires FG_BIN; no build or substitute server is run'
fge_note FG-HTTP-STOCK-SCOPE 'Unmodified installed Git client; not pinned differential conformance. The campaign records the fg binary digest and actual Git version. Both SHA-1 and SHA-256 must pass.'
WORK="$(fge_tempdir stock-http-receive)"
fge_phase action
fge_capture native-receive python3 "$E2E_ROOT/stock_http_receive_smoke.py" \
    --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --artifact-dir "$WORK/run" || true
RC=$FGE_LAST_EXIT
OUTPUT=$FGE_LAST_STDOUT
fge_phase assert
fge_assert_eq FG-HTTP-STOCK-002 0 "$RC" 'native stock pushes and restart replay pass with every listener drained'
fge_assert_contains FG-HTTP-STOCK-003 "$OUTPUT" '"type": "stock_http_receive_passed", "format": "sha1"' 'SHA-1 stock receive and replay campaign completed'
fge_assert_contains FG-HTTP-STOCK-004 "$OUTPUT" '"type": "stock_http_receive_passed", "format": "sha256"' 'SHA-256 stock receive and replay campaign completed'
