#!/usr/bin/env bash
# Actual archive/migrate CLIs -> native HTTP -> canonical Rust readback.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-native-milestone-migration
fge_kind e2e-binary
fge_context bead frankengit-fg045-issues-notifications-n70
fge_context evidence_class real_js_cli_native_http_and_canonical_reads
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip MILESTONE-MIGRATION-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir native-milestone-migration)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 600 campaign python3 "$E2E_ROOT/native_milestone_migration.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit MILESTONE-MIGRATION-001 0 "$FGE_LAST_EXIT" 'native archive, mapped phased migration and canonical reads completed'
fge_phase assert
fge_assert_file MILESTONE-MIGRATION-002 "$SUMMARY"
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" native-milestone-migration-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-milestone-migration-command-journal; fi
fge_phase teardown
