#!/usr/bin/env bash
# Shipped supervisor -> actual Rust execution/publication and offline custody.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-workflow-supervisor
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Fixed secret-free trusted-host scripts; not hostile isolation, required-check authority, artifacts, multi-lane contention, current-native or full operator/release qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-SUPERVISOR-001 'A supplied prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit OPERATOR-SUPERVISOR-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-supervisor || true
fge_assert_exit OPERATOR-SUPERVISOR-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-workflow-supervisor)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_workflow_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" --supervisor || true
fge_assert_exit OPERATOR-SUPERVISOR-004 0 "$FGE_LAST_EXIT" 'actual supervisor and canonical Rust checks complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'supervisor summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in failed_execution_still_publishes exact_native_job_identities status_restart_dedup permitted_revision_and_bounded_service offline_summary_reconciliation original_custody_and_owners native_authority_and_scope; do
    fge_assert_eq "OPERATOR-SUPERVISOR-$format-$property" true "$(fact "${format}_$property")" "native supervisor $property"
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-supervisor-summary; fi
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  fge_artifact "$ORACLE_RUN/work/campaign/commands.jsonl" native-supervisor-command-journal
fi
fge_phase teardown
