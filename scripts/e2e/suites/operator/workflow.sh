#!/usr/bin/env bash
# Real JS watcher -> native execution/custody -> publisher -> canonical PR checks.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-workflow
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Fixed trusted-host scripts, actual output/input/log custody and read-only artifact downloads through two JS entrypoints; not hostile isolation, all operators, current-source native qualification, TLS, retention enforcement or required-check policy.'
fge_phase setup
case "${FGE_WORKFLOW_NESTED_INPUTS:-0}" in
  0|1) ;;
  *) fge_die 'FGE_WORKFLOW_NESTED_INPUTS must be 0 or 1; selection is never broadened implicitly' ;;
esac
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-WORKFLOW-001 'A supplied prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit OPERATOR-WORKFLOW-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-workflow || true
fge_assert_exit OPERATOR-WORKFLOW-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-workflow)"
SUMMARY="$WORK/summary.json"
INPUTS=()
if [ "${FGE_WORKFLOW_NESTED_INPUTS:-0}" = 1 ]; then INPUTS=(--nested-inputs); fi
fge_context nested_inputs "${FGE_WORKFLOW_NESTED_INPUTS:-0}"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_workflow_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" "${INPUTS[@]}" || true
fge_assert_exit OPERATOR-WORKFLOW-004 0 "$FGE_LAST_EXIT" 'actual watcher, check publisher and canonical Rust reads complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'workflow operator summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in watch_execution_and_input_selection watch_dedup_and_reconcile artifact_native_capture_and_delivery artifact_download_grant_and_ceiling_twins artifact_binary_empty_failed_logs artifact_output_loss_retains_bytes artifact_restart_custody_and_no_reexecution canonical_success_failure_and_skip publisher_dedup_and_original_keys watch_output_failure_no_execution publication_output_failure_retains_terminal outcome_grant_twins_and_service_drain recovery_no_execution_or_publication; do
    fge_assert_eq "OPERATOR-WORKFLOW-$format-$property" true "$(fact "${format}_$property")" "native workflow operator $property"
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-workflow-summary; fi
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  fge_artifact "$ORACLE_RUN/work/campaign/commands.jsonl" native-operator-and-oracle-command-journal
fi
fge_phase teardown
