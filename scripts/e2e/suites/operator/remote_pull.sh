#!/usr/bin/env bash
# Actual remote PR CLI -> native HTTP -> Rust canonical metadata/discussion/refs.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-remote-pull
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Ten PR actions and binary-conflict resolution in both hash domains and merge methods; not every operator, TLS, deployment or same-source native qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-PULL-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit OPERATOR-PULL-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git oracle verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-pull || true
fge_assert_exit OPERATOR-PULL-003 0 "$FGE_LAST_EXIT" 'oracle creates an isolated retained run'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-remote-pull)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_pull_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-PULL-004 0 "$FGE_LAST_EXIT" 'actual PR operator and native canonical reads completed'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'operator PR summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in pinned_git_fixture lifecycle_and_stale_twin discussion_and_original_recovery independent_outcome_grant fast_forward_and_code_grant independent_review_grant candidate_review_and_stale_twin candidate_bundle_recovery native_review_snapshot native_candidate_package reviewed_merge_and_method_twin owned_service_drained; do
    fge_assert_eq "OPERATOR-PULL-$format-$property" true "$(fact "${format}_$property")" "native PR $property"
  done
  for method in merge-commit squash; do
    for property in conflict_resolution exact_reviewed_result resolution_service_drained; do
      fge_assert_eq "OPERATOR-PULL-$format-$method-$property" true "$(fact "${format}_${method}_$property")" "native $method $property"
    done
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-pull-summary; fi
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  fge_artifact "$ORACLE_RUN/work/campaign/commands.jsonl" native-operator-and-oracle-command-journal
fi
fge_phase teardown
