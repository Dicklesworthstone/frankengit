#!/usr/bin/env bash
# Actual JS issue CLI -> native HTTP -> canonical Rust readback, both hash domains.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-remote-issue
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context evidence_class real_js_cli_native_http_and_canonical_reads
fge_context non_claim 'Three issue/inbox operator entrypoints in SHA-1/SHA-256; not discussion inboxes, the complete operator matrix, browser UI, TLS, D10 or same-revision native build qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-ISSUE-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir operator-remote-issue)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_issue_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-ISSUE-001 0 "$FGE_LAST_EXIT" 'actual operator requests and native canonical reads completed'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'operator issue summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  fge_assert_eq "OPERATOR-ISSUE-$format-002" true "$(fact "${format}_stale_refusal_and_current_twin")" 'stale comment refuses without issue/event mutation; current twin commits'
  fge_assert_eq "OPERATOR-ISSUE-$format-003" true "$(fact "${format}_all_actions_and_original_key_recovery")" 'all eight actions have canonical Rust readback and original-key recovery'
  fge_assert_eq "OPERATOR-ISSUE-$format-004" true "$(fact "${format}_independent_outcome_grant")" 'unavailable outcome read preserves uncertainty; recovery never resubmits'
  fge_assert_eq "OPERATOR-ISSUE-$format-005" true "$(fact "${format}_owned_service_drained")" 'native listener drains every accepted transport'
  fge_assert_eq "OPERATOR-ISSUE-$format-006" true "$(fact "${format}_forge_all_actions_and_recovery")" 'shipped IssueClient performs every forge mutation with canonical readback and original-key recovery'
  fge_assert_eq "OPERATOR-ISSUE-$format-007" true "$(fact "${format}_forge_stale_and_grant_twins")" 'forge stale preflight and denied write preserve state; exact retry commits after restored grant'
  fge_assert_eq "OPERATOR-ISSUE-$format-008" true "$(fact "${format}_forge_retained_reads_and_unknown_pin_refusal")" 'forge list/history/search preserve native pages and retained history; unknown pins refuse'
  fge_assert_eq "OPERATOR-ISSUE-$format-009" true "$(fact "${format}_forge_additive_assignees")" 'additive assignee operator preserves native union and unrelated locked/closed metadata'
  fge_assert_eq "OPERATOR-ISSUE-$format-010" true "$(fact "${format}_forge_additive_recovery")" 'original additive recovery never re-adds a later removed assignee'
  fge_assert_eq "OPERATOR-ISSUE-$format-011" true "$(fact "${format}_forge_additive_grant_twins")" 'denied additive write preserves uncertainty; the same recorded request commits after restored grant'
  fge_assert_eq "OPERATOR-ISSUE-$format-012" true "$(fact "${format}_inbox_actions_prefix_and_original_recovery")" 'all five inbox actions reach Rust; older read prefixes preserve newer activity and old recovery never reapplies'
  fge_assert_eq "OPERATOR-ISSUE-$format-013" true "$(fact "${format}_inbox_retained_reads_and_canonical_state")" 'inbox continuation and historical show retain their original source after preference changes'
  fge_assert_eq "OPERATOR-ISSUE-$format-014" true "$(fact "${format}_inbox_stale_and_identity_refusals")" 'stale preference and changed owner refuse before custody or native mutation'
  fge_assert_eq "OPERATOR-ISSUE-$format-015" true "$(fact "${format}_inbox_independent_grant_twins")" 'notification-write denial preserves original custody; restored grant admits its exact retry'
  fge_assert_eq "OPERATOR-ISSUE-$format-016" true "$(fact "${format}_inbox_missing_native_service_refusal")" 'disabled native inbox service cannot produce a complete operator observation'
done
fge_capture entrypoint-receipts python3 - "$SUMMARY" "$FG_BIN" "$E2E_ROOT/../.." <<'PY' || true
import hashlib, json, sys
from pathlib import Path
summary = json.loads(Path(sys.argv[1]).read_text())
with Path(sys.argv[2]).open('rb') as stream:
    hasher = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(block)
    digest = hasher.hexdigest()
rows = summary['entrypoint_runs']
assert summary['complete'] is True and len(rows) == len(summary['entrypoints']) == 3
assert {row['path'] for row in rows} == set(summary['entrypoints'])
assert all(row['binary_sha256'] == summary['binary_sha256'] == digest
           and row['client_sha256'] == hashlib.sha256((Path(sys.argv[3]) / row['path']).read_bytes()).hexdigest()
           and row['success_count'] > 0 and row['expected_nonzero_count'] > 0 for row in rows)
PY
fge_assert_exit OPERATOR-ISSUE-ENTRYPOINT-001 0 "$FGE_LAST_EXIT" 'all three entrypoint receipts retain actual success/expected-nonzero calls and native/client digests'
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-issue-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-and-operator-command-journal; fi
fge_phase teardown
