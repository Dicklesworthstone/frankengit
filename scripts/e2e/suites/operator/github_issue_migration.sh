#!/usr/bin/env bash
# Shipped GitHub issue CLIs -> real native authority and independent Rust reads.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-github-issue-migration
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context evidence_class real_js_cli_native_http_and_canonical_reads
fge_context non_claim 'Synthetic GitHub inputs; not live GitHub, TLS, crash durability, every operator entrypoint, independent batch or same-source native build qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-GITHUB-ISSUE-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
fge_context native_source_cut "${FG_SIGNED_BUNDLE_SOURCE_CUT:-undeclared}"
WORK="$(fge_tempdir operator-github-issue-migration)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 300 campaign python3 "$E2E_ROOT/operator_github_issue_migration.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-GITHUB-ISSUE-001 0 "$FGE_LAST_EXIT" 'actual migration/import CLIs completed through native HTTP'
fge_phase assert
fge_assert_file OPERATOR-GITHUB-ISSUE-002 "$SUMMARY"
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'GitHub issue migration summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for name in offline_preparation global_budget_and_status owned_sources_and_resume \
    denied_write_and_exact_retry canonical_text_lifecycle_and_actor completed_recovery \
    occupied_target_refusal later_request_tamper disabled_service_and_exact_retry owned_services_drained \
    discovery_cli_pinned_inventory inventory_offline_pin_twins batch_cli_matches_capture \
    capture_offline_prepare capture_pin_refusal capture_bounded_resume capture_offline_recovery \
    capture_handoff_pin_refusal capture_native_readback capture_native_recovery; do
    fge_assert_eq "OPERATOR-GITHUB-ISSUE-$format-$name" true "$(fact "${format}_$name")" "$name"
  done
done
fge_capture acquisition-command-readback python3 - "$SUMMARY" "$WORK/campaign" <<'PY' || true
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text())
assert summary['complete'] is True
root = Path(sys.argv[2])
commands = [json.loads(line) for line in (root / 'commands.jsonl').read_text().splitlines()]
source_calls = []
for row in commands:
    if row.get('kind') != 'operator':
        continue
    command = row['command']
    preloaded = command[1:2] == ['--import']
    index = 3 if preloaded else 1
    name, operation = Path(command[index]).name, command[index + 1]
    if name == 'import_github_issues.mjs' and operation in ('discover', 'inspect-inventory', 'capture-batch'):
        assert preloaded
        args = command[index + 2:]
        flag = '--out' if operation == 'discover' else '--inventory'
        fmt = Path(args[args.index(flag) + 1]).relative_to(root).parts[0]
        source_calls.append((fmt, operation, row['exit']))
    elif name == 'capture_github_issue_migration.mjs':
        assert preloaded
    elif name in ('import_github_issues.mjs', 'migrate_github_issues.mjs'):
        assert not preloaded, 'native destination child received the source fixture'
for fmt in ('sha1', 'sha256'):
    for operation in ('discover', 'inspect-inventory', 'capture-batch'):
        exits = {code for selected, op, code in source_calls if selected == fmt and op == operation}
        assert {0, 2} <= exits, (fmt, operation, exits)
print('both hash domains execute source discovery/inspection/batch-capture success and refusal; native children have no preload')
PY
fge_assert_exit OPERATOR-GITHUB-ISSUE-003 0 "$FGE_LAST_EXIT" 'actual source CLI success/refusal dispatch and native fixture isolation read back'
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" github-issue-migration-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-and-operator-command-journal; fi
fge_phase teardown
