#!/usr/bin/env bash
# Real PR archive/import, canonical Rust reads and an absent native route control.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-native-pull-migration
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Two native PR portability entrypoints; not every operator, independent batch verification, D10, power loss or full/release qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip PULL-MIGRATION-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit PULL-MIGRATION-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-pull-migration || true
fge_assert_exit PULL-MIGRATION-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-native-pull-migration)"
SUMMARY="$WORK/summary.json"
NEGATIVE="$WORK/missing-route.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_pull_migration.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit PULL-MIGRATION-004 0 "$FGE_LAST_EXIT" 'native PR portability and separate canonical reads complete'
fge_capture oracle-negative-create "$ORACLE" create-run git-2.54.0 operator-pull-migration-negative || true
fge_assert_exit PULL-MIGRATION-007 0 "$FGE_LAST_EXIT" 'negative control has its own isolated oracle run'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r NEGATIVE_ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context negative_oracle_run "$NEGATIVE_ORACLE_RUN"
fge_run_timeout 120 missing-route python3 "$E2E_ROOT/operator_pull_migration.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$NEGATIVE_ORACLE_RUN/work/campaign" \
  --oracle-run "$NEGATIVE_ORACLE_RUN" --summary "$NEGATIVE" --omit-source-pull-service || true
fge_assert_exit PULL-MIGRATION-005 0 "$FGE_LAST_EXIT" 'missing native PR service produces the exact required entrypoint failure'
fge_phase assert
fge_capture summary-readback python3 - "$SUMMARY" "$NEGATIVE" "$FG_BIN" <<'PY' || true
import hashlib, json, sys
from pathlib import Path
positive, negative = (json.loads(Path(p).read_text()) for p in sys.argv[1:3])
with Path(sys.argv[3]).open('rb') as stream:
    hasher = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(block)
    digest = hasher.hexdigest()
assert positive['complete'] is True and positive['negative_control'] is False
assert len(positive['selected_facts']) == 22 and len(set(positive['selected_facts'])) == 22
assert set(positive['facts']) == set(positive['selected_facts'])
assert all(value is True for value in positive['facts'].values())
assert {row['path'] for row in positive['entrypoints']} == {
    'scripts/archive_native_pulls.mjs', 'scripts/migrate_native_pulls.mjs'}
assert positive['binary_sha256'] == negative['binary_sha256'] == digest
assert all(row['binary_sha256'] == digest for row in positive['entrypoints'])
assert negative['negative_control'] is True and negative['negative_observed'] is True and negative['complete'] is False
assert 'operator exit 4, expected 0' in negative['failure']
assert set(negative['facts']) == {'sha1_pinned_git_fixture'}
commands = [json.loads(line) for line in (Path(negative['artifacts']) / 'commands.jsonl').read_text().splitlines()]
operators = [row for row in commands if row.get('kind') == 'operator']
assert len(operators) == 3
assert Path(operators[-1]['command'][1]).name == 'archive_native_pulls.mjs'
assert operators[-1]['command'][2] == 'export' and operators[-1]['exit'] == 4
drains = [row for row in commands if row.get('kind') == 'service_stop']
starts = [row for row in commands if row.get('kind') == 'service_start']
assert 1 <= len(starts) <= 16 and len(starts) == len(drains)
assert {row['pid'] for row in starts} == {row['pid'] for row in drains}
assert all('--allow-pulls' not in row['command'] for row in starts)
assert all(row['exit'] == 0 and row['forced'] is False for row in drains)
print('22 native portability facts and the real missing-route negative verified')
PY
fge_assert_exit PULL-MIGRATION-006 0 "$FGE_LAST_EXIT" 'exact fact population, entrypoint digests and planted negative read back'
cp "$ORACLE_RUN/work/campaign/commands.jsonl" "$WORK/positive-commands.jsonl"
cp "$NEGATIVE_ORACLE_RUN/work/campaign/commands.jsonl" "$WORK/negative-commands.jsonl"
for artifact in "$SUMMARY" "$NEGATIVE" "$WORK/positive-commands.jsonl" "$WORK/negative-commands.jsonl"; do
  if [ -f "$artifact" ]; then fge_artifact "$artifact" native-pull-migration; fi
done
fge_preserve "$WORK" 'retain native PR portability receipts and distinct command journals for original .4.59 review'
fge_phase teardown
