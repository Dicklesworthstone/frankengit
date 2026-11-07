#!/usr/bin/env bash
# Synthetic GitHub input -> actual branch/PR operators -> canonical Rust reads.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-github-pull-migration
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Five shipped source/destination CLIs with synthetic GitHub source and real native destination; not live GitHub, SHA-256 translation, every operator, independent batch, D10 or full/release qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_fail GITHUB-PULL-MIGRATION-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 1
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit GITHUB-PULL-MIGRATION-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git fixture oracle verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-github-pull-migration || true
fge_assert_exit GITHUB-PULL-MIGRATION-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-github-pull-migration)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_github_pull_migration.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit GITHUB-PULL-MIGRATION-004 0 "$FGE_LAST_EXIT" 'actual native branch and GitHub PR operators complete with canonical readback'
fge_phase assert
fge_capture summary-readback python3 - "$SUMMARY" "$FG_BIN" <<'PY' || true
from pathlib import Path
import hashlib, json, sys
def require(condition):
    if not condition:
        raise AssertionError('PR acquisition journal check failed')

summary = json.loads(Path(sys.argv[1]).read_text())
hasher = hashlib.sha256()
with Path(sys.argv[2]).open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(block)
digest = hasher.hexdigest()
require(summary['complete'] is True and summary['binary_sha256'] == digest)
require(summary['oracle_pin'] == 'git-2.54.0')
require(len(summary['selected_facts']) == len(set(summary['selected_facts'])) == 38)
require(set(summary['facts']) == set(summary['selected_facts']) and all(v is True for v in summary['facts'].values()))
native_entrypoints = {'scripts/bootstrap_native_branches.mjs', 'scripts/migrate_github_pulls.mjs', 'scripts/migrate_github_pull_collection.mjs'}
source_entrypoints = {'scripts/discover_github_pulls.mjs', 'scripts/collect_github_pulls.mjs'}
entrypoints = native_entrypoints | source_entrypoints
require({row['path'] for row in summary['entrypoints']} == entrypoints)
require(all(row['binary_sha256'] == digest for row in summary['entrypoints']))
commands = [json.loads(line) for line in (Path(summary['artifacts']) / 'commands.jsonl').read_text().splitlines()]
native = [row for row in commands if row.get('kind') == 'command']
require(native and all(row['exit'] == 0 for row in native))
require(all(any(row['command'][1:3] == ['pr', op] for row in native) for op in ['show', 'comments', 'reviews']))
operators = [row for row in commands if row.get('kind') == 'operator']
for name in entrypoints:
    calls = [row for row in operators
             if Path(row['command'][3 if row['command'][1] == '--import' else 1]).name == Path(name).name]
    require(any(row['exit'] == 0 for row in calls) and any(row['exit'] == (1 if name in native_entrypoints else 2) for row in calls))
    require(all(('--import' in row['command']) == (name in source_entrypoints) for row in calls))
for operation, expected in [('prepare-begin', {0, 2}), ('prepare-resume', {0, 2, 3}), ('prepare-status', {0, 2})]:
    calls = [row for row in operators if Path(row['command'][1]).name == 'migrate_github_pulls.mjs'
             and row['command'][2] == operation]
    require(expected <= {row['exit'] for row in calls})
capacity = [row for row in operators if Path(row['command'][1]).name == 'migrate_github_pull_collection.mjs'
            and row['command'][2] == 'prepare' and '--max-request-bytes' in row['command']]
require({0, 2} <= {row['exit'] for row in capacity})
starts = [row for row in commands if row.get('kind') == 'service_start']
drains = [row for row in commands if row.get('kind') == 'service_stop']
require(1 <= len(starts) <= 16 and len(starts) == len(drains))
require({row['pid'] for row in starts} == {row['pid'] for row in drains})
require(all(row['exit'] == 0 and row['forced'] is False for row in drains))
print('38 selected facts, encoded capacity, bounded preparation phases, five entrypoint/digest rows and native owner drains verified')
PY
fge_assert_exit GITHUB-PULL-MIGRATION-005 0 "$FGE_LAST_EXIT" 'exact facts, entrypoint success/refusal, native reads and owner drains read back'
cp "$ORACLE_RUN/work/campaign/commands.jsonl" "$WORK/native-github-pull-commands.jsonl"
fge_artifact "$SUMMARY" github-pull-native-summary
fge_artifact "$WORK/native-github-pull-commands.jsonl" github-pull-native-command-journal
fge_preserve "$WORK" 'retain original .4.59 native GitHub PR migration receipts and command custody'
fge_phase teardown
