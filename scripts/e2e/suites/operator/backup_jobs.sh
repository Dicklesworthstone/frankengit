#!/usr/bin/env bash
# Signed immutable jobs and replenishment -> real native archive/forge recovery.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-backup-jobs
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Real signed native archives and canonical restores; retained diagnostic originals and local copies, not independent storage, destructive crash/power-loss, full capsule, HTTPS, current-main native or whole operator qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_fail BACKUP-JOBS-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 1
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit BACKUP-JOBS-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git fixture oracle verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-backup-jobs || true
fge_assert_exit BACKUP-JOBS-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-backup-jobs)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_backup_jobs.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit BACKUP-JOBS-004 0 "$FGE_LAST_EXIT" 'signed jobs, replenishment and actual Rust restore/readback complete'
fge_phase assert
fge_capture summary-readback python3 - "$SUMMARY" "$FG_BIN" <<'PY' || true
from pathlib import Path
import hashlib, json, sys
summary = json.loads(Path(sys.argv[1]).read_text())
hasher = hashlib.sha256()
with Path(sys.argv[2]).open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(block)
digest = hasher.hexdigest()
assert summary['complete'] is True and summary['binary_sha256'] == digest
assert summary['oracle_pin'] == 'git-2.54.0'
properties = ('signed_native_archive', 'immutable_seal_without_replicas',
    'witness_and_budget_refusal_twins', 'original_approval_loss',
    'source_loss_replica_failover_and_resume', 'corrupt_output_preserved',
    'replenishment_budget_and_checkpoint_twins', 'replenishment_exact_resume',
    'native_restore_exact_git_and_forge', 'newer_witness_blocks_older_job')
expected = {f'{fmt}_{name}' for fmt in ('sha1', 'sha256') for name in properties}
assert len(summary['selected_facts']) == len(set(summary['selected_facts'])) == len(expected) == 20
assert set(summary['selected_facts']) == set(summary['facts']) == expected
assert all(value is True for value in summary['facts'].values())
entrypoints = {'scripts/repository_backup_job.mjs', 'scripts/replenish_repository_backups.mjs'}
assert len(summary['entrypoints']) == 2 and {row['path'] for row in summary['entrypoints']} == entrypoints
assert all(row['binary_sha256'] == digest for row in summary['entrypoints'])
commands = [json.loads(line) for line in (Path(summary['artifacts']) / 'commands.jsonl').read_text().splitlines()]
native = [row for row in commands if row.get('kind') == 'command']
assert native and all(row['exit'] == 0 for row in native)
assert all(any(row['command'][1:3] == words for row in native)
    for words in [['backup', 'export'], ['issue', 'show']])
assert all(any(row['command'][1] == name for row in native) for name in ['show', 'doctor'])
assert sum(row.get('kind') == 'pinned_git_fixture_check' and row['exit'] == 0 for row in commands) == 2
operators = [row for row in commands if row.get('kind') == 'operator']
for name in entrypoints:
    calls = [row for row in operators if Path(row['command'][1]).name == Path(name).name]
    assert any(row['exit'] == 0 for row in calls) and any(row['exit'] == 1 for row in calls)
assert all('interruption' not in row and row.get('cleanup_error') is None for row in operators)
print('20 exact facts, both CLI success/refusal populations and actual native reads verified')
PY
fge_assert_exit BACKUP-JOBS-005 0 "$FGE_LAST_EXIT" 'exact facts, entrypoint/digest population and successful native reads read back'
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  cp "$ORACLE_RUN/work/campaign/commands.jsonl" "$WORK/native-backup-job-commands.jsonl"
  fge_artifact "$WORK/native-backup-job-commands.jsonl" native-backup-job-command-journal
fi
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" native-backup-job-summary; fi
fge_preserve "$WORK" 'retain original .4.59 signed native backup job/replenishment command custody'
fge_phase teardown
