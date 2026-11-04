#!/usr/bin/env bash
# Real signed native archives -> HTTPS operator CLIs -> canonical Rust restore.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-backup-https
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Native archives/restores are real; HTTPS object service is a disk-backed loopback transport fixture, not a public provider, independent storage, destructive/hardware fault, full capsule, current-main native or whole operator gate.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null || ! command -v openssl >/dev/null; then
  fge_fail BACKUP-HTTPS-001 'A prebuilt FG_BIN, pinned Node, Python 3 and test-only OpenSSL are required'
  exit 1
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit BACKUP-HTTPS-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git fixture oracle verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-backup-https || true
fge_assert_exit BACKUP-HTTPS-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-backup-https)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_capture fixture-owner-selftests env FGE_ARTIFACT_ROOT="$WORK" python3 "$E2E_ROOT/selftests/test_backup_https_fixture.py" || true
fge_assert_exit BACKUP-HTTPS-OWNER-001 0 "$FGE_LAST_EXIT" 'real TLS fixture ownership survives startup/body/terminal journal failures'
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_backup_https.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit BACKUP-HTTPS-004 0 "$FGE_LAST_EXIT" 'actual signed native archives traverse HTTPS clients and canonical Rust recovery'
fge_phase assert
fge_capture summary-readback python3 - "$SUMMARY" "$FG_BIN" <<'PY' || true
from pathlib import Path
import hashlib, json, sys
summary = json.loads(Path(sys.argv[1]).read_text())
with Path(sys.argv[2]).open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
assert summary['complete'] is True and summary['binary_sha256'] == digest
assert summary['oracle_pin'] == 'git-2.54.0'
properties = ('signed_native_archive', 'direct_upload_pin_budget_and_exact_retry',
    'sealed_source_custody_without_network', 'job_policy_target_budget_refusals',
    'lost_approval_response_retains_partial_completion', 'renewed_capabilities_reuse_without_put',
    'download_trust_checkpoint_and_corrupt_mirror_twins', 'downloaded_native_restore',
    'https_recovery_then_offline_cache_resume', 'redacted_capabilities_and_fixture_drain')
expected = {f'{fmt}_{name}' for fmt in ('sha1', 'sha256') for name in properties}
assert len(summary['selected_facts']) == len(set(summary['selected_facts'])) == len(expected) == 20
assert set(summary['selected_facts']) == set(summary['facts']) == expected and all(v is True for v in summary['facts'].values())
entrypoints = {'scripts/upload_repository_backup.mjs', 'scripts/repository_backup_upload_job.mjs',
               'scripts/download_repository_backup.mjs', 'scripts/recover_repository_backup.mjs'}
assert len(summary['entrypoints']) == 4 and {row['path'] for row in summary['entrypoints']} == entrypoints
assert all(row['binary_sha256'] == digest for row in summary['entrypoints'])
commands = [json.loads(line) for line in (Path(summary['artifacts']) / 'commands.jsonl').read_text().splitlines()]
native = [row for row in commands if row.get('kind') == 'command']
assert native and all(row['exit'] == 0 for row in native)
assert all(any(row['command'][1:3] == words for row in native) for words in [['backup', 'export'], ['issue', 'show']])
assert all(any(row['command'][1] == name for row in native) for name in ['show', 'doctor', 'at'])
assert sum(row.get('kind') == 'pinned_git_fixture_check' and row['exit'] == 0 for row in commands) == 2
operators = [row for row in commands if row.get('kind') == 'operator']
for name in entrypoints:
    calls = [row for row in operators if Path(row['command'][1]).name == Path(name).name]
    assert any(row['exit'] == 0 for row in calls) and any(row['exit'] == 1 for row in calls)
assert all('interruption' not in row and row.get('cleanup_error') is None for row in operators)
starts = [row for row in commands if row.get('kind') == 'https_fixture_start']
stops = [row for row in commands if row.get('kind') == 'https_fixture_stop']
assert len(starts) == len(stops) == 2 and {row['port'] for row in starts} == {row['port'] for row in stops}
assert all(row['drained'] is True and row['active_sockets'] == 0 and not row['failures'] for row in stops)
print('20 exact facts, four entrypoint success/refusal populations, native reads and both TLS fixture drains verified')
PY
fge_assert_exit BACKUP-HTTPS-005 0 "$FGE_LAST_EXIT" 'exact facts/digests, native readback and loopback fixture ownership verified'
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  cp "$ORACLE_RUN/work/campaign/commands.jsonl" "$WORK/native-backup-https-commands.jsonl"
  fge_artifact "$WORK/native-backup-https-commands.jsonl" native-backup-https-command-journal
fi
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" native-backup-https-summary; fi
fge_preserve "$WORK" 'retain original .4.59 HTTPS backup/native restore receipts and source custody'
fge_phase teardown
