#!/usr/bin/env bash
# Seven shipped backup CLIs -> actual native source/forge recovery and exact resume.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-backup
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Original source paths unavailable but retained elsewhere; local inode replicas, not destructive crash/power-loss, independent failure domains, full capsule, HTTPS, current-source native or every operator qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-BACKUP-001 'A supplied prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit OPERATOR-BACKUP-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-backup || true
fge_assert_exit OPERATOR-BACKUP-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-backup)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_backup_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-BACKUP-004 0 "$FGE_LAST_EXIT" 'actual backup CLIs and canonical Rust recovery reads complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'backup operator summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in native_export_sign_and_floor selected_and_direct_native_preflight witness_rejects_omitted_newer_checkpoint exact_replicas_and_healthy_scrub corruption_is_degraded_not_native_success native_git_and_forge_recovery_without_original_paths cache_only_exact_resume_without_republication changed_envelope_refuses_without_native_change; do
    fge_assert_eq "OPERATOR-BACKUP-$format-$property" true "$(fact "${format}_$property")" "native backup operator $property"
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-backup-summary; fi
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  fge_artifact "$ORACLE_RUN/work/campaign/commands.jsonl" native-operator-and-oracle-command-journal
fi
fge_phase teardown
