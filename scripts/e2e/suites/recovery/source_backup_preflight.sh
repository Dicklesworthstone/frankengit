#!/usr/bin/env bash
# e2e: native fg backup export/verify/restore after loss of the original source
# Bead: frankengit-root-doctrine-x2mv.4.11
# Stock Git constructs only the deterministic input fixture. All backup,
# verification, restoration, ref writes and outcome recovery use the real fg.
set -euo pipefail

if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
  printf '%s\n' 'FG_BIN must name a prebuilt native fg executable; no build or emulation is performed' >&2
  exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init source-backup-preflight
fge_context bead frankengit-root-doctrine-x2mv.4.11
fge_context evidence_class e2e_native_source_recovery
fge_context fg_sha256 "$(fge_digest_file "$FG_BIN")"
fge_context git_version "$(git --version)"
fge_context non_claim 'Source metadata and selected Git objects only; not external artifacts, newest checkpoint, signatures, hostile filesystem, power-loss or network service recovery.'

TENANT=11111111111111111111111111111111
REPOSITORY=22222222222222222222222222222222
PRINCIPAL=33333333333333333333333333333333
WORK="$(fge_tempdir source-recovery)"
mkdir "$WORK/template" "$WORK/home"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_NAMESPACE GIT_REPLACE_REF_BASE
export GIT_NO_REPLACE_OBJECTS=1
export HOME="$WORK/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_TEMPLATE_DIR="$WORK/template" GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME='Backup fixture' GIT_COMMITTER_NAME='Backup fixture'
export GIT_AUTHOR_EMAIL=backup@example.invalid GIT_COMMITTER_EMAIL=backup@example.invalid
export GIT_AUTHOR_DATE='2001-01-01T00:00:00+0000' GIT_COMMITTER_DATE='2001-01-01T00:00:00+0000'

fixture() {
  local format=$1 source=$2
  git init -q --object-format="$format" -b main "$source"
  printf 'source recovery fixture\n' > "$source/README"
  git -C "$source" -c core.hooksPath=/dev/null add README
  git -C "$source" -c core.hooksPath=/dev/null -c gc.auto=0 commit -qm 'source recovery'
  git -C "$source" branch topic
  git -C "$source" fsck --strict
}
export -f fixture

run_expected() {
  local id=$1 expected=$2 step=$3
  shift 3
  fge_capture "$step" "$@" || true
  fge_assert_exit "$id" "$expected" "$FGE_LAST_EXIT"
  [[ "$FGE_LAST_EXIT" == "$expected" ]] || fge_die "unexpected exit during $step; dependent assertions cannot proceed"
}
json_receipt() {
  fge_json_top "$FGE_LAST_STDOUT" || fge_die 'expected one complete native JSON receipt'
}

for format in sha1 sha256; do
  domain="${format^^}"
  fge_context object_format "$format"
  fge_phase setup
  source="$WORK/source-$format"
  node="$WORK/node-$format"
  archive="$WORK/source-$format.fg"
  restored="$WORK/restored-$format"
  scratch="$WORK/check-$format"
  key="backup-original-$format"
  fge_run_ok "fixture-$format" bash -euo pipefail -c 'fixture "$@"' _ "$format" "$source"
  tip="$(git -C "$source" rev-parse refs/heads/main)"
  run_expected "BACKUP-$domain-001" 0 "init-$format" "$FG_BIN" init "$node" "$TENANT" "$REPOSITORY" "$format"
  run_expected "BACKUP-$domain-002" 0 "import-$format" "$FG_BIN" import "$node" "$TENANT" "$REPOSITORY" "$PRINCIPAL" "$key" "$source" --json
  json_receipt
  original_tx="${FGE_JSON[tx_id]}"
  original_record="${FGE_JSON[repository_commit_id]}"
  fge_assert_eq "BACKUP-$domain-003" 2 "${FGE_JSON[command_count]}" 'one atomic import establishes both branches'
  run_expected "BACKUP-$domain-004" 0 "source-refs-$format" "$FG_BIN" refs "$node" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format"
  json_receipt
  original_refs="${FGE_JSON[references]}"

  fge_phase action
  run_expected "BACKUP-$domain-010" 0 "export-$format" "$FG_BIN" backup export "$node" "$archive" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format" --timeout-secs 300
  json_receipt
  pin="$(fge_json_unquote "${FGE_JSON[sha256]}")"
  fge_assert_eq "BACKUP-$domain-011" true "${FGE_JSON[complete]}" 'export completed and closed'
  fge_assert_eq "BACKUP-$domain-012" 3 "${FGE_JSON[objects]}" 'complete selected object inventory'
  fge_assert_digest "BACKUP-$domain-013" "$pin" "$archive"
  run_expected "BACKUP-$domain-014" 2 "no-overwrite-$format" "$FG_BIN" backup export "$node" "$archive" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format"
  fge_assert_digest "BACKUP-$domain-015" "$pin" "$archive" 'preexisting archive was preserved'
  # Destroy only the two private fixture directories created above. Subsequent
  # commands have the archive alone; neither live node nor source Git is available.
  rm -rf -- "$node" "$source"
  fge_assert_cmd "BACKUP-$domain-016" 'source node removed' test ! -e "$node"
  fge_assert_cmd "BACKUP-$domain-017" 'source Git directory removed' test ! -e "$source"

  bad_pin="0${pin:1}"
  [[ "$bad_pin" != "$pin" ]] || bad_pin="1${pin:1}"
  run_expected "BACKUP-$domain-020" 2 "verify-wrong-pin-$format" "$FG_BIN" backup verify "$archive" "$scratch" --trusted-local --expected-sha256 "$bad_pin" --verification-instance 991
  fge_assert_cmd "BACKUP-$domain-021" 'wrong pin created no scratch' test ! -e "$scratch"
  run_expected "BACKUP-$domain-022" 2 "verify-budget-$format" "$FG_BIN" backup verify "$archive" "$scratch" --trusted-local --expected-sha256 "$pin" --verification-instance 991 --max-archive-bytes 1
  fge_assert_cmd "BACKUP-$domain-023" 'insufficient byte budget created no scratch' test ! -e "$scratch"
  run_expected "BACKUP-$domain-024" 0 "verify-$format" "$FG_BIN" backup verify "$archive" "$scratch" --trusted-local --expected-sha256 "$pin" --verification-instance 991
  json_receipt
  fge_assert_eq "BACKUP-$domain-025" true "${FGE_JSON[object_graph_verified]}" 'canonical selected graph verified'
  fge_assert_eq "BACKUP-$domain-026" false "${FGE_JSON[git_payloads_written]}" 'preflight did not restore payloads'
  fge_assert_eq "BACKUP-$domain-027" false "${FGE_JSON[destination_authority_published]}" 'preflight did not publish a destination'
  fge_assert_eq "BACKUP-$domain-028" true "${FGE_JSON[node_closed]}" 'preflight node explicitly closed'
  fge_assert_cmd "BACKUP-$domain-029" 'successful preflight removed its private scratch' test ! -e "$scratch"

  run_expected "BACKUP-$domain-030" 2 "restore-wrong-pin-$format" "$FG_BIN" backup restore "$archive" "$restored" --trusted-local --expected-sha256 "$bad_pin" --destination-instance 992
  fge_assert_cmd "BACKUP-$domain-031" 'wrong pin created no restore destination' test ! -e "$restored"
  run_expected "BACKUP-$domain-032" 0 "restore-$format" "$FG_BIN" backup restore "$archive" "$restored" --trusted-local --expected-sha256 "$pin" --destination-instance 992
  json_receipt
  fge_assert_eq "BACKUP-$domain-033" true "${FGE_JSON[reopened_and_verified]}" 'actual restored payloads read back and verified'
  fge_assert_eq "BACKUP-$domain-034" false "${FGE_JSON[source_tokens_preserved]}" 'destination has independent CAS tokens'
  fge_assert_eq "BACKUP-$domain-035" 3 "${FGE_JSON[objects]}"
  run_expected "BACKUP-$domain-036" 0 "restored-refs-$format" "$FG_BIN" refs "$restored" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format"
  json_receipt
  fge_assert_eq "BACKUP-$domain-037" "$original_refs" "${FGE_JSON[references]}" 'exact native refs survive source loss'
  run_expected "BACKUP-$domain-038" 0 "restored-outcome-$format" "$FG_BIN" outcome "$restored" "$TENANT" "$REPOSITORY" --trusted-local --principal "$PRINCIPAL" --idempotency-key "$key" --object-format "$format"
  json_receipt
  decision="${FGE_JSON[decision]}"
  transaction="${FGE_JSON[transaction]}"
  fge_json_top "$transaction" || fge_die 'missing recovered transaction'
  fge_assert_eq "BACKUP-$domain-039" "$original_tx" "${FGE_JSON[tx_id]}" 'original transaction identity recovered'
  fge_json_top "$decision" || fge_die 'missing recovered decision'
  fge_assert_eq "BACKUP-$domain-040" "$original_record" "${FGE_JSON[repository_commit_id]}" 'original canonical outcome recovered'

  run_expected "BACKUP-$domain-041" 0 "exact-resume-$format" "$FG_BIN" backup restore "$archive" "$restored" --trusted-local --expected-sha256 "$pin" --destination-instance 992 --resume
  json_receipt
  fge_assert_eq "BACKUP-$domain-042" true "${FGE_JSON[already_published]}" 'exact resume verifies rather than republishing'
  run_expected "BACKUP-$domain-043" 0 "new-work-$format" "$FG_BIN" branch create "$restored" "$TENANT" "$REPOSITORY" --trusted-local --principal "$PRINCIPAL" --idempotency-key "after-restore-$format" --ref refs/heads/after-restore --target "$tip" --object-format "$format"
  run_expected "BACKUP-$domain-044" 0 "advanced-refs-$format" "$FG_BIN" refs "$restored" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format"
  json_receipt
  advanced_refs="${FGE_JSON[references]}"
  fge_assert_ne "BACKUP-$domain-045" "$original_refs" "$advanced_refs" 'destination accepted real new canonical work'
  run_expected "BACKUP-$domain-046" 2 "refuse-rewind-$format" "$FG_BIN" backup restore "$archive" "$restored" --trusted-local --expected-sha256 "$pin" --destination-instance 992 --resume
  fge_assert_contains "BACKUP-$domain-051" "$FGE_LAST_STDERR" "complete imported snapshot" 'resume refused for newer canonical work, not an unrelated failure'
  run_expected "BACKUP-$domain-047" 0 "preserved-refs-$format" "$FG_BIN" refs "$restored" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format"
  json_receipt
  fge_assert_eq "BACKUP-$domain-048" "$advanced_refs" "${FGE_JSON[references]}" 'old archive cannot rewind a published repository'
  fge_assert_digest "BACKUP-$domain-049" "$pin" "$archive" 'all operations kept the source archive immutable'
  fge_assert_cmd "BACKUP-$domain-050" 'completed restore has no quarantine' test ! -e "$restored/.restore-quarantine"
done
