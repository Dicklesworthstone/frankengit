#!/usr/bin/env bash
# Actual local workspace -> packed authoring -> canonical native source publication.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-source-workspace
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Nineteen source/context entrypoints with native acquisition, remote bundle transfer, detached approval, recovery and source publication; not every operator, broad search completeness, retained authority proofs, TLS or deployment.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-WORKSPACE-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
BINARY_DIGEST="$(fge_digest_file "$FG_BIN")"
fge_context binary_sha256 "$BINARY_DIGEST"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
fge_capture oracle-verify "$ORACLE" verify git-2.54.0 || true
fge_assert_exit OPERATOR-WORKSPACE-002 0 "$FGE_LAST_EXIT" 'pinned sandboxed Git verifies'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
fge_capture oracle-create "$ORACLE" create-run git-2.54.0 operator-workspace || true
fge_assert_exit OPERATOR-WORKSPACE-003 0 "$FGE_LAST_EXIT" 'isolated retained oracle run created'
if [ "$FGE_LAST_EXIT" -ne 0 ]; then exit 1; fi
IFS= read -r ORACLE_RUN < "$FGE_LAST_STDOUT_FILE"
fge_context oracle_run "$ORACLE_RUN"
WORK="$(fge_tempdir operator-source-workspace)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_workspace_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$ORACLE_RUN/work/campaign" \
  --oracle-run "$ORACLE_RUN" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-WORKSPACE-004 0 "$FGE_LAST_EXIT" 'actual source operator and canonical Rust reads complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'workspace operator summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in workspace_capture_and_binary_twin native_prepare_grant_and_exact_pack canonical_bytes_modes_and_sibling original_key_and_outcome_grant service_drained verified_parent_trees parent_evidence_custody native_context_and_grant_twins native_package_and_proof_custody refresh_stale_publication refresh_review_and_exact_result refresh_publication_and_drain native_archive_and_grant_twins native_archive_reuse_and_offline_verification native_context_session_quota_and_grants native_context_session_dispatch_and_offline_export native_context_proof_bytes_and_grants native_context_proof_offline_pins native_workspace_scan_selection native_workspace_scan_capture_and_stale_twin composition_native_contributions_and_conflict composition_assembly_consent_and_canonical_publication composition_replay_refusal_and_explicit_next_base composition_replay_consent_and_canonical_publication composition_offline_custody_and_original_recovery; do
    fge_assert_eq "OPERATOR-WORKSPACE-$format-$property" true "$(fact "${format}_$property")" "native source workspace $property"
  done
done
for format in sha1 sha256; do
  for compiler in patch refactor; do
    fge_assert_eq "OPERATOR-WORKSPACE-$format-offline-$compiler" true "$(fact "${format}_offline_${compiler}_compiler_native_publication")" "offline $compiler CLI output reaches exact native publication"
  done
done
for format in sha1 sha256; do
  for property in verification import_custody recovery containment_diagnostics; do
    fge_assert_eq "OPERATOR-WORKSPACE-$format-native-bundle-$property" true "$(fact "${format}_native_bundle_cli_$property")" "actual native bundle CLI $property"
  done
done
for format in sha1 sha256; do
  for property in remote_bundle_native_export detached_attestation_native_source remote_bundle_native_import_recovery remote_bundle_native_fetch_leases; do
    fge_assert_eq "OPERATOR-WORKSPACE-$format-$property" true "$(fact "${format}_$property")" "actual native remote transfer/approval: $property"
  done
done
fge_capture entrypoint-receipts python3 - "$SUMMARY" "$BINARY_DIGEST" <<'PY' || true
import json, re, sys
with open(sys.argv[1], encoding='utf-8') as source:
    summary = json.load(source)
rows = summary['entrypoint_runs']
assert summary['complete'] is True and len(rows) == len(summary['entrypoints']) == 19
assert len({r['path'] for r in rows}) == 19 and {r['path'] for r in rows} == set(summary['entrypoints'])
assert all(r['binary_sha256'] == sys.argv[2] and re.fullmatch('[0-9a-f]{64}', r['client_sha256'])
           and r['success_count'] > 0 and r['expected_nonzero_count'] > 0 for r in rows)
PY
fge_assert_exit OPERATOR-WORKSPACE-ENTRYPOINT-001 0 "$FGE_LAST_EXIT" 'every listed source entrypoint has actual success/expected-nonzero calls and its selected native digest'
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-workspace-summary; fi
if [ -f "$ORACLE_RUN/work/campaign/commands.jsonl" ]; then
  fge_artifact "$ORACLE_RUN/work/campaign/commands.jsonl" native-operator-and-oracle-command-journal
fi
fge_phase teardown
