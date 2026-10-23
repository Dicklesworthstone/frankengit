#!/usr/bin/env bash
# e2e: native import survives exact object-placement syscall kills and a lost reply.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init import-stage-kill
fge_kind e2e-binary
fge_context bead frankengit-pc9g
fge_context non_claim 'Six observed object-placement/lost-response stages; no power-loss, complete CAS/SQLite boundary matrix, pinned-Git differential, or throughput claim.'
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ||
      ! "${FG_IMPORT_STAGE_SOURCE_CUT:-}" =~ ^[0-9a-f]{40}$ ]]; then
    fge_unsupported IMPORT-STAGE-001 'A qualified prebuilt native FG_BIN and its exact FG_IMPORT_STAGE_SOURCE_CUT are required.'
    exit 4
fi
if [[ "$(uname -s)" != Linux ]] || ! command -v strace >/dev/null ||
   ! command -v python3 >/dev/null; then
    fge_unsupported IMPORT-STAGE-002 'Linux, registered test-only strace, and Python 3 are required; no fault-injection fallback.'
    exit 4
fi
FG_DIGEST="$(fge_digest_file "$FG_BIN")"
fge_context source_cut "$FG_IMPORT_STAGE_SOURCE_CUT"
fge_context fg_digest "$FG_DIGEST"
# Keep every raw invocation and the owned staging residue, including green runs.
# This path is not registered as a disposable fge_tempdir.
WORK="$(fge_artifact_path import-stage-kill)"
fge_phase action
fge_run_timeout 900 IMPORT-STAGE-003 python3 -I "$E2E_ROOT/helpers/import_stage_kill.py" \
    "$FG_BIN" "$WORK" --source-cut "$FG_IMPORT_STAGE_SOURCE_CUT" --fg-sha256 "$FG_DIGEST" || true
fge_assert_exit IMPORT-STAGE-004 0 "$FGE_LAST_EXIT"
fge_phase assert
for artifact in "$WORK"/*.json "$WORK"/*.strace; do
    [[ -f "$artifact" ]] && fge_artifact "$artifact" import_stage_raw
done
fge_note IMPORT-STAGE-005 'The driver requires the complete two-format/six-stage kill-and-twin matrix, exact cold refs and authority, exact physical payload/native identities, and stable same-key recovery; no subset succeeds.'
