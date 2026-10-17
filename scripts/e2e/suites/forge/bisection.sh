#!/usr/bin/env bash
# Real native binary, immutable history and cold-process receipt campaign.
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'forge bisection requires FG_BIN naming a prebuilt native fg' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init forge-bisection
fge_kind e2e-binary
fge_context bead frankengit-fg038b-bisect-evidence-vnr
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Read-only trusted-local diagnostic; no remote disclosure, code execution, offline recovery, full-workspace or throughput claim.'
WORK="$(fge_tempdir forge-bisection)"
fge_phase action
fge_run_timeout 900 FORGE-BISECTION-001 python3 "$E2E_ROOT/helpers/forge_bisection.py" "$FG_BIN" "$WORK"
fge_assert_exit FORGE-BISECTION-002 0 "$FGE_LAST_EXIT"
fge_phase assert
for artifact in "$WORK"/*.json "$WORK"/*.out "$WORK"/*.err; do
    [[ ! -f "$artifact" ]] || fge_artifact "$artifact" bisection_evidence
done
fge_note FORGE-BISECTION-003 'Native SHA-1/SHA-256 issue, ref, policy and PR history; first-match, non-match, stale-head, budget, exact receipt digest and source-free cold-process checks.'
