#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init candidate-publication-frontier
fge_kind e2e-binary
fge_context bead frankengit-t0iw
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
NODE_BIN="${NODE_BIN:-$(command -v node)}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context node_version "$("$NODE_BIN" --version)"
fge_context non_claim 'Actual Node and native HTTP; admitted blob reuse is not a scrub or raw receive qualification; not hostile isolation, release or whole-workspace verification.'
WORK="$(fge_tempdir candidate-publication-frontier)"
fge_phase action
fge_run_timeout 900 CANDIDATE-PUBLICATION-001 python3 "$E2E_ROOT/helpers/candidate_publication_frontier.py" "$FG_BIN" "$NODE_BIN" "$WORK"
fge_assert_exit CANDIDATE-PUBLICATION-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" candidate_publication_results
