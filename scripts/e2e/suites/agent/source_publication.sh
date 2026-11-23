#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init agent-source-publication
fge_kind e2e-binary
fge_context suite sponsored-source-publication
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir agent-source-publication)"
fge_phase action
fge_run_timeout 480 AGENT-SOURCE-001 python3 "$E2E_ROOT/helpers/agent_source_publication.py" "$FG_BIN" "$WORK"
fge_phase assert
fge_assert_exit AGENT-SOURCE-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_agent_source_publication_results
