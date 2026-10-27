#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init source-profile-client
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
NODE_BIN="$(command -v node)"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context node_version "$("$NODE_BIN" --version)"
fge_context node_digest "$(fge_digest_file "$NODE_BIN")"
fge_context non_claim 'Actual operator CLI and native loopback HTTP; not hostile isolation, remote production deployment, full operator or release qualification.'
WORK="$(fge_tempdir source-profile-client)"
fge_phase action
fge_run_timeout 600 PROFILE-CLIENT-001 python3 "$E2E_ROOT/helpers/source_profile_client.py" "$FG_BIN" "$NODE_BIN" "$WORK"
fge_assert_exit PROFILE-CLIENT-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_profile_client_results
