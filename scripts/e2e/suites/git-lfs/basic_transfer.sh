#!/usr/bin/env bash
# e2e: real stock git-lfs basic upload/download, native identity, restart and refusals.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init git-lfs-basic-transfer
fge_kind e2e-binary
fge_context bead frankengit-fg053-lfs-i3h
fge_context evidence_class e2e_binary_stock_client
fge_context non_claim 'Installed Git and git-lfs over loopback basic transfer; not pinned differential, chunk resume, GC or full FG-053 acceptance.'
fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd LFS-BASIC-001 'FG_BIN names an already-built executable' test -x "$FG_BIN"
[[ -x "$FG_BIN" ]] || fge_die 'Git LFS requires a prebuilt FG_BIN; no build or substitute server is run'
fge_assert_cmd LFS-BASIC-002 'stock git-lfs is installed' "${GIT_ORACLE_BIN:-git}" lfs version
WORK="$(fge_tempdir git-lfs-basic)"
fge_phase action
fge_capture roundtrip python3 "$E2E_ROOT/lfs_roundtrip.py" --fg "$FG_BIN" \
    --git "${GIT_ORACLE_BIN:-git}" --artifact-dir "$WORK/run" || true
RC=$FGE_LAST_EXIT
OUTPUT=$FGE_LAST_STDOUT
fge_phase assert
fge_assert_eq LFS-BASIC-003 0 "$RC" 'stock LFS transfer, restart, refusals and all native listener drains completed'
fge_assert_contains LFS-BASIC-004 "$OUTPUT" '"type": "lfs_roundtrip_passed", "format": "sha1"' \
    'SHA-1 repository retains exact native pointer and LFS binary through restart'
fge_assert_contains LFS-BASIC-005 "$OUTPUT" '"type": "lfs_roundtrip_passed", "format": "sha256"' \
    'SHA-256 repository retains exact native pointer and LFS binary through restart'
