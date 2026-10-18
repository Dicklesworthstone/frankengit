#!/usr/bin/env bash
# Real product binaries: authenticated HTTP blob proof generation and pinned
# fg verification. Not a Cargo-test wrapper or a substitute server.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init verified-blob-http
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.41
fge_context evidence_class e2e_binary_native_http
fge_context acceptance '1,2,3: independently pinned HTTP bytes; tamper/staleness; small and 10000-entry tree cost; discovered prebuilt-binary suite'
fge_context non_claim 'Current exact-head blob profile; original trees are included; no browser D2 integration or historical transport mode.'
fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd VERIFIED-BLOB-001 'FG_BIN names a prebuilt fg executable' test -x "$FG_BIN"
WORK="$(fge_tempdir verified-blob-http)"
fge_phase action
fge_capture proof-http python3 "$E2E_ROOT/verified_blob_http.py" --fg "$FG_BIN" --work-dir "$WORK" || true
RC=$FGE_LAST_EXIT
OUTPUT=$FGE_LAST_STDOUT
fge_phase assert
fge_assert_eq VERIFIED-BLOB-002 0 "$RC" 'real HTTP/client proof and refusal campaign completed with server drain'
fge_assert_contains VERIFIED-BLOB-003 "$OUTPUT" '"object_format": "sha1", "tree_entries": 4' 'SHA-1 complete native blob proof'
fge_assert_contains VERIFIED-BLOB-004 "$OUTPUT" '"object_format": "sha256", "tree_entries": 4' 'SHA-256 complete native blob proof'
fge_assert_contains VERIFIED-BLOB-005 "$OUTPUT" '"object_format": "sha256", "tree_entries": 10000' '10000-entry native tree emits envelope bytes and client verification samples'
fge_phase teardown
