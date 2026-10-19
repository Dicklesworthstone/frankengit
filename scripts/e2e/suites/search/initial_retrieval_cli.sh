#!/usr/bin/env bash
# Joined Initial search and context packets through the real fg binary:
# fg init/import, fg index + fg symbol-index build, then fg search --initial
# and --context over the shared node entrypoint that HTTP search-initial and
# context-initial (and MCP frankengit_source_initial/_context) use.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init search-initial-retrieval-cli
fge_kind e2e-binary
fge_context bead frankengit-fg096-mcp-surface-h3f4.2
fge_context non_claim 'Model-free retrieval over persisted indexes only; no semantic channel, index maintenance or authorization claim.'

FG_BIN=${FG_BIN:-}
fge_phase setup
fge_assert_cmd SEARCH-INITIAL-001 'a prebuilt executable fg binary is supplied' test -x "${FG_BIN}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir search-initial)"
TENANT=c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1
REPOSITORY=c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2
PRINCIPAL=c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3
NODE="${WORK}/node"
mkdir -p "${WORK}/src/src" "${WORK}/src/src2"
printf 'pub fn Thing() {}\n' > "${WORK}/src/src/Thing.rs"
printf '// Thing\npub struct Other;\n' > "${WORK}/src/src/comment.rs"
printf 'pub fn Thing() {}\n' > "${WORK}/src/src2/Thing.rs"
git -C "${WORK}/src" init -q -b main
git -C "${WORK}/src" -c user.email=a@example.invalid -c user.name=A add -A
git -C "${WORK}/src" -c user.email=a@example.invalid -c user.name=A commit -qm corpus
git clone -q --bare "${WORK}/src" "${WORK}/bare"

fge_phase action
setup_exit=0
{
  "$FG_BIN" init "$NODE" "$TENANT" "$REPOSITORY" sha1 &&
    "$FG_BIN" import "$NODE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" initial-cli "${WORK}/bare" &&
    "$FG_BIN" index "$NODE" "$TENANT" "$REPOSITORY" sha1 refs/heads/main build genesis &&
    "$FG_BIN" symbol-index "$NODE" "$TENANT" "$REPOSITORY" sha1 refs/heads/main build genesis
} >"${WORK}/setup.out" 2>"${WORK}/setup.err" || setup_exit=$?
fge_assert_exit SEARCH-INITIAL-002 0 "$setup_exit" 'fg initializes, imports and builds lexical and symbol indexes'

search() { # mode outfile fields...
  local mode=$1 out=$2
  shift 2
  local rc=0
  "$FG_BIN" search "--$mode" "$NODE" "$TENANT" "$REPOSITORY" --trusted-local \
    ref=refs/heads/main term_hex=5468696e67 "$@" >"${WORK}/${out}" 2>"${WORK}/${out}.err" || rc=$?
  printf '%s' "$rc"
}
initial_exit=$(search initial initial.json symbol_name_hex=5468696e67 symbol_policy=required)
limited_exit=$(search initial limited.json max_results_per_channel=1)
context_exit=$(search context context.json context_selection=context-weighted-rrf-q16-v1)
raw_exit=$(search context raw.json)
refused_exit=$(search initial refused.json symbol_policy=required)
summary=$(python3 - "${WORK}" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
initial = json.loads((work / "initial.json").read_text())
context = json.loads((work / "context.json").read_text())
raw = json.loads((work / "raw.json").read_text())
paths = lambda doc: sorted(bytes.fromhex(f["path_hex"]).decode() for f in doc["files"])
print(json.dumps({
    "initial_type": initial["type"], "initial_complete": initial["complete"],
    "symbols": initial["symbols"]["state"], "read_only": initial["read_only"],
    "context_type": context["type"], "context_files": paths(context),
    "raw_files": paths(raw), "untrusted": context["source_material_untrusted"],
    "same_snapshot": context["retrieval"]["snapshot_token"] == initial["snapshot_token"],
}))
PY
)
fge_note SEARCH-INITIAL-SUMMARY "$summary"

fge_phase assert
fge_assert_exit SEARCH-INITIAL-003 0 "$initial_exit" 'complete joined Initial search exits 0'
fge_assert_contains SEARCH-INITIAL-004 "$summary" '"initial_type": "source_search_initial", "initial_complete": true, "symbols": "available", "read_only": true' \
  'one read-only document with the required symbol channel available'
fge_assert_exit SEARCH-INITIAL-005 3 "$limited_exit" 'a per-channel result ceiling is an explicitly truncated answer (exit 3)'
fge_assert_exit SEARCH-INITIAL-006 0 "$context_exit" 'ranked context packet exits 0'
fge_assert_exit SEARCH-INITIAL-007 0 "$raw_exit" 'raw-path context packet exits 0'
fge_assert_contains SEARCH-INITIAL-008 "$summary" '"context_files": ["src/Thing.rs", "src/comment.rs", "src2/Thing.rs"]' \
  'the ranked packet hydrates exactly the matching files'
fge_assert_contains SEARCH-INITIAL-009 "$summary" '"untrusted": true, "same_snapshot": true' \
  'packet source material is untrusted data from the same snapshot'
fge_assert_exit SEARCH-INITIAL-010 2 "$refused_exit" 'symbol options without a name refuse instead of answering'
fge_assert_contains SEARCH-INITIAL-011 "$(cat "${WORK}/refused.json.err")" 'symbol_options_without_name' \
  'the refusal carries the route code'
