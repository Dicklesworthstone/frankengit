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
fge_context scope 'Trusted local indexed retrieval, byte positions, finite work and original label membership.'

FG_BIN=${FG_BIN:-}
fge_phase setup
fge_assert_cmd SEARCH-INITIAL-001 'a prebuilt executable fg binary is supplied' test -x "${FG_BIN}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
suite_work="$(fge_tempdir search-initial)"
ORACLE="$E2E_ROOT/oracle/oracle.sh"
PIN=git-2.54.0
fge_run verify-search-oracle "$ORACLE" verify "$PIN" || true
if [[ "$FGE_LAST_EXIT" == 69 ]]; then
  fge_unsupported SEARCH-INITIAL-ORACLE 'the pinned Git oracle is unavailable'
  exit 0
fi
fge_assert_exit SEARCH-INITIAL-ORACLE 0 "$FGE_LAST_EXIT"
TENANT=c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1
REPOSITORY=c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2
PRINCIPAL=c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3

search() { # mode outfile fields...
  local mode=$1 out=$2
  shift 2
  local rc=0
  "$FG_BIN" search "--$mode" "$NODE" "$TENANT" "$REPOSITORY" --trusted-local --object-format "$format" \
    ref=refs/heads/main term_hex=5468696e67 "$@" >"${WORK}/${out}" 2>"${WORK}/${out}.err" || rc=$?
  printf '%s' "$rc"
}
for format in sha1 sha256; do
  suffix=""
  if [[ "$format" == sha256 ]]; then suffix="-SHA256"; fi
  WORK="$suite_work/$format"
  NODE="$WORK/node"
  mkdir -p "$WORK/src/src" "$WORK/src/src2"
  printf 'pub fn Thing() {}\n' > "$WORK/src/src/Thing.rs"
  printf '// Thing\npub struct Other;\n' > "$WORK/src/src/comment.rs"
  printf 'pub fn Thing() {}\n' > "$WORK/src/src2/Thing.rs"
  run=$("$ORACLE" create-run "$PIN" "initial-search-$format")
  "$ORACLE" run "$PIN" "$run" . -- init --quiet --bare --initial-branch=main --object-format="$format" bare
  {
    printf 'commit refs/heads/main\nmark :1\ncommitter A <a@example.invalid> 1720000000 +0000\ndata 6\ncorpus\n'
    for file in src/Thing.rs src/comment.rs src2/Thing.rs; do
      printf 'M 100644 inline %s\ndata %s\n' "$file" "$(wc -c < "$WORK/src/$file")"
      cat "$WORK/src/$file"
      printf '\n'
    done
    printf 'commit refs/heads/next\ncommitter A <a@example.invalid> 1720000001 +0000\ndata 4\nnext\nfrom :1\n'
    printf 'M 100644 inline src/NextThing.rs\ndata 22\npub fn NextThing() {}\n\ndone\n'
  } | "$ORACLE" run "$PIN" "$run" bare -- fast-import --quiet
  tip=$("$ORACLE" run "$PIN" "$run" bare -- rev-parse refs/heads/main)
  next_tip=$("$ORACLE" run "$PIN" "$run" bare -- rev-parse refs/heads/next)
  fge_phase action
  setup_exit=0
  {
    "$FG_BIN" init "$NODE" "$TENANT" "$REPOSITORY" "$format" &&
      "$FG_BIN" import "$NODE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" initial-cli "$run/work/bare" &&
      "$FG_BIN" index "$NODE" "$TENANT" "$REPOSITORY" "$format" refs/heads/main build genesis &&
      "$FG_BIN" symbol-index "$NODE" "$TENANT" "$REPOSITORY" "$format" refs/heads/main build genesis
  } >"${WORK}/setup.out" 2>"${WORK}/setup.err" || setup_exit=$?
  fge_assert_exit "SEARCH-INITIAL-002$suffix" 0 "$setup_exit" 'fg initializes, imports and builds lexical and symbol indexes'

  initial_exit=$(search initial initial.json max_work=4096 symbol_name_hex=5468696e67 symbol_policy=required)
  limited_exit=$(search initial limited.json max_results_per_channel=1)
  work_exit=$(search initial work.json max_work=32 symbol_name_hex=5468696e67 symbol_policy=required)
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
  fge_assert_exit "SEARCH-INITIAL-003$suffix" 0 "$initial_exit" 'complete joined Initial search exits 0'
  fge_assert_contains "SEARCH-INITIAL-004$suffix" "$summary" '"initial_type": "source_search_initial", "initial_complete": true, "symbols": "available", "read_only": true' \
    'one read-only document with the required symbol channel available'
  fge_assert_exit "SEARCH-INITIAL-005$suffix" 3 "$limited_exit" 'a per-channel result ceiling is an explicitly truncated answer (exit 3)'
  fge_assert_exit "SEARCH-INITIAL-006$suffix" 0 "$context_exit" 'ranked context packet exits 0'
  fge_assert_exit "SEARCH-INITIAL-007$suffix" 0 "$raw_exit" 'raw-path context packet exits 0'
  fge_assert_contains "SEARCH-INITIAL-008$suffix" "$summary" '"context_files": ["src/Thing.rs", "src/comment.rs", "src2/Thing.rs"]' \
    'the ranked packet hydrates exactly the matching files'
  fge_assert_contains "SEARCH-INITIAL-009$suffix" "$summary" '"untrusted": true, "same_snapshot": true' \
    'packet source material is untrusted data from the same snapshot'
  fge_assert_exit "SEARCH-INITIAL-010$suffix" 2 "$refused_exit" 'symbol options without a name refuse instead of answering'
  fge_assert_contains "SEARCH-INITIAL-011$suffix" "$(cat "${WORK}/refused.json.err")" 'symbol_options_without_name' \
    'the refusal carries the route code'

  fge_assert_cmd "SEARCH-INITIAL-012$suffix" 'every hit and anchor matches its Git byte position and original host-bound label' \
    python3 "$E2E_ROOT/helpers/initial_search_labels.py" "$WORK" "$WORK/src" "$format" "$tip"
  fge_assert_exit "SEARCH-INITIAL-013$suffix" 2 "$work_exit" 'the same three-channel request refuses an insufficient work budget'
  fge_assert_contains "SEARCH-INITIAL-014$suffix" "$(cat "$WORK/work.json.err")" 'resource_limit' 'budget exhaustion is visible'
  progress_exit=$(search progressive ranked.ndjson)
  progress_refusal=$(search progressive limited-context.ndjson context_max_source_bytes=1)
  progress_capped=$(search progressive capped.ndjson max_results_per_channel=1 symbol_name_hex=5468696e67 symbol_policy=required)
  current_exit=$(search progressive current.ndjson index_source=current-native-v1)
  initial_refusal=$(search progressive early-refusal.ndjson max_work=32 symbol_name_hex=5468696e67 symbol_policy=required)
  fge_assert_exit "SEARCH-PROGRESS-001$suffix" 0 "$progress_exit" 'a bounded progressive query returns a ranked context'
  fge_assert_exit "SEARCH-PROGRESS-002$suffix" 2 "$progress_refusal" 'the source-byte budget refuses the refinement'
  fge_assert_exit "SEARCH-PROGRESS-003$suffix" 2 "$initial_refusal" 'the Initial work budget refuses before publication'
  fge_assert_exit "SEARCH-PROGRESS-005$suffix" 3 "$progress_capped" 'three budget-limited channels retain the partial-answer exit'
  fge_assert_exit "SEARCH-PROGRESS-006$suffix" 0 "$current_exit" 'current native source supports the same bounded progressive ranker'
  fge_assert_cmd "SEARCH-PROGRESS-004$suffix" 'the two phases preserve the original answer, labels and anchored ranking across refinement success and failure' \
    python3 - "$WORK" <<'PYTHON'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
def records(name):
    return [json.loads(line) for line in (work / name).read_bytes().splitlines()]
initial, refined = records("ranked.ndjson")
kept, failure = records("limited-context.ndjson")
expected = json.loads((work / "context.json").read_bytes())
assert initial == {"phase": "Initial", "answer": expected["retrieval"]}
assert refined == {"phase": "Refined", "answer": expected}
assert kept == initial
assert failure == {"phase": "RefinementFailed", "code": "resource_limit"}, failure
assert records("early-refusal.ndjson") == []
current, current_ranked = records("current.ndjson")
assert current["phase"] == "Initial" and current_ranked["phase"] == "Refined"
assert current_ranked["answer"]["retrieval"] == current["answer"]
assert current_ranked["answer"]["selection"] == "context-weighted-rrf-q16-v1"
assert current["answer"]["generation_vector"] == initial["answer"]["generation_vector"]
partial, ranked = records("capped.ndjson")
assert partial["answer"]["complete"] is ranked["answer"]["complete"] is False
assert ranked["answer"]["retrieval"] == partial["answer"]
assert partial["answer"]["generation_vector"]["symbols"] is not None
PYTHON
  # A real issue write advances repository authority without changing source.
  # Reuse the original immutable indexes through every trusted-local read mode.
  metadata_exit=0
  "$FG_BIN" issue open "$NODE" "$TENANT" "$REPOSITORY" 1 --trusted-local \
    --principal "$PRINCIPAL" --idempotency-key initial-retrieval-metadata \
    --object-format "$format" --expected-version 0 --title 'Metadata only' --body '' \
    >"$WORK/metadata.out" 2>"$WORK/metadata.err" || metadata_exit=$?
  fge_assert_exit "SEARCH-PROGRESS-007$suffix" 0 "$metadata_exit" 'issue publication advances metadata without rebuilding either index'
  metadata_initial=$(search initial metadata-initial.json index_source=current-native-v1 symbol_name_hex=5468696e67 symbol_policy=required)
  metadata_ranked=$(search context metadata-context.json index_source=current-native-v1 context_selection=context-weighted-rrf-q16-v1 symbol_name_hex=5468696e67 symbol_policy=required)
  metadata_progressive=$(search progressive metadata.ndjson index_source=current-native-v1 symbol_name_hex=5468696e67 symbol_policy=required)
  metadata_strict=$(search context metadata-strict.json context_selection=context-weighted-rrf-q16-v1)
  fge_assert_exit "SEARCH-PROGRESS-008$suffix" 0 "$metadata_initial" 'current Initial remains available after a metadata-only write'
  fge_assert_exit "SEARCH-PROGRESS-009$suffix" 0 "$metadata_ranked" 'current ranked context retains source and index provenance after a metadata-only write'
  fge_assert_exit "SEARCH-PROGRESS-010$suffix" 0 "$metadata_progressive" 'both progressive phases preserve the selected current source'
  fge_assert_exit "SEARCH-PROGRESS-011$suffix" 2 "$metadata_strict" 'the strict ranked profile retains its exact-head refusal'
  fge_assert_cmd "SEARCH-PROGRESS-012$suffix" 'current ranked and progressive answers retain immutable generations and the original Initial labels' \
    python3 - "$WORK" <<'PYTHON'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
old = json.loads((work / "initial.json").read_bytes())
initial = json.loads((work / "metadata-initial.json").read_bytes())
context = json.loads((work / "metadata-context.json").read_bytes())
phases = [json.loads(line) for line in (work / "metadata.ndjson").read_bytes().splitlines()]
assert phases == [{"phase": "Initial", "answer": initial}, {"phase": "Refined", "answer": context}]
assert context["retrieval"] == initial
assert context["selection"] == "context-weighted-rrf-q16-v1"
assert initial["snapshot_token"] != old["snapshot_token"]
assert initial["generation_vector"] == old["generation_vector"]
assert initial["source_commit"] == old["source_commit"]
assert initial["root_tree"] == old["root_tree"]
for channel in ("lexical", "symbols"):
    source = initial["index_sources"][channel]
    assert source["snapshot_token"] == old["snapshot_token"]
    assert source["source_commit"] == initial["source_commit"]
assert (work / "metadata-strict.json").read_bytes() == b""
PYTHON
  fge_run_timeout 180 "search-initial-service-$format" python3 "$E2E_ROOT/helpers/initial_search_maintenance.py" \
    "$FG_BIN" "$WORK/service" "$format" "$run/work/bare" "$tip" "$next_tip" || true
  fge_assert_exit "SEARCH-INITIAL-015$suffix" 0 "$FGE_LAST_EXIT" \
    'a scoped reader gets both maintained indexes at the new tip after restart and a pulls-only reader is refused'
  other=sha256
  if [[ "$format" == sha256 ]]; then other=sha1; fi
  for mode in initial context; do
    duplicate_exit=0
    "$FG_BIN" search "--$mode" "$NODE" "$TENANT" "$REPOSITORY" --trusted-local \
      --object-format "$other" --object-format "$format" ref=refs/heads/main term_hex=5468696e67 \
      >"$WORK/$mode-duplicate.out" 2>"$WORK/$mode-duplicate.err" || duplicate_exit=$?
    fge_assert_exit "SEARCH-INITIAL-016-$mode$suffix" 2 "$duplicate_exit" \
      'conflicting hash domains refuse even when the last flag matches the stored repository'
    fge_assert_contains "SEARCH-INITIAL-017-$mode$suffix" "$(cat "$WORK/$mode-duplicate.err")" \
      'duplicate --object-format' 'the refusal identifies the conflicting option'
  done
done
