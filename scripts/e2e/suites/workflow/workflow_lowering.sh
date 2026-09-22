#!/usr/bin/env bash
# =============================================================================
# FG-095c / FG-095a: Workflow lowering, schema conformance, and refusal campaign
# =============================================================================
# The Rust tests cover the subset thoroughly in-process. This suite covers:
#   1. the REPOSITORY-OWNED COMMAND produces the committed golden, so AGENTS.md
#      12 ("YAML may not carry logic unavailable through a repository-owned
#      command") is demonstrated rather than asserted;
#   2. the refusal path exits 1 and NAMES the construct, which is what a CI
#      operator actually sees;
#   3. the published construct registry parses and its counts agree with the
#      rows it lists — a compatibility table that disagrees with itself is
#      worse than none;
#   4. in-process schema, span, condition, and literal-script verification tests.
set -euo pipefail

WF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WF_REPO="$(cd "$WF_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$WF_REPO/scripts/e2e/lib.sh"

fge_init fg095c-workflow-lowering
fge_context bead frankengit-fg095c-workflow-evidence-6opd
fge_context crate fgit-schema
fge_context command fgit-workflow
fge_context suite workflow-lowering

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/frankengit-targets/antigravity_rc}"

readonly WF_GOLDENS="$WF_REPO/crates/fgit-schema/tests/workflow-goldens"
readonly WF_SOURCE="$WF_GOLDENS/ci.workflow.yml"
readonly WF_GRAPH="$WF_GOLDENS/ci.graph"
readonly WF_REGISTRY="$WF_REPO/crates/fgit-schema/generated/workflow-constructs.json"

fge_phase setup

fge_assert_file FG-095A-E2E-001 "$WF_SOURCE" 'the workflow fixture is present'
fge_assert_file FG-095A-E2E-002 "$WF_GRAPH" 'the committed canonical graph is present'
fge_assert_file FG-095A-E2E-003 "$WF_REGISTRY" 'the published construct registry is present'
fge_context golden_digest "$(fge_digest_file "$WF_GRAPH")"

fge_phase action

# ------------------------------------------- the command reproduces the golden
fge_run 'fgit-workflow check' \
  cargo run -q -p fgit-schema --bin fgit-workflow -- check "$WF_SOURCE" "$WF_GRAPH" || true
fge_assert_exit FG-095A-E2E-010 0 "$FGE_LAST_EXIT" \
  'the committed graph is what the command produces'

fge_phase assert

# Determinism through the command: two invocations must agree byte for byte.
WF_WORK=$(fge_tempdir workflow-lower)
fge_run 'lower once' \
  cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_SOURCE" || true
fge_assert_exit FG-095A-E2E-020 0 "$FGE_LAST_EXIT" 'lowering succeeds'

cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_SOURCE" > "$WF_WORK/a.graph"
cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_SOURCE" > "$WF_WORK/b.graph"
fge_assert_eq FG-095A-E2E-021 \
  "$(fge_digest_file "$WF_WORK/a.graph")" "$(fge_digest_file "$WF_WORK/b.graph")" \
  'two lowerings of one source agree byte for byte'
fge_assert_eq FG-095A-E2E-022 \
  "$(fge_digest_file "$WF_GRAPH")" "$(fge_digest_file "$WF_WORK/a.graph")" \
  'the command reproduces the committed golden'

# Topological order is visible in the artifact: the fixture lists `lint` first
# and the graph must emit `build` first.
wf_build_line=$(grep -n '^job	build' "$WF_GRAPH" | cut -d: -f1)
wf_lint_line=$(grep -n '^job	lint' "$WF_GRAPH" | cut -d: -f1)
fge_assert_eq FG-095A-E2E-023 1 \
  "$([ "$wf_build_line" -lt "$wf_lint_line" ] && echo 1 || echo 0)" \
  'a dependency is emitted before its dependent'

fge_phase failpoint

# --------------------------------------------- the refusal path is reachable
printf 'name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - uses: actions/checkout\n' \
  > "$WF_WORK/uses.yml"
fge_run 'refuse step.uses' \
  cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_WORK/uses.yml" || true
fge_assert_exit FG-095A-E2E-030 1 "$FGE_LAST_EXIT" 'an out-of-subset construct exits 1'

wf_message=$(cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_WORK/uses.yml" 2>&1 || true)
fge_assert_contains FG-095A-E2E-031 "$wf_message" 'step.uses' \
  'the refusal names the construct, not just the file'
fge_assert_contains FG-095A-E2E-032 "$wf_message" 'line 7' \
  'the refusal names the line'

printf 'name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    if: always\n    steps:\n      - run: x\n' \
  > "$WF_WORK/ambiguous.yml"
wf_ambiguous=$(cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_WORK/ambiguous.yml" 2>&1 || true)
fge_assert_contains FG-095A-E2E-033 "$wf_ambiguous" 'job.if' \
  'an ambiguous construct is refused by name too'

# PERMITTED TWIN: the accepted fixture still lowers
fge_run 'permitted twin still lowers' \
  cargo run -q -p fgit-schema --bin fgit-workflow -- lower "$WF_SOURCE" || true
fge_assert_exit FG-095A-E2E-034 0 "$FGE_LAST_EXIT" \
  'the accepted fixture still lowers after the refusals'

fge_phase action

# ------------------------------------------------- the published registry
if command -v python3 >/dev/null 2>&1; then
  export PYTHONDONTWRITEBYTECODE=1
  fge_run 'registry parses and self-agrees' python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
rows = d['constructs']
counts = {k[len('count_'):]: v for k, v in d.items() if k.startswith('count_')}
tally = {}
for r in rows:
    tally[r['status']] = tally.get(r['status'], 0) + 1
    assert r['reason'], r['key']
    assert r['refuses'] == (r['status'] in ('unsupported', 'ambiguous')), r['key']
assert tally == {k: v for k, v in counts.items() if v}, (tally, counts)
assert [r['key'] for r in rows] == sorted(r['key'] for r in rows), 'registry is not key-sorted'
print(f'{len(rows)} constructs, counts agree with rows')
" "$WF_REGISTRY" || true
  fge_assert_exit FG-095A-E2E-040 0 "$FGE_LAST_EXIT" \
    'the construct registry parses, is sorted, and its counts match its rows'
else
  fge_unsupported FG-095A-E2E-040 'python3 is unavailable, so the registry check did not run'
fi

# Run the schema and workflow lowering test suites
local_test_exit=0
fge_capture 'workflow-schema-tests' \
  cargo test --locked -p fgit-schema --test workflow --test workflow_spans --test workflow_literal_scripts --test workflow_conditions || local_test_exit=$?
fge_assert_exit FG-095A-E2E-050 0 "$local_test_exit" \
  'in-process workflow schema and lowering unit test suites pass cleanly'

fge_phase teardown

fge_field accepted_constructs "$(grep -c '"status": "accepted"' "$WF_REGISTRY" || true)"
fge_field refused_constructs "$(grep -c '"refuses": true' "$WF_REGISTRY" || true)"
fge_note summary 'workflow lowering verified: deterministic graph production, source span tracking, and construct registry compliance'
