#!/usr/bin/env bash
# FG-003c: the exhaustive small-state model campaign, driven end to end.
#
# The campaign is bounded model checking over the pure reference model in
# crates/fgit-reference. It enumerates the reachable state space under declared
# bounds rather than sampling it, and asserts the five properties of plan §40.2
# across the whole of that space.
#
# What this suite adds beyond `cargo test` is the evidence boundary: it captures
# the campaign's NDJSON receipt, checks the receipt actually states its bounds
# and names every property, and refuses a run that was truncated by its own
# state ceiling. A bounded result whose bounds are unstated, or that silently
# covered a fraction of the space, is not evidence of anything.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='campaign_e2e'

main() {
  local artifacts=''
  local worker_exit=0
  local receipt=''

  fge_phase setup
  # `FGE_ARTIFACT_DIR` is where the harness collects evidence for this run; the
  # deflate differential worker publishes its receipt the same way.
  artifacts="$FGE_ARTIFACT_DIR/model-campaign"
  mkdir -p "$artifacts"

  fge_phase action

  # `--ignored` is how the worker is gated out of an ordinary test run; the
  # deflate differential worker uses the same shape.
  #
  # `fge_capture`, not `fge_run_ok`: `fge_run_ok` calls `fge_die` on a non-zero
  # exit, and `fge_die` exits the suite immediately. That would abort before a
  # single assertion below ran, so a failing campaign would report a bare
  # "step failed with exit 101" and lose the receipt, the violated property and
  # the minimised counterexample — exactly the evidence the suite exists to
  # surface. `fge_capture` returns the exit code instead, and additionally
  # saves the worker's stdout, which carries the NDJSON receipt and the
  # step-by-step counterexample the worker prints on violation.
  # `RCH_CARGO_WRAPPER_BYPASS=1` is set HERE rather than assumed from the
  # caller's environment (AGENTS.md 16.2). Without it the rch wrapper offloads
  # the build to a remote host: the worker runs and PASSES there, but it writes
  # the receipt into the remote artifact directory, only the built binary comes
  # back, and this suite then fails two assertions for a missing receipt. That
  # reads exactly like a campaign regression and is not one -- it cost real
  # diagnosis time once, which is why it is pinned in the suite instead of left
  # to whoever invokes it.
  fge_capture 'campaign-worker' env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_REFERENCE_CAMPAIGN_ARTIFACT_DIR=$artifacts" \
    "FGIT_REFERENCE_CAMPAIGN_MODE=${FGIT_REFERENCE_CAMPAIGN_MODE:-default}" \
    cargo test --locked -p fgit-reference --test "$TEST_NAME" -- --ignored || worker_exit=$?

  # Preserve the worker's own output whatever happened, so a violation is
  # diagnosable from the run's artifacts alone.
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" model-campaign-worker-stdout
  fi

  fge_assert_exit 'FG-003C-E2E-001' 0 "$worker_exit" \
    'the bounded campaign exhausts its declared space with no property violation'

  fge_assert_file 'FG-003C-E2E-002' "$artifacts/receipt.ndjson" \
    'the campaign emits a receipt'
  fge_assert_ndjson 'FG-003C-E2E-003' "$artifacts/receipt.ndjson" \
    'the campaign receipt is parseable NDJSON'

  if [[ -f "$artifacts/receipt.ndjson" ]]; then
    receipt="$(<"$artifacts/receipt.ndjson")"

    # The bounds must be in the receipt. This is the difference between
    # "the properties hold" and "the properties hold within this envelope".
    fge_assert_contains 'FG-003C-E2E-004' "$receipt" '"record":"model_campaign"' \
      'the receipt identifies itself'
    fge_assert_contains 'FG-003C-E2E-005' "$receipt" '"transactions":' \
      'the receipt states its transaction bound'
    fge_assert_contains 'FG-003C-E2E-006' "$receipt" '"depth":' \
      'the receipt states its depth bound'
    fge_assert_contains 'FG-003C-E2E-007' "$receipt" '"max_states":' \
      'the receipt states its state ceiling'

    # A truncated walk is not an exhaustive result and must never read as one.
    fge_assert_contains 'FG-003C-E2E-008' "$receipt" '"truncated":false' \
      'the walk exhausted the bounded space rather than hitting its ceiling'
    fge_assert_contains 'FG-003C-E2E-009' "$receipt" '"violations":0' \
      'no property failed anywhere in the bounded space'

    # Coverage denominators: a campaign that explored nothing would otherwise
    # satisfy every assertion above.
    fge_assert_not_contains 'FG-003C-E2E-010' "$receipt" '"states_explored":0' \
      'the walk explored a non-empty state space'
    fge_assert_not_contains 'FG-003C-E2E-011' "$receipt" '"refused_transitions":0' \
      'the walk offered structurally impossible inputs and they failed closed'

    # Every property of plan §40.2 must be named, so the receipt cannot claim a
    # clean run while silently checking fewer of them.
    fge_assert_contains 'FG-003C-E2E-012' "$receipt" '"unique_terminal_outcome"' \
      'the receipt names the unique-terminal-outcome property'
    fge_assert_contains 'FG-003C-E2E-013' "$receipt" '"head_chain_continuity"' \
      'the receipt names the head-chain-continuity property'
    fge_assert_contains 'FG-003C-E2E-014' "$receipt" '"atomic_ref_and_forge_effects"' \
      'the receipt names the atomic ref-and-forge property'
    fge_assert_contains 'FG-003C-E2E-015' "$receipt" '"no_root_omission"' \
      'the receipt names the no-root-omission property'
    fge_assert_contains 'FG-003C-E2E-016' "$receipt" '"no_silent_anti_rollback"' \
      'the receipt names the no-silent-anti-rollback property'

    # Naming a property is not checking one. A property whose subject never
    # occurs in the explored space holds vacuously, so the receipt carries a
    # witness count per property and these assertions refuse a run where any of
    # them is zero.
    fge_assert_contains 'FG-003C-E2E-017' "$receipt" '"vacuous_properties":0' \
      'every declared property was exercised by a reached state'
    fge_assert_not_contains 'FG-003C-E2E-018' "$receipt" '"exercised":false' \
      'no property in the receipt was checked over an empty set'

    # The space has to contain the cases the properties are about. Each of these
    # was zero before this bead was reopened, which is what made the clean
    # verdict misleading.
    fge_assert_not_contains 'FG-003C-E2E-019' "$receipt" '"refused_decisions":0' \
      'a terminal refusal is reachable in the explored space'
    fge_assert_not_contains 'FG-003C-E2E-020' "$receipt" '"forge_merge_commits":0' \
      'a committed merge event is reachable, so the atomicity property has a subject'
    fge_assert_not_contains 'FG-003C-E2E-021' "$receipt" '"cas_losses":0' \
      'a lost head compare-and-swap is reachable'
    fge_assert_not_contains 'FG-003C-E2E-022' "$receipt" '"deferred_repreparations":0' \
      'a superseded capsule is reachable, so the space can actually conflict'
    fge_assert_not_contains 'FG-003C-E2E-023' "$receipt" '"committed_decisions":0' \
      'a commit is reachable in the explored space'
    fge_assert_not_contains 'FG-003C-E2E-024' "$receipt" '"cas_retry_wins":0' \
      'a batch that lost the head can go on to win it — the retry of §10 step 19'
    fge_assert_not_contains 'FG-003C-E2E-025' "$receipt" '"max_head_generation":1' \
      'the head actually advanced, so publication was exercised rather than only staged'

    fge_artifact "$artifacts/receipt.ndjson" model-campaign-receipt
  fi
}

fge_init fg003c-model-campaign
fge_context bead frankengit-fg003c-smallstate-campaign-zig
fge_context evidence_class bounded_model
fge_context method 'explicit breadth-first state-space enumeration with exact deduplication over the canonical encoding of state'
fge_context deep_mode 'set FGIT_REFERENCE_CAMPAIGN_MODE=deep for the wider documented bounds'
fge_context non_claim 'bounded model checking over the reference model only; it is not a proof, and it says nothing about any implementation until trace refinement (plan §40.5) connects one to this oracle'
fge_context non_claim_scope 'the result holds for the bounds named in the receipt and for no wider envelope'
fge_context non_vacuity 'the receipt carries a per-property witness count and coverage counters; a property with zero witnesses fails this suite rather than reading as verified'
fge_context detection 'the walker is self-tested against six planted model defects, at least one per property, in fgit-reference unit tests — the suite asserts coverage, the unit tests assert detection'
fge_context reachability_limit 'these bounds spend their depth on retry breadth (two preparation attempts per transaction), so a transaction committing AFTER another one published is out of reach here; Bounds::SEQUENCED covers that execution and fgit-reference::campaign::tests::the_sequenced_bounds_reach_a_second_commit asserts it'
main
