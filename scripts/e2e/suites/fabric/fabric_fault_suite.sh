#!/usr/bin/env bash
# FG-021b: the object fabric's fault, corruption, and failure-domain campaign.
#
# Drives the independent adversarial suite in
# `crates/fgit-object-fabric/tests/fabric_fault_suite.rs` — written by a
# different agent than the fabric, through its public surface only.
#
# What this adds beyond `cargo test` is the evidence boundary. A fault campaign
# can be green and still worthless in three specific ways, and each has
# assertions below:
#
#   1. It exercises a subset of the declared fault points and reports "every
#      declared fault point". The Rust drill asserts its own denominator
#      (covered == 8); this suite asserts the drill count so a silently
#      shrinking campaign is visible from the receipt alone.
#   2. It reports a refusal without saying which one, so a fabric that refused
#      everything for the wrong reason would pass. Every drill asserts a
#      specific `StoreRefusal` variant.
#   3. It treats a non-durable reference backend as evidence about durable
#      placement. The reference profile is explicitly non-durable and this
#      suite records that as a non-claim rather than leaving it inferable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='fabric_fault_suite'
# The drill count the Rust suite is expected to run. Asserted, not assumed: a
# campaign that quietly loses drills is the failure this number exists to make
# visible.
readonly EXPECTED_DRILLS=16

main() {
  local artifacts='' worker_exit=0 output='' passed=''

  fge_phase setup
  artifacts="$FGE_ARTIFACT_DIR/fabric-faults"
  mkdir -p "$artifacts"

  fge_phase action

  # RCH_CARGO_WRAPPER_BYPASS is not optional (AGENTS.md §16.2). Without it the
  # rch offload wrapper intercepts cargo and produces a green worker whose
  # artifacts never appear locally, so assertions fail on MISSING output rather
  # than wrong output and the blame lands on whichever crate was last edited.
  # Set here from the first line rather than added after an audit.
  #
  # The only form that tests the unset case:
  #   env -u RCH_CARGO_WRAPPER_BYPASS bash scripts/e2e/suites/fabric/fabric_fault_suite.sh
  #
  # `fge_capture`, not `fge_run_ok`: the latter calls `fge_die` and would abort
  # before a single assertion ran, discarding the very output this suite reads.
  fge_capture 'fabric-fault-worker' env \
    "RCH_CARGO_WRAPPER_BYPASS=1" \
    cargo test --locked -p fgit-object-fabric --test "$TEST_NAME" \
    || worker_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" fabric-fault-worker-stdout
    output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  fge_assert_exit 'FG-021B-E2E-001' 0 "$worker_exit" \
    'the fabric fault campaign passes every drill'

  # The denominator. `test result: ok. N passed` is the only place the campaign
  # states how much it actually ran, and a campaign that loses drills would
  # otherwise still report success.
  fge_assert_contains 'FG-021B-E2E-002' "$output" "$EXPECTED_DRILLS passed" \
    'the campaign runs its full complement of drills'
  # Anchored on the full summary prefix, not the bare substring "0 passed":
  # "10 passed" and "20 passed" both CONTAIN "0 passed", so the loose form
  # would start failing the moment this campaign grew past nine drills. A
  # brittle assertion that only breaks later is worse than none, because it
  # breaks in someone else's sweep.
  fge_assert_not_contains 'FG-021B-E2E-003' "$output" 'test result: ok. 0 passed' \
    'the campaign is not vacuously empty'
  # NOTE: cargo's summary line always contains the word "ignored" ("0 ignored"),
  # so asserting its ABSENCE would always fail. The honest assertion is that the
  # count is zero. The first draft of this line got that backwards and masked it
  # with `|| true`, which would have recorded a permanent silent failure - the
  # same shape as an assertion that cannot fail, inverted.
  fge_assert_contains 'FG-021B-E2E-004' "$output" '0 ignored' \
    'no drill is skipped: zero #[ignore] and zero fge_skip in this campaign'

  # Every fault class named in the bead scope must have a drill, asserted by
  # name so a silently deleted drill is visible in the receipt.
  fge_assert_contains 'FG-021B-E2E-005' "$output" 'a_fault_before_the_write_refuses_and_stores_nothing' \
    'partial operation: a pre-write fault stores nothing'
  fge_assert_contains 'FG-021B-E2E-006' "$output" 'a_fault_after_the_write_refuses_and_never_claims_visibility' \
    'ambiguous operation: a post-write fault never claims visibility'
  fge_assert_contains 'FG-021B-E2E-007' "$output" 'a_failed_write_settles_its_obligation_as_an_abort_not_a_commit' \
    'obligation debt matches the injected backlog'
  fge_assert_contains 'FG-021B-E2E-008' "$output" 'a_range_read_is_refused_unless_it_covers_the_whole_verified_body' \
    'range truncation is refused, never clamped'
  fge_assert_contains 'FG-021B-E2E-009' "$output" 'an_object_cannot_even_be_built_while_claiming_another_identity' \
    'checksum/identity mismatch is unconstructable, not merely refused'
  fge_assert_contains 'FG-021B-E2E-010' "$output" 'a_resurrected_object_is_staged_only_and_never_regains_canonical_status' \
    'lifecycle resurrection: a reappeared placement does not regain canonical status'
  fge_assert_contains 'FG-021B-E2E-011' "$output" 'a_retained_object_cannot_be_deleted' \
    'retention gates deletion'
  fge_assert_contains 'FG-021B-E2E-012' "$output" 'a_placement_record_names_the_domain_that_actually_holds_it' \
    'failure-domain loss: placement records stay accurate'
  fge_assert_contains 'FG-021B-E2E-013' "$output" 'cancellation_surfaces_as_cancelled_and_never_collapses_into_a_refusal' \
    'cancellation mid-stream stays Cancelled and never becomes a StoreRefusal'
  fge_assert_contains 'FG-021B-E2E-014' "$output" 'every_declared_fault_point_produces_its_own_named_refusal' \
    'all eight declared fault points are exercised, with the denominator asserted'

  passed="$(fge_digest_string "$output" || true)"
  fge_assert_ne 'FG-021B-E2E-015' '' "$passed" \
    'the campaign output is committed to by content digest'
  fge_context campaign_output_sha256 "$passed"
}

fge_init fg021b-fabric-faults
fge_context bead frankengit-fg021b-fabric-faults-c8p
fge_context evidence_class fault_injection
fge_context adversary 'written by a different agent than the fabric under test; public surface only, no src edits'
fge_context non_claim 'ReferenceMemoryFabric is explicitly non-durable. Nothing here is evidence about a durable placement profile, media loss, or replication. A durable backend owes the same properties and its own campaign.'
fge_context non_claim_scope 'an injected Crash models the endpoint dying with its state intact - a process-crash model, not media loss'
fge_context denominator 'the Rust drill asserts covered == 8 against ReferenceFaultPoint; this suite asserts the drill count, so a shrinking campaign is visible from the receipt alone'
main
