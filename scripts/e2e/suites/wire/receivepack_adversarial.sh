#!/usr/bin/env bash
# FG-019c: receive-pack adversarial and race campaign, driven end to end.
#
# The bead's acceptance asks for this script to be registered in run_all.sh.
# PATH DEVIATION, DECLARED: the bead names `scripts/e2e/receivepack_adversarial.sh`.
# run_all.sh discovers suites by walking `scripts/e2e/suites/**`, so a script at
# the bead's literal path would never run. It lives here instead, which
# satisfies registration through discovery and needs NO edit to the frozen
# harness.
#
# WHAT THIS ADDS BEYOND `cargo test`. The Rust targets already assert the
# properties. What a lane adds is the evidence boundary: a receipt naming which
# corpora ran, at which revision, with the counts visible so a reader can tell a
# campaign that exercised eleven probes from one that silently shrank to two.
# Assertion counts are checked as NUMBERS, not merely as a zero exit, because a
# suite that stopped running probes would still exit zero.
#
# TWO TRAPS THIS SUITE DELIBERATELY AVOIDS, both paid for elsewhere today:
#
#   * `RCH_CARGO_WRAPPER_BYPASS=1` is pinned HERE rather than inherited from the
#     caller (AGENTS.md 16.2). Without it the rch wrapper offloads the build to a
#     remote host; the worker RUNS AND PASSES there but any artifact it writes
#     lands remotely, so a suite fails on a missing file while its worker reports
#     success. That misattributes itself to whichever crate was last touched.
#   * `fge_capture`, never `fge_run_ok`. `fge_run_ok` calls `fge_die` on a
#     non-zero exit, which would abort before a single assertion ran and discard
#     the evidence of WHICH probe failed.
#
# No jq/python/perl/awk anywhere (FG-000A-PORT-019); coreutils only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='receivepack_adversarial'

# The two corpora and the probe count each must run. Pinned as numbers so a
# corpus that silently stopped emitting probes fails this lane instead of
# quietly shrinking it.
readonly WIRE_PROBES=9
readonly ADMISSION_PROBES=4
readonly RACE_PROBES=6

main() {
  local wire_exit=0 admission_exit=0 race_exit=0
  local wire_out='' admission_out='' race_out=''
  local wire_passed=0 admission_passed=0 race_passed=0

  fge_phase setup
  local artifacts=''
  artifacts="$(fge_artifact_path receivepack-adversarial)"
  mkdir -p "${artifacts}"

  # ---- wire layer: quarantine, disconnect matrix, quota bounds -------------
  fge_phase action
  fge_capture wire-probes env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-wire --test receivepack_adversarial \
    || wire_exit=$?
  wire_exit=${wire_exit:-0}
  wire_out="${FGE_LAST_STDOUT:-}"

  # ---- admission layer: pre-seal refusal boundary ---------------------------
  fge_capture admission-probes env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-admission --test receive_admission_adversarial \
    || admission_exit=$?
  admission_exit=${admission_exit:-0}
  admission_out="${FGE_LAST_STDOUT:-}"

  # ---- authority layer: disconnect matrix and the racing-push corpus -------
  fge_capture race-probes env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-admission --test receive_disconnect_and_race \
    || race_exit=$?
  race_exit=${race_exit:-0}
  race_out="${FGE_LAST_STDOUT:-}"

  fge_phase assert
  fge_assert_exit 'FG-019C-E2E-001' 0 "${wire_exit}" \
    'the wire-layer adversarial corpus passes'
  fge_assert_exit 'FG-019C-E2E-002' 0 "${admission_exit}" \
    'the admission-boundary corpus passes'
  fge_assert_exit 'FG-019C-E2E-003' 0 "${race_exit}" \
    'the disconnect-matrix and race corpus passes'

  # Counts, not just exits. A corpus that stopped running probes would exit 0
  # and satisfy the two assertions above while proving nothing.
  wire_passed="$(printf '%s' "${wire_out}" | grep -c '^test .* ok$' || printf '0')"
  admission_passed="$(printf '%s' "${admission_out}" | grep -c '^test .* ok$' || printf '0')"
  race_passed="$(printf '%s' "${race_out}" | grep -c '^test .* ok$' || printf '0')"

  fge_assert_eq 'FG-019C-E2E-010' "${WIRE_PROBES}" "${wire_passed}" \
    'every wire-layer probe ran and passed, so the corpus did not shrink'
  fge_assert_eq 'FG-019C-E2E-011' "${ADMISSION_PROBES}" "${admission_passed}" \
    'every admission-boundary probe ran and passed'
  fge_assert_eq 'FG-019C-E2E-012' "${RACE_PROBES}" "${race_passed}" \
    'every disconnect-matrix and race probe ran and passed'

  # The two load-bearing probes named explicitly, so a rename or deletion is a
  # failure rather than a silent reduction in what this lane covers.
  fge_assert_contains 'FG-019C-E2E-020' "${wire_out}" \
    'cancelling_at_every_checkpoint_leaves_no_stuck_intermediate' \
    'the disconnect matrix probe is present in the run'
  fge_assert_contains 'FG-019C-E2E-021' "${wire_out}" \
    'a_refusal_after_pack_bytes_were_buffered_still_leaves_nothing' \
    'the non-vacuous quarantine-discard probe is present in the run'
  fge_assert_contains 'FG-019C-E2E-022' "${admission_out}" \
    'a_pack_requiring_request_without_a_pack_is_refused_and_the_delete_twin_is_admitted' \
    'the pre-seal refusal probe and its permitted twin are present in the run'
  fge_assert_contains 'FG-019C-E2E-023' "${race_out}" \
    'every_disconnect_at_every_phase_leaves_a_resolvable_transaction' \
    'the authority-layer disconnect matrix is present in the run'
  fge_assert_contains 'FG-019C-E2E-024' "${race_out}" \
    'a_transaction_that_cannot_be_resolved_is_classified_stuck' \
    'the presence case proving the forbidden state is detectable is present in the run'
  fge_assert_contains 'FG-019C-E2E-025' "${race_out}" \
    'a_decision_that_landed_during_a_lost_response_is_not_decided_twice' \
    'the decide-once probe over the push path is present in the run'
  fge_assert_contains 'FG-019C-E2E-026' "${race_out}" \
    'the_race_shape_is_invariant_across_the_projection_family' \
    'the projection-invariance probe that bounds every race claim is present in the run'

  # Preserve both outputs whatever happened, so a failure is diagnosable from
  # the run's artifacts alone rather than needing a re-run.
  printf '%s\n' "${wire_out}" > "${artifacts}/wire-probes.txt"
  printf '%s\n' "${admission_out}" > "${artifacts}/admission-probes.txt"
  printf '%s\n' "${race_out}" > "${artifacts}/race-probes.txt"
  fge_artifact "${artifacts}/wire-probes.txt" receivepack-wire-probes
  fge_artifact "${artifacts}/admission-probes.txt" receivepack-admission-probes
  fge_artifact "${artifacts}/race-probes.txt" receivepack-race-probes
}

fge_init fg019c-receivepack-adversarial
fge_context bead frankengit-fg019c-receivepack-adversarial-sht
fge_context evidence_class adversarial
fge_context method 'independent adversary over ProudJaguar receive-pack (fgit-wire) and admission (fgit-admission); every probe drives the public API and no source of theirs is modified'
fge_context covered 'quarantine discard proven non-vacuously (real bytes buffered then asserted gone); cancellation contract exactly as its owner specified; quota bound refused past and accepted at; pre-seal refusal boundary with its documented delete-only twin; authority-layer disconnect matrix over projection x fault-kind x every operation position a push reaches, classified from the authenticated decision stream; decide-once under a lost response; a duplicated head CAS does not decide one push twice; two sessions over one ref each reported from their own authenticated decision'
fge_context blocked_hidden_refs 'the hidden-ref acceptance line is BLOCKED on a missing capability, not on testing: RefusalCode::HiddenRefUnauthorized (0x0206) is defined in fgit-types and classified in fgit-reference but PRODUCED BY NOTHING; no layer knows principal ref visibility. Confirmed by ProudJaguar. No probe is written for it, because a red assertion against every layer and a green one pinning the absent control are both worse than none'
fge_context claim_class 'BOUNDED MODEL, not invariant. The disconnect and race results range over three authored conforming projections and seven fault kinds, crossed with every operation position a clean admission reaches. They do not quantify over all projections or all schedules'
fge_context projection_bound 'no public AdmissionProjection exists, so the corpus quantifies over a family of authored conforming projections and asserts ONLY what is identical across all of them. Ref-policy questions (whether a losing push is refused ExpectedOldRefMismatch or permitted) belong to the still-absent production projection and are NOT answered here; what is evidenced is that the status reaching report-status comes from the authenticated terminal decision, never from a pack receipt'
fge_context stuck_state_is_detectable 'the forbidden stuck-intermediate class is proven reachable and recognised by driving the exported reconcile_outcome to its fail-closed accelerator-conflict arm, with an agreeing-reads twin, so the matrix assertion can fail in the direction that matters'
fge_context non_claim 'in-process probes of two state machines; nothing here is differential evidence against upstream Git, and nothing speaks for a real network peer'
main
