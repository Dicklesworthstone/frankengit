#!/usr/bin/env bash
# e2e: replayable FG-033c recovery, repair, GC, retention, and erasure incidents.
#
# The harness discovers suites recursively, so this ruled location is the
# registered form of the incident matrix without a root-level wrapper or a
# runner edit.  Shell owns only the matrix receipt: every scenario below runs
# an existing real crate test, whose typed result remains the oracle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

capture_test() {
  local step=$1
  local output_name=$2
  shift 2

  fge_capture "$step" env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked "$@" || true
  printf -v "$output_name" '%s' "$FGE_LAST_STDOUT"
  return "$FGE_LAST_EXIT"
}

main() {
  local report_exit=0 restore_exit=0 raptor_exit=0 scrub_exit=0 repair_race_exit=0
  local gc_exit=0 rollback_exit=0 erasure_exit=0 resurrection_exit=0
  local report_out='' restore_out='' raptor_out='' scrub_out='' repair_race_out=''
  local gc_out='' rollback_out='' erasure_out='' resurrection_out=''

  fge_phase setup
  fge_context matrix 'materialization loss; bounded and beyond-budget repair; repair/newer-write; GC retention race; legal-hold retention; interrupted root-last capsule; cryptographic erasure; residual resurrection'
  fge_context profile 'full_closure_with_repair'
  fge_context report_binding 'RecoveryReport canonical body is committed through existing AttestedBackupExport durability_evidence_root; no signing authority is created here'
  fge_context non_claim 'This is a bounded deterministic incident matrix over in-process real crate tests. It does not claim provider-media recovery, a production fleet RPO/RTO SLO, or physical deletion of every historical copy.'

  fge_assert_file 'FG-033C-E2E-001' \
    "$REPOSITORY_ROOT/crates/fgit-repair/tests/recovery_report.rs" \
    'the canonical per-profile RecoveryReport and its existing S5 attestation binding are checked in'
  fge_assert_file 'FG-033C-E2E-002' \
    "$REPOSITORY_ROOT/crates/fgit-raptorq/tests/unrecoverable_region.rs" \
    'the within-budget control and typed beyond-budget refusal drill are checked in'

  fge_phase action
  capture_test 'rpo-rto-attested-report' report_out \
    -p fgit-repair --test recovery_report || report_exit=$?
  capture_test 'attested-materialization-restore' restore_out \
    -p fgit-chronicle --test live_capsule_freeze \
    attested_export_restores_a_clean_authority_boundary_without_routing -- --exact \
    || restore_exit=$?
  capture_test 'bounded-and-unrecoverable-repair' raptor_out \
    -p fgit-raptorq --test unrecoverable_region \
    repair_envelope_has_a_permitted_twin_and_a_typed_beyond_budget_verdict -- --exact \
    || raptor_exit=$?
  capture_test 'bounded-repair-worker' scrub_out \
    -p fgit-repair --test scrub_scheduler || scrub_exit=$?
  capture_test 'repair-versus-newer-write' repair_race_out \
    -p fgit-resource --test obligation_kinds \
    decoder_success_alone_cannot_commit_a_repair -- --exact \
    || repair_race_exit=$?
  capture_test 'gc-retention-races' gc_out \
    -p fgit-repair --test gc_epoch || gc_exit=$?
  capture_test 'interrupted-capsule-anti-rollback' rollback_out \
    -p fgit-chronicle --test recovery_rules \
    an_unverified_acknowledged_root_halts_instead_of_retreating -- --exact \
    || rollback_exit=$?
  capture_test 'cryptographic-erasure' erasure_out \
    -p fgit-crypto --test sealing \
    erasure_makes_dependent_ciphertext_typed_unrecoverable_and_never_unknown -- --exact \
    || erasure_exit=$?
  capture_test 'residual-resurrection' resurrection_out \
    -p fgit-object-fabric --test fabric_fault_suite \
    a_resurrected_object_is_staged_only_and_never_regains_canonical_status -- --exact \
    || resurrection_exit=$?

  fge_phase assert
  fge_assert_exit 'FG-033C-E2E-010' 0 "$report_exit" \
    'the full eight-cell report with measured RPO/RTO samples has a canonical, attestation-bound body'
  fge_assert_contains 'FG-033C-E2E-011' "$report_out" \
    'report_round_trips_and_binds_to_the_existing_export_attestation ... ok' \
    'the selected profile report binds through existing S5 export attestation'
  fge_assert_contains 'FG-033C-E2E-012' "$report_out" \
    'changing_measured_rto_after_attestation_is_refused ... ok' \
    'measured RTO cannot be edited after attestation'

  fge_assert_exit 'FG-033C-E2E-020' 0 "$restore_exit" \
    'total materialization/index boundary restores only through the attested root-last path'
  fge_assert_contains 'FG-033C-E2E-021' "$restore_out" \
    'attested_export_restores_a_clean_authority_boundary_without_routing ... ok' \
    'restored state remains unrouted until its verified boundary is installed'

  fge_assert_exit 'FG-033C-E2E-030' 0 "$raptor_exit" \
    'the bounded-loss control reconstructs while the beyond-budget twin is typed unrecoverable'
  fge_assert_contains 'FG-033C-E2E-031' "$raptor_out" \
    'repair_envelope_has_a_permitted_twin_and_a_typed_beyond_budget_verdict ... ok' \
    'one extra missing source symbol cannot be presented as recovered'
  fge_assert_exit 'FG-033C-E2E-032' 0 "$scrub_exit" \
    'the resource-bounded repair worker completes its live missing/corrupt-placement drills'
  fge_assert_contains 'FG-033C-E2E-033' "$scrub_out" \
    'missing_and_corrupt_placements_emit_suspects_and_reach_repair' \
    'a bounded worker turns a live missing or corrupt placement into a repair attempt'

  fge_assert_exit 'FG-033C-E2E-040' 0 "$repair_race_exit" \
    'a decoded candidate must revalidate current authority before repair publication'
  fge_assert_contains 'FG-033C-E2E-041' "$repair_race_out" \
    'decoder_success_alone_cannot_commit_a_repair ... ok' \
    'a moved head or expired retention refuses stale repair rather than overwriting or resurrecting'

  fge_assert_exit 'FG-033C-E2E-050' 0 "$gc_exit" \
    'the authenticated GC epoch campaign completes'
  fge_assert_contains 'FG-033C-E2E-051' "$gc_out" \
    'objects_created_after_the_gc_basis_are_protected_without_tombstones ... ok' \
    'a new commit after mark is protected'
  fge_assert_contains 'FG-033C-E2E-052' "$gc_out" \
    'revalidation_prevents_physical_deletion_when_an_object_becomes_retained ... ok' \
    'a newly added retention or legal-hold root blocks sweep after mark'

  fge_assert_exit 'FG-033C-E2E-060' 0 "$rollback_exit" \
    'an interrupted acknowledged capsule refuses silent rollback'
  fge_assert_contains 'FG-033C-E2E-061' "$rollback_out" \
    'an_unverified_acknowledged_root_halts_instead_of_retreating ... ok' \
    'a newer unresolved root is preserved for audit instead of falling back'

  fge_assert_exit 'FG-033C-E2E-070' 0 "$erasure_exit" \
    'cryptographically erased ciphertext has a typed permanent-unrecoverable result'
  fge_assert_contains 'FG-033C-E2E-071' "$erasure_out" \
    'erasure_makes_dependent_ciphertext_typed_unrecoverable_and_never_unknown ... ok' \
    'erasure is never downgraded into a retryable unknown-key condition'

  fge_assert_exit 'FG-033C-E2E-080' 0 "$resurrection_exit" \
    'a residual placement cannot recover canonical visibility without current authority'
  fge_assert_contains 'FG-033C-E2E-081' "$resurrection_out" \
    'a_resurrected_object_is_staged_only_and_never_regains_canonical_status ... ok' \
    'resurrection is staged evidence, never unauthorized visible or durable data'
}

fge_init fg033c-recovery-incident-matrix
fge_context bead frankengit-fg033c-recovery-campaign-q7v
fge_context evidence_class bounded_fault_and_recovery_campaign
fge_context harness_seed "$(fge_seed)"
main
