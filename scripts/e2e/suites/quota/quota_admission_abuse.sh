#!/usr/bin/env bash
# FG-056b: Quota/admission cross-tenant abuse campaign.
#
# Acceptance criteria verified:
# - cross-tenant quota isolation: abuse by one tenant never exhausts another tenant's guaranteed share;
# - multi-level hierarchy (tenant > org > user > repo) enforces the tightest applicable bound;
# - fair-share queueing drains requests in deficit round-robin order under sustained overload;
# - containment is reversible; irreversible action requires deterministic policy + review;
# - per-tenant NDJSON verdicts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

fge_init fg056b-quota-admission-abuse

fge_phase setup
fge_context suite 'fg056b-quota-admission-abuse'
fge_context crate 'fgit-resource (quota/admission economy)'
fge_context claim_class 'bounded-model and deterministic invariant testing'
fge_context non_claim 'This proves deterministic quota enforcement, multi-level hierarchy tightening, queue fair-share, and reversible containment in library and integration tests. It does not claim cluster-level network packet shaping.'

fge_assert_file FG056B-E2E-001 "${REPOSITORY_ROOT}/crates/fgit-resource/tests/quota_admission_abuse.rs" \
  'the quota admission abuse integration test file exists'

fge_phase action
run_test_step() {
  local step="$1"
  local filter="$2"
  fge_capture "${step}" env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked -p fgit-resource --test quota_admission_abuse "${filter}" -- --exact || true
}

run_test_step step-cross-tenant-isolation test_cross_tenant_quota_isolation_under_abuse
test_iso_exit="${FGE_LAST_EXIT}"
test_iso_out="${FGE_LAST_STDOUT}"

run_test_step step-multi-level-hierarchy test_multi_level_hierarchy_tightest_bound
test_hier_exit="${FGE_LAST_EXIT}"
test_hier_out="${FGE_LAST_STDOUT}"

run_test_step step-fair-share-queue test_fair_share_queueing_deficit_round_robin_order
test_fair_exit="${FGE_LAST_EXIT}"
test_fair_out="${FGE_LAST_STDOUT}"

run_test_step step-containment-reversibility test_containment_reversibility_and_moderation_event
test_cont_exit="${FGE_LAST_EXIT}"
test_cont_out="${FGE_LAST_STDOUT}"

run_test_step step-semantics-pin test_semantics_pin_empty_economy_vs_explicit_ceiling
test_pin_exit="${FGE_LAST_EXIT}"
test_pin_out="${FGE_LAST_STDOUT}"

run_test_step step-ceiling-before-pool test_ceiling_before_pool_order_no_side_effects
test_pool_exit="${FGE_LAST_EXIT}"
test_pool_out="${FGE_LAST_STDOUT}"

run_test_step step-degraded-profile test_degraded_profile_escape_hatch_and_no_double_degrade
test_deg_exit="${FGE_LAST_EXIT}"
test_deg_out="${FGE_LAST_STDOUT}"

run_test_step step-queue-deadline test_queue_deadline_behavior
test_qd_exit="${FGE_LAST_EXIT}"
test_qd_out="${FGE_LAST_STDOUT}"

run_test_step step-determinism test_determinism_across_instances
test_det_exit="${FGE_LAST_EXIT}"
test_det_out="${FGE_LAST_STDOUT}"

fge_phase assert

fge_assert_exit FG056B-E2E-010 0 "${test_iso_exit}" \
  'cross-tenant quota isolation: abusive tenant traffic never exhausts another tenant share'
fge_assert_contains FG056B-E2E-011 "${test_iso_out}" \
  'test test_cross_tenant_quota_isolation_under_abuse ... ok' \
  'cross-tenant quota isolation test passed'

fge_assert_exit FG056B-E2E-012 0 "${test_hier_exit}" \
  'multi-level hierarchy enforces the tightest applicable bound'
fge_assert_contains FG056B-E2E-013 "${test_hier_out}" \
  'test test_multi_level_hierarchy_tightest_bound ... ok' \
  'multi-level hierarchy test passed'

fge_assert_exit FG056B-E2E-014 0 "${test_fair_exit}" \
  'fair-share queueing drains requests in deficit round-robin order'
fge_assert_contains FG056B-E2E-015 "${test_fair_out}" \
  'test test_fair_share_queueing_deficit_round_robin_order ... ok' \
  'fair-share queue test passed'

fge_assert_exit FG056B-E2E-016 0 "${test_cont_exit}" \
  'containment is reversible and moderation events are recorded for audit'
fge_assert_contains FG056B-E2E-017 "${test_cont_out}" \
  'test test_containment_reversibility_and_moderation_event ... ok' \
  'containment reversibility test passed'

fge_assert_exit FG056B-E2E-018 0 "${test_pin_exit}" \
  'semantics pin: empty economy admits up to pool capacity; explicit ceiling hard-refuses'
fge_assert_contains FG056B-E2E-019 "${test_pin_out}" \
  'test test_semantics_pin_empty_economy_vs_explicit_ceiling ... ok' \
  'semantics pin test passed'

fge_assert_exit FG056B-E2E-020 0 "${test_pool_exit}" \
  'ceiling-before-pool: over-ceiling asks hard-refuse without touching ledger'
fge_assert_contains FG056B-E2E-021 "${test_pool_out}" \
  'test test_ceiling_before_pool_order_no_side_effects ... ok' \
  'ceiling before pool test passed'

fge_assert_exit FG056B-E2E-022 0 "${test_deg_exit}" \
  'degraded profile escape hatch operates without double-degrade'
fge_assert_contains FG056B-E2E-023 "${test_deg_out}" \
  'test test_degraded_profile_escape_hatch_and_no_double_degrade ... ok' \
  'degraded profile test passed'

fge_assert_exit FG056B-E2E-024 0 "${test_qd_exit}" \
  'queue deadline zero disables queueing and returns retry hint with duration'
fge_assert_contains FG056B-E2E-025 "${test_qd_out}" \
  'test test_queue_deadline_behavior ... ok' \
  'queue deadline test passed'

fge_assert_exit FG056B-E2E-026 0 "${test_det_exit}" \
  'deterministic execution across independent ledger and queue instances'
fge_assert_contains FG056B-E2E-027 "${test_det_out}" \
  'test test_determinism_across_instances ... ok' \
  'determinism test passed'

fge_phase teardown
