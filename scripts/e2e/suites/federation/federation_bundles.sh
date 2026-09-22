#!/usr/bin/env bash
# FG-063 — federation and local-first collaboration evidence campaign.
#
# This suite drives the federation and local-first collaboration contracts:
# 1. Offline work bundle round-trip: create offline against a capsule, import online,
#    revalidation catches a staged conflict fixture;
# 2. Mirror-namespace and proposed-RefTxn flows: direct remote-head merge into canonical
#    refs is unrepresentable;
# 3. Equivocation fixture: one peer signing conflicting claims produces durable evidence
#    and review-surface routing;
# 4. Federated event classes each declare monotone/CRDT/coordinated per the CALM registry.
# 5. Two-instance collaboration workflow with paired permitted/refusal twins.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='federation'
readonly RUN_OBLIGATION='fg063-federation-test-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg063-federation-t6yd
  fge_context suite federation-bundles
  fge_context evidence_class local_exact
  fge_context non_claim 'Federation is import under local admission, never shared authority; this suite verifies cryptographic bundle exchange, staged conflict detection, mirror namespace isolation, equivocation evidence, and CALM declarations without requiring remote network nodes.'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture federation-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/frankengit-targets/antigravity_rc}" \
    cargo test --locked -p fgit-forge --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" federation-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" federation-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-063-E2E-001' 0 "$test_exit" \
    'the federation test target completes successfully'
  fge_assert_contains 'FG-063-E2E-002' "$output" \
    'offline_work_bundle_codec_round_trip' \
    'offline work bundle codec round-trip succeeds'
  fge_assert_contains 'FG-063-E2E-003' "$output" \
    'offline_bundle_import_revalidation_staged_conflict_refused_vs_matching_permitted' \
    'revalidation catches staged conflict while matching basis is permitted'
  fge_assert_contains 'FG-063-E2E-004' "$output" \
    'mirror_ref_uses_isolated_namespace_and_prevents_canonical_direct_write' \
    'mirror-namespace flow isolates remote refs and direct canonical write is unrepresentable'
  fge_assert_contains 'FG-063-E2E-005' "$output" \
    'proposed_reftxn_evaluation_against_authority_head' \
    'proposed-RefTxn evaluates expected basis against authority head'
  fge_assert_contains 'FG-063-E2E-006' "$output" \
    'equivocation_fixture_produces_durable_evidence_and_routes_to_review' \
    'equivocation fixture produces durable evidence and routes to review queue'
  fge_assert_contains 'FG-063-E2E-007' "$output" \
    'federated_event_classes_declare_calm_properties' \
    'federated event classes each declare monotone/CRDT/coordinated per the CALM registry'
  fge_assert_contains 'FG-063-E2E-008' "$output" \
    'two_instance_collaboration_roundtrip_exchange' \
    'two-instance collaboration exchange completes successfully'
}

fge_init fg063-federation-bundles
main
