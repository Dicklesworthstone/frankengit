#!/usr/bin/env bash
# FG-081: receipt-backed architecture-analysis product fixtures.
#
# This suite lives under suites/ because run_all.sh discovers that tree
# recursively; a root-level script would not execute in any verification lane.
set -euo pipefail

AA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AA_REPO=$(cd "$AA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$AA_REPO/scripts/e2e/lib.sh"

fge_init fg081-architecture-analysis
fge_context bead frankengit-fg081-architecture-analysis-zees
fge_context crate fgit-graph
fge_context evidence_class deterministic_known_answer_and_authority_fence
fge_context non_claim 'This suite exercises bounded advisory analysis over fixtures; it does not authorize refs, access, merge decisions, or claim an organization-specific architecture recommendation.'

fge_phase setup
fge_assert_file FG-081-E2E-001 "$AA_REPO/crates/fgit-graph/src/architecture.rs" \
  'bounded architecture-analysis implementation is present'
fge_assert_file FG-081-E2E-002 "$AA_REPO/crates/fgit-graph/tests/architecture_analysis.rs" \
  'known-answer and authority-fence fixture is present'

fge_phase action
fge_capture architecture-analysis-known-answers \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked -p fgit-graph --test architecture_analysis || true
aa_exit=$FGE_LAST_EXIT
aa_output="$FGE_LAST_STDOUT"$'\n'"$FGE_LAST_STDERR"

fge_phase assert
fge_assert_exit FG-081-E2E-003 0 "$aa_exit" \
  'all bounded architecture-analysis known-answer fixtures pass'
fge_assert_contains FG-081-E2E-004 "$aa_output" \
  'feedback_edge_set_is_minimal_deterministic_and_advisory_even_for_exact_input' \
  'feedback proposal is deterministic and retains its advisory authority fence'
fge_assert_contains FG-081-E2E-005 "$aa_output" \
  'transitive_reduction_removes_only_the_redundant_dependency_explanation' \
  'transitive reduction identifies only the redundant DAG dependency'
fge_assert_contains FG-081-E2E-006 "$aa_output" \
  'core_and_bridge_partition_proposals_identify_cores_and_shard_boundary' \
  'core and community partition fixture exercises deterministic shard boundaries'
fge_assert_contains FG-081-E2E-007 "$aa_output" \
  'receipt_bound_temporal_join_produces_structural_drift' \
  'drift analysis consumes a receipt-bound temporal join'

fge_phase teardown
fge_note 'all FG-081 products are structurally advisory and preserve source-generation authority classes'
