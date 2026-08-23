#!/usr/bin/env bash
# e2e: FG-080 temporal half-open visibility and cross-time receipt conformance.
set -euo pipefail

TG_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TG_REPO=$(cd "$TG_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$TG_REPO/scripts/e2e/lib.sh"

readonly TG_TEST="$TG_REPO/crates/fgit-graph/tests/temporal_graph.rs"
readonly TG_SUITE='suites-graph-temporal_graph'

fge_init fg080-temporal-graph
fge_context bead frankengit-fg080-temporal-graph-3m8i
fge_context crate fgit-graph
fge_context non_claim 'bounded temporal-query conformance only; no durable authority-store or performance claim'
export RCH_CARGO_WRAPPER_BYPASS=1

fge_phase setup
fge_assert_file FG-080-E2E-001 "$TG_TEST" 'the temporal graph conformance corpus is present'
fge_artifact "$TG_TEST" temporal-graph-test-source

fge_phase action
fge_capture temporal-run-all-discovery "$TG_REPO/scripts/e2e/run_all.sh" --list || true
tg_discovery_exit=$FGE_LAST_EXIT
tg_discovery=$(<"$FGE_LAST_STDOUT_FILE")
fge_run temporal-graph-corpus cargo test --locked -p fgit-graph --test temporal_graph || true
tg_corpus_exit=$FGE_LAST_EXIT
tg_corpus=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert
fge_assert_exit FG-080-E2E-010 0 "$tg_discovery_exit" 'run_all discovery completed'
fge_assert_contains FG-080-E2E-011 "$tg_discovery" "$TG_SUITE" 'the discovered suite path registers the temporal campaign'
fge_assert_exit FG-080-E2E-012 0 "$tg_corpus_exit" 'the public temporal conformance corpus passes'
fge_assert_contains FG-080-E2E-013 "$tg_corpus" 'half_open_visibility_includes_created_position_and_excludes_retired_position' 'half-open bounds are covered at both boundaries'
fge_assert_contains FG-080-E2E-014 "$tg_corpus" 'all_five_temporal_modes_return_position_correct_labeled_results' 'all five modes remain position-labeled'
fge_assert_contains FG-080-E2E-015 "$tg_corpus" 'mixing_positions_without_a_join_receipt_is_refused' 'cross-time mixing requires an explicit receipt'
