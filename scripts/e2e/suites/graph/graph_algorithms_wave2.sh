#!/usr/bin/env bash
# e2e: public scalar parity and witness coverage for graph algorithm wave two.
#
# `run_all.sh` discovers executable suites below `scripts/e2e/suites/`; this
# path is the live registration mechanism for the FG-082 suite.
set -euo pipefail

GRAPH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GRAPH_REPO=$(cd "$GRAPH_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$GRAPH_REPO/scripts/e2e/lib.sh"

fge_init fg082-graph-algorithms-wave2
fge_context bead frankengit-fg082-graph-algorithms-wave2-nuft
fge_context crate fgit-graph
fge_context campaign wave_two_public_scalar_parity
fge_context non_claim 'bounded deterministic algorithm fixtures; no unbounded performance or authorization claim'

export RCH_CARGO_WRAPPER_BYPASS=1

readonly GRAPH_TEST="$GRAPH_REPO/crates/fgit-graph/tests/graph_algorithms_wave2.rs"
readonly GRAPH_SUITE='suites-graph-graph_algorithms_wave2'

fge_phase setup

fge_assert_file FG-082-E2E-001 "$GRAPH_TEST" \
  'the public wave-two graph algorithm campaign is present'
fge_artifact "$GRAPH_TEST" graph-algorithms-wave2-source

graph_missing_controls=''
for graph_control in \
  'fn min_cost_flow_and_k_shortest_paths_match_independent_scalar_enumeration' \
  'fn centrality_and_fixed_point_rankings_are_deterministic_and_advisory' \
  'fn steiner_tree_and_set_cover_use_closed_greedy_tie_breaks_and_refuse_gaps' \
  'scalar_flow_cost_for_three_units' \
  'scalar_simple_paths'; do
  if ! grep -qF "$graph_control" "$GRAPH_TEST"; then
    graph_missing_controls="$graph_missing_controls [$graph_control]"
  fi
done

fge_phase action

fge_capture graph-run-all-discovery "$GRAPH_REPO/scripts/e2e/run_all.sh" --list || true
graph_discovery_exit=$FGE_LAST_EXIT
graph_discovery=$(<"$FGE_LAST_STDOUT_FILE")

fge_run graph-wave-two-campaign \
  cargo test --locked -p fgit-graph --test graph_algorithms_wave2 || true
graph_campaign_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-082-E2E-010 0 "$graph_discovery_exit" \
  'run_all discovery completed before the wave-two campaign was evaluated'
fge_assert_contains FG-082-E2E-011 "$graph_discovery" "$GRAPH_SUITE" \
  'run_all discovers this graph suite from its suites registration path'
fge_assert_exit FG-082-E2E-012 0 "$graph_campaign_exit" \
  'public scalar flow/path parity, deterministic ranking, and context selection tests pass'
fge_assert_eq FG-082-E2E-013 '' "$graph_missing_controls" \
  'the independent scalar controls and every wave-two public-surface fixture remain present'
