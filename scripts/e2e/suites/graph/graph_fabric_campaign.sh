#!/usr/bin/env bash
# e2e: public graph determinism, mutation-parity, and authority-safety campaign.
#
# `run_all.sh` discovers executable scripts beneath `scripts/e2e/suites/`; this
# location is therefore the registration path.  A literal top-level script
# would satisfy the older bead wording while never running in the owned lane.
set -euo pipefail

GRAPH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GRAPH_REPO=$(cd "$GRAPH_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$GRAPH_REPO/scripts/e2e/lib.sh"

fge_init fg031b-graph-fabric-campaign
fge_context bead frankengit-fg031b-graph-evidence-ndf
fge_context crate fgit-graph
fge_context campaign deterministic_public_graph_surface
fge_context non_claim 'bounded public-surface campaign; no performance or unbounded-proof claim'

export RCH_CARGO_WRAPPER_BYPASS=1

readonly GRAPH_TEST="$GRAPH_REPO/crates/fgit-graph/tests/graph_fabric_campaign.rs"
readonly GRAPH_SUITE='suites-graph-graph_fabric_campaign'

fge_phase setup

fge_assert_file FG-031B-E2E-001 "$GRAPH_TEST" \
  'the public graph campaign integration test is present'
fge_artifact "$GRAPH_TEST" graph-fabric-campaign-source

graph_missing_controls=''
for graph_control in \
  'fn seeded_permutations_and_worker_sweeps_produce_identical_outputs_and_witnesses' \
  'fn incremental_prefixes_match_full_rebuild_and_scalar_oracles' \
  'fn authority_policy_refusal_and_generation_labels_never_grant_or_hide_staleness' \
  'scalar_reachability' \
  'scalar_components' \
  'scalar_topological'; do
  if ! grep -qF "$graph_control" "$GRAPH_TEST"; then
    graph_missing_controls="$graph_missing_controls [$graph_control]"
  fi
done

graph_reaches_into_src=''
if grep -qE '(include!|path *= *"[^"]*fgit-graph/src)' "$GRAPH_TEST"; then
  graph_reaches_into_src=yes
fi

fge_phase action

fge_capture graph-run-all-discovery "$GRAPH_REPO/scripts/e2e/run_all.sh" --list || true
graph_discovery_exit=$FGE_LAST_EXIT
graph_discovery=$(<"$FGE_LAST_STDOUT_FILE")

fge_run graph-public-campaign \
  cargo test --locked -p fgit-graph --test graph_fabric_campaign || true
graph_campaign_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-031B-E2E-010 0 "$graph_discovery_exit" \
  'run_all discovery completed before the campaign was evaluated'
fge_assert_contains FG-031B-E2E-011 "$graph_discovery" "$GRAPH_SUITE" \
  'run_all discovers the graph-fabric campaign from its suites registration path'
fge_assert_exit FG-031B-E2E-012 0 "$graph_campaign_exit" \
  'seeded permutations, worker-count sweeps, prefix rebuild parity, scalar oracles, policy refusal, generation labels, and stale activation refusal all pass'
fge_assert_eq FG-031B-E2E-013 '' "$graph_missing_controls" \
  'every campaign mechanism and independent scalar oracle remains present'
fge_assert_eq FG-031B-E2E-014 '' "$graph_reaches_into_src" \
  'the campaign drives only the fgit-graph public surface'
