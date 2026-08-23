#![forbid(unsafe_code)]
//! Public, deterministic scalar checks for the graph wave-two algorithm surface.

use std::collections::BTreeMap;

use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_graph::{
    AdvisoryRank, BuilderProfileId, ComplexityTerm, FlowCost, GraphAlgorithm, GraphAuthorityClass,
    GraphBuilder, GraphDecision, GraphDecisionWitness, GraphEdge, GraphGenerationBody, GraphLimits,
    GraphNodeId, GraphQuery, GraphRefusal, GraphSnapshot, GraphSourceStamp, GraphViewId,
    HitsConfig, MinCostFlowRequest, PageRankConfig, SetCoverCandidate, SetCoverRequest,
    ShortestPath,
};
use fgit_types::{CodecVersion, Digest, RepositoryCommitId, SchemaFamily, SchemaId};

const LIMITS: GraphLimits = GraphLimits {
    nodes: 32,
    edges: 96,
};

const RANK_SCALE: u64 = 1_000_000_000;

const fn node(value: u64) -> GraphNodeId {
    GraphNodeId::new(value)
}

fn digest(label: &[u8]) -> Digest {
    let bytes = internal_digest_value(
        IdentityDomain::MerkleLeaf,
        SchemaId::new(SchemaFamily::from_static("graph-wave2-digest"), 1, 0),
        label,
    );
    Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf), bytes)
}

fn source() -> GraphSourceStamp {
    let rcr = internal_object_id(
        IdentityDomain::RepositoryCommitRecord,
        SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
        CodecVersion::new(1, 0),
        b"fg082-wave-two-rcr",
    );
    GraphSourceStamp {
        source_rcr_id: RepositoryCommitId::from_internal_object_id(rcr)
            .expect("registered RCR domain is accepted"),
        source_forge_position_root: digest(b"fg082-forge-position"),
        builder_profile: BuilderProfileId::try_new(b"fg082-public-scalar-oracle")
            .expect("static builder profile is canonical"),
        parser_model_root: digest(b"fg082-parser-model"),
    }
}

fn snapshot(
    label: &[u8],
    directed: bool,
    nodes: &[GraphNodeId],
    edges: &[GraphEdge],
) -> GraphSnapshot {
    let body = GraphGenerationBody::new(
        GraphViewId::try_new(b"dependency").expect("static view is canonical"),
        SchemaId::new(SchemaFamily::from_static("fg082-graph-schema"), 1, 0),
        GraphAuthorityClass::Exact,
        source(),
        digest(label),
        digest(&[label, b"-edges"].concat()),
        digest(&[label, b"-index"].concat()),
        digest(&[label, b"-evidence"].concat()),
        None,
    );
    GraphBuilder::new(body, LIMITS)
        .build(directed, nodes, edges)
        .expect("fixed public corpus is admissible")
}

fn query(snapshot: &GraphSnapshot) -> GraphQuery {
    snapshot.query(
        GraphViewPolicy::new([
            GraphDecision::MinCostFlow,
            GraphDecision::KShortestPaths,
            GraphDecision::BetweennessCentrality,
            GraphDecision::PageRank,
            GraphDecision::Hits,
            GraphDecision::PersonalizedPageRank,
            GraphDecision::SteinerTree,
            GraphDecision::SetCover,
        ]),
        digest(b"fg082-resource-receipt"),
        1_000_000,
    )
}

use fgit_graph::GraphViewPolicy;

fn flow_rows() -> (Vec<GraphNodeId>, Vec<GraphEdge>) {
    (
        vec![node(1), node(2), node(3), node(4)],
        vec![
            GraphEdge::new(node(1), node(2), 3),
            GraphEdge::new(node(1), node(3), 1),
            GraphEdge::new(node(2), node(3), 1),
            GraphEdge::new(node(2), node(4), 2),
            GraphEdge::new(node(3), node(4), 2),
        ],
    )
}

fn flow_costs() -> Vec<FlowCost> {
    vec![
        FlowCost::new(node(1), node(2), 1),
        FlowCost::new(node(1), node(3), 5),
        FlowCost::new(node(2), node(3), 1),
        FlowCost::new(node(2), node(4), 3),
        FlowCost::new(node(3), node(4), 1),
    ]
}

fn scalar_flow_cost_for_three_units() -> u64 {
    let mut best = None;
    for via_two_to_four in 0_u64..=2 {
        for via_two_to_three in 0_u64..=1 {
            for via_three in 0_u64..=1 {
                if via_two_to_four + via_two_to_three + via_three != 3
                    || via_two_to_four + via_two_to_three > 3
                    || via_two_to_three + via_three > 2
                {
                    continue;
                }
                let cost = via_two_to_four * 4 + via_two_to_three * 3 + via_three * 6;
                if best.is_none_or(|prior| cost < prior) {
                    best = Some(cost);
                }
            }
        }
    }
    best.expect("the scalar flow corpus has one feasible assignment")
}

fn scalar_simple_paths(
    nodes: &[GraphNodeId],
    edges: &[GraphEdge],
    source: GraphNodeId,
    target: GraphNodeId,
) -> Vec<ShortestPath> {
    let mut adjacency: BTreeMap<_, Vec<_>> = nodes
        .iter()
        .copied()
        .map(|candidate| (candidate, Vec::new()))
        .collect();
    for edge in edges {
        adjacency
            .get_mut(&edge.from)
            .expect("scalar corpus has known endpoints")
            .push((edge.to, edge.capacity));
    }
    for arcs in adjacency.values_mut() {
        arcs.sort_unstable();
    }
    fn visit(
        current: GraphNodeId,
        target: GraphNodeId,
        adjacency: &BTreeMap<GraphNodeId, Vec<(GraphNodeId, u64)>>,
        path: &mut Vec<GraphNodeId>,
        cost: u64,
        output: &mut Vec<ShortestPath>,
    ) {
        if current == target {
            output.push(ShortestPath {
                nodes: path.clone(),
                cost,
            });
            return;
        }
        for &(next, edge_cost) in adjacency
            .get(&current)
            .expect("current scalar node is known")
        {
            if path.contains(&next) {
                continue;
            }
            path.push(next);
            visit(
                next,
                target,
                adjacency,
                path,
                cost.checked_add(edge_cost)
                    .expect("fixed scalar corpus does not overflow"),
                output,
            );
            path.pop();
        }
    }
    let mut paths = Vec::new();
    let mut path = vec![source];
    visit(source, target, &adjacency, &mut path, 0, &mut paths);
    paths.sort_unstable_by(|left, right| {
        left.cost
            .cmp(&right.cost)
            .then_with(|| left.nodes.cmp(&right.nodes))
    });
    paths
}

fn assert_witness(witness: &GraphDecisionWitness, algorithm: GraphAlgorithm) {
    assert_eq!(witness.algorithm, algorithm);
    assert_eq!(witness.graph_generation_ids.len(), 1);
    assert!(witness.observed_operations > 0);
    assert_eq!(witness.tie_break_policy, "ascending-stable-node-id-v1");
}

fn scalar_uniform_rank(nodes: &[GraphNodeId]) -> AdvisoryRank {
    let count = u64::try_from(nodes.len()).expect("fixed corpus has nodes");
    let base = RANK_SCALE / count;
    let remainder = usize::try_from(RANK_SCALE % count).expect("remainder fits usize");
    let mut ranks: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(index, &candidate)| (candidate, base + u64::from(index < remainder)))
        .collect();
    ranks.sort_unstable_by(|(left_node, left_score), (right_node, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_node.cmp(right_node))
    });
    AdvisoryRank { ranks }
}

fn scalar_personalized_zero_damping() -> AdvisoryRank {
    AdvisoryRank {
        ranks: vec![
            (node(1), 750_000_000),
            (node(2), 250_000_000),
            (node(3), 0),
            (node(4), 0),
        ],
    }
}

fn scalar_hits_one_iteration() -> (AdvisoryRank, AdvisoryRank) {
    (
        AdvisoryRank {
            ranks: vec![
                (node(3), 400_000_000),
                (node(4), 400_000_000),
                (node(2), 200_000_000),
                (node(1), 0),
            ],
        },
        AdvisoryRank {
            ranks: vec![
                (node(2), 444_444_444),
                (node(1), 333_333_334),
                (node(3), 222_222_222),
                (node(4), 0),
            ],
        },
    )
}

#[test]
fn min_cost_flow_and_k_shortest_paths_match_independent_scalar_enumeration() {
    let (nodes, edges) = flow_rows();
    let graph = snapshot(b"flow-and-paths", true, &nodes, &edges);
    let query = query(&graph);
    let flow = graph
        .min_cost_flow(
            &query,
            &MinCostFlowRequest::new(node(1), node(4), 3, flow_costs()),
        )
        .expect("the scalar corpus can deliver three units");
    assert_eq!(flow.value.flow, 3);
    assert_eq!(flow.value.total_cost, scalar_flow_cost_for_three_units());
    assert_witness(&flow.witness, GraphAlgorithm::MinCostFlowV1);
    assert_eq!(
        flow.witness.dominant_term,
        ComplexityTerm::FlowTimesVerticesEdges
    );

    let paths = graph
        .k_shortest_paths(&query, node(1), node(4), 3)
        .expect("the bounded path request is admissible");
    assert_eq!(
        paths.value.paths,
        scalar_simple_paths(&nodes, &edges, node(1), node(4))
            .into_iter()
            .take(3)
            .collect::<Vec<_>>()
    );
    assert_witness(&paths.witness, GraphAlgorithm::KShortestPathsV1);
    assert_eq!(
        paths.witness.dominant_term,
        ComplexityTerm::OperationBoundedPathEnumeration
    );
    assert!(matches!(
        graph.k_shortest_paths(&query, node(1), node(4), 0),
        Err(GraphRefusal::InvalidPathCount { requested: 0, .. })
    ));
}

#[test]
fn centrality_and_fixed_point_rankings_are_deterministic_and_advisory() {
    let chain_nodes = [node(1), node(2), node(3)];
    let chain_edges = [
        GraphEdge::new(node(1), node(2), 1),
        GraphEdge::new(node(2), node(3), 1),
    ];
    let chain = snapshot(b"centrality", true, &chain_nodes, &chain_edges);
    let chain_query = query(&chain);
    let centrality = chain
        .betweenness_centrality(&chain_query)
        .expect("chain betweenness is bounded");
    assert_eq!(centrality.value.scores[0].1.numerator(), 0);
    assert_eq!(centrality.value.scores[1].1.numerator(), 1);
    assert_eq!(centrality.value.scores[1].1.denominator(), 1);
    assert_eq!(centrality.value.scores[2].1.numerator(), 0);
    assert_witness(&centrality.witness, GraphAlgorithm::BetweennessCentralityV1);
    assert_eq!(
        centrality.witness.dominant_term,
        ComplexityTerm::VertexTimesVerticesEdges
    );

    let (nodes, edges) = flow_rows();
    let graph = snapshot(b"ranks", true, &nodes, &edges);
    let query = query(&graph);
    let config = PageRankConfig::new(24, 850_000);
    let first = graph.page_rank(&query, config).expect("rank is bounded");
    let second = graph.page_rank(&query, config).expect("rank is repeatable");
    assert_eq!(first, second);
    assert_eq!(
        first
            .value
            .ranks
            .iter()
            .map(|(_, score)| score)
            .sum::<u64>(),
        RANK_SCALE
    );
    assert_witness(&first.witness, GraphAlgorithm::PageRankV1);
    assert_eq!(
        first.witness.dominant_term,
        ComplexityTerm::VertexTimesEdges
    );
    let zero_damping = graph
        .page_rank(&query, PageRankConfig::new(1, 0))
        .expect("zero damping has a scalar uniform answer");
    assert_eq!(zero_damping.value, scalar_uniform_rank(&nodes));

    let personalized = graph
        .personalized_page_rank(&query, config, &[(node(1), 3), (node(2), 1)])
        .expect("positive known seeds are accepted");
    assert_eq!(
        personalized
            .value
            .ranking
            .ranks
            .iter()
            .map(|(_, score)| score)
            .sum::<u64>(),
        RANK_SCALE
    );
    assert_witness(
        &personalized.witness,
        GraphAlgorithm::PersonalizedPageRankV1,
    );
    let personalized_zero_damping = graph
        .personalized_page_rank(
            &query,
            PageRankConfig::new(1, 0),
            &[(node(1), 3), (node(2), 1)],
        )
        .expect("zero damping has an independent seed-distribution answer");
    assert_eq!(
        personalized_zero_damping.value.ranking,
        scalar_personalized_zero_damping()
    );

    let hits = graph
        .hits(&query, HitsConfig::new(16))
        .expect("bounded HITS is accepted");
    assert_eq!(hits.value.authorities.ranks.len(), nodes.len());
    assert_eq!(hits.value.hubs.ranks.len(), nodes.len());
    assert_witness(&hits.witness, GraphAlgorithm::HitsV1);
    let hits_one_iteration = graph
        .hits(&query, HitsConfig::new(1))
        .expect("one HITS iteration has an independent scalar answer");
    let (authorities, hubs) = scalar_hits_one_iteration();
    assert_eq!(hits_one_iteration.value.authorities, authorities);
    assert_eq!(hits_one_iteration.value.hubs, hubs);

    fn accepts_only_advisory_rank(_: AdvisoryRank) {}
    accepts_only_advisory_rank(first.value);
}

#[test]
fn steiner_tree_and_set_cover_use_closed_greedy_tie_breaks_and_refuse_gaps() {
    let nodes = [node(1), node(2), node(3), node(4)];
    let edges = [
        GraphEdge::new(node(1), node(2), 2),
        GraphEdge::new(node(2), node(3), 1),
        GraphEdge::new(node(2), node(4), 3),
    ];
    let graph = snapshot(b"context-coverage", false, &nodes, &edges);
    let query = query(&graph);
    let steiner = graph
        .steiner_tree(&query, &[node(1), node(3), node(4)])
        .expect("all terminals are connected");
    assert_eq!(steiner.value.root, node(1));
    assert_eq!(steiner.value.total_cost, 6);
    assert_eq!(steiner.value.edges, edges);
    assert_witness(&steiner.witness, GraphAlgorithm::SteinerTreeGreedyV1);
    assert_eq!(
        steiner.witness.dominant_term,
        ComplexityTerm::VertexTimesVerticesEdges
    );

    let cover = graph
        .set_cover(
            &query,
            &SetCoverRequest::new(
                vec![node(1), node(2), node(3)],
                vec![
                    SetCoverCandidate::new(node(1), 2, vec![node(1), node(2)]),
                    SetCoverCandidate::new(node(2), 1, vec![node(2), node(3)]),
                    SetCoverCandidate::new(node(3), 1, vec![node(1)]),
                ],
            ),
        )
        .expect("the scalar cover corpus is coverable");
    assert_eq!(cover.value.selected, vec![node(2), node(3)]);
    assert_eq!(cover.value.total_cost, 2);
    assert_witness(&cover.witness, GraphAlgorithm::SetCoverGreedyV1);
    assert_eq!(
        cover.witness.dominant_term,
        ComplexityTerm::VertexTimesEdges
    );
    assert!(matches!(
        graph.set_cover(
            &query,
            &SetCoverRequest::new(vec![node(4)], Vec::new())
        ),
        Err(GraphRefusal::UncoverableElement { element }) if element == node(4)
    ));
}
