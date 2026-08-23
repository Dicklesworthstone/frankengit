//! FG-081 known-answer and authority-fence fixtures.

use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_graph::{
    ArchitectureAdvisoryFence, ArchitectureAnalysis, ArchitectureLimits, BuilderProfileId,
    CrossTimeJoinPolicy, CrossTimeJoinRequest, GraphAuthorityClass, GraphBuilder, GraphEdge,
    GraphGenerationBody, GraphLimits, GraphNodeId, GraphSourceStamp, GraphViewId, TemporalEdge,
    TemporalGraphCatalog, TemporalGraphGeneration, TemporalGraphLimits, TemporalNode,
    TemporalPosition, TemporalProjection, TemporalQueryMode, TemporalQueryResult, TemporalValidity,
};
use fgit_types::{CodecVersion, Digest, RepositoryCommitId, SchemaFamily, SchemaId};

fn node(value: u64) -> GraphNodeId {
    GraphNodeId::new(value)
}

fn digest(label: &[u8]) -> Digest {
    let bytes = internal_digest_value(
        IdentityDomain::MerkleLeaf,
        SchemaId::new(SchemaFamily::from_static("fg081-architecture-digest"), 1, 0),
        label,
    );
    Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf), bytes)
}

fn source(label: &[u8]) -> GraphSourceStamp {
    let rcr = internal_object_id(
        IdentityDomain::RepositoryCommitRecord,
        SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
        CodecVersion::new(1, 0),
        label,
    );
    GraphSourceStamp {
        source_rcr_id: RepositoryCommitId::from_internal_object_id(rcr)
            .expect("registered repository-commit-record identity"),
        source_forge_position_root: digest(b"forge-position"),
        builder_profile: BuilderProfileId::try_new(b"fg081-architecture-profile")
            .expect("canonical profile"),
        parser_model_root: digest(label),
    }
}

fn snapshot(label: &[u8], nodes: &[GraphNodeId], edges: &[GraphEdge]) -> fgit_graph::GraphSnapshot {
    let generation = GraphGenerationBody::new(
        GraphViewId::try_new(b"dependency-graph").expect("canonical graph view"),
        SchemaId::new(SchemaFamily::from_static("fg081-architecture-schema"), 1, 0),
        GraphAuthorityClass::Exact,
        source(label),
        digest(b"vertices"),
        digest(b"edges"),
        digest(b"index"),
        digest(b"evidence"),
        None,
    );
    GraphBuilder::new(generation, GraphLimits::default())
        .build(true, nodes, edges)
        .expect("bounded graph fixture")
}

fn analysis<'a>(snapshot: &'a fgit_graph::GraphSnapshot) -> ArchitectureAnalysis<'a> {
    ArchitectureAnalysis::try_new(snapshot, ArchitectureLimits::default())
        .expect("bounded architecture analysis")
}

#[test]
fn feedback_edge_set_is_minimal_deterministic_and_advisory_even_for_exact_input() {
    let graph = snapshot(
        b"feedback",
        &[node(1), node(2), node(3)],
        &[
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(2), node(3), 1),
            GraphEdge::new(node(3), node(1), 1),
        ],
    );
    let first = analysis(&graph)
        .feedback_edge_set()
        .expect("three-cycle has a one-edge feedback set");
    let second = analysis(&graph)
        .feedback_edge_set()
        .expect("same immutable generation reproduces its proposal");

    assert_eq!(first, second, "stable IDs break equal minimum-set ties");
    assert_eq!(
        first.value.removed_edges,
        vec![GraphEdge::new(node(1), node(2), 1)]
    );
    assert_eq!(first.value.candidates_examined, 8);
    assert_eq!(
        first.authority_fence(),
        ArchitectureAdvisoryFence::AdvisoryOnly
    );
    assert_eq!(
        first.witness.source_authority_classes,
        vec![GraphAuthorityClass::Exact],
        "an exact source is preserved, never promoted into proposal authority"
    );
}

#[test]
fn transitive_reduction_removes_only_the_redundant_dependency_explanation() {
    let graph = snapshot(
        b"reduction",
        &[node(1), node(2), node(3)],
        &[
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(2), node(3), 1),
            GraphEdge::new(node(1), node(3), 1),
        ],
    );
    let proposal = analysis(&graph)
        .transitive_reduction()
        .expect("DAG reduction is defined");

    assert_eq!(
        proposal.value.redundant_edges,
        vec![GraphEdge::new(node(1), node(3), 1)]
    );
    assert_eq!(
        proposal.value.retained_edges,
        vec![
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(2), node(3), 1),
        ]
    );
}

#[test]
fn core_and_bridge_partition_proposals_identify_cores_and_shard_boundary() {
    let graph = snapshot(
        b"cores-and-shards",
        &[node(1), node(2), node(3), node(4), node(5), node(6)],
        &[
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(1), node(3), 1),
            GraphEdge::new(node(2), node(3), 1),
            GraphEdge::new(node(3), node(4), 1),
            GraphEdge::new(node(4), node(5), 1),
            GraphEdge::new(node(4), node(6), 1),
            GraphEdge::new(node(5), node(6), 1),
        ],
    );
    let core = analysis(&graph)
        .core_decomposition()
        .expect("weak core decomposition is defined");
    let communities = analysis(&graph)
        .community_partition()
        .expect("bridge partition is defined");

    assert!(core.value.memberships.iter().all(|row| row.core == 2));
    assert_eq!(
        communities.value.communities,
        vec![
            vec![node(1), node(2), node(3)],
            vec![node(4), node(5), node(6)]
        ]
    );
    assert_eq!(communities.value.boundaries.len(), 1);
    assert_eq!(communities.value.boundaries[0].from, node(3));
    assert_eq!(communities.value.boundaries[0].to, node(4));
}

fn position(value: u64) -> TemporalPosition {
    TemporalPosition::try_new(value).expect("nonzero temporal position")
}

fn generation(
    at: u64,
    label: &[u8],
    nodes: &[GraphNodeId],
    edges: &[GraphEdge],
) -> TemporalGraphGeneration {
    let rows = nodes
        .iter()
        .copied()
        .map(|node| {
            TemporalNode::new(
                node,
                TemporalValidity::try_new(position(1), None).expect("open validity"),
            )
        })
        .collect::<Vec<_>>();
    let edge_rows = edges
        .iter()
        .copied()
        .map(|edge| {
            TemporalEdge::new(
                edge,
                TemporalValidity::try_new(position(1), None).expect("open validity"),
            )
        })
        .collect::<Vec<_>>();
    TemporalGraphGeneration::try_new(
        position(at),
        TemporalProjection::Canonical,
        snapshot(label, nodes, edges),
        &rows,
        &edge_rows,
        TemporalGraphLimits::default(),
    )
    .expect("complete temporal fixture")
}

#[test]
fn receipt_bound_temporal_join_produces_structural_drift() {
    let catalog = TemporalGraphCatalog::try_new(
        [
            generation(
                1,
                b"earlier",
                &[node(1), node(2)],
                &[GraphEdge::new(node(1), node(2), 1)],
            ),
            generation(
                2,
                b"later",
                &[node(1), node(2), node(3)],
                &[
                    GraphEdge::new(node(1), node(2), 1),
                    GraphEdge::new(node(2), node(3), 1),
                ],
            ),
        ],
        TemporalGraphLimits::default(),
    )
    .expect("two immutable temporal views");
    let join = catalog
        .query(&TemporalQueryMode::BetweenTwoPositions {
            earlier: position(1),
            later: position(2),
            receipt: Some(CrossTimeJoinRequest::new(
                CrossTimeJoinPolicy::StableIdentityComparison,
            )),
        })
        .expect("declared cross-time receipt");
    let TemporalQueryResult::CrossTime(join) = join else {
        panic!("between query must retain both views");
    };
    let drift = ArchitectureAnalysis::temporal_drift(&join, ArchitectureLimits::default())
        .expect("receipt-bound temporal difference");

    assert_eq!(drift.value.added_nodes, vec![node(3)]);
    assert_eq!(
        drift.value.added_edges,
        vec![GraphEdge::new(node(2), node(3), 1)]
    );
    assert!(drift.value.removed_nodes.is_empty());
    assert!(drift.value.removed_edges.is_empty());
    assert_eq!(
        drift.authority_fence(),
        ArchitectureAdvisoryFence::AdvisoryOnly
    );
}
