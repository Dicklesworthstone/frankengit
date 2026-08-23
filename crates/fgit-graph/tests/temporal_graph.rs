//! FG-080 temporal graph conformance corpus.

use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_graph::{
    BranchAgentOverlay, BuilderProfileId, CrossTimeJoinPolicy, CrossTimeJoinRequest,
    GraphAuthorityClass, GraphBuilder, GraphEdge, GraphGenerationBody, GraphLimits, GraphNodeId,
    GraphSourceStamp, GraphViewId, ModelEpoch, TemporalEdge, TemporalGraphCatalog,
    TemporalGraphGeneration, TemporalGraphLimits, TemporalGraphRefusal, TemporalNode,
    TemporalPosition, TemporalProjection, TemporalQueryMode, TemporalQueryResult, TemporalValidity,
};
use fgit_types::{CodecVersion, Digest, RepositoryCommitId, SchemaFamily, SchemaId};

fn digest(label: &[u8]) -> Digest {
    let bytes = internal_digest_value(
        IdentityDomain::MerkleLeaf,
        SchemaId::new(SchemaFamily::from_static("fg080-temporal-digest"), 1, 0),
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
            .expect("registered RCR identity domain"),
        source_forge_position_root: digest(b"forge-position"),
        builder_profile: BuilderProfileId::try_new(b"fg080-temporal-profile")
            .expect("canonical builder profile"),
        parser_model_root: digest(label),
    }
}

fn snapshot(
    label: &[u8],
    class: GraphAuthorityClass,
    include_retired_edge: bool,
) -> fgit_graph::GraphSnapshot {
    let generation = GraphGenerationBody::new(
        GraphViewId::try_new(b"commit-ancestry").expect("canonical graph view"),
        SchemaId::new(SchemaFamily::from_static("fg080-temporal-schema"), 1, 0),
        class,
        source(label),
        digest(b"vertices"),
        digest(b"edges"),
        digest(b"index"),
        digest(b"evidence"),
        None,
    );
    let mut edges = vec![GraphEdge::new(GraphNodeId::new(2), GraphNodeId::new(3), 2)];
    if include_retired_edge {
        edges.push(GraphEdge::new(GraphNodeId::new(1), GraphNodeId::new(2), 1));
    }
    GraphBuilder::new(generation, GraphLimits::default())
        .build(
            true,
            &[
                GraphNodeId::new(1),
                GraphNodeId::new(2),
                GraphNodeId::new(3),
            ],
            &edges,
        )
        .expect("bounded canonical graph snapshot")
}

fn position(value: u64) -> TemporalPosition {
    TemporalPosition::try_new(value).expect("nonzero temporal position")
}

fn validity(created: u64, retired: Option<u64>) -> TemporalValidity {
    TemporalValidity::try_new(position(created), retired.map(position))
        .expect("well-formed half-open interval")
}

fn rows(include_retired_edge: bool) -> (Vec<TemporalNode>, Vec<TemporalEdge>) {
    let nodes = vec![
        TemporalNode::new(GraphNodeId::new(1), validity(1, None)),
        TemporalNode::new(GraphNodeId::new(2), validity(1, None)),
        TemporalNode::new(GraphNodeId::new(3), validity(1, None)),
    ];
    let mut edges = vec![TemporalEdge::new(
        GraphEdge::new(GraphNodeId::new(2), GraphNodeId::new(3), 2),
        validity(1, None),
    )];
    if include_retired_edge {
        edges.push(TemporalEdge::new(
            GraphEdge::new(GraphNodeId::new(1), GraphNodeId::new(2), 1),
            validity(1, Some(2)),
        ));
    }
    (nodes, edges)
}

fn generation(
    at: u64,
    label: &[u8],
    class: GraphAuthorityClass,
    projection: TemporalProjection,
    include_retired_edge: bool,
) -> TemporalGraphGeneration {
    let (nodes, edges) = rows(include_retired_edge);
    TemporalGraphGeneration::try_new(
        position(at),
        projection,
        snapshot(label, class, include_retired_edge),
        &nodes,
        &edges,
        TemporalGraphLimits::default(),
    )
    .expect("complete temporal rows match the immutable snapshot")
}

fn catalog() -> TemporalGraphCatalog {
    TemporalGraphCatalog::try_new(
        [
            generation(
                1,
                b"canonical-one",
                GraphAuthorityClass::Exact,
                TemporalProjection::Canonical,
                true,
            ),
            generation(
                2,
                b"canonical-two",
                GraphAuthorityClass::Exact,
                TemporalProjection::Canonical,
                false,
            ),
            generation(
                2,
                b"inferred-two",
                GraphAuthorityClass::Statistical,
                TemporalProjection::Inferred {
                    model_epoch: ModelEpoch::try_new(7).expect("nonzero model epoch"),
                },
                false,
            ),
        ],
        TemporalGraphLimits::default(),
    )
    .expect("bounded immutable temporal catalogue")
}

#[test]
fn half_open_visibility_includes_created_position_and_excludes_retired_position() {
    let interval = validity(2, Some(4));
    assert!(!interval.is_visible_at(position(1)));
    assert!(interval.is_visible_at(position(2)));
    assert!(interval.is_visible_at(position(3)));
    assert!(!interval.is_visible_at(position(4)));

    let created = match catalog()
        .query(&TemporalQueryMode::AsOfRcr {
            position: position(1),
        })
        .expect("position one has a canonical generation")
    {
        TemporalQueryResult::Single(view) => view,
        TemporalQueryResult::CrossTime(_) => panic!("as-of is one position"),
    };
    assert!(
        created
            .edges
            .contains(&GraphEdge::new(GraphNodeId::new(1), GraphNodeId::new(2), 1))
    );
    let retired = match catalog()
        .query(&TemporalQueryMode::AsOfRcr {
            position: position(2),
        })
        .expect("position two has a canonical generation")
    {
        TemporalQueryResult::Single(view) => view,
        TemporalQueryResult::CrossTime(_) => panic!("as-of is one position"),
    };
    assert!(
        !retired
            .edges
            .contains(&GraphEdge::new(GraphNodeId::new(1), GraphNodeId::new(2), 1))
    );
    assert_eq!(retired.requested_position, position(2));
}

#[test]
fn all_five_temporal_modes_return_position_correct_labeled_results() {
    let catalog = catalog();
    let current = catalog
        .query(&TemporalQueryMode::CurrentCanonical)
        .expect("current canonical resolves");
    let TemporalQueryResult::Single(current) = current else {
        panic!("current canonical is not cross-time");
    };
    assert_eq!(current.requested_position, position(2));
    assert_eq!(current.projection, TemporalProjection::Canonical);

    let as_of = catalog
        .query(&TemporalQueryMode::AsOfRcr {
            position: position(1),
        })
        .expect("exact RCR position resolves");
    let TemporalQueryResult::Single(as_of) = as_of else {
        panic!("as-of is not cross-time");
    };
    assert_eq!(as_of.requested_position, position(1));

    let between = catalog
        .query(&TemporalQueryMode::BetweenTwoPositions {
            earlier: position(1),
            later: position(2),
            receipt: Some(CrossTimeJoinRequest::new(
                CrossTimeJoinPolicy::StableIdentityComparison,
            )),
        })
        .expect("declared cross-time join resolves");
    let TemporalQueryResult::CrossTime(between) = between else {
        panic!("between positions is explicitly cross-time");
    };
    assert_eq!(between.receipt.earlier_position(), position(1));
    assert_eq!(between.receipt.later_position(), position(2));
    assert_eq!(between.earlier.requested_position, position(1));
    assert_eq!(between.later.requested_position, position(2));

    let overlay = BranchAgentOverlay::try_new(
        b"agent-overlay",
        position(2),
        &[GraphNodeId::new(4)],
        &[],
        &[GraphEdge::new(GraphNodeId::new(3), GraphNodeId::new(4), 1)],
        &[],
    )
    .expect("valid non-canonical overlay");
    let overlay = catalog
        .query(&TemporalQueryMode::BranchAgentOverlay { overlay })
        .expect("overlay is bound to its canonical base position");
    let TemporalQueryResult::Single(overlay) = overlay else {
        panic!("overlay is a single labeled view");
    };
    assert!(overlay.nodes.contains(&GraphNodeId::new(4)));
    assert_eq!(overlay.source_position, position(2));
    assert_eq!(
        overlay
            .overlay_id
            .expect("overlay result is labeled")
            .as_bytes(),
        b"agent-overlay"
    );

    let inferred = catalog
        .query(&TemporalQueryMode::ProjectedInferredWithModelEpoch {
            position: position(2),
            model_epoch: ModelEpoch::try_new(7).expect("nonzero model epoch"),
        })
        .expect("pinned inferred projection resolves");
    let TemporalQueryResult::Single(inferred) = inferred else {
        panic!("inferred projection is one position");
    };
    assert_eq!(inferred.authority_class, GraphAuthorityClass::Statistical);
    assert!(matches!(
        inferred.projection,
        TemporalProjection::Inferred { model_epoch } if model_epoch.get() == 7
    ));
}

#[test]
fn mixing_positions_without_a_join_receipt_is_refused() {
    let refusal = catalog()
        .query(&TemporalQueryMode::BetweenTwoPositions {
            earlier: position(1),
            later: position(2),
            receipt: None,
        })
        .expect_err("two positions cannot silently become one view");
    assert!(matches!(
        refusal,
        TemporalGraphRefusal::CrossTimeReceiptRequired { earlier, later }
            if earlier == position(1) && later == position(2)
    ));
}

#[test]
fn source_generation_rejects_a_row_that_is_not_visible_at_its_own_position() {
    let (nodes, mut edges) = rows(true);
    edges[0] = TemporalEdge::new(
        GraphEdge::new(GraphNodeId::new(1), GraphNodeId::new(2), 1),
        validity(1, Some(2)),
    );
    let refusal = TemporalGraphGeneration::try_new(
        position(2),
        TemporalProjection::Canonical,
        snapshot(b"invalid-source", GraphAuthorityClass::Exact, true),
        &nodes,
        &edges,
        TemporalGraphLimits::default(),
    )
    .expect_err("a source snapshot cannot carry an invisible row");
    assert!(matches!(
        refusal,
        TemporalGraphRefusal::RowNotVisibleAtSource {
            kind: fgit_graph::TemporalRowKind::Edge,
            position: observed,
        } if observed == position(2)
    ));
}
