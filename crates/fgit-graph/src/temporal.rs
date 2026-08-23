//! Immutable temporal graph queries over position-bound graph generations.
//!
//! This module is the query half of the graph temporal contract.  Its caller
//! supplies already-built immutable [`GraphSnapshot`] values after the source
//! authority has established their RCR-to-position mapping; this module never
//! treats a local index or an overlay as canonical authority.  In particular,
//! selecting two positions requires an explicit cross-time join request and
//! returns a receipt naming both contributing positions and generations.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::{AsciiSlug, TypeRefusal};

use crate::{GraphAuthorityClass, GraphEdge, GraphGenerationId, GraphNodeId, GraphSnapshot};

/// One nonzero RCR position in the graph temporal order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TemporalPosition(u64);

impl TemporalPosition {
    /// Creates a position from the source authority's committed RCR sequence.
    pub const fn try_new(value: u64) -> Result<Self, TypeRefusal> {
        if value == 0 {
            return Err(TypeRefusal::ValueOutOfRange {
                field: "temporal_graph.position",
                observed: value,
                minimum: 1,
                maximum: u64::MAX,
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical position value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonzero epoch identifying the model used to project inferred graph data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelEpoch(u64);

impl ModelEpoch {
    /// Creates a model epoch from a committed model-registry epoch.
    pub const fn try_new(value: u64) -> Result<Self, TypeRefusal> {
        if value == 0 {
            return Err(TypeRefusal::ValueOutOfRange {
                field: "temporal_graph.model_epoch",
                observed: value,
                minimum: 1,
                maximum: u64::MAX,
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical model-epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A half-open validity interval for one graph node or edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalValidity {
    created_at: TemporalPosition,
    retired_at: Option<TemporalPosition>,
}

impl TemporalValidity {
    /// Creates `[created_at, retired_at)`, or an interval with no known end.
    pub const fn try_new(
        created_at: TemporalPosition,
        retired_at: Option<TemporalPosition>,
    ) -> Result<Self, TemporalGraphRefusal> {
        if let Some(retired_at) = retired_at
            && retired_at.get() <= created_at.get()
        {
            return Err(TemporalGraphRefusal::InvalidValidityInterval {
                created_at,
                retired_at,
            });
        }
        Ok(Self {
            created_at,
            retired_at,
        })
    }

    /// First position at which the row is visible.
    #[must_use]
    pub const fn created_at(self) -> TemporalPosition {
        self.created_at
    }

    /// First position at which the row is no longer visible, when retired.
    #[must_use]
    pub const fn retired_at(self) -> Option<TemporalPosition> {
        self.retired_at
    }

    /// Tests the normative half-open rule: `created_at <= as_of < retired_at`.
    #[must_use]
    pub const fn is_visible_at(self, as_of: TemporalPosition) -> bool {
        self.created_at.get() <= as_of.get()
            && match self.retired_at {
                Some(retired_at) => as_of.get() < retired_at.get(),
                None => true,
            }
    }
}

/// One node and its half-open visibility interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalNode {
    node: GraphNodeId,
    validity: TemporalValidity,
}

impl TemporalNode {
    /// Binds a graph node to its half-open visibility interval.
    #[must_use]
    pub const fn new(node: GraphNodeId, validity: TemporalValidity) -> Self {
        Self { node, validity }
    }

    /// Stable node identity.
    #[must_use]
    pub const fn node(self) -> GraphNodeId {
        self.node
    }

    /// Half-open visibility interval.
    #[must_use]
    pub const fn validity(self) -> TemporalValidity {
        self.validity
    }
}

/// One edge and its half-open visibility interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalEdge {
    edge: GraphEdge,
    validity: TemporalValidity,
}

impl TemporalEdge {
    /// Binds a graph edge to its half-open visibility interval.
    #[must_use]
    pub const fn new(edge: GraphEdge, validity: TemporalValidity) -> Self {
        Self { edge, validity }
    }

    /// Stable edge identity and capacity.
    #[must_use]
    pub const fn edge(self) -> GraphEdge {
        self.edge
    }

    /// Half-open visibility interval.
    #[must_use]
    pub const fn validity(self) -> TemporalValidity {
        self.validity
    }
}

/// Whether an immutable generation is canonical graph material or an inferred
/// projection under one explicit model epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TemporalProjection {
    /// Graph material derived from the canonical source position.
    Canonical,
    /// Advisory inferred graph material whose model epoch remains observable.
    Inferred { model_epoch: ModelEpoch },
}

/// Bounds checked before the temporal catalogue owns row or generation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalGraphLimits {
    /// Largest supported number of immutable generations in one catalogue.
    pub generations: u32,
    /// Largest supported node-row count in one generation.
    pub nodes_per_generation: u32,
    /// Largest supported edge-row count in one generation.
    pub edges_per_generation: u32,
}

impl Default for TemporalGraphLimits {
    fn default() -> Self {
        Self {
            generations: 4_096,
            nodes_per_generation: 4_096,
            edges_per_generation: 65_536,
        }
    }
}

/// One immutable graph generation indexed by its exact RCR position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalGraphGeneration {
    position: TemporalPosition,
    projection: TemporalProjection,
    snapshot: GraphSnapshot,
    nodes: Vec<TemporalNode>,
    edges: Vec<TemporalEdge>,
}

impl TemporalGraphGeneration {
    /// Validates a complete temporal row set for an immutable graph snapshot.
    ///
    /// Every node and edge of the snapshot appears exactly once, and every row
    /// is visible at the source position.  This prevents an index from
    /// presenting a graph generation that was never valid at its own RCR.
    pub fn try_new(
        position: TemporalPosition,
        projection: TemporalProjection,
        snapshot: GraphSnapshot,
        nodes: &[TemporalNode],
        edges: &[TemporalEdge],
        limits: TemporalGraphLimits,
    ) -> Result<Self, TemporalGraphRefusal> {
        check_limit("temporal_nodes", nodes.len(), limits.nodes_per_generation)?;
        check_limit("temporal_edges", edges.len(), limits.edges_per_generation)?;
        match projection {
            TemporalProjection::Inferred { .. }
                if snapshot.generation().authority_class() != GraphAuthorityClass::Statistical =>
            {
                return Err(
                    TemporalGraphRefusal::InferredProjectionRequiresStatistical {
                        observed: snapshot.generation().authority_class(),
                    },
                );
            }
            TemporalProjection::Canonical | TemporalProjection::Inferred { .. } => {}
        }

        let snapshot_nodes: BTreeSet<_> = snapshot.graph().nodes().iter().copied().collect();
        let snapshot_edges: BTreeSet<_> = snapshot.graph().edges().iter().copied().collect();
        let mut temporal_nodes = BTreeMap::new();
        for row in nodes {
            if !snapshot_nodes.contains(&row.node) {
                return Err(TemporalGraphRefusal::NodeOutsideSnapshot { node: row.node });
            }
            if !row.validity.is_visible_at(position) {
                return Err(TemporalGraphRefusal::RowNotVisibleAtSource {
                    kind: TemporalRowKind::Node,
                    position,
                });
            }
            if temporal_nodes.insert(row.node, *row).is_some() {
                return Err(TemporalGraphRefusal::DuplicateTemporalNode { node: row.node });
            }
        }
        if temporal_nodes.keys().copied().collect::<BTreeSet<_>>() != snapshot_nodes {
            return Err(TemporalGraphRefusal::TemporalNodesDoNotMatchSnapshot);
        }

        let mut temporal_edges = BTreeMap::new();
        for row in edges {
            if !snapshot_edges.contains(&row.edge) {
                return Err(TemporalGraphRefusal::EdgeOutsideSnapshot { edge: row.edge });
            }
            if !row.validity.is_visible_at(position) {
                return Err(TemporalGraphRefusal::RowNotVisibleAtSource {
                    kind: TemporalRowKind::Edge,
                    position,
                });
            }
            if temporal_edges.insert(row.edge, *row).is_some() {
                return Err(TemporalGraphRefusal::DuplicateTemporalEdge { edge: row.edge });
            }
        }
        if temporal_edges.keys().copied().collect::<BTreeSet<_>>() != snapshot_edges {
            return Err(TemporalGraphRefusal::TemporalEdgesDoNotMatchSnapshot);
        }

        Ok(Self {
            position,
            projection,
            snapshot,
            nodes: temporal_nodes.into_values().collect(),
            edges: temporal_edges.into_values().collect(),
        })
    }

    /// Exact source RCR position for this immutable generation.
    #[must_use]
    pub const fn position(&self) -> TemporalPosition {
        self.position
    }

    /// Canonical or inferred projection class for this generation.
    #[must_use]
    pub const fn projection(&self) -> TemporalProjection {
        self.projection
    }

    /// Immutable graph generation backing the temporal rows.
    #[must_use]
    pub const fn snapshot(&self) -> &GraphSnapshot {
        &self.snapshot
    }

    fn view_at(&self, as_of: TemporalPosition) -> TemporalGraphView {
        TemporalGraphView {
            requested_position: as_of,
            source_position: self.position,
            projection: self.projection,
            overlay_id: None,
            generation_id: self.snapshot.generation_id(),
            authority_class: self.snapshot.generation().authority_class(),
            nodes: self
                .nodes
                .iter()
                .copied()
                .filter(|row| row.validity.is_visible_at(as_of))
                .map(TemporalNode::node)
                .collect(),
            edges: self
                .edges
                .iter()
                .copied()
                .filter(|row| row.validity.is_visible_at(as_of))
                .map(TemporalEdge::edge)
                .collect(),
        }
    }
}

/// An explicit request to combine two exact positions under one closed policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossTimeJoinRequest {
    policy: CrossTimeJoinPolicy,
}

impl CrossTimeJoinRequest {
    /// Declares the policy before a cross-time query may run.
    #[must_use]
    pub const fn new(policy: CrossTimeJoinPolicy) -> Self {
        Self { policy }
    }
}

/// Closed policies for an explicit cross-time join.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CrossTimeJoinPolicy {
    /// Compare rows by their stable graph node and edge identities only.
    StableIdentityComparison,
}

/// Receipt proving that a result intentionally combines two exact positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossTimeJoinReceipt {
    earlier_position: TemporalPosition,
    later_position: TemporalPosition,
    earlier_generation_id: GraphGenerationId,
    later_generation_id: GraphGenerationId,
    policy: CrossTimeJoinPolicy,
}

impl CrossTimeJoinReceipt {
    /// Earlier exact position named by the receipt.
    #[must_use]
    pub const fn earlier_position(self) -> TemporalPosition {
        self.earlier_position
    }

    /// Later exact position named by the receipt.
    #[must_use]
    pub const fn later_position(self) -> TemporalPosition {
        self.later_position
    }

    /// Immutable generation selected at the earlier position.
    #[must_use]
    pub const fn earlier_generation_id(self) -> GraphGenerationId {
        self.earlier_generation_id
    }

    /// Immutable generation selected at the later position.
    #[must_use]
    pub const fn later_generation_id(self) -> GraphGenerationId {
        self.later_generation_id
    }

    /// Closed join policy chosen before the query ran.
    #[must_use]
    pub const fn policy(self) -> CrossTimeJoinPolicy {
        self.policy
    }
}

/// An immutable non-canonical overlay over one canonical graph position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchAgentOverlay {
    overlay_id: AsciiSlug,
    base_position: TemporalPosition,
    added_nodes: Vec<GraphNodeId>,
    removed_nodes: Vec<GraphNodeId>,
    added_edges: Vec<GraphEdge>,
    removed_edges: Vec<GraphEdge>,
}

impl BranchAgentOverlay {
    /// Builds a bounded, deterministic overlay.  It is deliberately a query
    /// input only: this type cannot activate or replace a canonical generation.
    pub fn try_new(
        overlay_id: &[u8],
        base_position: TemporalPosition,
        added_nodes: &[GraphNodeId],
        removed_nodes: &[GraphNodeId],
        added_edges: &[GraphEdge],
        removed_edges: &[GraphEdge],
    ) -> Result<Self, TemporalGraphRefusal> {
        let overlay_id = AsciiSlug::try_new("branch_agent_overlay", overlay_id)
            .map_err(TemporalGraphRefusal::Type)?;
        let added_nodes = unique_nodes(added_nodes, TemporalOverlayRowKind::AddedNode)?;
        let removed_nodes = unique_nodes(removed_nodes, TemporalOverlayRowKind::RemovedNode)?;
        let added_edges = unique_edges(added_edges, TemporalOverlayRowKind::AddedEdge)?;
        let removed_edges = unique_edges(removed_edges, TemporalOverlayRowKind::RemovedEdge)?;
        if added_nodes.iter().any(|node| removed_nodes.contains(node))
            || added_edges.iter().any(|edge| removed_edges.contains(edge))
        {
            return Err(TemporalGraphRefusal::OverlayAddsAndRemovesSameRow);
        }
        Ok(Self {
            overlay_id,
            base_position,
            added_nodes,
            removed_nodes,
            added_edges,
            removed_edges,
        })
    }

    /// Stable identity of this non-canonical overlay.
    #[must_use]
    pub const fn overlay_id(&self) -> &AsciiSlug {
        &self.overlay_id
    }

    /// The sole canonical position this overlay may extend.
    #[must_use]
    pub const fn base_position(&self) -> TemporalPosition {
        self.base_position
    }
}

/// The five position-bound temporal graph query modes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemporalQueryMode {
    /// Latest canonical graph generation in this immutable catalogue.
    CurrentCanonical,
    /// Canonical graph generation at one exact committed RCR position.
    AsOfRcr { position: TemporalPosition },
    /// Explicitly combine two canonical positions.  Omitted receipts refuse.
    BetweenTwoPositions {
        earlier: TemporalPosition,
        later: TemporalPosition,
        receipt: Option<CrossTimeJoinRequest>,
    },
    /// Apply an explicitly labeled branch/agent overlay to one canonical view.
    BranchAgentOverlay { overlay: BranchAgentOverlay },
    /// Select an advisory inferred projection at one exact position and epoch.
    ProjectedInferredWithModelEpoch {
        position: TemporalPosition,
        model_epoch: ModelEpoch,
    },
}

/// A single position-correct temporal graph view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalGraphView {
    /// Position the caller asked to observe.
    pub requested_position: TemporalPosition,
    /// Exact immutable generation position contributing this graph.
    pub source_position: TemporalPosition,
    /// Canonical or inferred provenance of this graph generation.
    pub projection: TemporalProjection,
    /// Explicit non-canonical overlay identity, when this is an overlay view.
    pub overlay_id: Option<AsciiSlug>,
    /// Immutable graph generation identity.
    pub generation_id: GraphGenerationId,
    /// Non-promotable authority class carried by the source generation.
    pub authority_class: GraphAuthorityClass,
    /// Visible node IDs in ascending canonical order.
    pub nodes: Vec<GraphNodeId>,
    /// Visible edges in ascending canonical order.
    pub edges: Vec<GraphEdge>,
}

/// Two intentionally joined temporal views and their mandatory receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalCrossTimeJoin {
    /// Earlier position-correct graph view.
    pub earlier: TemporalGraphView,
    /// Later position-correct graph view.
    pub later: TemporalGraphView,
    /// Names both exact positions and generations plus the join policy.
    pub receipt: CrossTimeJoinReceipt,
}

/// Result of a temporal graph query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemporalQueryResult {
    /// One position-correct graph view.
    Single(Box<TemporalGraphView>),
    /// An explicitly requested cross-time join only.
    CrossTime(Box<TemporalCrossTimeJoin>),
}

/// Immutable, bounded catalogue of temporal graph generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalGraphCatalog {
    generations: BTreeMap<TemporalGenerationKey, TemporalGraphGeneration>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct TemporalGenerationKey {
    position: TemporalPosition,
    projection: TemporalProjection,
}

impl TemporalGraphCatalog {
    /// Freezes canonical and inferred graph generations for deterministic query.
    pub fn try_new(
        generations: impl IntoIterator<Item = TemporalGraphGeneration>,
        limits: TemporalGraphLimits,
    ) -> Result<Self, TemporalGraphRefusal> {
        let mut frozen = BTreeMap::new();
        for generation in generations {
            let next_len =
                frozen
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| TemporalGraphRefusal::ResourceLimit {
                        resource: "temporal_generations",
                        observed: u64::MAX,
                        limit: u64::from(limits.generations),
                    })?;
            check_limit("temporal_generations", next_len, limits.generations)?;
            let key = TemporalGenerationKey {
                position: generation.position,
                projection: generation.projection,
            };
            if frozen.insert(key, generation).is_some() {
                return Err(TemporalGraphRefusal::DuplicateGeneration {
                    position: key.position,
                    projection: key.projection,
                });
            }
        }
        if !frozen
            .keys()
            .any(|key| key.projection == TemporalProjection::Canonical)
        {
            return Err(TemporalGraphRefusal::CanonicalGenerationRequired);
        }
        Ok(Self {
            generations: frozen,
        })
    }

    /// Executes exactly one of the five temporal query modes.
    pub fn query(
        &self,
        mode: &TemporalQueryMode,
    ) -> Result<TemporalQueryResult, TemporalGraphRefusal> {
        match mode {
            TemporalQueryMode::CurrentCanonical => {
                let (_, generation) = self
                    .generations
                    .iter()
                    .rev()
                    .find(|(key, _)| key.projection == TemporalProjection::Canonical)
                    .ok_or(TemporalGraphRefusal::CanonicalGenerationRequired)?;
                Ok(TemporalQueryResult::Single(Box::new(
                    generation.view_at(generation.position),
                )))
            }
            TemporalQueryMode::AsOfRcr { position } => Ok(TemporalQueryResult::Single(Box::new(
                self.canonical_at(*position)?.view_at(*position),
            ))),
            TemporalQueryMode::BetweenTwoPositions {
                earlier,
                later,
                receipt,
            } => self.cross_time(*earlier, *later, *receipt),
            TemporalQueryMode::BranchAgentOverlay { overlay } => {
                let base = self.canonical_at(overlay.base_position)?;
                let view = base.view_at(overlay.base_position);
                Ok(TemporalQueryResult::Single(Box::new(apply_overlay(
                    view, overlay,
                )?)))
            }
            TemporalQueryMode::ProjectedInferredWithModelEpoch {
                position,
                model_epoch,
            } => {
                let key = TemporalGenerationKey {
                    position: *position,
                    projection: TemporalProjection::Inferred {
                        model_epoch: *model_epoch,
                    },
                };
                let generation = self.generations.get(&key).ok_or(
                    TemporalGraphRefusal::GenerationUnavailable {
                        position: *position,
                        projection: key.projection,
                    },
                )?;
                Ok(TemporalQueryResult::Single(Box::new(
                    generation.view_at(*position),
                )))
            }
        }
    }

    fn canonical_at(
        &self,
        position: TemporalPosition,
    ) -> Result<&TemporalGraphGeneration, TemporalGraphRefusal> {
        self.generations
            .get(&TemporalGenerationKey {
                position,
                projection: TemporalProjection::Canonical,
            })
            .ok_or(TemporalGraphRefusal::GenerationUnavailable {
                position,
                projection: TemporalProjection::Canonical,
            })
    }

    fn cross_time(
        &self,
        earlier: TemporalPosition,
        later: TemporalPosition,
        request: Option<CrossTimeJoinRequest>,
    ) -> Result<TemporalQueryResult, TemporalGraphRefusal> {
        if earlier >= later {
            return Err(TemporalGraphRefusal::CrossTimeOrderInvalid { earlier, later });
        }
        let request =
            request.ok_or(TemporalGraphRefusal::CrossTimeReceiptRequired { earlier, later })?;
        let earlier_generation = self.canonical_at(earlier)?;
        let later_generation = self.canonical_at(later)?;
        let receipt = CrossTimeJoinReceipt {
            earlier_position: earlier,
            later_position: later,
            earlier_generation_id: earlier_generation.snapshot.generation_id(),
            later_generation_id: later_generation.snapshot.generation_id(),
            policy: request.policy,
        };
        Ok(TemporalQueryResult::CrossTime(Box::new(
            TemporalCrossTimeJoin {
                earlier: earlier_generation.view_at(earlier),
                later: later_generation.view_at(later),
                receipt,
            },
        )))
    }
}

/// The row class that failed a temporal admission check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalRowKind {
    /// Node row.
    Node,
    /// Edge row.
    Edge,
}

/// The overlay row class that was duplicated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalOverlayRowKind {
    /// Added node row.
    AddedNode,
    /// Removed node row.
    RemovedNode,
    /// Added edge row.
    AddedEdge,
    /// Removed edge row.
    RemovedEdge,
}

/// Typed refusal for temporal graph admission or query.
#[derive(Debug)]
pub enum TemporalGraphRefusal {
    /// A bound would be exceeded before this module allocates indexed state.
    ResourceLimit {
        /// Bounded resource name.
        resource: &'static str,
        /// Requested count.
        observed: u64,
        /// Declared upper bound.
        limit: u64,
    },
    /// A validity interval has no visible position.
    InvalidValidityInterval {
        /// Claimed first visible position.
        created_at: TemporalPosition,
        /// Claimed first invisible position.
        retired_at: TemporalPosition,
    },
    /// A temporal node did not occur in its immutable snapshot.
    NodeOutsideSnapshot { node: GraphNodeId },
    /// A temporal edge did not occur in its immutable snapshot.
    EdgeOutsideSnapshot { edge: GraphEdge },
    /// A source snapshot's node did not receive exactly one temporal row.
    TemporalNodesDoNotMatchSnapshot,
    /// A source snapshot's edge did not receive exactly one temporal row.
    TemporalEdgesDoNotMatchSnapshot,
    /// A node identity occurred twice in one temporal generation.
    DuplicateTemporalNode { node: GraphNodeId },
    /// An edge identity occurred twice in one temporal generation.
    DuplicateTemporalEdge { edge: GraphEdge },
    /// A row that the snapshot exposes is not visible at the snapshot's source position.
    RowNotVisibleAtSource {
        /// Node or edge row.
        kind: TemporalRowKind,
        /// Source position being checked.
        position: TemporalPosition,
    },
    /// An inferred temporal projection tried to relabel non-statistical material.
    InferredProjectionRequiresStatistical { observed: GraphAuthorityClass },
    /// Two immutable generations claimed the same temporal key.
    DuplicateGeneration {
        /// Exact source position.
        position: TemporalPosition,
        /// Canonical or inferred projection key.
        projection: TemporalProjection,
    },
    /// A catalogue cannot answer canonical queries without canonical material.
    CanonicalGenerationRequired,
    /// No immutable generation exists for the exact requested position and projection.
    GenerationUnavailable {
        /// Exact requested position.
        position: TemporalPosition,
        /// Requested projection.
        projection: TemporalProjection,
    },
    /// A two-position operation was not declared with a cross-time receipt request.
    CrossTimeReceiptRequired {
        /// Earlier requested position.
        earlier: TemporalPosition,
        /// Later requested position.
        later: TemporalPosition,
    },
    /// A cross-time request did not move forward in the temporal order.
    CrossTimeOrderInvalid {
        /// Claimed earlier position.
        earlier: TemporalPosition,
        /// Claimed later position.
        later: TemporalPosition,
    },
    /// Overlay identity bytes were not canonical.
    Type(TypeRefusal),
    /// An overlay supplied the same row more than once.
    DuplicateOverlayRow { kind: TemporalOverlayRowKind },
    /// An overlay attempted to add and remove the same node or edge.
    OverlayAddsAndRemovesSameRow,
    /// An overlay removed a row absent from its canonical base view.
    OverlayRemovalUnavailable,
    /// An overlay added an edge whose endpoints are absent after node changes.
    OverlayEdgeEndpointUnavailable { edge: GraphEdge },
    /// An overlay added an edge that is not a valid graph edge.
    OverlayZeroCapacity { edge: GraphEdge },
    /// An overlay introduced an already-visible row.
    OverlayAdditionDuplicatesBase,
}

fn check_limit(
    resource: &'static str,
    observed: usize,
    limit: u32,
) -> Result<(), TemporalGraphRefusal> {
    let observed = u64::try_from(observed).map_err(|_| TemporalGraphRefusal::ResourceLimit {
        resource,
        observed: u64::MAX,
        limit: u64::from(limit),
    })?;
    if observed > u64::from(limit) {
        return Err(TemporalGraphRefusal::ResourceLimit {
            resource,
            observed,
            limit: u64::from(limit),
        });
    }
    Ok(())
}

fn unique_nodes(
    rows: &[GraphNodeId],
    kind: TemporalOverlayRowKind,
) -> Result<Vec<GraphNodeId>, TemporalGraphRefusal> {
    let unique: BTreeSet<_> = rows.iter().copied().collect();
    if unique.len() != rows.len() {
        return Err(TemporalGraphRefusal::DuplicateOverlayRow { kind });
    }
    Ok(unique.into_iter().collect())
}

fn unique_edges(
    rows: &[GraphEdge],
    kind: TemporalOverlayRowKind,
) -> Result<Vec<GraphEdge>, TemporalGraphRefusal> {
    let unique: BTreeSet<_> = rows.iter().copied().collect();
    if unique.len() != rows.len() {
        return Err(TemporalGraphRefusal::DuplicateOverlayRow { kind });
    }
    Ok(unique.into_iter().collect())
}

fn apply_overlay(
    mut base: TemporalGraphView,
    overlay: &BranchAgentOverlay,
) -> Result<TemporalGraphView, TemporalGraphRefusal> {
    let mut nodes: BTreeSet<_> = base.nodes.into_iter().collect();
    let mut edges: BTreeSet<_> = base.edges.into_iter().collect();
    for node in &overlay.removed_nodes {
        if !nodes.remove(node) {
            return Err(TemporalGraphRefusal::OverlayRemovalUnavailable);
        }
    }
    for edge in &overlay.removed_edges {
        if !edges.remove(edge) {
            return Err(TemporalGraphRefusal::OverlayRemovalUnavailable);
        }
    }
    for node in &overlay.added_nodes {
        if !nodes.insert(*node) {
            return Err(TemporalGraphRefusal::OverlayAdditionDuplicatesBase);
        }
    }
    for edge in &overlay.added_edges {
        if edge.capacity == 0 {
            return Err(TemporalGraphRefusal::OverlayZeroCapacity { edge: *edge });
        }
        if !nodes.contains(&edge.from) || !nodes.contains(&edge.to) {
            return Err(TemporalGraphRefusal::OverlayEdgeEndpointUnavailable { edge: *edge });
        }
        if !edges.insert(*edge) {
            return Err(TemporalGraphRefusal::OverlayAdditionDuplicatesBase);
        }
    }
    if let Some(edge) = edges
        .iter()
        .find(|edge| !nodes.contains(&edge.from) || !nodes.contains(&edge.to))
    {
        return Err(TemporalGraphRefusal::OverlayEdgeEndpointUnavailable { edge: *edge });
    }
    base.nodes = nodes.into_iter().collect();
    base.edges = edges.into_iter().collect();
    base.overlay_id = Some(overlay.overlay_id);
    Ok(base)
}
