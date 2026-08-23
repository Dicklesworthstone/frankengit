//! Deterministic, advisory architecture proposals over immutable graph views.
//!
//! These products explain graph structure but cannot authorize publication,
//! access, or merge decisions.  Every proposal preserves the source
//! generation class and carries an [`ArchitectureAdvisoryFence`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_digest_value};
use fgit_types::{Digest, SchemaFamily, SchemaId};

use crate::{
    GraphAuthorityClass, GraphEdge, GraphGenerationId, GraphNodeId, GraphSnapshot,
    TemporalCrossTimeJoin,
};

const WITNESS_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("architecture-analysis-witness"),
    1,
    0,
);

/// Fixed resource bounds for one architecture-analysis request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchitectureLimits {
    /// Largest graph admitted to the bounded analysis slice.
    pub nodes: u32,
    /// Largest edge table admitted to the bounded analysis slice.
    pub edges: u32,
    /// Largest edge table for exhaustive exact feedback-edge search.
    pub feedback_search_edges: u8,
}

impl Default for ArchitectureLimits {
    fn default() -> Self {
        Self {
            nodes: 4_096,
            edges: 16_384,
            feedback_search_edges: 20,
        }
    }
}

/// The closed, deterministic profile that produced an architecture proposal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArchitectureAlgorithm {
    /// Exhaustive minimum-cardinality feedback-edge selection.
    FeedbackEdgeSetV1,
    /// Exact transitive reduction of a directed acyclic graph.
    TransitiveReductionV1,
    /// Weakly-undirected deterministic core decomposition.
    CoreDecompositionV1,
    /// Bridge-boundary partition proposal for monorepo shards.
    BridgePartitionV1,
    /// Receipt-bound difference of two temporal graph views.
    TemporalDriftV1,
}

impl ArchitectureAlgorithm {
    const fn tag(self) -> u8 {
        match self {
            Self::FeedbackEdgeSetV1 => 0,
            Self::TransitiveReductionV1 => 1,
            Self::CoreDecompositionV1 => 2,
            Self::BridgePartitionV1 => 3,
            Self::TemporalDriftV1 => 4,
        }
    }
}

/// A structural authority fence carried by every architecture result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArchitectureAdvisoryFence {
    /// The output may explain or prioritize work but cannot authorize effects.
    AdvisoryOnly,
}

/// Roots and tie-break facts needed to reproduce one architecture proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureDecisionWitness {
    /// Immutable source generations in the order used by the algorithm.
    pub graph_generation_ids: Vec<GraphGenerationId>,
    /// Source authority classes preserved without promotion.
    pub source_authority_classes: Vec<GraphAuthorityClass>,
    /// Closed implementation profile.
    pub algorithm: ArchitectureAlgorithm,
    /// Stable ordering policy for every equal choice.
    pub tie_break_policy: &'static str,
    /// Count of deterministic candidate or traversal operations.
    pub observed_operations: u64,
    /// Digest of the canonical decision trace.
    pub decision_path_root: Digest,
    /// Digest of the canonical returned proposal body.
    pub result_root: Digest,
}

/// A non-promotable architecture product and its reproducibility witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureProposal<T> {
    /// The proposed explanation or partition.
    pub value: T,
    /// Facts sufficient to reproduce the decision.
    pub witness: ArchitectureDecisionWitness,
    fence: ArchitectureAdvisoryFence,
}

impl<T> ArchitectureProposal<T> {
    /// Proves that this product cannot be used as graph authority.
    #[must_use]
    pub const fn authority_fence(&self) -> ArchitectureAdvisoryFence {
        self.fence
    }
}

/// Exact minimum-cardinality edge removals that make a directed graph acyclic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackEdgeSetProposal {
    /// Edges selected for removal, in ascending canonical edge order.
    pub removed_edges: Vec<GraphEdge>,
    /// Number of candidate subsets checked under the bounded exact search.
    pub candidates_examined: u64,
}

/// A redundant dependency edge and the retained alternate reachability path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitiveReductionProposal {
    /// The irredundant dependency explanation, in canonical edge order.
    pub retained_edges: Vec<GraphEdge>,
    /// Edges removed because another directed path already connects endpoints.
    pub redundant_edges: Vec<GraphEdge>,
}

/// One node's weakly-undirected core number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreMembership {
    /// Stable node identity.
    pub node: GraphNodeId,
    /// Largest core to which this node belongs.
    pub core: u32,
}

/// A core/periphery decomposition in ascending node order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreDecompositionProposal {
    /// Exactly one row per source node.
    pub memberships: Vec<CoreMembership>,
}

/// An undirected integration boundary between two proposed communities.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommunityBoundary {
    /// Lower stable endpoint identity.
    pub from: GraphNodeId,
    /// Higher stable endpoint identity.
    pub to: GraphNodeId,
}

/// A deterministic bridge-boundary proposal for monorepo shards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPartitionProposal {
    /// Proposed communities, with members and communities in canonical order.
    pub communities: Vec<Vec<GraphNodeId>>,
    /// Bridges removed to form the proposed partition.
    pub boundaries: Vec<CommunityBoundary>,
}

/// Position-bound structural changes between two temporal graph views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitecturalDriftReport {
    /// Nodes newly visible at the later position.
    pub added_nodes: Vec<GraphNodeId>,
    /// Nodes no longer visible at the later position.
    pub removed_nodes: Vec<GraphNodeId>,
    /// Edges newly visible at the later position.
    pub added_edges: Vec<GraphEdge>,
    /// Edges no longer visible at the later position.
    pub removed_edges: Vec<GraphEdge>,
}

/// Why a bounded architecture proposal was refused.
#[derive(Debug)]
pub enum ArchitectureRefusal {
    /// Input exceeds the bound checked before analysis-owned state is allocated.
    ResourceLimit {
        /// Bounded input class.
        resource: &'static str,
        /// Observed input size.
        observed: u64,
        /// Fixed request limit.
        limit: u64,
    },
    /// The selected product requires a directed dependency graph.
    DirectedGraphRequired { algorithm: ArchitectureAlgorithm },
    /// The selected product requires a directed acyclic graph.
    AcyclicGraphRequired,
    /// Exhaustive feedback search is unsupported above its declared bound.
    FeedbackSearchBound { observed: u64, limit: u64 },
    /// A public temporal join did not bind its views to its own receipt.
    TemporalJoinReceiptMismatch,
    /// Canonical witness encoding refused an unrepresentable value.
    Codec(Box<CodecRefusal>),
    /// Count or bound arithmetic overflowed before analysis could proceed.
    ArithmeticOverflow,
}

impl From<CodecRefusal> for ArchitectureRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(Box::new(value))
    }
}

/// A bounded analysis session over exactly one immutable graph snapshot.
pub struct ArchitectureAnalysis<'a> {
    snapshot: &'a GraphSnapshot,
    limits: ArchitectureLimits,
}

impl<'a> ArchitectureAnalysis<'a> {
    /// Admits one immutable snapshot after checking analysis resource bounds.
    pub fn try_new(
        snapshot: &'a GraphSnapshot,
        limits: ArchitectureLimits,
    ) -> Result<Self, ArchitectureRefusal> {
        check_limit(
            "architecture_nodes",
            snapshot.graph().nodes().len(),
            limits.nodes,
        )?;
        check_limit(
            "architecture_edges",
            snapshot.graph().edges().len(),
            limits.edges,
        )?;
        Ok(Self { snapshot, limits })
    }

    /// Proposes an exact minimum-cardinality feedback-edge set under a fixed bound.
    pub fn feedback_edge_set(
        &self,
    ) -> Result<ArchitectureProposal<FeedbackEdgeSetProposal>, ArchitectureRefusal> {
        self.require_directed(ArchitectureAlgorithm::FeedbackEdgeSetV1)?;
        let edges = self.snapshot.graph().edges();
        let limit = u64::from(self.limits.feedback_search_edges);
        let edge_count =
            u64::try_from(edges.len()).map_err(|_| ArchitectureRefusal::ArithmeticOverflow)?;
        if edge_count > limit {
            return Err(ArchitectureRefusal::FeedbackSearchBound {
                observed: edge_count,
                limit,
            });
        }
        let candidate_count = 1_u64
            .checked_shl(
                u32::try_from(edges.len()).map_err(|_| ArchitectureRefusal::ArithmeticOverflow)?,
            )
            .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
        let mut selected: Option<Vec<GraphEdge>> = None;
        let mut trace = Encoder::new();
        trace.write_raw_byte(ArchitectureAlgorithm::FeedbackEdgeSetV1.tag());
        trace.write_scalar(edge_count);
        for mask in 0..candidate_count {
            let removed: Vec<_> = edges
                .iter()
                .enumerate()
                .filter_map(|(index, edge)| ((mask & (1_u64 << index)) != 0).then_some(*edge))
                .collect();
            if selected
                .as_ref()
                .is_some_and(|best| removed.len() > best.len())
            {
                continue;
            }
            let retained: Vec<_> = edges
                .iter()
                .enumerate()
                .filter_map(|(index, edge)| ((mask & (1_u64 << index)) == 0).then_some(*edge))
                .collect();
            if !has_directed_cycle(self.snapshot.graph().nodes(), &retained) {
                if selected.as_ref().is_none_or(|best| removed < *best) {
                    selected = Some(removed);
                }
            }
        }
        let removed_edges = selected.ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
        encode_edges(&mut trace, "feedback_removed", &removed_edges)?;
        let value = FeedbackEdgeSetProposal {
            removed_edges,
            candidates_examined: candidate_count,
        };
        let mut result = Encoder::new();
        result.write_scalar(value.candidates_examined);
        encode_edges(&mut result, "feedback_result", &value.removed_edges)?;
        self.proposal(
            ArchitectureAlgorithm::FeedbackEdgeSetV1,
            candidate_count,
            trace,
            result,
            value,
        )
    }

    /// Removes every edge whose endpoints remain connected through another DAG path.
    pub fn transitive_reduction(
        &self,
    ) -> Result<ArchitectureProposal<TransitiveReductionProposal>, ArchitectureRefusal> {
        self.require_directed(ArchitectureAlgorithm::TransitiveReductionV1)?;
        let graph = self.snapshot.graph();
        if has_directed_cycle(graph.nodes(), graph.edges()) {
            return Err(ArchitectureRefusal::AcyclicGraphRequired);
        }
        let mut retained_edges = Vec::new();
        let mut redundant_edges = Vec::new();
        let mut trace = Encoder::new();
        trace.write_raw_byte(ArchitectureAlgorithm::TransitiveReductionV1.tag());
        let mut operations = 0_u64;
        for (index, edge) in graph.edges().iter().copied().enumerate() {
            operations = operations
                .checked_add(1)
                .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
            if has_path_excluding(graph.edges(), edge.from, edge.to, index) {
                redundant_edges.push(edge);
                trace.write_raw_byte(1);
                encode_edge(&mut trace, edge)?;
            } else {
                retained_edges.push(edge);
            }
        }
        let value = TransitiveReductionProposal {
            retained_edges,
            redundant_edges,
        };
        let mut result = Encoder::new();
        encode_edges(&mut result, "reduction_retained", &value.retained_edges)?;
        encode_edges(&mut result, "reduction_redundant", &value.redundant_edges)?;
        self.proposal(
            ArchitectureAlgorithm::TransitiveReductionV1,
            operations,
            trace,
            result,
            value,
        )
    }

    /// Computes deterministic weakly-undirected core numbers for core/periphery explanation.
    pub fn core_decomposition(
        &self,
    ) -> Result<ArchitectureProposal<CoreDecompositionProposal>, ArchitectureRefusal> {
        let graph = self.snapshot.graph();
        let neighbors = weak_neighbors(graph.nodes(), graph.edges());
        let mut remaining: BTreeSet<_> = graph.nodes().iter().copied().collect();
        let mut degrees: BTreeMap<_, u32> = neighbors
            .iter()
            .map(|(&node, adjacent)| {
                let degree = u32::try_from(adjacent.len())
                    .map_err(|_| ArchitectureRefusal::ArithmeticOverflow)?;
                Ok((node, degree))
            })
            .collect::<Result<_, ArchitectureRefusal>>()?;
        let mut cores = BTreeMap::new();
        let mut operations = 0_u64;
        while !remaining.is_empty() {
            let node = remaining
                .iter()
                .copied()
                .min_by_key(|node| (degrees.get(node).copied().unwrap_or(u32::MAX), *node))
                .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
            let degree = degrees
                .get(&node)
                .copied()
                .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
            operations = operations
                .checked_add(1)
                .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
            remaining.remove(&node);
            cores.insert(node, degree);
            for neighbor in neighbors.get(&node).into_iter().flatten() {
                if remaining.contains(neighbor) {
                    if let Some(current) = degrees.get(neighbor).copied() {
                        if current > degree {
                            degrees.insert(*neighbor, current - 1);
                        }
                    }
                }
            }
        }
        let value = CoreDecompositionProposal {
            memberships: cores
                .into_iter()
                .map(|(node, core)| CoreMembership { node, core })
                .collect(),
        };
        let mut trace = Encoder::new();
        trace.write_raw_byte(ArchitectureAlgorithm::CoreDecompositionV1.tag());
        encode_core_memberships(&mut trace, &value.memberships)?;
        let mut result = Encoder::new();
        encode_core_memberships(&mut result, &value.memberships)?;
        self.proposal(
            ArchitectureAlgorithm::CoreDecompositionV1,
            operations,
            trace,
            result,
            value,
        )
    }

    /// Proposes shard boundaries by removing every weakly-undirected bridge.
    pub fn community_partition(
        &self,
    ) -> Result<ArchitectureProposal<CommunityPartitionProposal>, ArchitectureRefusal> {
        let graph = self.snapshot.graph();
        let pairs = weak_pairs(graph.edges());
        let baseline = weak_components(graph.nodes(), &pairs, &BTreeSet::new()).len();
        let mut boundaries = Vec::new();
        let mut operations = 0_u64;
        for pair in &pairs {
            operations = operations
                .checked_add(1)
                .ok_or(ArchitectureRefusal::ArithmeticOverflow)?;
            let removed = BTreeSet::from([*pair]);
            if weak_components(graph.nodes(), &pairs, &removed).len() > baseline {
                boundaries.push(CommunityBoundary {
                    from: pair.0,
                    to: pair.1,
                });
            }
        }
        let removed: BTreeSet<_> = boundaries.iter().map(|edge| (edge.from, edge.to)).collect();
        let value = CommunityPartitionProposal {
            communities: weak_components(graph.nodes(), &pairs, &removed),
            boundaries,
        };
        let mut trace = Encoder::new();
        trace.write_raw_byte(ArchitectureAlgorithm::BridgePartitionV1.tag());
        encode_boundaries(&mut trace, &value.boundaries)?;
        let mut result = Encoder::new();
        encode_components(&mut result, "communities", &value.communities)?;
        encode_boundaries(&mut result, &value.boundaries)?;
        self.proposal(
            ArchitectureAlgorithm::BridgePartitionV1,
            operations,
            trace,
            result,
            value,
        )
    }

    /// Computes receipt-bound structural drift between the two views of a temporal join.
    pub fn temporal_drift(
        join: &TemporalCrossTimeJoin,
        limits: ArchitectureLimits,
    ) -> Result<ArchitectureProposal<ArchitecturalDriftReport>, ArchitectureRefusal> {
        check_limit(
            "architecture_earlier_nodes",
            join.earlier.nodes.len(),
            limits.nodes,
        )?;
        check_limit(
            "architecture_later_nodes",
            join.later.nodes.len(),
            limits.nodes,
        )?;
        check_limit(
            "architecture_earlier_edges",
            join.earlier.edges.len(),
            limits.edges,
        )?;
        check_limit(
            "architecture_later_edges",
            join.later.edges.len(),
            limits.edges,
        )?;
        if join.earlier.requested_position != join.receipt.earlier_position()
            || join.later.requested_position != join.receipt.later_position()
            || join.earlier.generation_id != join.receipt.earlier_generation_id()
            || join.later.generation_id != join.receipt.later_generation_id()
        {
            return Err(ArchitectureRefusal::TemporalJoinReceiptMismatch);
        }
        let earlier_nodes: BTreeSet<_> = join.earlier.nodes.iter().copied().collect();
        let later_nodes: BTreeSet<_> = join.later.nodes.iter().copied().collect();
        let earlier_edges: BTreeSet<_> = join.earlier.edges.iter().copied().collect();
        let later_edges: BTreeSet<_> = join.later.edges.iter().copied().collect();
        let value = ArchitecturalDriftReport {
            added_nodes: later_nodes.difference(&earlier_nodes).copied().collect(),
            removed_nodes: earlier_nodes.difference(&later_nodes).copied().collect(),
            added_edges: later_edges.difference(&earlier_edges).copied().collect(),
            removed_edges: earlier_edges.difference(&later_edges).copied().collect(),
        };
        let mut trace = Encoder::new();
        trace.write_raw_byte(ArchitectureAlgorithm::TemporalDriftV1.tag());
        trace.write_scalar(join.receipt.earlier_position().get());
        trace.write_scalar(join.receipt.later_position().get());
        let mut result = Encoder::new();
        encode_nodes(&mut result, "drift_added_nodes", &value.added_nodes)?;
        encode_nodes(&mut result, "drift_removed_nodes", &value.removed_nodes)?;
        encode_edges(&mut result, "drift_added_edges", &value.added_edges)?;
        encode_edges(&mut result, "drift_removed_edges", &value.removed_edges)?;
        proposal_from_parts(
            vec![join.earlier.generation_id, join.later.generation_id],
            vec![join.earlier.authority_class, join.later.authority_class],
            ArchitectureAlgorithm::TemporalDriftV1,
            u64::try_from(
                value
                    .added_nodes
                    .len()
                    .checked_add(value.removed_nodes.len())
                    .and_then(|count| count.checked_add(value.added_edges.len()))
                    .and_then(|count| count.checked_add(value.removed_edges.len()))
                    .ok_or(ArchitectureRefusal::ArithmeticOverflow)?,
            )
            .map_err(|_| ArchitectureRefusal::ArithmeticOverflow)?,
            trace,
            result,
            value,
        )
    }

    fn require_directed(
        &self,
        algorithm: ArchitectureAlgorithm,
    ) -> Result<(), ArchitectureRefusal> {
        if self.snapshot.graph().is_directed() {
            Ok(())
        } else {
            Err(ArchitectureRefusal::DirectedGraphRequired { algorithm })
        }
    }

    fn proposal<T>(
        &self,
        algorithm: ArchitectureAlgorithm,
        operations: u64,
        trace: Encoder,
        result: Encoder,
        value: T,
    ) -> Result<ArchitectureProposal<T>, ArchitectureRefusal> {
        proposal_from_parts(
            vec![self.snapshot.generation_id()],
            vec![self.snapshot.generation().authority_class()],
            algorithm,
            operations,
            trace,
            result,
            value,
        )
    }
}

fn proposal_from_parts<T>(
    graph_generation_ids: Vec<GraphGenerationId>,
    source_authority_classes: Vec<GraphAuthorityClass>,
    algorithm: ArchitectureAlgorithm,
    observed_operations: u64,
    trace: Encoder,
    result: Encoder,
    value: T,
) -> Result<ArchitectureProposal<T>, ArchitectureRefusal> {
    Ok(ArchitectureProposal {
        value,
        witness: ArchitectureDecisionWitness {
            graph_generation_ids,
            source_authority_classes,
            algorithm,
            tie_break_policy: "ascending-stable-node-id-and-edge-order-v1",
            observed_operations,
            decision_path_root: architecture_digest(b"decision-path", trace.as_bytes())?,
            result_root: architecture_digest(b"result", result.as_bytes())?,
        },
        fence: ArchitectureAdvisoryFence::AdvisoryOnly,
    })
}

fn check_limit(
    resource: &'static str,
    observed: usize,
    limit: u32,
) -> Result<(), ArchitectureRefusal> {
    let observed = u64::try_from(observed).map_err(|_| ArchitectureRefusal::ArithmeticOverflow)?;
    let limit = u64::from(limit);
    if observed > limit {
        Err(ArchitectureRefusal::ResourceLimit {
            resource,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn has_directed_cycle(nodes: &[GraphNodeId], edges: &[GraphEdge]) -> bool {
    let mut indegree: BTreeMap<_, u32> = nodes.iter().copied().map(|node| (node, 0)).collect();
    let mut outbound: BTreeMap<_, Vec<_>> = nodes
        .iter()
        .copied()
        .map(|node| (node, Vec::new()))
        .collect();
    for edge in edges {
        let degree = indegree.entry(edge.to).or_insert(0);
        *degree = degree.saturating_add(1);
        outbound.entry(edge.from).or_default().push(edge.to);
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(&node, &degree)| (degree == 0).then_some(node))
        .collect();
    let mut visited = 0_usize;
    while let Some(node) = ready.pop_first() {
        visited += 1;
        for target in outbound.get(&node).into_iter().flatten() {
            if let Some(degree) = indegree.get_mut(target) {
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.insert(*target);
                }
            }
        }
    }
    visited != nodes.len()
}

fn has_path_excluding(
    edges: &[GraphEdge],
    start: GraphNodeId,
    target: GraphNodeId,
    excluded: usize,
) -> bool {
    let mut outbound: BTreeMap<GraphNodeId, Vec<GraphNodeId>> = BTreeMap::new();
    for (index, edge) in edges.iter().enumerate() {
        if index != excluded {
            outbound.entry(edge.from).or_default().push(edge.to);
        }
    }
    for next in outbound.values_mut() {
        next.sort_unstable();
    }
    let mut seen = BTreeSet::from([start]);
    let mut queue = VecDeque::from([start]);
    while let Some(node) = queue.pop_front() {
        if node == target {
            return true;
        }
        for &next in outbound.get(&node).into_iter().flatten() {
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    false
}

fn weak_neighbors(
    nodes: &[GraphNodeId],
    edges: &[GraphEdge],
) -> BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>> {
    let mut result: BTreeMap<_, _> = nodes
        .iter()
        .copied()
        .map(|node| (node, BTreeSet::new()))
        .collect();
    for edge in edges {
        result.entry(edge.from).or_default().insert(edge.to);
        result.entry(edge.to).or_default().insert(edge.from);
    }
    result
}

fn weak_pairs(edges: &[GraphEdge]) -> BTreeSet<(GraphNodeId, GraphNodeId)> {
    edges
        .iter()
        .filter_map(|edge| {
            (edge.from != edge.to).then_some((edge.from.min(edge.to), edge.from.max(edge.to)))
        })
        .collect()
}

fn weak_components(
    nodes: &[GraphNodeId],
    pairs: &BTreeSet<(GraphNodeId, GraphNodeId)>,
    removed: &BTreeSet<(GraphNodeId, GraphNodeId)>,
) -> Vec<Vec<GraphNodeId>> {
    let mut neighbors: BTreeMap<_, BTreeSet<_>> = nodes
        .iter()
        .copied()
        .map(|node| (node, BTreeSet::new()))
        .collect();
    for &(from, to) in pairs {
        if !removed.contains(&(from, to)) {
            neighbors.entry(from).or_default().insert(to);
            neighbors.entry(to).or_default().insert(from);
        }
    }
    let mut unseen: BTreeSet<_> = nodes.iter().copied().collect();
    let mut components = Vec::new();
    while let Some(start) = unseen.pop_first() {
        let mut component = BTreeSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(node) = queue.pop_front() {
            for &next in neighbors.get(&node).into_iter().flatten() {
                if unseen.remove(&next) {
                    component.insert(next);
                    queue.push_back(next);
                }
            }
        }
        components.push(component.into_iter().collect());
    }
    components
}

fn encode_nodes(
    out: &mut Encoder,
    field: &'static str,
    nodes: &[GraphNodeId],
) -> Result<(), CodecRefusal> {
    out.write_sequence(field, nodes, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })
}

fn encode_edge(out: &mut Encoder, edge: GraphEdge) -> Result<(), CodecRefusal> {
    out.write_scalar(edge.from.get());
    out.write_scalar(edge.to.get());
    out.write_scalar(edge.capacity);
    Ok(())
}

fn encode_edges(
    out: &mut Encoder,
    field: &'static str,
    edges: &[GraphEdge],
) -> Result<(), CodecRefusal> {
    out.write_sequence(field, edges, |out, edge| encode_edge(out, *edge))
}

fn encode_components(
    out: &mut Encoder,
    field: &'static str,
    components: &[Vec<GraphNodeId>],
) -> Result<(), CodecRefusal> {
    out.write_sequence(field, components, |out, component| {
        encode_nodes(out, "community", component)
    })
}

fn encode_core_memberships(out: &mut Encoder, rows: &[CoreMembership]) -> Result<(), CodecRefusal> {
    out.write_sequence("core_memberships", rows, |out, row| {
        out.write_scalar(row.node.get());
        out.write_scalar(u64::from(row.core));
        Ok(())
    })
}

fn encode_boundaries(out: &mut Encoder, rows: &[CommunityBoundary]) -> Result<(), CodecRefusal> {
    out.write_sequence("community_boundaries", rows, |out, row| {
        out.write_scalar(row.from.get());
        out.write_scalar(row.to.get());
        Ok(())
    })
}

fn architecture_digest(label: &[u8], bytes: &[u8]) -> Result<Digest, ArchitectureRefusal> {
    let mut body = Encoder::new();
    body.write_bytes("architecture_digest.label", label)?;
    body.write_bytes("architecture_digest.value", bytes)?;
    let digest = internal_digest_value(IdentityDomain::MerkleLeaf, WITNESS_SCHEMA, body.as_bytes());
    Ok(Digest::new(
        internal_algorithm_id(IdentityDomain::MerkleLeaf),
        digest,
    ))
}
