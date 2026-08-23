//! Bounded exact graph algorithms with stable order and decision witnesses.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{IdentityDomain, internal_algorithm_id, internal_digest_value};
use fgit_types::{Digest, SchemaFamily, SchemaId};

use crate::generation::{
    ExactGraphGeneration, GenerationAuthorityError, GraphAuthorityClass,
    GraphAuthorityClassRefusal, GraphGenerationBody, GraphGenerationId, GraphSourceStamp,
};

mod wave_two;

pub use wave_two::{
    AdvisoryRank, BetweennessCentrality, FlowCost, HitsConfig, HitsScores, KShortestPaths,
    MinCostFlow, MinCostFlowRequest, PageRankConfig, PersonalizedPageRank, RationalScore, SetCover,
    SetCoverCandidate, SetCoverRequest, ShortestPath, SteinerTree,
};

const WITNESS_SCHEMA: SchemaId = SchemaId::new(SchemaFamily::from_static("graph-witness"), 1, 0);

/// Stable external identity of one graph vertex.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GraphNodeId(u64);

impl GraphNodeId {
    /// Builds a stable graph-node identity from its canonical numeric value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The canonical numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One capacity-bearing graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GraphEdge {
    /// Source endpoint for a directed graph, or one endpoint for an undirected graph.
    pub from: GraphNodeId,
    /// Destination endpoint for a directed graph, or the other endpoint for an undirected graph.
    pub to: GraphNodeId,
    /// Positive integral capacity, also used as a DAG edge duration.
    pub capacity: u64,
}

impl GraphEdge {
    /// Constructs one positive-capacity edge. Zero is refused during graph admission.
    #[must_use]
    pub const fn new(from: GraphNodeId, to: GraphNodeId, capacity: u64) -> Self {
        Self { from, to, capacity }
    }
}

/// Bounds checked before the graph core allocates adjacency or result state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphLimits {
    /// Largest supported vertex count.
    pub nodes: u32,
    /// Largest supported edge count.
    pub edges: u32,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            nodes: 4_096,
            edges: 65_536,
        }
    }
}

/// A graph decision family subject to per-view policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphDecision {
    /// Exact directed or undirected reachability closure.
    Reachability,
    /// Exact strongly-connected-component condensation.
    StronglyConnectedComponents,
    /// Exact dominator sets for a declared root set.
    Dominators,
    /// Exact articulation vertices and bridge edges of an undirected graph.
    ArticulationBridges,
    /// Exact global minimum cut of an undirected capacitated graph.
    MinimumCut,
    /// Exact maximum-cardinality bipartite matching.
    BipartiteMatching,
    /// Deterministic directed acyclic topological order.
    TopologicalOrder,
    /// Deterministic directed acyclic critical path.
    CriticalPath,
    /// Exact capacity-constrained, minimum-cost source-to-sink flow.
    MinCostFlow,
    /// Bounded deterministic enumeration of shortest simple paths.
    KShortestPaths,
    /// Exact shortest-path betweenness measurement.
    BetweennessCentrality,
    /// Deterministic fixed-point `PageRank` proposal.
    PageRank,
    /// Deterministic fixed-point HITS proposal.
    Hits,
    /// Deterministic personalized-PageRank context proposal.
    PersonalizedPageRank,
    /// Deterministic greedy Steiner-tree context proposal.
    SteinerTree,
    /// Deterministic greedy set-cover context proposal.
    SetCover,
}

/// Algorithm profile named in a [`GraphDecisionWitness`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphAlgorithm {
    /// Breadth-first reachability under ascending node IDs.
    ReachabilityV1,
    /// Iterative Kosaraju SCC decomposition under ascending node IDs.
    StronglyConnectedComponentsV1,
    /// Fixed-point dominator-set computation under ascending node IDs.
    DominatorsV1,
    /// Exhaustive removal-based articulation/bridge analysis.
    ArticulationBridgesV1,
    /// Stoer-Wagner global minimum cut under ascending node IDs.
    MinimumCutV1,
    /// Deterministic augmenting-path bipartite matching.
    BipartiteMatchingV1,
    /// Kahn topological sort under ascending node IDs.
    TopologicalOrderV1,
    /// Longest-path dynamic program over the deterministic topological order.
    CriticalPathV1,
    /// Bellman-Ford residual min-cost flow with stable predecessor selection.
    MinCostFlowV1,
    /// Uniform-cost bounded simple-path enumeration.
    KShortestPathsV1,
    /// Weighted Brandes shortest-path betweenness accumulation.
    BetweennessCentralityV1,
    /// Fixed-point `PageRank` with deterministic residual distribution.
    PageRankV1,
    /// Fixed-point HITS with deterministic normalization.
    HitsV1,
    /// Fixed-point personalized `PageRank` with deterministic residual distribution.
    PersonalizedPageRankV1,
    /// Rooted greedy shortest-path Steiner-tree approximation.
    SteinerTreeGreedyV1,
    /// Maximum-new-coverage-per-cost set-cover approximation.
    SetCoverGreedyV1,
}

impl GraphAlgorithm {
    const fn decision(self) -> GraphDecision {
        match self {
            Self::ReachabilityV1 => GraphDecision::Reachability,
            Self::StronglyConnectedComponentsV1 => GraphDecision::StronglyConnectedComponents,
            Self::DominatorsV1 => GraphDecision::Dominators,
            Self::ArticulationBridgesV1 => GraphDecision::ArticulationBridges,
            Self::MinimumCutV1 => GraphDecision::MinimumCut,
            Self::BipartiteMatchingV1 => GraphDecision::BipartiteMatching,
            Self::TopologicalOrderV1 => GraphDecision::TopologicalOrder,
            Self::CriticalPathV1 => GraphDecision::CriticalPath,
            Self::MinCostFlowV1 => GraphDecision::MinCostFlow,
            Self::KShortestPathsV1 => GraphDecision::KShortestPaths,
            Self::BetweennessCentralityV1 => GraphDecision::BetweennessCentrality,
            Self::PageRankV1 => GraphDecision::PageRank,
            Self::HitsV1 => GraphDecision::Hits,
            Self::PersonalizedPageRankV1 => GraphDecision::PersonalizedPageRank,
            Self::SteinerTreeGreedyV1 => GraphDecision::SteinerTree,
            Self::SetCoverGreedyV1 => GraphDecision::SetCover,
        }
    }

    const fn tag(self) -> &'static [u8] {
        match self {
            Self::ReachabilityV1 => b"reachability-v1",
            Self::StronglyConnectedComponentsV1 => b"scc-v1",
            Self::DominatorsV1 => b"dominators-v1",
            Self::ArticulationBridgesV1 => b"articulation-bridges-v1",
            Self::MinimumCutV1 => b"minimum-cut-v1",
            Self::BipartiteMatchingV1 => b"bipartite-matching-v1",
            Self::TopologicalOrderV1 => b"topological-order-v1",
            Self::CriticalPathV1 => b"critical-path-v1",
            Self::MinCostFlowV1 => b"min-cost-flow-v1",
            Self::KShortestPathsV1 => b"k-shortest-paths-v1",
            Self::BetweennessCentralityV1 => b"betweenness-centrality-v1",
            Self::PageRankV1 => b"page-rank-v1",
            Self::HitsV1 => b"hits-v1",
            Self::PersonalizedPageRankV1 => b"personalized-page-rank-v1",
            Self::SteinerTreeGreedyV1 => b"steiner-tree-greedy-v1",
            Self::SetCoverGreedyV1 => b"set-cover-greedy-v1",
        }
    }
}

/// Declared dominant complexity term for one exact implementation profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ComplexityTerm {
    /// O(V + E).
    LinearVerticesEdges,
    /// O(V * (V + E)).
    VertexTimesVerticesEdges,
    /// O(V³).
    CubicVertices,
    /// O(V * E).
    VertexTimesEdges,
    /// O(F * V * E) for requested flow F under Bellman-Ford residual relaxation.
    FlowTimesVerticesEdges,
    /// Bounded simple-path enumeration, with the query operation limit as the hard cap.
    OperationBoundedPathEnumeration,
}

/// A view-local allowlist for graph decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphViewPolicy {
    allowed: BTreeSet<GraphDecision>,
}

impl GraphViewPolicy {
    /// Allows exactly the supplied decision families.
    #[must_use]
    pub fn new(allowed: impl IntoIterator<Item = GraphDecision>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    /// Allows every exact algorithm this crate currently implements.
    #[must_use]
    pub fn exact_all() -> Self {
        Self::new([
            GraphDecision::Reachability,
            GraphDecision::StronglyConnectedComponents,
            GraphDecision::Dominators,
            GraphDecision::ArticulationBridges,
            GraphDecision::MinimumCut,
            GraphDecision::BipartiteMatching,
            GraphDecision::TopologicalOrder,
            GraphDecision::CriticalPath,
            GraphDecision::MinCostFlow,
            GraphDecision::KShortestPaths,
            GraphDecision::BetweennessCentrality,
        ])
    }

    fn require(&self, decision: GraphDecision) -> Result<(), GraphRefusal> {
        if self.allowed.contains(&decision) {
            Ok(())
        } else {
            Err(GraphRefusal::DecisionForbidden { decision })
        }
    }
}

/// Query-scoped facts carried into every result witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphQuery {
    generation_id: GraphGenerationId,
    authority_class: GraphAuthorityClass,
    policy: GraphViewPolicy,
    resource_receipt_root: Digest,
    operation_limit: u64,
}

impl GraphQuery {
    /// Pins a query to exactly one graph snapshot generation.
    ///
    /// Only [`GraphSnapshot::query`] may construct a query. This prevents a
    /// caller from relabeling a result from one snapshot as another generation.
    #[must_use]
    pub(crate) const fn new(
        generation_id: GraphGenerationId,
        authority_class: GraphAuthorityClass,
        policy: GraphViewPolicy,
        resource_receipt_root: Digest,
        operation_limit: u64,
    ) -> Self {
        Self {
            generation_id,
            authority_class,
            policy,
            resource_receipt_root,
            operation_limit,
        }
    }

    /// The one generation this query may observe.
    #[must_use]
    pub const fn generation_id(&self) -> GraphGenerationId {
        self.generation_id
    }

    /// The non-promotable authority class of the observed generation.
    #[must_use]
    pub const fn authority_class(&self) -> GraphAuthorityClass {
        self.authority_class
    }
}

/// A witnessed graph result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphResult<T> {
    /// Deterministic result under the declared graph authority class.
    pub value: T,
    /// Recomputable decision and complexity facts.
    pub witness: GraphDecisionWitness,
}

/// Exact decision facts emitted by every public graph algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphDecisionWitness {
    /// Exactly one generation in this initial single-view slice.
    pub graph_generation_ids: Vec<GraphGenerationId>,
    /// Authority class of the observed generation.
    ///
    /// An exact algorithm preserves this class; it never elevates a
    /// deterministic-derived or statistical graph to an authority source.
    pub authority_class: GraphAuthorityClass,
    /// The closed implementation profile.
    pub algorithm: GraphAlgorithm,
    /// Observed vertex count.
    pub vertices: u64,
    /// Observed edge count.
    pub edges: u64,
    /// Declared dominant complexity term.
    pub dominant_term: ComplexityTerm,
    /// Counted deterministic primitive operations.
    pub observed_operations: u64,
    /// Stable tie-break declaration for every profile in this crate.
    pub tie_break_policy: &'static str,
    /// Digest of the ordered decision trace.
    pub decision_path_root: Digest,
    /// Digest of the canonical result bytes.
    pub result_root: Digest,
    /// Resource reservation/receipt selected by the caller before work began.
    pub resource_receipt_root: Digest,
}

/// Why graph input or a requested exact computation was refused.
#[derive(Debug)]
pub enum GraphRefusal {
    /// A query issued by one snapshot was presented to another snapshot.
    GenerationMismatch {
        /// Generation materialized by the graph snapshot receiving the query.
        expected: Box<GraphGenerationId>,
        /// Generation named by the query.
        observed: Box<GraphGenerationId>,
    },
    /// A query's class does not match the snapshot that issued its generation.
    AuthorityClassMismatch {
        /// Class carried by the receiving graph snapshot.
        expected: GraphAuthorityClass,
        /// Class carried by the query.
        observed: GraphAuthorityClass,
    },
    /// A min-cost flow request named a cost for an edge outside this graph.
    UnknownFlowCost { from: GraphNodeId, to: GraphNodeId },
    /// A min-cost flow request named one edge cost more than once.
    DuplicateFlowCost { from: GraphNodeId, to: GraphNodeId },
    /// A min-cost flow request omitted the cost of a graph edge.
    MissingFlowCost { edge: GraphEdge },
    /// A flow source and sink must be distinct graph nodes.
    IdenticalFlowEndpoints { node: GraphNodeId },
    /// The graph cannot deliver the requested source-to-sink flow.
    InsufficientFlow {
        /// Flow demanded before work began.
        requested: u64,
        /// Flow delivered before no residual source-to-sink path remained.
        delivered: u64,
    },
    /// A bounded path request asked for no paths or exceeded the fixed request bound.
    InvalidPathCount { requested: u64, limit: u64 },
    /// A ranking configuration is outside the deterministic profile's bounds.
    InvalidRankConfiguration {
        /// Bounded iteration count requested by the caller.
        iterations: u32,
        /// Fixed-point damping in parts per million.
        damping_parts_per_million: u32,
    },
    /// A personalized ranking seed does not identify a graph node.
    UnknownRankingSeed { node: GraphNodeId },
    /// A personalized ranking seed was repeated.
    DuplicateRankingSeed { node: GraphNodeId },
    /// A personalized ranking seed must have positive integer weight.
    ZeroRankingSeedWeight { node: GraphNodeId },
    /// Personalized `PageRank` requires at least one positive seed.
    EmptyRankingSeeds,
    /// A Steiner-tree request supplied no terminals.
    EmptyTerminalSet,
    /// A Steiner-tree request repeated a terminal.
    DuplicateTerminal { node: GraphNodeId },
    /// A Steiner-tree terminal cannot be reached from the selected root.
    UnreachableTerminal { node: GraphNodeId },
    /// A set-cover universe element does not identify a graph node.
    UnknownCoverElement { node: GraphNodeId },
    /// A set-cover universe repeated one requested element.
    DuplicateCoverUniverse { element: GraphNodeId },
    /// A set-cover candidate was repeated.
    DuplicateCoverCandidate { candidate: GraphNodeId },
    /// A set-cover candidate must carry a positive integral cost.
    ZeroCoverCost { candidate: GraphNodeId },
    /// A set-cover candidate repeated one of its covered elements.
    DuplicateCoverElement {
        candidate: GraphNodeId,
        element: GraphNodeId,
    },
    /// No remaining candidate covers this universe element.
    UncoverableElement { element: GraphNodeId },
    /// Exact rational score arithmetic exceeded its bounded integer domain.
    RationalOverflow,
    /// A bound would be exceeded before this core allocates graph or result state.
    ResourceLimit {
        /// The bounded resource.
        resource: &'static str,
        /// The requested amount.
        observed: u64,
        /// The declared maximum.
        limit: u64,
    },
    /// A node was repeated in an input identity table.
    DuplicateNode { node: GraphNodeId },
    /// Two edges had the same canonical endpoints.
    DuplicateEdge { edge: GraphEdge },
    /// An edge refers to a node absent from the identity table.
    UnknownEndpoint { node: GraphNodeId },
    /// A capacity must be positive for cut and path semantics.
    ZeroCapacity { edge: GraphEdge },
    /// The requested API is forbidden by the selected view policy.
    DecisionForbidden { decision: GraphDecision },
    /// A requested node is absent from the graph.
    UnknownNode { node: GraphNodeId },
    /// An algorithm is defined only for directed graphs.
    DirectedGraphRequired { algorithm: GraphAlgorithm },
    /// An algorithm is defined only for undirected graphs.
    UndirectedGraphRequired { algorithm: GraphAlgorithm },
    /// A graph expected to be acyclic contains a cycle.
    CycleDetected,
    /// The dominator operation requires at least one root.
    EmptyRootSet,
    /// A bipartite side repeated a vertex.
    DuplicatePartitionNode { node: GraphNodeId },
    /// A vertex appeared in both bipartite sides.
    PartitionOverlap { node: GraphNodeId },
    /// Arithmetic in an exact capacity or duration computation would overflow.
    ArithmeticOverflow,
    /// The caller's operation budget was exhausted before the next operation.
    OperationLimit { limit: u64 },
    /// Canonical witness encoding refused an unrepresentable value.
    Codec(CodecRefusal),
    /// An internal invariant would have been violated; callers receive refusal, never a panic.
    Invariant,
}

impl From<CodecRefusal> for GraphRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Immutable graph plus both adjacency directions in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicGraph {
    directed: bool,
    nodes: Vec<GraphNodeId>,
    edges: Vec<GraphEdge>,
    outbound: BTreeMap<GraphNodeId, Vec<GraphArc>>,
    inbound: BTreeMap<GraphNodeId, Vec<GraphArc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GraphArc {
    to: GraphNodeId,
    capacity: u64,
    edge_index: usize,
}

impl DeterministicGraph {
    /// Validates and freezes a graph under bounds before allocating adjacency state.
    pub fn from_canonical_parts(
        directed: bool,
        nodes: &[GraphNodeId],
        edges: &[GraphEdge],
        limits: GraphLimits,
    ) -> Result<Self, GraphRefusal> {
        check_limit("nodes", nodes.len(), limits.nodes)?;
        check_limit("edges", edges.len(), limits.edges)?;

        let mut canonical_nodes = BTreeSet::new();
        for &node in nodes {
            if !canonical_nodes.insert(node) {
                return Err(GraphRefusal::DuplicateNode { node });
            }
        }

        let mut canonical_edges = BTreeSet::new();
        for &edge in edges {
            if edge.capacity == 0 {
                return Err(GraphRefusal::ZeroCapacity { edge });
            }
            if !canonical_nodes.contains(&edge.from) {
                return Err(GraphRefusal::UnknownEndpoint { node: edge.from });
            }
            if !canonical_nodes.contains(&edge.to) {
                return Err(GraphRefusal::UnknownEndpoint { node: edge.to });
            }
            let edge = if directed || edge.from <= edge.to {
                edge
            } else {
                GraphEdge::new(edge.to, edge.from, edge.capacity)
            };
            if !canonical_edges.insert(edge) {
                return Err(GraphRefusal::DuplicateEdge { edge });
            }
        }

        let canonical_nodes: Vec<_> = canonical_nodes.into_iter().collect();
        let canonical_edges: Vec<_> = canonical_edges.into_iter().collect();
        let mut outbound = BTreeMap::new();
        let mut inbound = BTreeMap::new();
        for &node in &canonical_nodes {
            outbound.insert(node, Vec::new());
            inbound.insert(node, Vec::new());
        }
        for (edge_index, edge) in canonical_edges.iter().copied().enumerate() {
            push_arc(
                &mut outbound,
                edge.from,
                GraphArc {
                    to: edge.to,
                    capacity: edge.capacity,
                    edge_index,
                },
            )?;
            push_arc(
                &mut inbound,
                edge.to,
                GraphArc {
                    to: edge.from,
                    capacity: edge.capacity,
                    edge_index,
                },
            )?;
            if !directed && edge.from != edge.to {
                push_arc(
                    &mut outbound,
                    edge.to,
                    GraphArc {
                        to: edge.from,
                        capacity: edge.capacity,
                        edge_index,
                    },
                )?;
                push_arc(
                    &mut inbound,
                    edge.from,
                    GraphArc {
                        to: edge.to,
                        capacity: edge.capacity,
                        edge_index,
                    },
                )?;
            }
        }
        for arcs in outbound.values_mut().chain(inbound.values_mut()) {
            arcs.sort_unstable_by_key(|arc| (arc.to, arc.edge_index));
        }
        Ok(Self {
            directed,
            nodes: canonical_nodes,
            edges: canonical_edges,
            outbound,
            inbound,
        })
    }

    /// Whether edge direction is semantically meaningful.
    #[must_use]
    pub const fn is_directed(&self) -> bool {
        self.directed
    }

    /// Stable vertex identities in ascending canonical order.
    #[must_use]
    pub fn nodes(&self) -> &[GraphNodeId] {
        &self.nodes
    }

    /// Stable edges in ascending canonical order.
    #[must_use]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    /// Computes the deterministic reachable closure from `start`.
    pub(crate) fn reachability(
        &self,
        query: &GraphQuery,
        start: GraphNodeId,
    ) -> Result<GraphResult<Reachability>, GraphRefusal> {
        query.policy.require(GraphDecision::Reachability)?;
        self.require_node(start)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::ReachabilityV1,
            ComplexityTerm::LinearVerticesEdges,
        )?;
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(start);
        queue.push_back(start);
        while let Some(node) = queue.pop_front() {
            witness.tick(1, &[node])?;
            for arc in self.outgoing(node)? {
                witness.tick(2, &[node, arc.to])?;
                if visited.insert(arc.to) {
                    queue.push_back(arc.to);
                }
            }
        }
        let nodes: Vec<_> = visited.into_iter().collect();
        let result = Reachability { start, nodes };
        let result_bytes = encode_nodes(b"reachability", &result.nodes)?;
        Ok(GraphResult {
            value: result,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes SCCs with an iterative two-pass traversal, never recursive DFS.
    pub(crate) fn strongly_connected_components(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<StronglyConnectedComponents>, GraphRefusal> {
        query
            .policy
            .require(GraphDecision::StronglyConnectedComponents)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::StronglyConnectedComponentsV1,
            ComplexityTerm::LinearVerticesEdges,
        )?;
        let mut seen = BTreeSet::new();
        let mut finishing = Vec::new();
        for &start in &self.nodes {
            if seen.contains(&start) {
                continue;
            }
            seen.insert(start);
            let mut stack = vec![(start, 0_usize)];
            while let Some((node, next)) = stack.last_mut() {
                witness.tick(3, &[*node])?;
                let arcs = self.outgoing(*node)?;
                if *next == arcs.len() {
                    finishing.push(*node);
                    stack.pop();
                    continue;
                }
                let arc = arcs[*next];
                *next += 1;
                witness.tick(4, &[*node, arc.to])?;
                if seen.insert(arc.to) {
                    stack.push((arc.to, 0));
                }
            }
        }

        let mut assigned = BTreeSet::new();
        let mut components = Vec::new();
        for &start in finishing.iter().rev() {
            if !assigned.insert(start) {
                continue;
            }
            let mut component = BTreeSet::new();
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                witness.tick(5, &[node])?;
                component.insert(node);
                for arc in self.incoming(node)? {
                    witness.tick(6, &[node, arc.to])?;
                    if assigned.insert(arc.to) {
                        stack.push(arc.to);
                    }
                }
            }
            components.push(component.into_iter().collect::<Vec<_>>());
        }
        components.sort_unstable();
        let mut component_of = BTreeMap::new();
        for (index, component) in components.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| GraphRefusal::ArithmeticOverflow)?;
            for &node in component {
                component_of.insert(node, index);
            }
        }
        let mut condensation_edges = BTreeSet::new();
        for edge in &self.edges {
            let from = component_of
                .get(&edge.from)
                .copied()
                .ok_or(GraphRefusal::Invariant)?;
            let to = component_of
                .get(&edge.to)
                .copied()
                .ok_or(GraphRefusal::Invariant)?;
            if from != to {
                condensation_edges.insert((from, to));
            }
        }
        let value = StronglyConnectedComponents {
            components,
            condensation_edges: condensation_edges.into_iter().collect(),
        };
        let result_bytes = encode_components(b"scc", &value.components, &value.condensation_edges)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes exact dominator sets by a deterministic fixed point.
    pub(crate) fn dominators(
        &self,
        query: &GraphQuery,
        roots: &[GraphNodeId],
    ) -> Result<GraphResult<BTreeMap<GraphNodeId, Vec<GraphNodeId>>>, GraphRefusal> {
        query.policy.require(GraphDecision::Dominators)?;
        if roots.is_empty() {
            return Err(GraphRefusal::EmptyRootSet);
        }
        let mut root_set = BTreeSet::new();
        for &root in roots {
            self.require_node(root)?;
            if !root_set.insert(root) {
                return Err(GraphRefusal::DuplicatePartitionNode { node: root });
            }
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::DominatorsV1,
            ComplexityTerm::VertexTimesVerticesEdges,
        )?;
        let all: BTreeSet<_> = self.nodes.iter().copied().collect();
        let mut dominators = BTreeMap::new();
        for &node in &self.nodes {
            dominators.insert(
                node,
                if root_set.contains(&node) {
                    BTreeSet::from([node])
                } else {
                    all.clone()
                },
            );
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &self.nodes {
                if root_set.contains(&node) {
                    continue;
                }
                witness.tick(7, &[node])?;
                let predecessors = self.incoming(node)?;
                let mut next = if let Some(first) = predecessors.first() {
                    dominators
                        .get(&first.to)
                        .cloned()
                        .ok_or(GraphRefusal::Invariant)?
                } else {
                    BTreeSet::new()
                };
                for predecessor in predecessors.iter().skip(1) {
                    witness.tick(8, &[node, predecessor.to])?;
                    let prior = dominators
                        .get(&predecessor.to)
                        .ok_or(GraphRefusal::Invariant)?;
                    next.retain(|candidate| prior.contains(candidate));
                }
                next.insert(node);
                let current = dominators.get(&node).ok_or(GraphRefusal::Invariant)?;
                if *current != next {
                    dominators.insert(node, next);
                    changed = true;
                }
            }
        }
        let value = dominators
            .into_iter()
            .map(|(node, set)| (node, set.into_iter().collect()))
            .collect();
        let result_bytes = encode_node_map(b"dominators", &value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes articulation vertices and bridge edges without recursion.
    pub(crate) fn articulation_bridges(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<ArticulationBridgeReport>, GraphRefusal> {
        query.policy.require(GraphDecision::ArticulationBridges)?;
        if self.directed {
            return Err(GraphRefusal::UndirectedGraphRequired {
                algorithm: GraphAlgorithm::ArticulationBridgesV1,
            });
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::ArticulationBridgesV1,
            ComplexityTerm::VertexTimesVerticesEdges,
        )?;
        let baseline = self.component_count(None, None, &mut witness)?;
        let mut articulations = Vec::new();
        for &node in &self.nodes {
            witness.tick(9, &[node])?;
            if self.component_count(Some(node), None, &mut witness)? > baseline {
                articulations.push(node);
            }
        }
        let mut bridges = Vec::new();
        for edge_index in 0..self.edges.len() {
            let edge = self.edges[edge_index];
            witness.tick(10, &[edge.from, edge.to])?;
            if self.component_count(None, Some(edge_index), &mut witness)? > baseline {
                bridges.push(edge);
            }
        }
        let value = ArticulationBridgeReport {
            articulations,
            bridges,
        };
        let result_bytes = encode_articulation_report(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes an exact global minimum cut with deterministic Stoer-Wagner phases.
    pub(crate) fn minimum_cut(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<MinimumCut>, GraphRefusal> {
        query.policy.require(GraphDecision::MinimumCut)?;
        if self.directed {
            return Err(GraphRefusal::UndirectedGraphRequired {
                algorithm: GraphAlgorithm::MinimumCutV1,
            });
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::MinimumCutV1,
            ComplexityTerm::CubicVertices,
        )?;
        if self.nodes.len() < 2 {
            let value = MinimumCut {
                capacity: 0,
                side: self.nodes.clone(),
            };
            return Ok(GraphResult {
                witness: witness.finish(&encode_minimum_cut(&value)?)?,
                value,
            });
        }
        let mut active: BTreeSet<_> = self.nodes.iter().copied().collect();
        let mut groups: BTreeMap<_, _> = self
            .nodes
            .iter()
            .copied()
            .map(|node| (node, BTreeSet::from([node])))
            .collect();
        let mut weights = BTreeMap::new();
        for edge in &self.edges {
            if edge.from != edge.to {
                add_weight(&mut weights, edge.from, edge.to, edge.capacity)?;
                add_weight(&mut weights, edge.to, edge.from, edge.capacity)?;
            }
        }
        let mut best: Option<(u64, Vec<GraphNodeId>)> = None;
        while active.len() > 1 {
            let mut added = BTreeSet::new();
            let mut connection = BTreeMap::new();
            let mut previous = None;
            for step in 0..active.len() {
                let selected = select_max_weight(&active, &added, &connection)
                    .ok_or(GraphRefusal::Invariant)?;
                witness.tick(11, &[selected])?;
                added.insert(selected);
                if step + 1 == active.len() {
                    let cut = connection.get(&selected).copied().unwrap_or(0);
                    let side: Vec<_> = groups
                        .get(&selected)
                        .ok_or(GraphRefusal::Invariant)?
                        .iter()
                        .copied()
                        .collect();
                    if best.as_ref().is_none_or(|(capacity, existing)| {
                        cut < *capacity || (cut == *capacity && side < *existing)
                    }) {
                        best = Some((cut, side));
                    }
                    let merged_into = previous.ok_or(GraphRefusal::Invariant)?;
                    for &other in &active {
                        if other == selected || other == merged_into {
                            continue;
                        }
                        let contribution = weights.get(&(selected, other)).copied().unwrap_or(0);
                        if contribution != 0 {
                            add_weight(&mut weights, merged_into, other, contribution)?;
                            add_weight(&mut weights, other, merged_into, contribution)?;
                        }
                    }
                    let selected_group = groups.remove(&selected).ok_or(GraphRefusal::Invariant)?;
                    groups
                        .get_mut(&merged_into)
                        .ok_or(GraphRefusal::Invariant)?
                        .extend(selected_group);
                    active.remove(&selected);
                    break;
                }
                previous = Some(selected);
                for &other in &active {
                    if added.contains(&other) {
                        continue;
                    }
                    let contribution = weights.get(&(selected, other)).copied().unwrap_or(0);
                    let entry = connection.entry(other).or_insert(0_u64);
                    *entry = entry
                        .checked_add(contribution)
                        .ok_or(GraphRefusal::ArithmeticOverflow)?;
                    witness.tick(12, &[selected, other])?;
                }
            }
        }
        let (capacity, side) = best.ok_or(GraphRefusal::Invariant)?;
        let value = MinimumCut { capacity, side };
        let result_bytes = encode_minimum_cut(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes a deterministic maximum-cardinality bipartite matching.
    pub(crate) fn bipartite_matching(
        &self,
        query: &GraphQuery,
        left: &[GraphNodeId],
        right: &[GraphNodeId],
    ) -> Result<GraphResult<BipartiteMatching>, GraphRefusal> {
        query.policy.require(GraphDecision::BipartiteMatching)?;
        let left = self.validate_partition(left)?;
        let right = self.validate_partition(right)?;
        if let Some(node) = left.intersection(&right).next() {
            return Err(GraphRefusal::PartitionOverlap { node: *node });
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::BipartiteMatchingV1,
            ComplexityTerm::VertexTimesEdges,
        )?;
        let mut match_left = BTreeMap::new();
        let mut match_right = BTreeMap::new();
        for &source in &left {
            if match_left.contains_key(&source) {
                continue;
            }
            let mut pending = VecDeque::from([source]);
            let mut seen_left = BTreeSet::from([source]);
            let mut seen_right = BTreeSet::new();
            let mut parent_right = BTreeMap::new();
            let mut exposed = None;
            'search: while let Some(current) = pending.pop_front() {
                witness.tick(13, &[current])?;
                for arc in self.outgoing(current)? {
                    if !right.contains(&arc.to) || !seen_right.insert(arc.to) {
                        continue;
                    }
                    witness.tick(14, &[current, arc.to])?;
                    parent_right.insert(arc.to, current);
                    if let Some(next_left) = match_right.get(&arc.to).copied() {
                        if seen_left.insert(next_left) {
                            pending.push_back(next_left);
                        }
                    } else {
                        exposed = Some(arc.to);
                        break 'search;
                    }
                }
            }
            if let Some(mut current_right) = exposed {
                loop {
                    let current_left = parent_right
                        .get(&current_right)
                        .copied()
                        .ok_or(GraphRefusal::Invariant)?;
                    let prior_right = match_left.insert(current_left, current_right);
                    match_right.insert(current_right, current_left);
                    if let Some(prior_right) = prior_right {
                        match_right.remove(&prior_right);
                        current_right = prior_right;
                    } else {
                        break;
                    }
                }
            }
        }
        let value = BipartiteMatching {
            pairs: match_left.into_iter().collect(),
        };
        let result_bytes = encode_pairs(b"matching", &value.pairs)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes a stable topological order for a directed acyclic graph.
    pub(crate) fn topological_order(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<TopologicalOrder>, GraphRefusal> {
        query.policy.require(GraphDecision::TopologicalOrder)?;
        self.require_directed(GraphAlgorithm::TopologicalOrderV1)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::TopologicalOrderV1,
            ComplexityTerm::LinearVerticesEdges,
        )?;
        let core = self.topological_core(&mut witness)?;
        let value = TopologicalOrder { nodes: core.order };
        let result_bytes = encode_nodes(b"topological", &value.nodes)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    /// Computes a stable maximum-duration critical path for a directed acyclic graph.
    pub(crate) fn critical_path(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<CriticalPath>, GraphRefusal> {
        query.policy.require(GraphDecision::CriticalPath)?;
        self.require_directed(GraphAlgorithm::CriticalPathV1)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::CriticalPathV1,
            ComplexityTerm::LinearVerticesEdges,
        )?;
        let core = self.topological_core(&mut witness)?;
        let mut endpoint = None;
        for &node in &self.nodes {
            let distance = core.distance.get(&node).copied().unwrap_or(0);
            if endpoint.is_none_or(|(best_distance, best_node)| {
                distance > best_distance || (distance == best_distance && node < best_node)
            }) {
                endpoint = Some((distance, node));
            }
        }
        let (duration, mut cursor) = endpoint.unwrap_or((0, GraphNodeId::new(0)));
        let mut reverse_path = Vec::new();
        if !self.nodes.is_empty() {
            reverse_path.push(cursor);
            while let Some(previous) = core.predecessor.get(&cursor).copied() {
                witness.tick(15, &[cursor, previous])?;
                cursor = previous;
                reverse_path.push(cursor);
            }
        }
        reverse_path.reverse();
        let value = CriticalPath {
            topological_order: core.order,
            duration,
            path: reverse_path,
        };
        let result_bytes = encode_critical_path(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    fn require_node(&self, node: GraphNodeId) -> Result<(), GraphRefusal> {
        if self.outbound.contains_key(&node) {
            Ok(())
        } else {
            Err(GraphRefusal::UnknownNode { node })
        }
    }

    const fn require_directed(&self, algorithm: GraphAlgorithm) -> Result<(), GraphRefusal> {
        if self.directed {
            Ok(())
        } else {
            Err(GraphRefusal::DirectedGraphRequired { algorithm })
        }
    }

    fn outgoing(&self, node: GraphNodeId) -> Result<&[GraphArc], GraphRefusal> {
        self.outbound
            .get(&node)
            .map(Vec::as_slice)
            .ok_or(GraphRefusal::UnknownNode { node })
    }

    fn incoming(&self, node: GraphNodeId) -> Result<&[GraphArc], GraphRefusal> {
        self.inbound
            .get(&node)
            .map(Vec::as_slice)
            .ok_or(GraphRefusal::UnknownNode { node })
    }

    fn component_count(
        &self,
        removed_node: Option<GraphNodeId>,
        removed_edge: Option<usize>,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<usize, GraphRefusal> {
        let mut seen = BTreeSet::new();
        let mut count = 0_usize;
        for &start in &self.nodes {
            if Some(start) == removed_node || !seen.insert(start) {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(GraphRefusal::ArithmeticOverflow)?;
            let mut pending = VecDeque::from([start]);
            while let Some(node) = pending.pop_front() {
                witness.tick(16, &[node])?;
                for arc in self.outgoing(node)? {
                    if Some(arc.edge_index) == removed_edge || Some(arc.to) == removed_node {
                        continue;
                    }
                    witness.tick(17, &[node, arc.to])?;
                    if seen.insert(arc.to) {
                        pending.push_back(arc.to);
                    }
                }
            }
        }
        Ok(count)
    }

    fn validate_partition(
        &self,
        nodes: &[GraphNodeId],
    ) -> Result<BTreeSet<GraphNodeId>, GraphRefusal> {
        let mut result = BTreeSet::new();
        for &node in nodes {
            self.require_node(node)?;
            if !result.insert(node) {
                return Err(GraphRefusal::DuplicatePartitionNode { node });
            }
        }
        Ok(result)
    }

    fn topological_core(
        &self,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<TopologicalCore, GraphRefusal> {
        let mut indegree: BTreeMap<_, u64> =
            self.nodes.iter().copied().map(|node| (node, 0)).collect();
        for edge in &self.edges {
            let entry = indegree.get_mut(&edge.to).ok_or(GraphRefusal::Invariant)?;
            *entry = entry
                .checked_add(1)
                .ok_or(GraphRefusal::ArithmeticOverflow)?;
        }
        let mut ready: BTreeSet<_> = indegree
            .iter()
            .filter_map(|(&node, &degree)| (degree == 0).then_some(node))
            .collect();
        let mut order = Vec::with_capacity(self.nodes.len());
        let mut distance: BTreeMap<_, u64> =
            self.nodes.iter().copied().map(|node| (node, 0)).collect();
        let mut predecessor = BTreeMap::new();
        while let Some(node) = ready.pop_first() {
            witness.tick(18, &[node])?;
            order.push(node);
            let node_distance = distance
                .get(&node)
                .copied()
                .ok_or(GraphRefusal::Invariant)?;
            for arc in self.outgoing(node)? {
                witness.tick(19, &[node, arc.to])?;
                let degree = indegree.get_mut(&arc.to).ok_or(GraphRefusal::Invariant)?;
                *degree = degree.checked_sub(1).ok_or(GraphRefusal::Invariant)?;
                if *degree == 0 {
                    ready.insert(arc.to);
                }
                let candidate = node_distance
                    .checked_add(arc.capacity)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                let current = distance
                    .get(&arc.to)
                    .copied()
                    .ok_or(GraphRefusal::Invariant)?;
                let current_predecessor = predecessor.get(&arc.to).copied();
                if candidate > current
                    || (candidate == current
                        && current_predecessor.is_none_or(|prior| node < prior))
                {
                    distance.insert(arc.to, candidate);
                    predecessor.insert(arc.to, node);
                }
            }
        }
        if order.len() != self.nodes.len() {
            return Err(GraphRefusal::CycleDetected);
        }
        Ok(TopologicalCore {
            order,
            distance,
            predecessor,
        })
    }
}

/// Builds a bounded graph view from one canonical generation body's source stamp.
///
/// This core does not claim to recompute the body's committed roots.  The
/// source subsystem provides those roots; callers use this builder only after
/// it has validated the corresponding canonical source material.
pub struct GraphBuilder {
    generation: GraphGenerationBody,
    limits: GraphLimits,
}

impl GraphBuilder {
    /// Binds a builder to an immutable position-stamped generation body.
    #[must_use]
    pub const fn new(generation: GraphGenerationBody, limits: GraphLimits) -> Self {
        Self { generation, limits }
    }

    /// The source position and pinned builder facts being materialized.
    #[must_use]
    pub const fn source_stamp(&self) -> &GraphSourceStamp {
        self.generation.source()
    }

    /// Freezes checked vertex and edge rows into a graph snapshot.
    pub fn build(
        &self,
        directed: bool,
        nodes: &[GraphNodeId],
        edges: &[GraphEdge],
    ) -> Result<GraphSnapshot, GraphBuilderError> {
        let generation_id = self.generation.generation_id()?;
        let graph = DeterministicGraph::from_canonical_parts(directed, nodes, edges, self.limits)?;
        Ok(GraphSnapshot {
            generation_id,
            generation: self.generation.clone(),
            graph,
        })
    }
}

/// A graph view pinned to one immutable generation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphSnapshot {
    generation_id: GraphGenerationId,
    generation: GraphGenerationBody,
    graph: DeterministicGraph,
}

impl GraphSnapshot {
    /// The immutable generation this snapshot represents.
    #[must_use]
    pub const fn generation_id(&self) -> GraphGenerationId {
        self.generation_id
    }

    /// The complete immutable generation body this snapshot materialized.
    #[must_use]
    pub const fn generation(&self) -> &GraphGenerationBody {
        &self.generation
    }

    /// Produces an exact-only proof for an exact-sensitive consumer.
    ///
    /// Graph execution itself remains advisory or derived unless a downstream
    /// consumer requires this proof; a score or traversal cannot manufacture one.
    pub const fn require_exact(
        &self,
    ) -> Result<ExactGraphGeneration<'_>, GraphAuthorityClassRefusal> {
        self.generation.require_exact()
    }

    /// The deterministic graph core.
    #[must_use]
    pub const fn graph(&self) -> &DeterministicGraph {
        &self.graph
    }

    /// Starts a query pinned to this snapshot's exact generation.
    #[must_use]
    pub const fn query(
        &self,
        policy: GraphViewPolicy,
        resource_receipt_root: Digest,
        operation_limit: u64,
    ) -> GraphQuery {
        GraphQuery::new(
            self.generation_id,
            self.generation.authority_class(),
            policy,
            resource_receipt_root,
            operation_limit,
        )
    }

    /// Computes the deterministic reachable closure from `start`.
    pub fn reachability(
        &self,
        query: &GraphQuery,
        start: GraphNodeId,
    ) -> Result<GraphResult<Reachability>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.reachability(query, start)
    }

    /// Computes deterministic strongly-connected components.
    pub fn strongly_connected_components(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<StronglyConnectedComponents>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.strongly_connected_components(query)
    }

    /// Computes exact dominator sets by a deterministic fixed point.
    pub fn dominators(
        &self,
        query: &GraphQuery,
        roots: &[GraphNodeId],
    ) -> Result<GraphResult<BTreeMap<GraphNodeId, Vec<GraphNodeId>>>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.dominators(query, roots)
    }

    /// Computes deterministic articulation vertices and bridge edges.
    pub fn articulation_bridges(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<ArticulationBridgeReport>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.articulation_bridges(query)
    }

    /// Computes an exact global minimum cut with deterministic tie-breaking.
    pub fn minimum_cut(&self, query: &GraphQuery) -> Result<GraphResult<MinimumCut>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.minimum_cut(query)
    }

    /// Computes a deterministic maximum-cardinality bipartite matching.
    pub fn bipartite_matching(
        &self,
        query: &GraphQuery,
        left: &[GraphNodeId],
        right: &[GraphNodeId],
    ) -> Result<GraphResult<BipartiteMatching>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.bipartite_matching(query, left, right)
    }

    /// Computes a stable topological order for a directed acyclic graph.
    pub fn topological_order(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<TopologicalOrder>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.topological_order(query)
    }

    /// Computes a stable maximum-duration critical path for a directed acyclic graph.
    pub fn critical_path(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<CriticalPath>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.critical_path(query)
    }

    /// Computes a deterministic minimum-cost flow proposal over this snapshot.
    pub fn min_cost_flow(
        &self,
        query: &GraphQuery,
        request: &MinCostFlowRequest,
    ) -> Result<GraphResult<MinCostFlow>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.min_cost_flow(query, request)
    }

    /// Enumerates the first `k` shortest simple paths under stable tie-breaking.
    pub fn k_shortest_paths(
        &self,
        query: &GraphQuery,
        source: GraphNodeId,
        target: GraphNodeId,
        k: u64,
    ) -> Result<GraphResult<KShortestPaths>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.k_shortest_paths(query, source, target, k)
    }

    /// Computes exact shortest-path betweenness values with rational scores.
    pub fn betweenness_centrality(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<BetweennessCentrality>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.betweenness_centrality(query)
    }

    /// Computes a bounded deterministic `PageRank` proposal.
    pub fn page_rank(
        &self,
        query: &GraphQuery,
        config: PageRankConfig,
    ) -> Result<GraphResult<AdvisoryRank>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.page_rank(query, config)
    }

    /// Computes a bounded deterministic personalized-PageRank proposal.
    pub fn personalized_page_rank(
        &self,
        query: &GraphQuery,
        config: PageRankConfig,
        seeds: &[(GraphNodeId, u64)],
    ) -> Result<GraphResult<PersonalizedPageRank>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.personalized_page_rank(query, config, seeds)
    }

    /// Computes a bounded deterministic HITS proposal.
    pub fn hits(
        &self,
        query: &GraphQuery,
        config: HitsConfig,
    ) -> Result<GraphResult<HitsScores>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.hits(query, config)
    }

    /// Computes a deterministic greedy Steiner-tree context proposal.
    pub fn steiner_tree(
        &self,
        query: &GraphQuery,
        terminals: &[GraphNodeId],
    ) -> Result<GraphResult<SteinerTree>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.steiner_tree(query, terminals)
    }

    /// Computes a deterministic greedy set-cover context proposal.
    pub fn set_cover(
        &self,
        query: &GraphQuery,
        request: &SetCoverRequest,
    ) -> Result<GraphResult<SetCover>, GraphRefusal> {
        self.require_query(query)?;
        self.graph.set_cover(query, request)
    }

    fn require_query(&self, query: &GraphQuery) -> Result<(), GraphRefusal> {
        if query.generation_id != self.generation_id {
            return Err(GraphRefusal::GenerationMismatch {
                expected: Box::new(self.generation_id),
                observed: Box::new(query.generation_id),
            });
        }
        let expected = self.generation.authority_class();
        if query.authority_class != expected {
            return Err(GraphRefusal::AuthorityClassMismatch {
                expected,
                observed: query.authority_class,
            });
        }
        Ok(())
    }
}

/// A graph builder may refuse either a generation body or bounded graph input.
#[derive(Debug)]
pub enum GraphBuilderError {
    /// The generation body or its registered identity refused validation.
    Generation(Box<GenerationAuthorityError>),
    /// The graph rows or bounds were not admissible.
    Graph(GraphRefusal),
}

impl From<GenerationAuthorityError> for GraphBuilderError {
    fn from(value: GenerationAuthorityError) -> Self {
        Self::Generation(Box::new(value))
    }
}

impl From<GraphRefusal> for GraphBuilderError {
    fn from(value: GraphRefusal) -> Self {
        Self::Graph(value)
    }
}

/// Reachability result under ascending-node BFS tie-breaking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reachability {
    /// Start vertex.
    pub start: GraphNodeId,
    /// Reachable vertices in ascending stable identity order.
    pub nodes: Vec<GraphNodeId>,
}

/// SCC result, with components and component members sorted canonically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StronglyConnectedComponents {
    /// Sorted component members, sorted lexicographically by component.
    pub components: Vec<Vec<GraphNodeId>>,
    /// Edges of the acyclic SCC condensation graph, by sorted component index.
    pub condensation_edges: Vec<(u32, u32)>,
}

/// Exact articulation and bridge report for an undirected graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArticulationBridgeReport {
    /// Removing one of these vertices increases component count.
    pub articulations: Vec<GraphNodeId>,
    /// Removing one of these edges increases component count.
    pub bridges: Vec<GraphEdge>,
}

/// Exact global minimum cut with the lexicographically selected cut side on ties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimumCut {
    /// Sum of capacities crossing the cut.
    pub capacity: u64,
    /// One selected side of the cut in ascending stable identity order.
    pub side: Vec<GraphNodeId>,
}

/// Deterministic maximum-cardinality bipartite matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BipartiteMatching {
    /// Pairs in ascending left-node identity order.
    pub pairs: Vec<(GraphNodeId, GraphNodeId)>,
}

/// Deterministic topological order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologicalOrder {
    /// Nodes ordered by Kahn's ascending-node tie-break.
    pub nodes: Vec<GraphNodeId>,
}

/// Deterministic longest critical path over a DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalPath {
    /// Full deterministic topological order used by the dynamic program.
    pub topological_order: Vec<GraphNodeId>,
    /// Sum of edge capacities/durations on `path`.
    pub duration: u64,
    /// Chosen path, with lower predecessor ID breaking equal-duration ties.
    pub path: Vec<GraphNodeId>,
}

struct TopologicalCore {
    order: Vec<GraphNodeId>,
    distance: BTreeMap<GraphNodeId, u64>,
    predecessor: BTreeMap<GraphNodeId, GraphNodeId>,
}

struct WitnessBuilder<'a> {
    query: &'a GraphQuery,
    algorithm: GraphAlgorithm,
    vertices: u64,
    edges: u64,
    dominant_term: ComplexityTerm,
    observed_operations: u64,
    trace: Encoder,
}

impl<'a> WitnessBuilder<'a> {
    fn new(
        query: &'a GraphQuery,
        graph: &DeterministicGraph,
        algorithm: GraphAlgorithm,
        dominant_term: ComplexityTerm,
    ) -> Result<Self, GraphRefusal> {
        query.policy.require(algorithm.decision())?;
        if query.operation_limit == 0 {
            return Err(GraphRefusal::OperationLimit { limit: 0 });
        }
        let mut trace = Encoder::new();
        trace.write_bytes("graph_trace.algorithm", algorithm.tag())?;
        trace.write_internal_object_id(query.generation_id.as_internal_object_id())?;
        Ok(Self {
            query,
            algorithm,
            vertices: u64::try_from(graph.nodes.len())
                .map_err(|_| GraphRefusal::ArithmeticOverflow)?,
            edges: u64::try_from(graph.edges.len())
                .map_err(|_| GraphRefusal::ArithmeticOverflow)?,
            dominant_term,
            observed_operations: 0,
            trace,
        })
    }

    fn tick(&mut self, event: u8, nodes: &[GraphNodeId]) -> Result<(), GraphRefusal> {
        if self.observed_operations == self.query.operation_limit {
            return Err(GraphRefusal::OperationLimit {
                limit: self.query.operation_limit,
            });
        }
        self.observed_operations = self
            .observed_operations
            .checked_add(1)
            .ok_or(GraphRefusal::ArithmeticOverflow)?;
        self.trace.write_raw_byte(event);
        self.trace
            .write_sequence("graph_trace.nodes", nodes, |encoder, node| {
                encoder.write_scalar(node.get());
                Ok(())
            })?;
        Ok(())
    }

    fn finish(self, result_bytes: &[u8]) -> Result<GraphDecisionWitness, GraphRefusal> {
        Ok(GraphDecisionWitness {
            graph_generation_ids: vec![self.query.generation_id],
            authority_class: self.query.authority_class,
            algorithm: self.algorithm,
            vertices: self.vertices,
            edges: self.edges,
            dominant_term: self.dominant_term,
            observed_operations: self.observed_operations,
            tie_break_policy: "ascending-stable-node-id-v1",
            decision_path_root: graph_digest(b"decision-path", self.trace.as_bytes())?,
            result_root: graph_digest(b"result", result_bytes)?,
            resource_receipt_root: self.query.resource_receipt_root,
        })
    }
}

fn check_limit(resource: &'static str, observed: usize, limit: u32) -> Result<(), GraphRefusal> {
    let observed = u64::try_from(observed).map_err(|_| GraphRefusal::ArithmeticOverflow)?;
    let limit = u64::from(limit);
    if observed > limit {
        Err(GraphRefusal::ResourceLimit {
            resource,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn push_arc(
    adjacency: &mut BTreeMap<GraphNodeId, Vec<GraphArc>>,
    node: GraphNodeId,
    arc: GraphArc,
) -> Result<(), GraphRefusal> {
    adjacency
        .get_mut(&node)
        .ok_or(GraphRefusal::UnknownNode { node })?
        .push(arc);
    Ok(())
}

fn add_weight(
    weights: &mut BTreeMap<(GraphNodeId, GraphNodeId), u64>,
    from: GraphNodeId,
    to: GraphNodeId,
    amount: u64,
) -> Result<(), GraphRefusal> {
    let entry = weights.entry((from, to)).or_insert(0);
    *entry = entry
        .checked_add(amount)
        .ok_or(GraphRefusal::ArithmeticOverflow)?;
    Ok(())
}

fn select_max_weight(
    active: &BTreeSet<GraphNodeId>,
    added: &BTreeSet<GraphNodeId>,
    connection: &BTreeMap<GraphNodeId, u64>,
) -> Option<GraphNodeId> {
    let mut selected = None;
    for &node in active {
        if added.contains(&node) {
            continue;
        }
        let weight = connection.get(&node).copied().unwrap_or(0);
        if selected.is_none_or(|current| {
            let current_weight = connection.get(&current).copied().unwrap_or(0);
            weight > current_weight || (weight == current_weight && node < current)
        }) {
            selected = Some(node);
        }
    }
    selected
}

fn graph_digest(label: &[u8], value: &[u8]) -> Result<Digest, GraphRefusal> {
    let mut body = Encoder::new();
    body.write_bytes("graph_digest.label", label)?;
    body.write_bytes("graph_digest.value", value)?;
    let bytes = internal_digest_value(IdentityDomain::MerkleLeaf, WITNESS_SCHEMA, body.as_bytes());
    Ok(Digest::new(
        internal_algorithm_id(IdentityDomain::MerkleLeaf),
        bytes,
    ))
}

fn encode_nodes(label: &[u8], nodes: &[GraphNodeId]) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_bytes("graph_result.label", label)?;
    encoder.write_sequence("graph_result.nodes", nodes, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_components(
    label: &[u8],
    components: &[Vec<GraphNodeId>],
    condensation_edges: &[(u32, u32)],
) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_bytes("graph_result.label", label)?;
    encoder.write_sequence("graph_result.components", components, |out, component| {
        out.write_sequence("graph_result.component", component, |nested, node| {
            nested.write_scalar(node.get());
            Ok(())
        })
    })?;
    encoder.write_sequence(
        "graph_result.condensation_edges",
        condensation_edges,
        |out, (from, to)| {
            out.write_scalar(*from);
            out.write_scalar(*to);
            Ok(())
        },
    )?;
    Ok(encoder.into_bytes())
}

fn encode_node_map(
    label: &[u8],
    entries: &BTreeMap<GraphNodeId, Vec<GraphNodeId>>,
) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_bytes("graph_result.label", label)?;
    let entries: Vec<_> = entries
        .iter()
        .map(|(&node, values)| (node, values))
        .collect();
    encoder.write_sequence("graph_result.map", &entries, |out, (node, values)| {
        out.write_scalar(node.get());
        out.write_sequence("graph_result.map_values", values, |nested, value| {
            nested.write_scalar(value.get());
            Ok(())
        })
    })?;
    Ok(encoder.into_bytes())
}

fn encode_articulation_report(value: &ArticulationBridgeReport) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_sequence(
        "graph_result.articulations",
        &value.articulations,
        |out, node| {
            out.write_scalar(node.get());
            Ok(())
        },
    )?;
    encoder.write_sequence("graph_result.bridges", &value.bridges, |out, edge| {
        out.write_scalar(edge.from.get());
        out.write_scalar(edge.to.get());
        out.write_scalar(edge.capacity);
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_minimum_cut(value: &MinimumCut) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_scalar(value.capacity);
    encoder.write_sequence("graph_result.cut_side", &value.side, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_pairs(
    label: &[u8],
    pairs: &[(GraphNodeId, GraphNodeId)],
) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_bytes("graph_result.label", label)?;
    encoder.write_sequence("graph_result.pairs", pairs, |out, (left, right)| {
        out.write_scalar(left.get());
        out.write_scalar(right.get());
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_critical_path(value: &CriticalPath) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = Encoder::new();
    encoder.write_scalar(value.duration);
    encoder.write_sequence(
        "graph_result.topological",
        &value.topological_order,
        |out, node| {
            out.write_scalar(node.get());
            Ok(())
        },
    )?;
    encoder.write_sequence("graph_result.path", &value.path, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

#[cfg(test)]
mod tests {
    use fgit_crypto::{
        IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
    };
    use fgit_types::{CodecVersion, Digest, GenerationId, SchemaFamily, SchemaId};

    use super::{
        DeterministicGraph, GraphAlgorithm, GraphAuthorityClass, GraphDecision, GraphEdge,
        GraphLimits, GraphNodeId, GraphQuery, GraphRefusal, GraphViewPolicy,
    };

    fn node(value: u64) -> GraphNodeId {
        GraphNodeId::new(value)
    }

    fn digest(label: &[u8]) -> Digest {
        let bytes = internal_digest_value(
            IdentityDomain::MerkleLeaf,
            SchemaId::new(SchemaFamily::from_static("graph-test-digest"), 1, 0),
            label,
        );
        Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf), bytes)
    }

    fn query(policy: GraphViewPolicy) -> GraphQuery {
        let identity = internal_object_id(
            IdentityDomain::Generation,
            SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
            CodecVersion::new(1, 0),
            b"graph-test-generation",
        );
        GraphQuery::new(
            GenerationId::from_internal_object_id(identity).expect("identity domain is generation"),
            GraphAuthorityClass::Exact,
            policy,
            digest(b"resource-receipt"),
            100_000,
        )
    }

    fn directed_graph() -> DeterministicGraph {
        DeterministicGraph::from_canonical_parts(
            true,
            &[node(1), node(2), node(3), node(4), node(5), node(6)],
            &[
                GraphEdge::new(node(1), node(2), 1),
                GraphEdge::new(node(1), node(3), 1),
                GraphEdge::new(node(2), node(4), 1),
                GraphEdge::new(node(3), node(4), 1),
                GraphEdge::new(node(3), node(6), 2),
                GraphEdge::new(node(4), node(5), 1),
                GraphEdge::new(node(5), node(4), 1),
            ],
            GraphLimits::default(),
        )
        .expect("fixed corpus is admissible")
    }

    #[test]
    fn exact_algorithms_match_the_small_scalar_corpus_and_witnesses_are_stable() {
        let graph = directed_graph();
        let query = query(GraphViewPolicy::exact_all());
        let first = graph
            .reachability(&query, node(1))
            .expect("reachability is allowed");
        let second = graph
            .reachability(&query, node(1))
            .expect("same exact computation is allowed");
        assert_eq!(first, second);
        assert_eq!(
            first.value.nodes,
            vec![node(1), node(2), node(3), node(4), node(5), node(6)]
        );
        assert_eq!(first.witness.algorithm, GraphAlgorithm::ReachabilityV1);

        let scc = graph
            .strongly_connected_components(&query)
            .expect("SCC computation is allowed");
        assert_eq!(
            scc.value.components,
            vec![
                vec![node(1)],
                vec![node(2)],
                vec![node(3)],
                vec![node(4), node(5)],
                vec![node(6)]
            ]
        );
        assert_eq!(
            scc.value.condensation_edges,
            vec![(0, 1), (0, 2), (1, 3), (2, 3), (2, 4)]
        );

        let dominators = graph
            .dominators(&query, &[node(1)])
            .expect("dominator computation is allowed");
        assert_eq!(
            dominators.value.get(&node(4)),
            Some(&vec![node(1), node(4)])
        );
        assert_eq!(
            dominators.value.get(&node(5)),
            Some(&vec![node(1), node(4), node(5)])
        );
    }

    #[test]
    fn undirected_fragility_and_cut_match_the_small_scalar_corpus() {
        let graph = DeterministicGraph::from_canonical_parts(
            false,
            &[node(1), node(2), node(3), node(4)],
            &[
                GraphEdge::new(node(1), node(2), 1),
                GraphEdge::new(node(2), node(3), 1),
                GraphEdge::new(node(2), node(4), 1),
            ],
            GraphLimits::default(),
        )
        .expect("tree corpus is admissible");
        let query = query(GraphViewPolicy::exact_all());
        let fragility = graph
            .articulation_bridges(&query)
            .expect("undirected fragility computation is allowed");
        assert_eq!(fragility.value.articulations, vec![node(2)]);
        assert_eq!(fragility.value.bridges.len(), 3);
        let cut = graph.minimum_cut(&query).expect("minimum cut is allowed");
        assert_eq!(cut.value.capacity, 1);
    }

    #[test]
    fn matching_and_dag_order_close_ties_by_stable_node_id() {
        let matching_graph = DeterministicGraph::from_canonical_parts(
            true,
            &[node(1), node(2), node(3), node(4)],
            &[
                GraphEdge::new(node(1), node(3), 1),
                GraphEdge::new(node(1), node(4), 1),
                GraphEdge::new(node(2), node(3), 1),
            ],
            GraphLimits::default(),
        )
        .expect("matching corpus is admissible");
        let query = query(GraphViewPolicy::exact_all());
        let matching = matching_graph
            .bipartite_matching(&query, &[node(1), node(2)], &[node(3), node(4)])
            .expect("matching is allowed");
        assert_eq!(
            matching.value.pairs,
            vec![(node(1), node(4)), (node(2), node(3))]
        );

        let dag = DeterministicGraph::from_canonical_parts(
            true,
            &[node(1), node(2), node(3), node(4)],
            &[
                GraphEdge::new(node(1), node(3), 2),
                GraphEdge::new(node(2), node(3), 2),
                GraphEdge::new(node(3), node(4), 3),
            ],
            GraphLimits::default(),
        )
        .expect("DAG corpus is admissible");
        let order = dag
            .topological_order(&query)
            .expect("DAG topological order");
        assert_eq!(order.value.nodes, vec![node(1), node(2), node(3), node(4)]);
        let critical = dag.critical_path(&query).expect("DAG critical path");
        assert_eq!(critical.value.duration, 5);
        assert_eq!(critical.value.path, vec![node(1), node(3), node(4)]);
    }

    #[test]
    fn policy_and_bounds_refuse_before_algorithm_work() {
        let graph = directed_graph();
        let query = query(GraphViewPolicy::new([GraphDecision::Reachability]));
        assert!(matches!(
            graph.topological_order(&query),
            Err(GraphRefusal::DecisionForbidden {
                decision: GraphDecision::TopologicalOrder
            })
        ));
        assert!(matches!(
            DeterministicGraph::from_canonical_parts(
                true,
                &[node(1), node(2)],
                &[],
                GraphLimits { nodes: 1, edges: 0 }
            ),
            Err(GraphRefusal::ResourceLimit {
                resource: "nodes",
                ..
            })
        ));
    }
}
