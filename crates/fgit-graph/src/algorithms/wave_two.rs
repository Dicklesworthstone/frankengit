//! Wave-two, bounded graph algorithms built on the generation-bound witness core.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ComplexityTerm, DeterministicGraph, GraphAlgorithm, GraphDecision, GraphEdge, GraphNodeId,
    GraphQuery, GraphRefusal, GraphResult, WitnessBuilder,
};

const MAX_K_SHORTEST_PATHS: u64 = 128;
const MAX_RANK_ITERATIONS: u32 = 128;
const RANK_SCALE: u64 = 1_000_000_000;

/// The integral traversal cost assigned to one capacity-bearing graph edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowCost {
    from: GraphNodeId,
    to: GraphNodeId,
    cost: u64,
}

impl FlowCost {
    /// Names the non-negative cost of one directed graph edge.
    #[must_use]
    pub const fn new(from: GraphNodeId, to: GraphNodeId, cost: u64) -> Self {
        Self { from, to, cost }
    }

    /// The edge source.
    #[must_use]
    pub const fn from(self) -> GraphNodeId {
        self.from
    }

    /// The edge destination.
    #[must_use]
    pub const fn to(self) -> GraphNodeId {
        self.to
    }

    /// The non-negative per-unit flow cost.
    #[must_use]
    pub const fn cost(self) -> u64 {
        self.cost
    }
}

/// Bounded source-to-sink flow demand and its complete edge-cost table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinCostFlowRequest {
    source: GraphNodeId,
    sink: GraphNodeId,
    required_flow: u64,
    costs: Vec<FlowCost>,
}

impl MinCostFlowRequest {
    /// Builds one flow request. Validation happens before residual allocation.
    #[must_use]
    pub const fn new(
        source: GraphNodeId,
        sink: GraphNodeId,
        required_flow: u64,
        costs: Vec<FlowCost>,
    ) -> Self {
        Self {
            source,
            sink,
            required_flow,
            costs,
        }
    }

    /// The source node.
    #[must_use]
    pub const fn source(&self) -> GraphNodeId {
        self.source
    }

    /// The sink node.
    #[must_use]
    pub const fn sink(&self) -> GraphNodeId {
        self.sink
    }

    /// The demanded amount of flow.
    #[must_use]
    pub const fn required_flow(&self) -> u64 {
        self.required_flow
    }

    /// The complete cost table supplied by the caller.
    #[must_use]
    pub fn costs(&self) -> &[FlowCost] {
        &self.costs
    }
}

/// Exact delivered flow and total non-negative cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinCostFlow {
    /// The flow delivered to the requested sink.
    pub flow: u64,
    /// The exact summed integral cost.
    pub total_cost: u64,
}

/// One stable shortest path, ordered by total cost then node-ID sequence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ShortestPath {
    /// Node sequence from source through target.
    pub nodes: Vec<GraphNodeId>,
    /// Sum of edge capacities used as strictly positive path costs.
    pub cost: u64,
}

/// The first bounded number of shortest simple paths for an explanatory query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KShortestPaths {
    /// Requested source node.
    pub source: GraphNodeId,
    /// Requested target node.
    pub target: GraphNodeId,
    /// Paths in ascending `(cost, node sequence)` order.
    pub paths: Vec<ShortestPath>,
}

/// An exact reduced non-negative rational value for a centrality score.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RationalScore {
    numerator: u64,
    denominator: u64,
}

impl RationalScore {
    /// The reduced numerator.
    #[must_use]
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// The reduced positive denominator.
    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    const fn zero() -> Self {
        Self {
            numerator: 0,
            denominator: 1,
        }
    }

    const fn one() -> Self {
        Self {
            numerator: 1,
            denominator: 1,
        }
    }

    const fn new(numerator: u64, denominator: u64) -> Result<Self, GraphRefusal> {
        if denominator == 0 {
            return Err(GraphRefusal::Invariant);
        }
        if numerator == 0 {
            return Ok(Self::zero());
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn checked_add(self, other: Self) -> Result<Self, GraphRefusal> {
        let left_gcd = gcd(self.denominator, other.denominator);
        let left_factor = other.denominator / left_gcd;
        let right_factor = self.denominator / left_gcd;
        let numerator = self
            .numerator
            .checked_mul(left_factor)
            .and_then(|value| {
                other
                    .numerator
                    .checked_mul(right_factor)
                    .and_then(|rhs| value.checked_add(rhs))
            })
            .ok_or(GraphRefusal::RationalOverflow)?;
        let denominator = self
            .denominator
            .checked_mul(left_factor)
            .ok_or(GraphRefusal::RationalOverflow)?;
        Self::new(numerator, denominator)
    }

    fn checked_mul(self, other: Self) -> Result<Self, GraphRefusal> {
        let left_cancel = gcd(self.numerator, other.denominator);
        let right_cancel = gcd(other.numerator, self.denominator);
        let numerator = (self.numerator / left_cancel)
            .checked_mul(other.numerator / right_cancel)
            .ok_or(GraphRefusal::RationalOverflow)?;
        let denominator = (self.denominator / right_cancel)
            .checked_mul(other.denominator / left_cancel)
            .ok_or(GraphRefusal::RationalOverflow)?;
        Self::new(numerator, denominator)
    }
}

/// Exact shortest-path betweenness values, sorted by stable node identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BetweennessCentrality {
    /// One exact score for every graph node, in ascending node-ID order.
    pub scores: Vec<(GraphNodeId, RationalScore)>,
}

/// Fixed-point configuration for bounded PageRank-style proposals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageRankConfig {
    iterations: u32,
    damping_parts_per_million: u32,
}

impl PageRankConfig {
    /// Constructs a bounded integer-only ranking profile.
    #[must_use]
    pub const fn new(iterations: u32, damping_parts_per_million: u32) -> Self {
        Self {
            iterations,
            damping_parts_per_million,
        }
    }

    /// The fixed iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Damping in parts per million, inclusive of zero and one million.
    #[must_use]
    pub const fn damping_parts_per_million(self) -> u32 {
        self.damping_parts_per_million
    }
}

/// Fixed-point HITS iteration count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HitsConfig {
    iterations: u32,
}

impl HitsConfig {
    /// Constructs a bounded HITS profile.
    #[must_use]
    pub const fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// The fixed iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }
}

/// A deterministic advisory ranking; scores cannot serve as authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryRank {
    /// Nodes ordered by descending fixed-point score, then ascending node identity.
    pub ranks: Vec<(GraphNodeId, u64)>,
}

/// A personalized `PageRank` proposal, preserving its explicitly advisory ranking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizedPageRank {
    /// The bounded, fixed-point advisory rank ordering.
    pub ranking: AdvisoryRank,
}

/// Independent authority and hub advisory rankings from deterministic HITS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HitsScores {
    /// Authority candidates in descending score / ascending-ID tie-break order.
    pub authorities: AdvisoryRank,
    /// Hub candidates in descending score / ascending-ID tie-break order.
    pub hubs: AdvisoryRank,
}

/// A deterministic greedy connected-context proposal for requested terminals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SteinerTree {
    /// Lowest stable terminal selected as the rooted approximation anchor.
    pub root: GraphNodeId,
    /// Requested terminals in ascending stable identity order.
    pub terminals: Vec<GraphNodeId>,
    /// Included nodes in ascending stable identity order.
    pub nodes: Vec<GraphNodeId>,
    /// Included canonical graph edges in ascending stable order.
    pub edges: Vec<GraphEdge>,
    /// Sum of unique included edge capacities.
    pub total_cost: u64,
}

/// One bounded set-cover candidate keyed by an existing graph node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCoverCandidate {
    id: GraphNodeId,
    cost: u64,
    elements: Vec<GraphNodeId>,
}

impl SetCoverCandidate {
    /// Builds a candidate. Duplicate and unknown elements are refused before selection work.
    #[must_use]
    pub const fn new(id: GraphNodeId, cost: u64, elements: Vec<GraphNodeId>) -> Self {
        Self { id, cost, elements }
    }

    /// Stable candidate identity.
    #[must_use]
    pub const fn id(&self) -> GraphNodeId {
        self.id
    }

    /// Positive integral selection cost.
    #[must_use]
    pub const fn cost(&self) -> u64 {
        self.cost
    }

    /// Elements this candidate covers.
    #[must_use]
    pub fn elements(&self) -> &[GraphNodeId] {
        &self.elements
    }
}

/// Bounded universe and candidates for one deterministic greedy coverage query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCoverRequest {
    universe: Vec<GraphNodeId>,
    candidates: Vec<SetCoverCandidate>,
}

impl SetCoverRequest {
    /// Builds one request. Validation happens before selection allocation or work.
    #[must_use]
    pub const fn new(universe: Vec<GraphNodeId>, candidates: Vec<SetCoverCandidate>) -> Self {
        Self {
            universe,
            candidates,
        }
    }

    /// Universe elements requested for coverage.
    #[must_use]
    pub fn universe(&self) -> &[GraphNodeId] {
        &self.universe
    }

    /// Candidate cover sets.
    #[must_use]
    pub fn candidates(&self) -> &[SetCoverCandidate] {
        &self.candidates
    }
}

/// Deterministic greedy set-cover proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCover {
    /// Candidate IDs in the exact greedy selection order.
    pub selected: Vec<GraphNodeId>,
    /// Sum of selected candidate costs.
    pub total_cost: u64,
}

#[derive(Clone, Copy)]
struct ResidualArc {
    to: usize,
    reverse: usize,
    capacity: u64,
    cost: i128,
}

type ResidualPredecessor = Option<(usize, usize)>;
type ResidualShortestPath = (Vec<Option<i128>>, Vec<ResidualPredecessor>);

struct ShortestPathDag {
    distance: BTreeMap<GraphNodeId, Option<u64>>,
    sigma: BTreeMap<GraphNodeId, u64>,
    predecessors: BTreeMap<GraphNodeId, Vec<GraphNodeId>>,
    order: Vec<GraphNodeId>,
}

impl DeterministicGraph {
    pub(crate) fn min_cost_flow(
        &self,
        query: &GraphQuery,
        request: &MinCostFlowRequest,
    ) -> Result<GraphResult<MinCostFlow>, GraphRefusal> {
        query.policy.require(GraphDecision::MinCostFlow)?;
        self.require_directed(GraphAlgorithm::MinCostFlowV1)?;
        self.require_node(request.source)?;
        self.require_node(request.sink)?;
        if request.source == request.sink {
            return Err(GraphRefusal::IdenticalFlowEndpoints {
                node: request.source,
            });
        }
        if request.costs.len() != self.edges.len() {
            let missing = self.edges.first().copied().ok_or(GraphRefusal::Invariant)?;
            return Err(GraphRefusal::MissingFlowCost { edge: missing });
        }

        let mut cost_table = BTreeMap::new();
        for cost in &request.costs {
            if !self
                .edges
                .iter()
                .any(|edge| edge.from == cost.from && edge.to == cost.to)
            {
                return Err(GraphRefusal::UnknownFlowCost {
                    from: cost.from,
                    to: cost.to,
                });
            }
            if cost_table.insert((cost.from, cost.to), cost.cost).is_some() {
                return Err(GraphRefusal::DuplicateFlowCost {
                    from: cost.from,
                    to: cost.to,
                });
            }
        }
        for &edge in &self.edges {
            if !cost_table.contains_key(&(edge.from, edge.to)) {
                return Err(GraphRefusal::MissingFlowCost { edge });
            }
        }

        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::MinCostFlowV1,
            ComplexityTerm::FlowTimesVerticesEdges,
        )?;
        let mut residual = vec![Vec::new(); self.nodes.len()];
        for &edge in &self.edges {
            let from = self.node_index(edge.from)?;
            let to = self.node_index(edge.to)?;
            let cost = i128::from(
                *cost_table
                    .get(&(edge.from, edge.to))
                    .ok_or(GraphRefusal::Invariant)?,
            );
            add_residual_arc(&mut residual, from, to, edge.capacity, cost);
        }

        let source = self.node_index(request.source)?;
        let sink = self.node_index(request.sink)?;
        let mut delivered = 0_u64;
        let mut total_cost = 0_i128;
        while delivered < request.required_flow {
            let (distance, predecessor) =
                residual_shortest_path(&mut witness, &residual, &self.nodes, source)?;
            let Some(path_cost) = distance[sink] else {
                return Err(GraphRefusal::InsufficientFlow {
                    requested: request.required_flow,
                    delivered,
                });
            };
            let mut cursor = sink;
            let mut augment = request.required_flow - delivered;
            let mut steps = 0_usize;
            while cursor != source {
                let (from, arc_index) = predecessor[cursor].ok_or(GraphRefusal::Invariant)?;
                augment = augment.min(residual[from][arc_index].capacity);
                cursor = from;
                steps = steps
                    .checked_add(1)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                if steps > self.nodes.len() {
                    return Err(GraphRefusal::Invariant);
                }
            }
            if augment == 0 {
                return Err(GraphRefusal::Invariant);
            }
            cursor = sink;
            while cursor != source {
                let (from, arc_index) = predecessor[cursor].ok_or(GraphRefusal::Invariant)?;
                let reverse = residual[from][arc_index].reverse;
                residual[from][arc_index].capacity -= augment;
                residual[cursor][reverse].capacity = residual[cursor][reverse]
                    .capacity
                    .checked_add(augment)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                cursor = from;
            }
            delivered = delivered
                .checked_add(augment)
                .ok_or(GraphRefusal::ArithmeticOverflow)?;
            total_cost = total_cost
                .checked_add(
                    path_cost
                        .checked_mul(i128::from(augment))
                        .ok_or(GraphRefusal::ArithmeticOverflow)?,
                )
                .ok_or(GraphRefusal::ArithmeticOverflow)?;
        }
        let total_cost = u64::try_from(total_cost).map_err(|_| GraphRefusal::Invariant)?;
        let value = MinCostFlow {
            flow: delivered,
            total_cost,
        };
        let result_bytes = encode_min_cost_flow(value);
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    pub(crate) fn k_shortest_paths(
        &self,
        query: &GraphQuery,
        source: GraphNodeId,
        target: GraphNodeId,
        k: u64,
    ) -> Result<GraphResult<KShortestPaths>, GraphRefusal> {
        query.policy.require(GraphDecision::KShortestPaths)?;
        self.require_node(source)?;
        self.require_node(target)?;
        if k == 0 || k > MAX_K_SHORTEST_PATHS {
            return Err(GraphRefusal::InvalidPathCount {
                requested: k,
                limit: MAX_K_SHORTEST_PATHS,
            });
        }
        let count = usize::try_from(k).map_err(|_| GraphRefusal::ArithmeticOverflow)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::KShortestPathsV1,
            ComplexityTerm::OperationBoundedPathEnumeration,
        )?;
        let mut frontier = BTreeSet::from([(0_u64, vec![source])]);
        let mut paths = Vec::with_capacity(count);
        while paths.len() < count {
            let Some((cost, path)) = frontier.pop_first() else {
                break;
            };
            let current = *path.last().ok_or(GraphRefusal::Invariant)?;
            witness.tick(21, &[current])?;
            if current == target {
                paths.push(ShortestPath { nodes: path, cost });
                continue;
            }
            for arc in self.outgoing(current)? {
                witness.tick(22, &[current, arc.to])?;
                if path.contains(&arc.to) {
                    continue;
                }
                let next_cost = cost
                    .checked_add(arc.capacity)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                let mut next_path = path.clone();
                next_path.push(arc.to);
                frontier.insert((next_cost, next_path));
            }
        }
        let value = KShortestPaths {
            source,
            target,
            paths,
        };
        let result_bytes = encode_k_shortest_paths(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    pub(crate) fn betweenness_centrality(
        &self,
        query: &GraphQuery,
    ) -> Result<GraphResult<BetweennessCentrality>, GraphRefusal> {
        query.policy.require(GraphDecision::BetweennessCentrality)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::BetweennessCentralityV1,
            ComplexityTerm::VertexTimesVerticesEdges,
        )?;
        let mut scores: BTreeMap<_, _> = self
            .nodes
            .iter()
            .copied()
            .map(|node| (node, RationalScore::zero()))
            .collect();
        for &source in &self.nodes {
            let paths = self.shortest_path_dag(&mut witness, source)?;
            let mut dependency: BTreeMap<_, _> = self
                .nodes
                .iter()
                .copied()
                .map(|node| (node, RationalScore::zero()))
                .collect();
            for &node in paths.order.iter().rev() {
                let propagated = dependency
                    .get(&node)
                    .copied()
                    .ok_or(GraphRefusal::Invariant)?
                    .checked_add(RationalScore::one())?;
                for predecessor in paths
                    .predecessors
                    .get(&node)
                    .ok_or(GraphRefusal::Invariant)?
                {
                    witness.tick(24, &[*predecessor, node])?;
                    let numerator = *paths
                        .sigma
                        .get(predecessor)
                        .ok_or(GraphRefusal::Invariant)?;
                    let denominator = *paths.sigma.get(&node).ok_or(GraphRefusal::Invariant)?;
                    let contribution =
                        RationalScore::new(numerator, denominator)?.checked_mul(propagated)?;
                    let next = dependency
                        .get(predecessor)
                        .copied()
                        .ok_or(GraphRefusal::Invariant)?
                        .checked_add(contribution)?;
                    dependency.insert(*predecessor, next);
                }
                if node != source {
                    let next = scores
                        .get(&node)
                        .copied()
                        .ok_or(GraphRefusal::Invariant)?
                        .checked_add(
                            dependency
                                .get(&node)
                                .copied()
                                .ok_or(GraphRefusal::Invariant)?,
                        )?;
                    scores.insert(node, next);
                }
            }
        }
        let value = BetweennessCentrality {
            scores: scores.into_iter().collect(),
        };
        let result_bytes = encode_betweenness(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    pub(crate) fn page_rank(
        &self,
        query: &GraphQuery,
        config: PageRankConfig,
    ) -> Result<GraphResult<AdvisoryRank>, GraphRefusal> {
        query.policy.require(GraphDecision::PageRank)?;
        validate_page_rank_config(config)?;
        let teleport = uniform_distribution(&self.nodes)?;
        self.page_rank_with_teleport(query, config, &teleport, GraphAlgorithm::PageRankV1)
    }

    pub(crate) fn personalized_page_rank(
        &self,
        query: &GraphQuery,
        config: PageRankConfig,
        seeds: &[(GraphNodeId, u64)],
    ) -> Result<GraphResult<PersonalizedPageRank>, GraphRefusal> {
        query.policy.require(GraphDecision::PersonalizedPageRank)?;
        validate_page_rank_config(config)?;
        if seeds.is_empty() {
            return Err(GraphRefusal::EmptyRankingSeeds);
        }
        let mut seed_weights = BTreeMap::new();
        for &(node, weight) in seeds {
            self.require_node(node)
                .map_err(|_| GraphRefusal::UnknownRankingSeed { node })?;
            if weight == 0 {
                return Err(GraphRefusal::ZeroRankingSeedWeight { node });
            }
            if seed_weights.insert(node, weight).is_some() {
                return Err(GraphRefusal::DuplicateRankingSeed { node });
            }
        }
        let teleport = distribute_weighted(RANK_SCALE, &seed_weights)?;
        let result = self.page_rank_with_teleport(
            query,
            config,
            &teleport,
            GraphAlgorithm::PersonalizedPageRankV1,
        )?;
        Ok(GraphResult {
            value: PersonalizedPageRank {
                ranking: result.value,
            },
            witness: result.witness,
        })
    }

    pub(crate) fn hits(
        &self,
        query: &GraphQuery,
        config: HitsConfig,
    ) -> Result<GraphResult<HitsScores>, GraphRefusal> {
        query.policy.require(GraphDecision::Hits)?;
        if config.iterations == 0 || config.iterations > MAX_RANK_ITERATIONS {
            return Err(GraphRefusal::InvalidRankConfiguration {
                iterations: config.iterations,
                damping_parts_per_million: 0,
            });
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::HitsV1,
            ComplexityTerm::VertexTimesEdges,
        )?;
        let mut hubs = uniform_distribution(&self.nodes)?;
        let mut authorities = BTreeMap::new();
        for _ in 0..config.iterations {
            let mut raw_authorities = zero_distribution(&self.nodes);
            for &from in &self.nodes {
                let hub = *hubs.get(&from).ok_or(GraphRefusal::Invariant)?;
                for arc in self.outgoing(from)? {
                    witness.tick(25, &[from, arc.to])?;
                    let entry = raw_authorities
                        .get_mut(&arc.to)
                        .ok_or(GraphRefusal::Invariant)?;
                    *entry = entry
                        .checked_add(hub)
                        .ok_or(GraphRefusal::ArithmeticOverflow)?;
                }
            }
            authorities = normalize_distribution(&raw_authorities)?;
            let mut raw_hubs = zero_distribution(&self.nodes);
            for &from in &self.nodes {
                for arc in self.outgoing(from)? {
                    witness.tick(26, &[from, arc.to])?;
                    let authority = *authorities.get(&arc.to).ok_or(GraphRefusal::Invariant)?;
                    let entry = raw_hubs.get_mut(&from).ok_or(GraphRefusal::Invariant)?;
                    *entry = entry
                        .checked_add(authority)
                        .ok_or(GraphRefusal::ArithmeticOverflow)?;
                }
            }
            hubs = normalize_distribution(&raw_hubs)?;
        }
        let value = HitsScores {
            authorities: advisory_rank(authorities),
            hubs: advisory_rank(hubs),
        };
        let result_bytes = encode_hits(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    fn page_rank_with_teleport(
        &self,
        query: &GraphQuery,
        config: PageRankConfig,
        teleport: &BTreeMap<GraphNodeId, u64>,
        algorithm: GraphAlgorithm,
    ) -> Result<GraphResult<AdvisoryRank>, GraphRefusal> {
        let mut witness =
            WitnessBuilder::new(query, self, algorithm, ComplexityTerm::VertexTimesEdges)?;
        let damping = u64::from(config.damping_parts_per_million)
            .checked_mul(RANK_SCALE / 1_000_000)
            .ok_or(GraphRefusal::ArithmeticOverflow)?;
        let mut current = teleport.clone();
        for _ in 0..config.iterations {
            let mut next = zero_distribution(&self.nodes);
            add_distribution(&mut next, teleport, RANK_SCALE - damping)?;
            let source_mass = distribute_weighted(damping, &current)?;
            for (&source, &mass) in &source_mass {
                witness.tick(27, &[source])?;
                let outgoing = self.outgoing(source)?;
                if outgoing.is_empty() {
                    add_distribution(&mut next, teleport, mass)?;
                    continue;
                }
                let targets: BTreeMap<_, _> = outgoing.iter().map(|arc| (arc.to, 1_u64)).collect();
                for arc in outgoing {
                    witness.tick(28, &[source, arc.to])?;
                }
                let distributed = distribute_weighted(mass, &targets)?;
                add_distribution(&mut next, &distributed, mass)?;
            }
            current = next;
        }
        let value = advisory_rank(current);
        let result_bytes = encode_advisory_rank(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    pub(crate) fn steiner_tree(
        &self,
        query: &GraphQuery,
        terminals: &[GraphNodeId],
    ) -> Result<GraphResult<SteinerTree>, GraphRefusal> {
        query.policy.require(GraphDecision::SteinerTree)?;
        if terminals.is_empty() {
            return Err(GraphRefusal::EmptyTerminalSet);
        }
        let mut terminal_set = BTreeSet::new();
        for &terminal in terminals {
            self.require_node(terminal)?;
            if !terminal_set.insert(terminal) {
                return Err(GraphRefusal::DuplicateTerminal { node: terminal });
            }
        }
        let terminals: Vec<_> = terminal_set.into_iter().collect();
        let root = *terminals.first().ok_or(GraphRefusal::Invariant)?;
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::SteinerTreeGreedyV1,
            ComplexityTerm::VertexTimesVerticesEdges,
        )?;
        let mut node_set = BTreeSet::from([root]);
        let mut edge_set = BTreeSet::new();
        for &terminal in terminals.iter().skip(1) {
            let path = self.shortest_path_between(&mut witness, root, terminal)?;
            let Some(path) = path else {
                return Err(GraphRefusal::UnreachableTerminal { node: terminal });
            };
            for pair in path.nodes.windows(2) {
                let [from, to] = pair else {
                    return Err(GraphRefusal::Invariant);
                };
                witness.tick(30, &[*from, *to])?;
                node_set.insert(*from);
                node_set.insert(*to);
                edge_set.insert(self.canonical_edge_between(*from, *to)?);
            }
        }
        let total_cost = edge_set.iter().try_fold(0_u64, |sum, edge| {
            sum.checked_add(edge.capacity)
                .ok_or(GraphRefusal::ArithmeticOverflow)
        })?;
        let value = SteinerTree {
            root,
            terminals,
            nodes: node_set.into_iter().collect(),
            edges: edge_set.into_iter().collect(),
            total_cost,
        };
        let result_bytes = encode_steiner_tree(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    pub(crate) fn set_cover(
        &self,
        query: &GraphQuery,
        request: &SetCoverRequest,
    ) -> Result<GraphResult<SetCover>, GraphRefusal> {
        query.policy.require(GraphDecision::SetCover)?;
        if request.candidates.len() > self.nodes.len() {
            return Err(GraphRefusal::ResourceLimit {
                resource: "set_cover_candidates",
                observed: u64::try_from(request.candidates.len())
                    .map_err(|_| GraphRefusal::ArithmeticOverflow)?,
                limit: u64::try_from(self.nodes.len())
                    .map_err(|_| GraphRefusal::ArithmeticOverflow)?,
            });
        }
        let mut uncovered = BTreeSet::new();
        for &element in &request.universe {
            self.require_node(element)
                .map_err(|_| GraphRefusal::UnknownCoverElement { node: element })?;
            if !uncovered.insert(element) {
                return Err(GraphRefusal::DuplicateCoverUniverse { element });
            }
        }
        let mut candidate_ids = BTreeSet::new();
        for candidate in &request.candidates {
            self.require_node(candidate.id)
                .map_err(|_| GraphRefusal::UnknownCoverElement { node: candidate.id })?;
            if !candidate_ids.insert(candidate.id) {
                return Err(GraphRefusal::DuplicateCoverCandidate {
                    candidate: candidate.id,
                });
            }
            if candidate.cost == 0 {
                return Err(GraphRefusal::ZeroCoverCost {
                    candidate: candidate.id,
                });
            }
            let mut elements = BTreeSet::new();
            for &element in &candidate.elements {
                self.require_node(element)
                    .map_err(|_| GraphRefusal::UnknownCoverElement { node: element })?;
                if !elements.insert(element) {
                    return Err(GraphRefusal::DuplicateCoverElement {
                        candidate: candidate.id,
                        element,
                    });
                }
            }
        }
        let mut witness = WitnessBuilder::new(
            query,
            self,
            GraphAlgorithm::SetCoverGreedyV1,
            ComplexityTerm::VertexTimesEdges,
        )?;
        let mut selected_indexes = BTreeSet::new();
        let mut selected = Vec::new();
        let mut total_cost = 0_u64;
        while !uncovered.is_empty() {
            let mut best: Option<(usize, BTreeSet<GraphNodeId>)> = None;
            for (index, candidate) in request.candidates.iter().enumerate() {
                if selected_indexes.contains(&index) {
                    continue;
                }
                witness.tick(31, &[candidate.id])?;
                let mut newly_covered = BTreeSet::new();
                for &element in &candidate.elements {
                    witness.tick(32, &[candidate.id, element])?;
                    if uncovered.contains(&element) {
                        newly_covered.insert(element);
                    }
                }
                if newly_covered.is_empty() {
                    continue;
                }
                let replace = match &best {
                    None => true,
                    Some((best_index, best_cover)) => {
                        let current = &request.candidates[*best_index];
                        let candidate_ratio = u128::try_from(newly_covered.len())
                            .map_err(|_| GraphRefusal::ArithmeticOverflow)?
                            * u128::from(current.cost);
                        let current_ratio = u128::try_from(best_cover.len())
                            .map_err(|_| GraphRefusal::ArithmeticOverflow)?
                            * u128::from(candidate.cost);
                        let tie_break = (candidate.cost, candidate.id)
                            .cmp(&(current.cost, current.id))
                            .is_lt();
                        candidate_ratio > current_ratio
                            || (candidate_ratio == current_ratio && tie_break)
                    }
                };
                if replace {
                    best = Some((index, newly_covered));
                }
            }
            let Some((index, covered)) = best else {
                return Err(GraphRefusal::UncoverableElement {
                    element: *uncovered.first().ok_or(GraphRefusal::Invariant)?,
                });
            };
            let candidate = &request.candidates[index];
            selected_indexes.insert(index);
            selected.push(candidate.id);
            total_cost = total_cost
                .checked_add(candidate.cost)
                .ok_or(GraphRefusal::ArithmeticOverflow)?;
            for element in covered {
                uncovered.remove(&element);
            }
        }
        let value = SetCover {
            selected,
            total_cost,
        };
        let result_bytes = encode_set_cover(&value)?;
        Ok(GraphResult {
            value,
            witness: witness.finish(&result_bytes)?,
        })
    }

    fn shortest_path_between(
        &self,
        witness: &mut WitnessBuilder<'_>,
        source: GraphNodeId,
        target: GraphNodeId,
    ) -> Result<Option<ShortestPath>, GraphRefusal> {
        let paths = self.shortest_path_dag(witness, source)?;
        let Some(cost) = paths.distance.get(&target).copied().flatten() else {
            return Ok(None);
        };
        let mut reverse = vec![target];
        let mut current = target;
        while current != source {
            let predecessor = paths
                .predecessors
                .get(&current)
                .and_then(|candidates| candidates.first())
                .copied()
                .ok_or(GraphRefusal::Invariant)?;
            reverse.push(predecessor);
            current = predecessor;
            if reverse.len() > self.nodes.len() {
                return Err(GraphRefusal::Invariant);
            }
        }
        reverse.reverse();
        Ok(Some(ShortestPath {
            nodes: reverse,
            cost,
        }))
    }

    fn canonical_edge_between(
        &self,
        from: GraphNodeId,
        to: GraphNodeId,
    ) -> Result<GraphEdge, GraphRefusal> {
        let (from, to) = if self.directed || from <= to {
            (from, to)
        } else {
            (to, from)
        };
        self.edges
            .iter()
            .find(|edge| edge.from == from && edge.to == to)
            .copied()
            .ok_or(GraphRefusal::Invariant)
    }

    fn shortest_path_dag(
        &self,
        witness: &mut WitnessBuilder<'_>,
        source: GraphNodeId,
    ) -> Result<ShortestPathDag, GraphRefusal> {
        self.require_node(source)?;
        let mut distance = BTreeMap::new();
        let mut sigma = BTreeMap::new();
        let mut predecessors = BTreeMap::new();
        for &node in &self.nodes {
            distance.insert(node, None::<u64>);
            sigma.insert(node, 0_u64);
            predecessors.insert(node, Vec::new());
        }
        distance.insert(source, Some(0));
        sigma.insert(source, 1);
        let mut frontier = BTreeSet::from([(0_u64, source)]);
        let mut order = Vec::new();
        while let Some((cost, node)) = frontier.pop_first() {
            if distance.get(&node).copied().flatten() != Some(cost) {
                continue;
            }
            order.push(node);
            let paths_to_node = *sigma.get(&node).ok_or(GraphRefusal::Invariant)?;
            for arc in self.outgoing(node)? {
                witness.tick(29, &[node, arc.to])?;
                let candidate = cost
                    .checked_add(arc.capacity)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                match distance.get(&arc.to).copied().flatten() {
                    None => {
                        distance.insert(arc.to, Some(candidate));
                        sigma.insert(arc.to, paths_to_node);
                        predecessors.insert(arc.to, vec![node]);
                        frontier.insert((candidate, arc.to));
                    }
                    Some(current) if candidate < current => {
                        distance.insert(arc.to, Some(candidate));
                        sigma.insert(arc.to, paths_to_node);
                        predecessors.insert(arc.to, vec![node]);
                        frontier.insert((candidate, arc.to));
                    }
                    Some(current) if candidate == current => {
                        let entry = predecessors
                            .get_mut(&arc.to)
                            .ok_or(GraphRefusal::Invariant)?;
                        if !entry.contains(&node) {
                            entry.push(node);
                            entry.sort_unstable();
                            let updated = sigma
                                .get(&arc.to)
                                .copied()
                                .ok_or(GraphRefusal::Invariant)?
                                .checked_add(paths_to_node)
                                .ok_or(GraphRefusal::ArithmeticOverflow)?;
                            sigma.insert(arc.to, updated);
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(ShortestPathDag {
            distance,
            sigma,
            predecessors,
            order,
        })
    }

    fn node_index(&self, node: GraphNodeId) -> Result<usize, GraphRefusal> {
        self.nodes
            .binary_search(&node)
            .map_err(|_| GraphRefusal::UnknownNode { node })
    }
}

fn add_residual_arc(
    residual: &mut [Vec<ResidualArc>],
    from: usize,
    to: usize,
    capacity: u64,
    cost: i128,
) {
    let forward_index = residual[from].len();
    let reverse_index = residual[to].len();
    residual[from].push(ResidualArc {
        to,
        reverse: reverse_index,
        capacity,
        cost,
    });
    residual[to].push(ResidualArc {
        to: from,
        reverse: forward_index,
        capacity: 0,
        cost: -cost,
    });
}

fn residual_shortest_path(
    witness: &mut WitnessBuilder<'_>,
    residual: &[Vec<ResidualArc>],
    nodes: &[GraphNodeId],
    source: usize,
) -> Result<ResidualShortestPath, GraphRefusal> {
    let mut distance: Vec<Option<i128>> = vec![None; nodes.len()];
    let mut predecessor = vec![None; nodes.len()];
    distance[source] = Some(0);
    for _ in 0..nodes.len().saturating_sub(1) {
        let mut changed = false;
        for from in 0..nodes.len() {
            let Some(prior) = distance[from] else {
                continue;
            };
            for (arc_index, arc) in residual[from].iter().enumerate() {
                if arc.capacity == 0 {
                    continue;
                }
                witness.tick(23, &[nodes[from], nodes[arc.to]])?;
                let candidate = prior
                    .checked_add(arc.cost)
                    .ok_or(GraphRefusal::ArithmeticOverflow)?;
                let replacement = match distance[arc.to] {
                    None => true,
                    Some(current) if candidate < current => true,
                    Some(current) if candidate == current => {
                        predecessor[arc.to].is_none_or(|existing| (from, arc_index) < existing)
                    }
                    Some(_) => false,
                };
                if replacement {
                    distance[arc.to] = Some(candidate);
                    predecessor[arc.to] = Some((from, arc_index));
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok((distance, predecessor))
}

const fn validate_page_rank_config(config: PageRankConfig) -> Result<(), GraphRefusal> {
    if config.iterations == 0
        || config.iterations > MAX_RANK_ITERATIONS
        || config.damping_parts_per_million > 1_000_000
    {
        return Err(GraphRefusal::InvalidRankConfiguration {
            iterations: config.iterations,
            damping_parts_per_million: config.damping_parts_per_million,
        });
    }
    Ok(())
}

fn zero_distribution(nodes: &[GraphNodeId]) -> BTreeMap<GraphNodeId, u64> {
    nodes.iter().copied().map(|node| (node, 0_u64)).collect()
}

fn uniform_distribution(nodes: &[GraphNodeId]) -> Result<BTreeMap<GraphNodeId, u64>, GraphRefusal> {
    if nodes.is_empty() {
        return Ok(BTreeMap::new());
    }
    let weights: BTreeMap<_, _> = nodes.iter().copied().map(|node| (node, 1_u64)).collect();
    distribute_weighted(RANK_SCALE, &weights)
}

fn normalize_distribution(
    weights: &BTreeMap<GraphNodeId, u64>,
) -> Result<BTreeMap<GraphNodeId, u64>, GraphRefusal> {
    let total = weights.values().try_fold(0_u64, |sum, weight| {
        sum.checked_add(*weight)
            .ok_or(GraphRefusal::ArithmeticOverflow)
    })?;
    if total == 0 {
        return Ok(zero_distribution(
            &weights.keys().copied().collect::<Vec<_>>(),
        ));
    }
    distribute_weighted(RANK_SCALE, weights)
}

fn distribute_weighted(
    total: u64,
    weights: &BTreeMap<GraphNodeId, u64>,
) -> Result<BTreeMap<GraphNodeId, u64>, GraphRefusal> {
    let weight_sum = weights.values().try_fold(0_u64, |sum, weight| {
        sum.checked_add(*weight)
            .ok_or(GraphRefusal::ArithmeticOverflow)
    })?;
    if weight_sum == 0 {
        return Err(GraphRefusal::Invariant);
    }
    let mut output = BTreeMap::new();
    let mut assigned = 0_u64;
    for (&node, &weight) in weights {
        let value = u64::try_from(u128::from(total) * u128::from(weight) / u128::from(weight_sum))
            .map_err(|_| GraphRefusal::ArithmeticOverflow)?;
        assigned = assigned
            .checked_add(value)
            .ok_or(GraphRefusal::ArithmeticOverflow)?;
        output.insert(node, value);
    }
    let remainder = total.checked_sub(assigned).ok_or(GraphRefusal::Invariant)?;
    let recipients: Vec<_> = weights
        .iter()
        .filter_map(|(&node, &weight)| (weight != 0).then_some(node))
        .collect();
    if recipients.is_empty() {
        return Err(GraphRefusal::Invariant);
    }
    for node in recipients
        .into_iter()
        .cycle()
        .take(usize::try_from(remainder).map_err(|_| GraphRefusal::ArithmeticOverflow)?)
    {
        let entry = output.get_mut(&node).ok_or(GraphRefusal::Invariant)?;
        *entry = entry
            .checked_add(1)
            .ok_or(GraphRefusal::ArithmeticOverflow)?;
    }
    Ok(output)
}

fn add_distribution(
    target: &mut BTreeMap<GraphNodeId, u64>,
    distribution: &BTreeMap<GraphNodeId, u64>,
    total: u64,
) -> Result<(), GraphRefusal> {
    if total == 0 {
        return Ok(());
    }
    let portion = distribute_weighted(total, distribution)?;
    for (node, value) in portion {
        let entry = target.get_mut(&node).ok_or(GraphRefusal::Invariant)?;
        *entry = entry
            .checked_add(value)
            .ok_or(GraphRefusal::ArithmeticOverflow)?;
    }
    Ok(())
}

fn advisory_rank(scores: BTreeMap<GraphNodeId, u64>) -> AdvisoryRank {
    let mut ranks: Vec<_> = scores.into_iter().collect();
    ranks.sort_unstable_by(|(left_node, left_score), (right_node, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_node.cmp(right_node))
    });
    AdvisoryRank { ranks }
}

fn encode_betweenness(value: &BetweennessCentrality) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_sequence("betweenness.scores", &value.scores, |out, (node, score)| {
        out.write_scalar(node.get());
        out.write_scalar(score.numerator);
        out.write_scalar(score.denominator);
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_advisory_rank(value: &AdvisoryRank) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_sequence("advisory_rank", &value.ranks, |out, (node, score)| {
        out.write_scalar(node.get());
        out.write_scalar(*score);
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_hits(value: &HitsScores) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_bytes(
        "hits.authorities",
        &encode_advisory_rank(&value.authorities)?,
    )?;
    encoder.write_bytes("hits.hubs", &encode_advisory_rank(&value.hubs)?)?;
    Ok(encoder.into_bytes())
}

fn encode_steiner_tree(value: &SteinerTree) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_scalar(value.root.get());
    encoder.write_scalar(value.total_cost);
    encoder.write_sequence("steiner.terminals", &value.terminals, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    encoder.write_sequence("steiner.nodes", &value.nodes, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    encoder.write_sequence("steiner.edges", &value.edges, |out, edge| {
        out.write_scalar(edge.from.get());
        out.write_scalar(edge.to.get());
        out.write_scalar(edge.capacity);
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_set_cover(value: &SetCover) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_scalar(value.total_cost);
    encoder.write_sequence("set_cover.selected", &value.selected, |out, node| {
        out.write_scalar(node.get());
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

fn encode_min_cost_flow(value: MinCostFlow) -> Vec<u8> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_scalar(value.flow);
    encoder.write_scalar(value.total_cost);
    encoder.into_bytes()
}

fn encode_k_shortest_paths(value: &KShortestPaths) -> Result<Vec<u8>, GraphRefusal> {
    let mut encoder = fgit_codec::Encoder::new();
    encoder.write_scalar(value.source.get());
    encoder.write_scalar(value.target.get());
    encoder.write_sequence("k_shortest_paths", &value.paths, |out, path| {
        out.write_scalar(path.cost);
        out.write_sequence("k_shortest_path.nodes", &path.nodes, |inner, node| {
            inner.write_scalar(node.get());
            Ok(())
        })?;
        Ok(())
    })?;
    Ok(encoder.into_bytes())
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
