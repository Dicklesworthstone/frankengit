#![forbid(unsafe_code)]
//! Independent, deterministic checks over the public graph-fabric surface.
//!
//! The campaign uses only `fgit_graph` exports.  Its scalar oracles and
//! prefix-rebuild ledger are deliberately separate from the crate's adjacency
//! and witness implementations, so a stable-but-wrong implementation cannot
//! pass by comparing itself to itself.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::thread;

use fgit_authority::{HeadKey, MemoryAuthorityStore, StoreInstanceId};
use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_graph::{
    ArticulationBridgeReport, BipartiteMatching, BuilderProfileId, CriticalPath,
    DeterministicGraph, ExactGraphGeneration, GenerationAuthority, GenerationAuthorityError,
    GraphAuthorityClass, GraphAuthorityClassRefusal, GraphDecision, GraphEdge, GraphGenerationBody,
    GraphGenerationId, GraphLimits, GraphNodeId, GraphQuery, GraphRefusal, GraphResult,
    GraphSourceStamp, GraphViewId, GraphViewPolicy, MinimumCut, Reachability,
    StronglyConnectedComponents, TopologicalOrder,
};
use fgit_types::{CodecVersion, Digest, RepositoryCommitId, SchemaFamily, SchemaId};

const LIMITS: GraphLimits = GraphLimits {
    nodes: 32,
    edges: 96,
};

const fn node(value: u64) -> GraphNodeId {
    GraphNodeId::new(value)
}

fn digest(label: &[u8]) -> Digest {
    let bytes = internal_digest_value(
        IdentityDomain::MerkleLeaf,
        SchemaId::new(SchemaFamily::from_static("graph-campaign-digest"), 1, 0),
        label,
    );
    Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf), bytes)
}

fn labeled_digest(prefix: &[u8], label: &[u8]) -> Digest {
    let mut value = prefix.to_vec();
    value.extend_from_slice(label);
    digest(&value)
}

fn source() -> GraphSourceStamp {
    let rcr = internal_object_id(
        IdentityDomain::RepositoryCommitRecord,
        SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
        CodecVersion::new(1, 0),
        b"fg031b-graph-campaign-rcr",
    );
    GraphSourceStamp {
        source_rcr_id: RepositoryCommitId::from_internal_object_id(rcr)
            .expect("the registered RCR identity domain is accepted"),
        source_forge_position_root: digest(b"fg031b-forge-position"),
        builder_profile: BuilderProfileId::try_new(b"fg031b-public-oracle")
            .expect("static campaign profile is canonical"),
        parser_model_root: digest(b"fg031b-parser-model"),
    }
}

fn generation_body_with_class(
    label: &[u8],
    authority_class: GraphAuthorityClass,
    predecessor: Option<GraphGenerationId>,
) -> GraphGenerationBody {
    GraphGenerationBody::new(
        GraphViewId::try_new(b"commit-ancestry").expect("static graph view is canonical"),
        SchemaId::new(SchemaFamily::from_static("fg031b-graph-schema"), 1, 0),
        authority_class,
        source(),
        labeled_digest(b"vertices-", label),
        labeled_digest(b"edges-", label),
        labeled_digest(b"index-", label),
        labeled_digest(b"evidence-", label),
        predecessor,
    )
}

fn generation_body(label: &[u8], predecessor: Option<GraphGenerationId>) -> GraphGenerationBody {
    generation_body_with_class(label, GraphAuthorityClass::Exact, predecessor)
}

fn accepts_exact_generation(_: ExactGraphGeneration<'_>) {}

#[test]
fn authority_class_is_canonical_and_exact_call_sites_refuse_non_exact_generations() {
    let exact = generation_body_with_class(b"class", GraphAuthorityClass::Exact, None);
    let deterministic =
        generation_body_with_class(b"class", GraphAuthorityClass::DeterministicDerived, None);
    let statistical = generation_body_with_class(b"class", GraphAuthorityClass::Statistical, None);

    assert_ne!(
        exact.generation_id().expect("exact class has an identity"),
        deterministic
            .generation_id()
            .expect("derived class has an identity")
    );
    assert_ne!(
        exact.generation_id().expect("exact class has an identity"),
        statistical
            .generation_id()
            .expect("statistical class has an identity")
    );
    assert_ne!(
        deterministic
            .generation_id()
            .expect("derived class has an identity"),
        statistical
            .generation_id()
            .expect("statistical class has an identity")
    );

    let exact_proof = exact.require_exact().expect("exact class is accepted");
    assert_eq!(
        exact_proof.body().authority_class(),
        GraphAuthorityClass::Exact
    );
    accepts_exact_generation(exact_proof);
    assert_eq!(
        deterministic.require_exact(),
        Err(GraphAuthorityClassRefusal::ExactRequired {
            observed: GraphAuthorityClass::DeterministicDerived,
        })
    );
    assert_eq!(
        statistical.require_exact(),
        Err(GraphAuthorityClassRefusal::ExactRequired {
            observed: GraphAuthorityClass::Statistical,
        })
    );
}

fn query(generation_id: GraphGenerationId, policy: GraphViewPolicy) -> GraphQuery {
    GraphQuery::new(
        generation_id,
        policy,
        digest(b"fg031b-resource-receipt"),
        100_000,
    )
}

const fn next_seed(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn shuffled<T: Copy>(values: &[T], mut seed: u64) -> Vec<T> {
    let mut result = values.to_vec();
    for index in (1..result.len()).rev() {
        let bound = u64::try_from(index + 1).expect("slice length fits in u64");
        let swap = usize::try_from(next_seed(&mut seed) % bound)
            .expect("bounded pseudo-random index fits usize");
        result.swap(index, swap);
    }
    result
}

fn dag_rows() -> (Vec<GraphNodeId>, Vec<GraphEdge>) {
    (
        vec![node(1), node(2), node(3), node(4), node(5), node(6)],
        vec![
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(1), node(3), 1),
            GraphEdge::new(node(2), node(4), 1),
            GraphEdge::new(node(3), node(4), 1),
            GraphEdge::new(node(3), node(6), 2),
            GraphEdge::new(node(4), node(5), 1),
        ],
    )
}

fn cyclic_rows() -> (Vec<GraphNodeId>, Vec<GraphEdge>) {
    (
        vec![node(1), node(2), node(3), node(4), node(5), node(6)],
        vec![
            GraphEdge::new(node(1), node(2), 1),
            GraphEdge::new(node(1), node(3), 1),
            GraphEdge::new(node(2), node(4), 1),
            GraphEdge::new(node(3), node(4), 1),
            GraphEdge::new(node(3), node(6), 2),
            GraphEdge::new(node(4), node(5), 1),
            GraphEdge::new(node(5), node(4), 1),
        ],
    )
}

fn undirected_rows() -> (Vec<GraphNodeId>, Vec<GraphEdge>) {
    (
        vec![node(1), node(2), node(3), node(4)],
        vec![
            GraphEdge::new(node(1), node(2), 4),
            GraphEdge::new(node(2), node(3), 3),
            GraphEdge::new(node(2), node(4), 1),
        ],
    )
}

#[derive(Debug, Eq, PartialEq)]
struct CampaignObservation {
    reachability: GraphResult<Reachability>,
    dominators: GraphResult<BTreeMap<GraphNodeId, Vec<GraphNodeId>>>,
    topological: GraphResult<TopologicalOrder>,
    critical: GraphResult<CriticalPath>,
    matching: GraphResult<BipartiteMatching>,
    components: GraphResult<StronglyConnectedComponents>,
    articulation: GraphResult<ArticulationBridgeReport>,
    minimum_cut: GraphResult<MinimumCut>,
}

fn campaign_observation(seed: u64) -> CampaignObservation {
    let generation_id = generation_body(b"determinism", None)
        .generation_id()
        .expect("campaign generation identity is registered");
    let query = query(generation_id, GraphViewPolicy::exact_all());

    let (dag_nodes, dag_edges) = dag_rows();
    let dag = DeterministicGraph::from_canonical_parts(
        true,
        &shuffled(&dag_nodes, seed),
        &shuffled(&dag_edges, seed.wrapping_add(1)),
        LIMITS,
    )
    .expect("seeded DAG rows remain admissible");
    let (cyclic_nodes, cyclic_edges) = cyclic_rows();
    let cyclic = DeterministicGraph::from_canonical_parts(
        true,
        &shuffled(&cyclic_nodes, seed.wrapping_add(2)),
        &shuffled(&cyclic_edges, seed.wrapping_add(3)),
        LIMITS,
    )
    .expect("seeded cyclic rows remain admissible");
    let (undirected_nodes, undirected_edges) = undirected_rows();
    let undirected = DeterministicGraph::from_canonical_parts(
        false,
        &shuffled(&undirected_nodes, seed.wrapping_add(4)),
        &shuffled(&undirected_edges, seed.wrapping_add(5)),
        LIMITS,
    )
    .expect("seeded undirected rows remain admissible");

    CampaignObservation {
        reachability: dag
            .reachability(&query, node(1))
            .expect("exact reachability is allowed"),
        dominators: dag
            .dominators(&query, &[node(1)])
            .expect("exact dominators are allowed"),
        topological: dag
            .topological_order(&query)
            .expect("DAG topological order is allowed"),
        critical: dag
            .critical_path(&query)
            .expect("DAG critical path is allowed"),
        matching: dag
            .bipartite_matching(&query, &[node(1), node(2)], &[node(3), node(4)])
            .expect("bipartite matching is allowed"),
        components: cyclic
            .strongly_connected_components(&query)
            .expect("exact SCCs are allowed"),
        articulation: undirected
            .articulation_bridges(&query)
            .expect("undirected articulation analysis is allowed"),
        minimum_cut: undirected
            .minimum_cut(&query)
            .expect("undirected minimum cut is allowed"),
    }
}

fn scalar_reachability(
    nodes: &[GraphNodeId],
    edges: &[GraphEdge],
    start: GraphNodeId,
) -> Vec<GraphNodeId> {
    let mut adjacency: BTreeMap<_, Vec<_>> = nodes
        .iter()
        .copied()
        .map(|candidate| (candidate, Vec::new()))
        .collect();
    for edge in edges {
        adjacency
            .get_mut(&edge.from)
            .expect("scalar corpus has known endpoints")
            .push(edge.to);
    }
    for destinations in adjacency.values_mut() {
        destinations.sort_unstable();
    }
    let mut seen = BTreeSet::from([start]);
    let mut pending = VecDeque::from([start]);
    while let Some(current) = pending.pop_front() {
        for &destination in adjacency
            .get(&current)
            .expect("every discovered node remains known")
        {
            if seen.insert(destination) {
                pending.push_back(destination);
            }
        }
    }
    seen.into_iter().collect()
}

fn scalar_components(nodes: &[GraphNodeId], edges: &[GraphEdge]) -> Vec<Vec<GraphNodeId>> {
    let mut unseen: BTreeSet<_> = nodes.iter().copied().collect();
    let mut components = Vec::new();
    while let Some(start) = unseen.first().copied() {
        let forward = scalar_reachability(nodes, edges, start);
        let component: Vec<_> = nodes
            .iter()
            .copied()
            .filter(|candidate| {
                forward.contains(candidate)
                    && scalar_reachability(nodes, edges, *candidate).contains(&start)
            })
            .collect();
        for member in &component {
            unseen.remove(member);
        }
        components.push(component);
    }
    components
}

fn scalar_topological(nodes: &[GraphNodeId], edges: &[GraphEdge]) -> Vec<GraphNodeId> {
    let mut indegree: BTreeMap<_, u64> = nodes.iter().copied().map(|value| (value, 0)).collect();
    let mut adjacency: BTreeMap<_, BTreeSet<_>> = nodes
        .iter()
        .copied()
        .map(|value| (value, BTreeSet::new()))
        .collect();
    for edge in edges {
        adjacency
            .get_mut(&edge.from)
            .expect("scalar corpus has known endpoints")
            .insert(edge.to);
        let entry = indegree
            .get_mut(&edge.to)
            .expect("scalar corpus has known endpoints");
        *entry += 1;
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(&value, &count)| (count == 0).then_some(value))
        .collect();
    let mut order = Vec::new();
    while let Some(value) = ready.pop_first() {
        order.push(value);
        for destination in adjacency.get(&value).expect("every ready node is known") {
            let count = indegree
                .get_mut(destination)
                .expect("every destination is known");
            *count -= 1;
            if *count == 0 {
                ready.insert(*destination);
            }
        }
    }
    order
}

#[derive(Clone, Copy)]
enum Mutation {
    Node(GraphNodeId),
    Edge(GraphEdge),
}

#[derive(Default)]
struct IncrementalMaterialization {
    nodes: BTreeSet<GraphNodeId>,
    edges: BTreeSet<GraphEdge>,
}

impl IncrementalMaterialization {
    fn apply(&mut self, mutation: Mutation) {
        match mutation {
            Mutation::Node(value) => {
                self.nodes.insert(value);
            }
            Mutation::Edge(value) => {
                self.edges.insert(value);
            }
        }
    }

    fn snapshot(&self) -> DeterministicGraph {
        let nodes: Vec<_> = self.nodes.iter().copied().collect();
        let edges: Vec<_> = self.edges.iter().copied().collect();
        DeterministicGraph::from_canonical_parts(true, &nodes, &edges, LIMITS)
            .expect("incremental ledger keeps canonical rows admissible")
    }
}

fn full_rebuild(history: &[Mutation]) -> DeterministicGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for mutation in history {
        match mutation {
            Mutation::Node(value) if !nodes.contains(value) => nodes.push(*value),
            Mutation::Edge(value) if !edges.contains(value) => edges.push(*value),
            Mutation::Node(_) | Mutation::Edge(_) => {}
        }
    }
    DeterministicGraph::from_canonical_parts(true, &nodes, &edges, LIMITS)
        .expect("full rebuild history keeps canonical rows admissible")
}

#[test]
fn seeded_permutations_and_worker_sweeps_produce_identical_outputs_and_witnesses() {
    const SEEDS: [u64; 5] = [7, 11, 29, 41, 97];
    let expected = campaign_observation(SEEDS[0]);
    for worker_count in [1_usize, 2, 4] {
        let observations = thread::scope(|scope| {
            let handles: Vec<_> = (0..worker_count)
                .map(|worker| {
                    scope.spawn(move || campaign_observation(SEEDS[worker % SEEDS.len()]))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("campaign worker must not panic"))
                .collect::<Vec<_>>()
        });
        for observation in observations {
            assert_eq!(
                observation, expected,
                "worker count {worker_count} changed output"
            );
        }
    }
}

#[test]
fn incremental_prefixes_match_full_rebuild_and_scalar_oracles() {
    let mutations = [
        Mutation::Node(node(1)),
        Mutation::Node(node(2)),
        Mutation::Node(node(3)),
        Mutation::Node(node(4)),
        Mutation::Edge(GraphEdge::new(node(1), node(2), 1)),
        Mutation::Edge(GraphEdge::new(node(1), node(3), 1)),
        Mutation::Edge(GraphEdge::new(node(2), node(4), 1)),
        Mutation::Edge(GraphEdge::new(node(3), node(4), 1)),
    ];
    let generation_id = generation_body(b"mutation-ledger", None)
        .generation_id()
        .expect("campaign generation identity is registered");
    let query = query(generation_id, GraphViewPolicy::exact_all());
    let mut incremental = IncrementalMaterialization::default();
    for (index, mutation) in mutations.iter().copied().enumerate() {
        incremental.apply(mutation);
        let maintained = incremental.snapshot();
        let rebuilt = full_rebuild(&mutations[..=index]);
        assert_eq!(
            maintained,
            rebuilt,
            "incremental materialization diverged at mutation prefix {}",
            index + 1
        );
        if index >= 3 {
            let nodes: Vec<_> = incremental.nodes.iter().copied().collect();
            let edges: Vec<_> = incremental.edges.iter().copied().collect();
            let reachability = maintained
                .reachability(&query, node(1))
                .expect("reachability remains permitted through every prefix");
            assert_eq!(
                reachability.value.nodes,
                scalar_reachability(&nodes, &edges, node(1)),
                "scalar reachability parity failed at prefix {}",
                index + 1
            );
            let topological = maintained
                .topological_order(&query)
                .expect("the mutation corpus remains acyclic");
            assert_eq!(
                topological.value.nodes,
                scalar_topological(&nodes, &edges),
                "scalar topological parity failed at prefix {}",
                index + 1
            );
        }
    }

    let (nodes, edges) = cyclic_rows();
    let cyclic = DeterministicGraph::from_canonical_parts(true, &nodes, &edges, LIMITS)
        .expect("cyclic scalar corpus is admissible");
    assert_eq!(
        cyclic
            .strongly_connected_components(&query)
            .expect("SCC is permitted")
            .value
            .components,
        scalar_components(&nodes, &edges),
        "scalar SCC parity failed"
    );
}

#[test]
fn authority_policy_refusal_and_generation_labels_never_grant_or_hide_staleness() {
    let (nodes, edges) = dag_rows();
    let graph = DeterministicGraph::from_canonical_parts(true, &nodes, &edges, LIMITS)
        .expect("authority-safety corpus is admissible");
    let old_id = generation_body(b"old", None)
        .generation_id()
        .expect("old generation identity is registered");
    let new_id = generation_body(b"new", Some(old_id))
        .generation_id()
        .expect("new generation identity is registered");
    let permitted = graph
        .reachability(
            &query(old_id, GraphViewPolicy::new([GraphDecision::Reachability])),
            node(1),
        )
        .expect("the explicitly permitted decision proceeds");
    assert_eq!(permitted.witness.graph_generation_ids, vec![old_id]);
    assert!(matches!(
        graph.minimum_cut(&query(
            old_id,
            GraphViewPolicy::new([GraphDecision::Reachability]),
        )),
        Err(GraphRefusal::DecisionForbidden {
            decision: GraphDecision::MinimumCut
        })
    ));
    let labeled_new = graph
        .reachability(&query(new_id, GraphViewPolicy::exact_all()), node(1))
        .expect("new generation query is permitted");
    assert_eq!(labeled_new.witness.graph_generation_ids, vec![new_id]);
    assert_ne!(
        permitted.witness.graph_generation_ids, labeled_new.witness.graph_generation_ids,
        "a derived result must label the generation it actually observed"
    );

    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(313));
    let authority = GenerationAuthority::new(
        &store,
        HeadKey::new(b"tenant/repository/graph/commit-ancestry".to_vec())
            .expect("bounded graph head key"),
    );
    let genesis = generation_body(b"genesis", None);
    let first = authority
        .stage_and_activate(&genesis)
        .expect("predecessor-free genesis activates");
    let next = generation_body(b"next", Some(first.generation_id));
    authority
        .stage_and_activate(&next)
        .expect("exact predecessor activates");
    let stale = generation_body(b"stale", Some(first.generation_id));
    assert!(matches!(
        authority.stage_and_activate(&stale),
        Err(GenerationAuthorityError::PredecessorMismatch { .. })
    ));
}
