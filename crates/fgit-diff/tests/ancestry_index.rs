#![forbid(unsafe_code)]
//! Exact ancestry-index equivalence and refusal coverage for x2mv.4.36.
//!
//! These are synthetic graph tests, not native Git or end-to-end evidence.
//! The randomized oracle uses Boolean transitive closure and a pairwise
//! definition of best ancestors, independently of the index's generations,
//! traversal scratch, adjacency representation, and reduction algorithm.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fgit_diff::{
    AncestryQueryScratch, CommitAncestryIndex, CommitGraph, MergeBaseError, MergeBaseLimits,
    MergeBaseResult, ParentSet, merge_bases_all,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Fault {
    Missing(u64),
    Stopped,
}

#[derive(Default)]
struct Graph {
    parents: BTreeMap<u64, ParentSet<u64>>,
    reads: Cell<usize>,
}

impl Graph {
    fn from_edges(edges: &[(u64, &[u64])]) -> Self {
        Self {
            parents: edges
                .iter()
                .map(|(id, parents)| (*id, ParentSet::Complete(parents.to_vec())))
                .collect(),
            reads: Cell::new(0),
        }
    }
}

impl CommitGraph for Graph {
    type CommitId = u64;
    type Error = Fault;

    fn parents_of(&self, id: &u64) -> Result<ParentSet<u64>, Fault> {
        self.reads.set(self.reads.get() + 1);
        self.parents.get(id).cloned().ok_or(Fault::Missing(*id))
    }
}

const fn generous() -> MergeBaseLimits {
    MergeBaseLimits {
        max_commits: 200_000,
        max_edges: 1_000_000,
    }
}

// The generator is a pinned test input stream, not a production RNG.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % u64::try_from(limit).expect("small test bound")) as usize
    }
}

/// Floyd-Warshall over bit rows; no generation or candidate traversal is used.
fn transitive_closure(parents: &[Vec<usize>]) -> Vec<u64> {
    assert!(parents.len() <= 64);
    let mut reachable = parents
        .iter()
        .enumerate()
        .map(|(index, row)| {
            row.iter()
                .fold(1_u64 << index, |bits, parent| bits | (1_u64 << parent))
        })
        .collect::<Vec<_>>();
    for through in 0..parents.len() {
        let through_bit = 1_u64 << through;
        let suffix = reachable[through];
        for row in &mut reachable {
            if *row & through_bit != 0 {
                *row |= suffix;
            }
        }
    }
    reachable
}

fn oracle_bases(
    reachable: &[u64],
    identities: &[u64],
    left: usize,
    right: usize,
) -> MergeBaseResult<u64> {
    let common = reachable[left] & reachable[right];
    let mut bases = Vec::new();
    for (candidate, id) in identities.iter().enumerate() {
        if common & (1_u64 << candidate) == 0 {
            continue;
        }
        // The definition itself: no OTHER common ancestor descends from this
        // candidate. This deliberately does not copy parent-edge reduction.
        let dominated = reachable.iter().enumerate().any(|(other, ancestors)| {
            other != candidate
                && common & (1_u64 << other) != 0
                && ancestors & (1_u64 << candidate) != 0
        });
        if !dominated {
            bases.push(*id);
        }
    }
    bases.sort_unstable();
    if bases.is_empty() {
        MergeBaseResult::NoCommonAncestor
    } else {
        MergeBaseResult::Bases(bases)
    }
}

#[test]
fn one_hundred_thousand_seeded_query_pairs_match_independent_and_scalar_oracles() {
    const GRAPHS: usize = 1_000;
    const PAIRS_PER_GRAPH: usize = 100;
    const SEED: u64 = 0x7862_6d76_3436_0001;
    let mut random = Generator(SEED);
    let mut total_pairs = 0;
    let mut scratch = AncestryQueryScratch::default();

    for graph_number in 0..GRAPHS {
        let count = 8 + random.below(57);
        let mut identities = (0..count)
            .map(|index| u64::try_from(index).unwrap() * 17 + 11)
            .collect::<Vec<_>>();
        for index in (1..count).rev() {
            let other = random.below(index + 1);
            identities.swap(index, other);
        }
        let mut rows = Vec::with_capacity(count);
        let mut expected_generations: Vec<usize> = Vec::with_capacity(count);
        let mut graph = Graph::default();
        for index in 0..count {
            let mut parents = BTreeSet::new();
            if index != 0 && random.below(5) != 0 {
                let wanted = 1 + random.below(index.min(4));
                while parents.len() < wanted {
                    parents.insert(random.below(index));
                }
            }
            let parents = parents.into_iter().collect::<Vec<_>>();
            expected_generations.push(
                1 + parents
                    .iter()
                    .map(|parent| expected_generations[*parent])
                    .max()
                    .unwrap_or(0),
            );
            let mut external = parents
                .iter()
                .map(|parent| identities[*parent])
                .collect::<Vec<_>>();
            if random.below(2) == 0 {
                external.reverse();
            }
            graph
                .parents
                .insert(identities[index], ParentSet::Complete(external));
            rows.push(parents);
        }
        let expected_edges = rows.iter().map(Vec::len).sum::<usize>();
        let mut starts = identities.clone();
        starts.reverse();
        // Repeated starting tips are ordinary closure discovery, not repeated
        // parent edges, and must neither inflate budgets nor duplicate reads.
        starts.extend_from_slice(&identities[..2]);
        let index = CommitAncestryIndex::build(&graph, starts, generous()).unwrap();
        assert_eq!(index.commit_count(), count);
        assert_eq!(index.edge_count(), expected_edges);
        assert_eq!(graph.reads.get(), count);
        for (ordinal, id) in identities.iter().enumerate() {
            assert_eq!(
                index.generation(id),
                Some(expected_generations[ordinal]),
                "seed={SEED:x} graph={graph_number} commit={id}"
            );
        }
        let reachable = transitive_closure(&rows);
        for pair in 0..PAIRS_PER_GRAPH {
            let left = random.below(count);
            let right = if pair == 0 { left } else { random.below(count) };
            let expected_ancestor = reachable[right] & (1_u64 << left) != 0;
            let expected_bases = oracle_bases(&reachable, &identities, left, right);
            let reads_before = graph.reads.get();
            let actual_ancestor = index
                .is_ancestor(
                    &identities[left],
                    &identities[right],
                    &mut scratch,
                    generous(),
                    || Ok::<(), Fault>(()),
                )
                .unwrap();
            let actual_bases = index
                .merge_bases_all(
                    &identities[left],
                    &identities[right],
                    &mut scratch,
                    generous(),
                    || Ok::<(), Fault>(()),
                )
                .unwrap();
            assert_eq!(
                graph.reads.get(),
                reads_before,
                "queries must reuse the immutable index, not re-read source"
            );
            assert_eq!(
                actual_ancestor, expected_ancestor,
                "seed={SEED:x} graph={graph_number} pair={pair} ({left},{right})"
            );
            assert_eq!(
                actual_bases, expected_bases,
                "seed={SEED:x} graph={graph_number} pair={pair} ({left},{right})"
            );
            assert_eq!(
                merge_bases_all(&graph, identities[left], identities[right], generous(),).unwrap(),
                expected_bases,
                "scalar mismatch seed={SEED:x} graph={graph_number} pair={pair}"
            );
            total_pairs += 1;
        }
    }
    assert_eq!(total_pairs, 100_000);
}

#[test]
fn crisscross_octopus_and_redundant_ancestor_edges_keep_all_sorted_best_bases() {
    let graph = Graph::from_edges(&[
        (90, &[]),
        (80, &[90]),
        (20, &[90]),
        (60, &[90]),
        (5, &[80, 20, 60, 90]),
        (7, &[60, 20, 80]),
        (100, &[5, 7]),
        (101, &[7, 5]),
        (1, &[]),
    ]);
    let index = CommitAncestryIndex::build(&graph, [101, 100, 1], generous()).unwrap();
    let mut scratch = AncestryQueryScratch::default();
    for (left, right, expected) in [
        (5, 7, MergeBaseResult::Bases(vec![20, 60, 80])),
        (100, 101, MergeBaseResult::Bases(vec![5, 7])),
        (90, 101, MergeBaseResult::Bases(vec![90])),
        (100, 100, MergeBaseResult::Bases(vec![100])),
        (1, 101, MergeBaseResult::NoCommonAncestor),
    ] {
        for (left, right) in [(left, right), (right, left)] {
            assert_eq!(
                index
                    .merge_bases_all(&left, &right, &mut scratch, generous(), || Ok::<(), Fault>(
                        ()
                    ))
                    .unwrap(),
                expected,
            );
            assert_eq!(
                merge_bases_all(&graph, left, right, generous()).unwrap(),
                expected
            );
        }
    }
    assert_eq!(index.generation(&90), Some(1));
    assert_eq!(index.generation(&5), Some(3));
    assert_eq!(index.generation(&101), Some(4));
    assert_eq!(index.generation(&999), None);
}

#[test]
fn loading_preserves_duplicate_parent_shallow_cycle_and_source_error_refusals() {
    let duplicate = Graph::from_edges(&[(0, &[]), (1, &[0, 0])]);
    assert!(matches!(
        CommitAncestryIndex::build(&duplicate, [1], generous()),
        Err(MergeBaseError::DuplicateParent { commit: 1 })
    ));
    let permitted = Graph::from_edges(&[(0, &[]), (1, &[]), (2, &[0, 1])]);
    assert!(CommitAncestryIndex::build(&permitted, [2, 2], generous()).is_ok());

    let mut shallow = Graph::from_edges(&[(0, &[]), (1, &[0])]);
    shallow.parents.insert(0, ParentSet::ShallowBoundary);
    assert!(matches!(
        CommitAncestryIndex::build(&shallow, [1], generous()),
        Err(MergeBaseError::ShallowBoundary { commit: 0 })
    ));
    shallow.parents.insert(0, ParentSet::Complete(Vec::new()));
    assert!(CommitAncestryIndex::build(&shallow, [1], generous()).is_ok());

    for cyclic in [
        Graph::from_edges(&[(0, &[0])]),
        Graph::from_edges(&[(0, &[1]), (1, &[0])]),
        Graph::from_edges(&[(0, &[]), (1, &[2]), (2, &[3]), (3, &[1])]),
    ] {
        assert!(matches!(
            CommitAncestryIndex::build(&cyclic, cyclic.parents.keys().copied(), generous(),),
            Err(MergeBaseError::Cycle)
        ));
    }
    let acyclic = Graph::from_edges(&[(0, &[]), (1, &[2]), (2, &[3]), (3, &[0])]);
    assert!(CommitAncestryIndex::build(&acyclic, [1], generous()).is_ok());
    let missing = Graph::from_edges(&[(1, &[0])]);
    assert!(matches!(
        CommitAncestryIndex::build(&missing, [1], generous()),
        Err(MergeBaseError::Source(Fault::Missing(0)))
    ));
    let complete = Graph::from_edges(&[(1, &[0]), (0, &[])]);
    assert!(CommitAncestryIndex::build(&complete, [1], generous()).is_ok());
}

#[test]
fn build_limits_include_exact_boundary_and_count_shared_ancestors_only_once() {
    let graph = Graph::from_edges(&[(0, &[]), (1, &[0]), (2, &[0]), (3, &[2, 1])]);
    let exact = MergeBaseLimits {
        max_commits: 4,
        max_edges: 4,
    };
    let index = CommitAncestryIndex::build(&graph, [3, 2, 3], exact).unwrap();
    assert_eq!(index.commit_count(), 4);
    assert_eq!(index.edge_count(), 4);
    assert!(matches!(
        CommitAncestryIndex::build(
            &graph,
            [3],
            MergeBaseLimits {
                max_commits: 3,
                ..exact
            },
        ),
        Err(MergeBaseError::CommitLimitExceeded { limit: 3 })
    ));
    assert!(matches!(
        CommitAncestryIndex::build(
            &graph,
            [3],
            MergeBaseLimits {
                max_edges: 3,
                ..exact
            },
        ),
        Err(MergeBaseError::EdgeLimitExceeded { limit: 3 })
    ));
    let empty = CommitAncestryIndex::build(
        &graph,
        [],
        MergeBaseLimits {
            max_commits: 0,
            max_edges: 0,
        },
    )
    .unwrap();
    assert_eq!(empty.commit_count(), 0);
    assert_eq!(empty.edge_count(), 0);
}

fn query_fixture() -> (Graph, CommitAncestryIndex<u64>) {
    let graph = Graph::from_edges(&[
        (0, &[]),
        (1, &[0]),
        (2, &[0]),
        (3, &[1, 2]),
        (4, &[2, 1]),
        (5, &[3]),
        (6, &[4]),
    ]);
    let index = CommitAncestryIndex::build(&graph, [5, 6], generous()).unwrap();
    (graph, index)
}

#[test]
fn start_iteration_is_cancellable_and_unique_starts_are_bounded_before_source_reads() {
    let graph = Graph::from_edges(&[(0, &[])]);
    let tiny = MergeBaseLimits {
        max_commits: 3,
        max_edges: 0,
    };
    let consumed = Cell::new(0);
    let unique_starts = (0_u64..).inspect(|_| {
        consumed.set(consumed.get() + 1);
        assert!(
            consumed.get() <= 4,
            "start iteration exceeded its finite limit"
        );
    });
    assert!(matches!(
        CommitAncestryIndex::build(&graph, unique_starts, tiny),
        Err(MergeBaseError::CommitLimitExceeded { limit: 3 })
    ));
    assert_eq!(consumed.get(), 4);
    assert_eq!(graph.reads.get(), 0);

    consumed.set(0);
    let repeated_starts = std::iter::repeat(0).inspect(|_| {
        consumed.set(consumed.get() + 1);
        assert!(consumed.get() <= 8, "repeated starts ignored cancellation");
    });
    let mut checkpoints = 0;
    assert!(matches!(
        CommitAncestryIndex::build_with_checkpoints(&graph, repeated_starts, tiny, || {
            checkpoints += 1;
            if checkpoints == 8 {
                Err(Fault::Stopped)
            } else {
                Ok(())
            }
        }),
        Err(MergeBaseError::Source(Fault::Stopped))
    ));
    assert!((1..=8).contains(&consumed.get()));
    assert_eq!(graph.reads.get(), 0);

    let exact = MergeBaseLimits {
        max_commits: 1,
        max_edges: 0,
    };
    let permitted = CommitAncestryIndex::build(&graph, std::iter::repeat_n(0, 32), exact).unwrap();
    assert_eq!(permitted.commit_count(), 1);
    assert_eq!(graph.reads.get(), 1);
}

#[test]
fn query_limits_charge_only_the_requested_closure_and_zero_visits_refuse() {
    let (_, index) = query_fixture();
    let mut scratch = AncestryQueryScratch::default();
    let pair = MergeBaseLimits {
        max_commits: 2,
        max_edges: 1,
    };
    assert!(
        index
            .is_ancestor(&0, &1, &mut scratch, pair, || Ok::<(), Fault>(()))
            .unwrap()
    );
    assert_eq!(
        index
            .merge_bases_all(&0, &1, &mut scratch, pair, || Ok::<(), Fault>(()))
            .unwrap(),
        MergeBaseResult::Bases(vec![0])
    );
    assert_eq!(scratch.work().visited_commits, 2);
    assert_eq!(scratch.work().examined_edges, 1);

    let single = MergeBaseLimits {
        max_commits: 1,
        max_edges: 0,
    };
    assert!(
        index
            .is_ancestor(&5, &5, &mut scratch, single, || Ok::<(), Fault>(()))
            .unwrap()
    );
    assert_eq!(
        index
            .merge_bases_all(&5, &5, &mut scratch, single, || Ok::<(), Fault>(()))
            .unwrap(),
        MergeBaseResult::Bases(vec![5])
    );
    assert_eq!(scratch.work().visited_commits, 1);
    assert_eq!(scratch.work().examined_edges, 0);

    let empty = MergeBaseLimits {
        max_commits: 0,
        max_edges: 0,
    };
    for (left, right) in [(5, 5), (5, 0)] {
        assert_eq!(
            index.is_ancestor(&left, &right, &mut scratch, empty, || Ok::<(), Fault>(())),
            Err(MergeBaseError::CommitLimitExceeded { limit: 0 })
        );
        assert_eq!(scratch.work().visited_commits, 0);
        assert_eq!(scratch.work().examined_edges, 0);
        assert_eq!(
            index.merge_bases_all(&left, &right, &mut scratch, empty, || Ok::<(), Fault>(())),
            Err(MergeBaseError::CommitLimitExceeded { limit: 0 })
        );
        assert_eq!(scratch.work().visited_commits, 0);
        assert_eq!(scratch.work().examined_edges, 0);
    }
    assert!(
        index
            .is_ancestor(&0, &1, &mut scratch, pair, || Ok::<(), Fault>(()))
            .unwrap()
    );
}

#[test]
fn query_limits_are_inclusive_and_exhaustion_leaves_scratch_reusable() {
    let (_, index) = query_fixture();
    let mut scratch = AncestryQueryScratch::default();
    let expected = index
        .merge_bases_all(&5, &6, &mut scratch, generous(), || Ok::<(), Fault>(()))
        .unwrap();
    let work = scratch.work();
    assert!(work.visited_commits > 1);
    assert!(work.examined_edges > 1);
    let exact = MergeBaseLimits {
        max_commits: work.visited_commits,
        max_edges: work.examined_edges,
    };
    assert_eq!(
        index
            .merge_bases_all(&5, &6, &mut scratch, exact, || Ok::<(), Fault>(()))
            .unwrap(),
        expected
    );
    assert!(matches!(
        index.merge_bases_all(
            &5,
            &6,
            &mut scratch,
            MergeBaseLimits {
                max_commits: exact.max_commits - 1,
                ..exact
            },
            || Ok::<(), Fault>(()),
        ),
        Err(MergeBaseError::CommitLimitExceeded { .. })
    ));
    assert!(matches!(
        index.merge_bases_all(
            &5,
            &6,
            &mut scratch,
            MergeBaseLimits {
                max_edges: exact.max_edges - 1,
                ..exact
            },
            || Ok::<(), Fault>(()),
        ),
        Err(MergeBaseError::EdgeLimitExceeded { .. })
    ));
    assert_eq!(
        index
            .merge_bases_all(&5, &6, &mut scratch, exact, || Ok::<(), Fault>(()))
            .unwrap(),
        expected
    );

    assert!(
        index
            .is_ancestor(&0, &5, &mut scratch, generous(), || Ok::<(), Fault>(()))
            .unwrap()
    );
    let work = scratch.work();
    let exact = MergeBaseLimits {
        max_commits: work.visited_commits,
        max_edges: work.examined_edges,
    };
    assert!(exact.max_commits > 0 && exact.max_edges > 0);
    assert!(
        index
            .is_ancestor(&0, &5, &mut scratch, exact, || Ok::<(), Fault>(()))
            .unwrap()
    );
    assert!(matches!(
        index.is_ancestor(
            &0,
            &5,
            &mut scratch,
            MergeBaseLimits {
                max_edges: exact.max_edges - 1,
                ..exact
            },
            || Ok::<(), Fault>(()),
        ),
        Err(MergeBaseError::EdgeLimitExceeded { .. })
    ));
    assert!(
        index
            .is_ancestor(&0, &5, &mut scratch, exact, || Ok::<(), Fault>(()))
            .unwrap()
    );
}

#[test]
fn unknown_query_tips_never_become_false_ancestry_or_identity_success() {
    let (_, index) = query_fixture();
    let mut scratch = AncestryQueryScratch::default();
    for (left, right) in [(999, 5), (5, 999), (999, 999)] {
        assert_eq!(
            index.is_ancestor(&left, &right, &mut scratch, generous(), || Ok::<(), Fault>(
                ()
            )),
            Err(MergeBaseError::GraphClosureViolation)
        );
        assert_eq!(
            index.merge_bases_all(&left, &right, &mut scratch, generous(), || Ok::<(), Fault>(
                ()
            )),
            Err(MergeBaseError::GraphClosureViolation)
        );
    }
    assert!(
        index
            .is_ancestor(&5, &5, &mut scratch, generous(), || Ok::<(), Fault>(()))
            .unwrap()
    );
}

#[test]
fn every_build_and_query_checkpoint_can_cancel_without_poisoning_reuse() {
    let (graph, index) = query_fixture();
    let mut build_checkpoints = 0;
    CommitAncestryIndex::build_with_checkpoints(&graph, [5, 6], generous(), || {
        build_checkpoints += 1;
        Ok::<(), Fault>(())
    })
    .unwrap();
    assert!(build_checkpoints > 0);
    for stop in 1..=build_checkpoints {
        let mut visited = 0;
        assert!(matches!(
            CommitAncestryIndex::build_with_checkpoints(&graph, [5, 6], generous(), || {
                visited += 1;
                if visited == stop {
                    Err(Fault::Stopped)
                } else {
                    Ok::<(), Fault>(())
                }
            }),
            Err(MergeBaseError::Source(Fault::Stopped))
        ));
    }
    let mut scratch = AncestryQueryScratch::default();
    let mut query_checkpoints = 0;
    let expected = index
        .merge_bases_all(&5, &6, &mut scratch, generous(), || {
            query_checkpoints += 1;
            Ok::<(), Fault>(())
        })
        .unwrap();
    assert!(query_checkpoints > 0);
    for stop in 1..=query_checkpoints {
        let mut visited = 0;
        assert_eq!(
            index.merge_bases_all(&5, &6, &mut scratch, generous(), || {
                visited += 1;
                if visited == stop {
                    Err(Fault::Stopped)
                } else {
                    Ok::<(), Fault>(())
                }
            }),
            Err(MergeBaseError::Source(Fault::Stopped)),
            "merge-base checkpoint {stop}",
        );
        assert_eq!(
            index
                .merge_bases_all(&5, &6, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap(),
            expected
        );
    }
    let mut query_checkpoints = 0;
    assert!(
        index
            .is_ancestor(&0, &5, &mut scratch, generous(), || {
                query_checkpoints += 1;
                Ok::<(), Fault>(())
            })
            .unwrap()
    );
    assert!(query_checkpoints > 0);
    for stop in 1..=query_checkpoints {
        let mut visited = 0;
        assert_eq!(
            index.is_ancestor(&0, &5, &mut scratch, generous(), || {
                visited += 1;
                if visited == stop {
                    Err(Fault::Stopped)
                } else {
                    Ok::<(), Fault>(())
                }
            }),
            Err(MergeBaseError::Source(Fault::Stopped)),
            "ancestry checkpoint {stop}",
        );
        assert!(
            index
                .is_ancestor(&0, &5, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap()
        );
    }
    // Cancellation must be consulted even when generations/equality could
    // answer without traversing any parent.
    for (left, right) in [(5, 5), (5, 0)] {
        assert_eq!(
            index.is_ancestor(&left, &right, &mut scratch, generous(), || Err(
                Fault::Stopped
            )),
            Err(MergeBaseError::Source(Fault::Stopped))
        );
        assert_eq!(
            index.merge_bases_all(&left, &right, &mut scratch, generous(), || Err(
                Fault::Stopped
            )),
            Err(MergeBaseError::Source(Fault::Stopped))
        );
    }
}

#[test]
fn scratch_reuse_across_distinct_same_size_indexes_never_reuses_graph_answers() {
    let connected = Graph::from_edges(&[(0, &[]), (1, &[0]), (2, &[1])]);
    let disconnected = Graph::from_edges(&[(0, &[]), (1, &[]), (2, &[1])]);
    let first = CommitAncestryIndex::build(&connected, [0, 1, 2], generous()).unwrap();
    let second = CommitAncestryIndex::build(&disconnected, [0, 1, 2], generous()).unwrap();
    let mut scratch = AncestryQueryScratch::default();
    for _ in 0..8 {
        assert!(
            first
                .is_ancestor(&0, &2, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap()
        );
        assert!(
            !second
                .is_ancestor(&0, &2, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap()
        );
        assert_eq!(
            first
                .merge_bases_all(&0, &2, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap(),
            MergeBaseResult::Bases(vec![0])
        );
        assert_eq!(
            second
                .merge_bases_all(&0, &2, &mut scratch, generous(), || Ok::<(), Fault>(()))
                .unwrap(),
            MergeBaseResult::NoCommonAncestor
        );
    }
}

#[test]
fn one_hundred_thousand_commit_chain_is_nonrecursive_and_generations_prune() {
    const COUNT: u64 = 100_000;
    let graph = Graph {
        parents: (0..COUNT)
            .map(|id| {
                (
                    id,
                    ParentSet::Complete(if id == 0 { Vec::new() } else { vec![id - 1] }),
                )
            })
            .collect(),
        reads: Cell::new(0),
    };
    let index = CommitAncestryIndex::build(&graph, [COUNT - 1], generous()).unwrap();
    assert_eq!(index.commit_count(), COUNT as usize);
    assert_eq!(index.edge_count(), COUNT as usize - 1);
    assert_eq!(index.generation(&0), Some(1));
    assert_eq!(index.generation(&(COUNT - 1)), Some(COUNT as usize));
    let reads = graph.reads.get();
    let mut scratch = AncestryQueryScratch::default();
    assert!(
        index
            .is_ancestor(
                &0,
                &(COUNT - 1),
                &mut scratch,
                generous(),
                || Ok::<(), Fault>(())
            )
            .unwrap()
    );
    assert!(
        !index
            .is_ancestor(
                &(COUNT - 1),
                &0,
                &mut scratch,
                MergeBaseLimits {
                    max_commits: 2,
                    max_edges: 0
                },
                || Ok::<(), Fault>(()),
            )
            .unwrap()
    );
    assert_eq!(scratch.work().examined_edges, 0);
    assert_eq!(
        index
            .merge_bases_all(
                &(COUNT - 1),
                &(COUNT / 2),
                &mut scratch,
                generous(),
                || Ok::<(), Fault>(())
            )
            .unwrap(),
        MergeBaseResult::Bases(vec![COUNT / 2])
    );
    assert_eq!(
        graph.reads.get(),
        reads,
        "index query must not reopen commit objects"
    );
}
