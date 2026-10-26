#![forbid(unsafe_code)]
//! frankengit-rffg: the frontier merge-base traversal against an independent
//! oracle under every visit order, and its work and refusal boundaries.
//!
//! These are synthetic graph tests, not native Git or end-to-end evidence.
//! The oracle computes ancestor sets by plain depth-first search and applies
//! the definition of a best common ancestor pairwise. It shares no code with
//! the traversal, the scalar loader or the ancestry index, all three of which
//! are compared against it.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fgit_diff::{
    AncestryQueryScratch, AncestryQueryWork, CommitAncestryIndex, CommitGraph, MergeBaseError,
    MergeBaseLimits, MergeBaseResult, ParentSet, frontier_merge_bases_all, merge_bases_all,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Fault {
    Missing(u64),
    Stopped,
}

type Outcome = Result<MergeBaseResult<u64>, MergeBaseError<u64, Fault>>;

#[derive(Default)]
struct Graph {
    parents: BTreeMap<u64, ParentSet<u64>>,
    hints: BTreeMap<u64, i64>,
    reads: Cell<usize>,
}

impl Graph {
    fn link(&mut self, id: u64, parents: &[u64], hint: i64) {
        self.parents
            .insert(id, ParentSet::Complete(parents.to_vec()));
        self.hints.insert(id, hint);
    }
}

impl CommitGraph for Graph {
    type CommitId = u64;
    type Error = Fault;

    fn parents_of(&self, id: &u64) -> Result<ParentSet<u64>, Fault> {
        self.reads.set(self.reads.get() + 1);
        self.parents.get(id).cloned().ok_or(Fault::Missing(*id))
    }

    fn parents_with_order_hint(&self, id: &u64) -> Result<(ParentSet<u64>, i64), Fault> {
        Ok((
            self.parents_of(id)?,
            self.hints.get(id).copied().unwrap_or(0),
        ))
    }
}

const fn generous() -> MergeBaseLimits {
    MergeBaseLimits {
        max_commits: 1_000_000,
        max_edges: 4_000_000,
    }
}

/// The v1 merge-preparation profile (docs/NORMATIVE_PROTOCOL_CONTRACTS.md).
const fn profile() -> MergeBaseLimits {
    MergeBaseLimits {
        max_commits: 4096,
        max_edges: 16_384,
    }
}

fn frontier(
    graph: &Graph,
    left: u64,
    right: u64,
    limits: MergeBaseLimits,
) -> (Outcome, AncestryQueryWork) {
    graph.reads.set(0);
    let mut work = AncestryQueryWork {
        visited_commits: usize::MAX,
        examined_edges: usize::MAX,
    };
    let result = frontier_merge_bases_all(graph, left, right, limits, &mut work, || Ok(()));
    assert_eq!(
        graph.reads.get(),
        work.visited_commits,
        "each commit is read once, and every read is charged"
    );
    (result, work)
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

/// Node `i` may only name parents below `i`; identities are random so that
/// identity order says nothing about ancestry.
struct Dag {
    ids: Vec<u64>,
    parents: Vec<Vec<usize>>,
}

#[derive(Clone, Copy, Debug)]
enum Order {
    /// No hint at all: breadth-first.
    Flat,
    /// Children newer than parents, as honest committer dates are.
    Dated,
    /// Every ancestor looks newer than its descendants.
    Reversed,
    Random,
    /// Honest dates with one commit in eight given an arbitrary clock.
    Skewed,
}

const ORDERS: [Order; 5] = [
    Order::Flat,
    Order::Dated,
    Order::Reversed,
    Order::Random,
    Order::Skewed,
];

impl Dag {
    fn random(generator: &mut Generator, count: usize) -> Self {
        let mut seen = BTreeSet::new();
        let mut ids = Vec::with_capacity(count);
        while ids.len() < count {
            let id = generator.next();
            if seen.insert(id) {
                ids.push(id);
            }
        }
        let parents = (0..count)
            .map(|node| {
                let roll = generator.below(10);
                let wanted = match roll {
                    _ if node == 0 => 0,
                    0 => 0,
                    1..=5 => 1,
                    6..=8 => 2,
                    _ => 3,
                };
                let mut chosen = Vec::new();
                for _ in 0..wanted {
                    // Mostly recent parents, so histories are long and narrow.
                    let reach = 1 + generator.below(node.min(6));
                    let parent = node - reach;
                    if !chosen.contains(&parent) {
                        chosen.push(parent);
                    }
                }
                chosen
            })
            .collect();
        Self { ids, parents }
    }

    fn graph(&self, order: Order, generator: &mut Generator) -> Graph {
        let mut graph = Graph::default();
        for (node, parents) in self.parents.iter().enumerate() {
            let position = i64::try_from(node).unwrap();
            let hint = match order {
                Order::Flat => 0,
                Order::Dated => position,
                Order::Reversed => -position,
                Order::Random => generator.next() as i64,
                Order::Skewed if generator.below(8) == 0 => generator.next() as i64,
                Order::Skewed => position,
            };
            let parent_ids = parents
                .iter()
                .map(|parent| self.ids[*parent])
                .collect::<Vec<_>>();
            graph.link(self.ids[node], &parent_ids, hint);
        }
        graph
    }

    fn ancestor_sets(&self) -> Vec<BTreeSet<usize>> {
        (0..self.parents.len())
            .map(|start| {
                let mut seen = BTreeSet::from([start]);
                let mut stack = vec![start];
                while let Some(node) = stack.pop() {
                    for parent in &self.parents[node] {
                        if seen.insert(*parent) {
                            stack.push(*parent);
                        }
                    }
                }
                seen
            })
            .collect()
    }

    /// Best common ancestors by definition: common, and not a proper ancestor
    /// of another common ancestor.
    fn oracle(
        &self,
        ancestors: &[BTreeSet<usize>],
        left: usize,
        right: usize,
    ) -> MergeBaseResult<u64> {
        let common = ancestors[left]
            .intersection(&ancestors[right])
            .copied()
            .collect::<BTreeSet<_>>();
        let mut bases = common
            .iter()
            .filter(|candidate| {
                !common
                    .iter()
                    .any(|other| other != *candidate && ancestors[*other].contains(candidate))
            })
            .map(|node| self.ids[*node])
            .collect::<Vec<_>>();
        bases.sort_unstable();
        if bases.is_empty() {
            MergeBaseResult::NoCommonAncestor
        } else {
            MergeBaseResult::Bases(bases)
        }
    }
}

#[test]
fn seeded_dags_match_the_oracle_scalar_and_index_under_every_visit_order() {
    let mut generator = Generator(0x9e37_79b9_7f4a_7c15);
    let mut queries = 0_usize;
    let mut multiple = 0_usize;
    let mut unrelated = 0_usize;
    for round in 0..400 {
        let count = 1 + generator.below(48);
        let dag = Dag::random(&mut generator, count);
        let ancestors = dag.ancestor_sets();
        for order in ORDERS {
            let graph = dag.graph(order, &mut generator);
            let index = CommitAncestryIndex::build(&graph, dag.ids.iter().copied(), generous())
                .expect("generated graphs are complete and acyclic");
            let mut scratch = AncestryQueryScratch::default();
            for _ in 0..24 {
                let left = generator.below(count);
                let right = generator.below(count);
                let expected = dag.oracle(&ancestors, left, right);
                match &expected {
                    MergeBaseResult::Bases(bases) if bases.len() > 1 => multiple += 1,
                    MergeBaseResult::NoCommonAncestor => unrelated += 1,
                    MergeBaseResult::Bases(_) => {}
                }
                let (actual, work) = frontier(&graph, dag.ids[left], dag.ids[right], generous());
                assert_eq!(
                    actual.as_ref(),
                    Ok(&expected),
                    "round {round}, {order:?}, {left} / {right}"
                );
                assert!(work.visited_commits <= count);
                assert_eq!(
                    merge_bases_all(&graph, dag.ids[left], dag.ids[right], generous()),
                    Ok(expected.clone())
                );
                assert_eq!(
                    index.merge_bases_all(
                        &dag.ids[left],
                        &dag.ids[right],
                        &mut scratch,
                        generous(),
                        || Ok::<(), Fault>(())
                    ),
                    Ok(expected)
                );
                queries += 1;
            }
        }
    }
    assert_eq!(queries, 400 * ORDERS.len() * 24);
    // The stream must exercise the drain and the empty answer, not only
    // unique bases.
    assert!(multiple > 100, "{multiple} multiple-base queries");
    assert!(unrelated > 100, "{unrelated} unrelated queries");
}

/// main is commits 0..count, each the parent of the next, dated in order.
/// topic (id `count`) is newer and branches from main~`back`.
fn chain_with_topic(count: u64, back: u64) -> Graph {
    let mut graph = Graph::default();
    for id in 0..count {
        let parents = if id == 0 { Vec::new() } else { vec![id - 1] };
        graph.link(id, &parents, 1_700_000_000 + i64::try_from(id).unwrap());
    }
    graph.link(count, &[count - 1 - back], 1_800_000_000);
    graph
}

#[test]
fn one_hundred_thousand_commit_history_reads_only_the_region_above_a_recent_base() {
    const COUNT: u64 = 100_000;
    let graph = chain_with_topic(COUNT, 10);
    let base = COUNT - 11;
    let (result, work) = frontier(&graph, COUNT - 1, COUNT, profile());
    assert_eq!(result, Ok(MergeBaseResult::Bases(vec![base])));
    // main~0..=main~10, the topic and the base's parent: nothing else.
    assert_eq!(work.visited_commits, 13);
    assert_eq!(work.examined_edges, 13);
    // The full-closure index, under the same profile, refuses this history
    // outright. That is the defect this traversal removes.
    assert_eq!(
        CommitAncestryIndex::build(&graph, [COUNT - 1, COUNT], profile()).map(|_| ()),
        Err(MergeBaseError::CommitLimitExceeded { limit: 4096 })
    );
    // The answer does not depend on argument order.
    assert_eq!(
        frontier(&graph, COUNT, COUNT - 1, profile()).0,
        Ok(MergeBaseResult::Bases(vec![base]))
    );
    // The base is the topic's parent; merging main into itself is trivial.
    assert_eq!(
        frontier(&graph, COUNT - 1, COUNT - 1, profile()),
        (
            Ok(MergeBaseResult::Bases(vec![COUNT - 1])),
            AncestryQueryWork {
                visited_commits: 1,
                examined_edges: 1
            }
        )
    );
}

#[test]
fn equal_dates_do_not_make_a_recent_base_walk_the_whole_history() {
    const COUNT: u64 = 100_000;
    let mut graph = chain_with_topic(COUNT, 10);
    graph.hints.clear();
    let expected = MergeBaseResult::Bases(vec![COUNT - 11]);
    for (left, right) in [(COUNT - 1, COUNT), (COUNT, COUNT - 1)] {
        let (result, work) = frontier(&graph, left, right, profile());
        assert_eq!(result.as_ref(), Ok(&expected));
        // The shorter side can run slightly below the eventual base before
        // the other paint arrives. Once common ancestry is known, its cached
        // ancestors must be dominated immediately instead of chasing the old
        // one-sided frontier all the way to genesis.
        assert!(work.visited_commits <= 24, "{work:?}");
        assert_eq!(work.examined_edges, work.visited_commits);
        assert_eq!(frontier(&graph, left, right, profile()), (result, work));
        // Optimization does not waive the read limit: the exact observed
        // allowance succeeds and one fewer still refuses before another read.
        let exact = MergeBaseLimits {
            max_commits: work.visited_commits,
            max_edges: work.examined_edges,
        };
        assert_eq!(
            frontier(&graph, left, right, exact),
            (Ok(expected.clone()), work)
        );
        assert_eq!(
            frontier(
                &graph,
                left,
                right,
                MergeBaseLimits {
                    max_commits: work.visited_commits - 1,
                    ..exact
                }
            )
            .0,
            Err(MergeBaseError::CommitLimitExceeded {
                limit: work.visited_commits - 1
            })
        );
    }
}

#[test]
fn a_base_beyond_the_profile_refuses_typed_beside_a_permitted_twin() {
    const COUNT: u64 = 20_000;
    // 4,000 commits above the base fit the profile.
    let graph = chain_with_topic(COUNT, 4000);
    let (result, work) = frontier(&graph, COUNT - 1, COUNT, profile());
    assert_eq!(result, Ok(MergeBaseResult::Bases(vec![COUNT - 4001])));
    assert_eq!(work.visited_commits, 4003);
    // 5,000 do not, and the refusal names the commit limit it exhausted.
    let graph = chain_with_topic(COUNT, 5000);
    let (result, work) = frontier(&graph, COUNT - 1, COUNT, profile());
    assert_eq!(
        result,
        Err(MergeBaseError::CommitLimitExceeded { limit: 4096 })
    );
    assert_eq!(work.visited_commits, 4096);
    let (result, work) = frontier(
        &graph,
        COUNT - 1,
        COUNT,
        MergeBaseLimits {
            max_commits: 8192,
            max_edges: 32_768,
        },
    );
    assert_eq!(result, Ok(MergeBaseResult::Bases(vec![COUNT - 5001])));
    assert_eq!(work.visited_commits, 5003);
}

#[test]
fn commit_and_edge_limits_are_inclusive_and_report_the_work_spent() {
    let mut generator = Generator(0x5eed_f00d_1234_5678);
    let mut checked = 0;
    while checked < 60 {
        let dag = Dag::random(&mut generator, 40);
        let graph = dag.graph(Order::Dated, &mut generator);
        let (left, right) = (generator.below(40), generator.below(40));
        let (expected, needed) = frontier(&graph, dag.ids[left], dag.ids[right], generous());
        let expected = expected.unwrap();
        if needed.visited_commits < 2 || needed.examined_edges < 2 {
            continue;
        }
        let exact = MergeBaseLimits {
            max_commits: needed.visited_commits,
            max_edges: needed.examined_edges,
        };
        assert_eq!(
            frontier(&graph, dag.ids[left], dag.ids[right], exact),
            (Ok(expected), needed)
        );
        let (result, work) = frontier(
            &graph,
            dag.ids[left],
            dag.ids[right],
            MergeBaseLimits {
                max_commits: needed.visited_commits - 1,
                ..exact
            },
        );
        assert_eq!(
            result,
            Err(MergeBaseError::CommitLimitExceeded {
                limit: needed.visited_commits - 1
            })
        );
        assert_eq!(work.visited_commits, needed.visited_commits - 1);
        let (result, work) = frontier(
            &graph,
            dag.ids[left],
            dag.ids[right],
            MergeBaseLimits {
                max_edges: needed.examined_edges - 1,
                ..exact
            },
        );
        assert_eq!(
            result,
            Err(MergeBaseError::EdgeLimitExceeded {
                limit: needed.examined_edges - 1
            })
        );
        assert!(work.examined_edges <= needed.examined_edges - 1);
        checked += 1;
    }
    // A zero commit limit refuses before any read. A zero edge limit refuses
    // the first commit that has a parent, after charging its read.
    let graph = chain_with_topic(10, 2);
    let zero_commits = MergeBaseLimits {
        max_commits: 0,
        max_edges: 10,
    };
    assert_eq!(
        frontier(&graph, 9, 10, zero_commits),
        (
            Err(MergeBaseError::CommitLimitExceeded { limit: 0 }),
            AncestryQueryWork::default()
        )
    );
    let zero_edges = MergeBaseLimits {
        max_commits: 10,
        max_edges: 0,
    };
    assert_eq!(
        frontier(&graph, 9, 10, zero_edges),
        (
            Err(MergeBaseError::EdgeLimitExceeded { limit: 0 }),
            AncestryQueryWork {
                visited_commits: 1,
                examined_edges: 0
            }
        )
    );
}

#[test]
fn adversarial_dates_cost_work_but_flat_dates_stop_at_the_known_common_frontier() {
    const COUNT: u64 = 2_000;
    let honest = chain_with_topic(COUNT, 10);
    let (expected, cheap) = frontier(&honest, COUNT - 1, COUNT, generous());
    assert_eq!(expected, Ok(MergeBaseResult::Bases(vec![COUNT - 11])));
    let mut reversed = chain_with_topic(COUNT, 10);
    for hint in reversed.hints.values_mut() {
        *hint = -*hint;
    }
    let mut flat = chain_with_topic(COUNT, 10);
    flat.hints.clear();
    for graph in [&honest, &reversed, &flat] {
        assert_eq!(
            merge_bases_all(graph, COUNT - 1, COUNT, generous()),
            expected
        );
        assert_eq!(frontier(graph, COUNT - 1, COUNT, generous()).0, expected);
    }
    let (_, work) = frontier(&reversed, COUNT - 1, COUNT, generous());
    assert!(
        work.visited_commits > 10 * cheap.visited_commits,
        "{work:?} vs {cheap:?}"
    );
    // Misleading dates can still send one side far below the base before the
    // other side reaches it. Exhaustion refuses rather than guessing a base.
    assert_eq!(
        frontier(
            &reversed,
            COUNT - 1,
            COUNT,
            MergeBaseLimits {
                max_commits: 100,
                max_edges: 400
            }
        )
        .0,
        Err(MergeBaseError::CommitLimitExceeded { limit: 100 })
    );
    let (result, flat_work) = frontier(&flat, COUNT - 1, COUNT, profile());
    assert_eq!(result, expected);
    assert!(flat_work.visited_commits <= 2 * cheap.visited_commits);
}

#[test]
fn crisscross_and_octopus_bases_are_exact_above_a_long_shared_history() {
    // root <- 1..=300 chain; a and b both on 300; crisscross merges x = (a, b)
    // and y = (b, a); an octopus o = (x, y, c) with c on 300.
    let mut graph = Graph::default();
    for id in 0..=300_u64 {
        let parents = if id == 0 { Vec::new() } else { vec![id - 1] };
        graph.link(id, &parents, i64::try_from(id).unwrap());
    }
    let (a, b, c, x, y, octopus, lone) = (1001, 1002, 1003, 1004, 1005, 1006, 1007);
    graph.link(a, &[300], 400);
    graph.link(b, &[300], 401);
    graph.link(c, &[300], 402);
    graph.link(x, &[a, b], 500);
    graph.link(y, &[b, a], 501);
    graph.link(octopus, &[x, y, c], 600);
    graph.link(lone, &[], 700);
    let cases: [(u64, u64, Outcome); 7] = [
        (x, y, Ok(MergeBaseResult::Bases(vec![a, b]))),
        (octopus, c, Ok(MergeBaseResult::Bases(vec![c]))),
        (octopus, y, Ok(MergeBaseResult::Bases(vec![y]))),
        (x, c, Ok(MergeBaseResult::Bases(vec![300]))),
        (a, 150, Ok(MergeBaseResult::Bases(vec![150]))),
        (octopus, lone, Ok(MergeBaseResult::NoCommonAncestor)),
        (lone, lone, Ok(MergeBaseResult::Bases(vec![lone]))),
    ];
    for (left, right, expected) in cases {
        assert_eq!(merge_bases_all(&graph, left, right, generous()), expected);
        let (result, _) = frontier(&graph, left, right, generous());
        assert_eq!(result, expected, "{left} / {right}");
        assert_eq!(frontier(&graph, right, left, generous()).0, expected);
    }
    // Two incomparable bases are proved incomparable only by draining their
    // shared history; a profile too small for that refuses instead of
    // returning one of them.
    let (_, drained) = frontier(&graph, x, y, generous());
    assert!(drained.visited_commits > 300, "{drained:?}");
    assert_eq!(
        frontier(
            &graph,
            x,
            y,
            MergeBaseLimits {
                max_commits: 100,
                max_edges: 400
            }
        )
        .0,
        Err(MergeBaseError::CommitLimitExceeded { limit: 100 })
    );
    // A unique base needs no drain at all.
    let (_, unique) = frontier(&graph, octopus, c, generous());
    assert!(unique.visited_commits < 12, "{unique:?}");
}

#[test]
fn defects_the_traversal_reads_refuse_and_the_same_defects_below_it_are_unread() {
    const COUNT: u64 = 60;
    let base = COUNT - 11;
    let expected = Ok(MergeBaseResult::Bases(vec![base]));
    // On main's path above the base, and far below it.
    for (position, read) in [(COUNT - 4, true), (5, false)] {
        let mut shallow = chain_with_topic(COUNT, 10);
        shallow.parents.insert(position, ParentSet::ShallowBoundary);
        let mut duplicate = chain_with_topic(COUNT, 10);
        duplicate.parents.insert(
            position,
            ParentSet::Complete(vec![position - 1, position - 1]),
        );
        let mut missing = chain_with_topic(COUNT, 10);
        missing.parents.remove(&position);
        let cases = [
            (
                shallow,
                MergeBaseError::ShallowBoundary { commit: position },
            ),
            (
                duplicate,
                MergeBaseError::DuplicateParent { commit: position },
            ),
            (missing, MergeBaseError::Source(Fault::Missing(position))),
        ];
        for (graph, refusal) in cases {
            let (result, _) = frontier(&graph, COUNT - 1, COUNT, generous());
            if read {
                assert_eq!(result, Err(refusal));
            } else {
                assert_eq!(result, expected, "{refusal:?} below the frontier is unread");
                // The full loader reads all history and refuses either way.
                assert_eq!(
                    merge_bases_all(&graph, COUNT - 1, COUNT, generous()),
                    Err(refusal)
                );
            }
        }
    }
    // A cycle among expanded commits refuses like the full loaders; content
    // addressing makes it impossible for a verified source.
    let mut cycle = Graph::default();
    cycle.link(1, &[2], 3);
    cycle.link(2, &[1], 2);
    cycle.link(3, &[2], 4);
    cycle.link(4, &[1], 5);
    assert_eq!(
        frontier(&cycle, 3, 4, generous()).0,
        Err(MergeBaseError::Cycle)
    );
    assert_eq!(
        merge_bases_all(&cycle, 3, 4, generous()),
        Err(MergeBaseError::Cycle)
    );
    let mut acyclic = Graph::default();
    acyclic.link(1, &[], 1);
    acyclic.link(2, &[1], 2);
    acyclic.link(3, &[2], 4);
    acyclic.link(4, &[1], 5);
    assert_eq!(
        frontier(&acyclic, 3, 4, generous()).0,
        Ok(MergeBaseResult::Bases(vec![1]))
    );
}

#[test]
fn every_checkpoint_propagates_its_stop_and_a_fresh_query_still_succeeds() {
    let graph = chain_with_topic(40, 6);
    let mut flat = chain_with_topic(120, 20);
    flat.hints.clear();
    // Pick a pair with two bases so the drain's checkpoints are covered too.
    let mut generator = Generator(0x0123_4567_89ab_cdef);
    let (dag, pair) = (0..100)
        .find_map(|_| {
            let dag = Dag::random(&mut generator, 32);
            let ancestors = dag.ancestor_sets();
            let pair = (0..32)
                .flat_map(|left| (0..32).map(move |right| (left, right)))
                .find(|(left, right)| {
                    matches!(dag.oracle(&ancestors, *left, *right), MergeBaseResult::Bases(bases) if bases.len() > 1)
                })?;
            Some((dag, pair))
        })
        .expect("the pinned stream has a multiple-base pair");
    let random = dag.graph(Order::Dated, &mut generator);
    for (graph, left, right) in [
        (&graph, 39, 40),
        (&flat, 119, 120),
        (&random, dag.ids[pair.0], dag.ids[pair.1]),
    ] {
        let calls = Cell::new(0_usize);
        let mut work = AncestryQueryWork::default();
        let good = frontier_merge_bases_all(graph, left, right, generous(), &mut work, || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        let total = calls.get();
        assert!(
            total > work.visited_commits * 2,
            "{total} checkpoints for {work:?}"
        );
        for stop in 1..=total {
            calls.set(0);
            let result =
                frontier_merge_bases_all(graph, left, right, generous(), &mut work, || {
                    calls.set(calls.get() + 1);
                    if calls.get() == stop {
                        Err(Fault::Stopped)
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(
                result,
                Err(MergeBaseError::Source(Fault::Stopped)),
                "stop {stop}"
            );
            assert_eq!(calls.get(), stop, "no work continues after the stop");
        }
        assert_eq!(frontier(graph, left, right, generous()).0, Ok(good));
    }
}
