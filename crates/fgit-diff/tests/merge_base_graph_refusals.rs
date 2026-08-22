#![forbid(unsafe_code)]

//! frankengit-n1zs: the graph-integrity guards of `merge_bases_all`.
//!
//! Merge-base selection decides which commit a three-way merge is computed
//! against, so a graph the walker mis-handles produces a wrong merge rather
//! than a loud failure. AGENTS.md §7 requires resource bounds to be enforced
//! before allocation and work, and §8 requires graph algorithms to hold a
//! closed, deterministic policy.
//!
//! Two guards had no test anywhere in the workspace -- verified per variant
//! across all of `crates/`, counting the crate's own in-src `#[cfg(test)]`
//! module, which does cover `CommitLimitExceeded` and `ShallowBoundary` but
//! neither of these:
//!
//! * `DuplicateParent` (lib.rs:1571) -- a commit naming the same parent twice.
//! * `EdgeLimitExceeded` (lib.rs:1579) -- the traversal's edge budget.
//!
//! # `GraphClosureViolation` is unreachable, and this file deliberately does
//! # not test it
//!
//! That variant is constructed at FIVE sites (lib.rs:1486, :1506, :1510, :1523,
//! :1527), every one of them checking that a `ParentSnapshot` contains a commit
//! it references. `ParentSnapshot` is a PRIVATE type alias, and the only public
//! entry points -- `merge_bases_all` here and `select_merge_bases` in `merge.rs`,
//! which delegates to it -- both build their snapshot with `load_graph`.
//!
//! `load_graph` pushes every parent it reads onto `pending` and drains
//! `pending` to empty, inserting each visited commit into the snapshot, so a
//! snapshot it returns is closed by construction; its early exits all return
//! `Err` rather than a partial map. The five guards are therefore defensive
//! depth against a future constructor, not reachable behaviour, and no honest
//! test can drive them. Recorded as a truthful null, NOT counted as covered.
//!
//! # The permitted twins here are the load-bearing half
//!
//! Both refusals are one edit away from a catastrophic over-strict guard: a
//! `DuplicateParent` check that rejected every multi-parent commit would refuse
//! every merge in existence, and an edge budget applied at `>=` instead of `>`
//! would refuse graphs that exactly fit. Each refusal below is therefore paired
//! with the nearest input that must be ACCEPTED.

use std::collections::BTreeMap;

use fgit_diff::{CommitGraph, MergeBaseError, MergeBaseLimits, ParentSet, merge_bases_all};

/// A parent-only commit graph, matching the shape the crate's own in-src tests
/// use so this file does not invent a second convention.
#[derive(Default)]
struct Graph {
    parents: BTreeMap<&'static str, Vec<&'static str>>,
}

impl Graph {
    fn with_edges(edges: &[(&'static str, &[&'static str])]) -> Self {
        let mut graph = Self::default();
        for (commit, parents) in edges {
            graph.parents.insert(*commit, (*parents).to_vec());
        }
        graph
    }
}

impl CommitGraph for Graph {
    type CommitId = &'static str;
    type Error = ();

    fn parents_of(&self, commit: &&'static str) -> Result<ParentSet<Self::CommitId>, Self::Error> {
        Ok(ParentSet::Complete(
            self.parents.get(commit).cloned().unwrap_or_default(),
        ))
    }
}

/// Generous limits, so no probe about graph SHAPE can be refused for budget.
fn unbounded() -> MergeBaseLimits {
    MergeBaseLimits {
        max_commits: 1_000,
        max_edges: 1_000,
    }
}

/// A commit naming the same parent twice is refused, and the refusal names it.
///
/// A duplicate parent is not a merge; it is a malformed commit record. Left
/// unrefused it would be counted twice in the edge budget and walked twice.
#[test]
fn a_commit_naming_the_same_parent_twice_is_refused() {
    let graph = Graph::with_edges(&[("a", &[]), ("m", &["a", "a"])]);

    assert_eq!(
        merge_bases_all(&graph, "m", "a", unbounded()),
        Err(MergeBaseError::DuplicateParent { commit: "m" }),
        "a commit listing one parent twice is malformed, and the refusal must \
         say which commit",
    );
}

/// The permitted twin: an ordinary merge commit with two DISTINCT parents is
/// accepted.
///
/// This is the half that gives the test above its meaning, and it guards
/// against the worst nearby mistake. The guard is
/// `parents.windows(2).any(|pair| pair[0] == pair[1])` after a sort; weaken it
/// to `parents.len() > 1` and every merge commit in every repository is
/// refused, while the duplicate-parent probe above still passes.
#[test]
fn an_ordinary_merge_commit_with_two_distinct_parents_is_accepted() {
    let graph = Graph::with_edges(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("m", &["b", "c"])]);

    merge_bases_all(&graph, "m", "a", unbounded())
        .expect("a two-parent merge commit is the ordinary case and must be accepted");
}

/// A traversal whose edges exceed the budget is refused, and names the limit.
///
/// The fixture has exactly two edges (`c -> b` and `b -> a`), so a budget of
/// one must refuse. §7 requires the bound to be enforced during the walk rather
/// than after it.
#[test]
fn a_traversal_over_the_edge_budget_is_refused() {
    let graph = Graph::with_edges(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
    let limits = MergeBaseLimits {
        max_commits: 1_000,
        max_edges: 1,
    };

    assert_eq!(
        merge_bases_all(&graph, "c", "a", limits),
        Err(MergeBaseError::EdgeLimitExceeded { limit: 1 }),
    );
}

/// The permitted twin at the exact inclusive boundary: a graph of exactly
/// `max_edges` edges is accepted.
///
/// The guard is `edge_count > limits.max_edges`, so a budget equal to the edge
/// count must pass. A probe showing only that 2 edges exceed a budget of 1 is
/// equally consistent with `>=`, which would refuse every graph that exactly
/// fits its budget -- and that is the reading this test exists to rule out. Two
/// edges against a budget of two is the smallest input that distinguishes them.
#[test]
fn a_traversal_of_exactly_the_edge_budget_is_accepted() {
    let graph = Graph::with_edges(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
    let limits = MergeBaseLimits {
        max_commits: 1_000,
        max_edges: 2,
    };

    merge_bases_all(&graph, "c", "a", limits).expect("two edges must fit a budget of exactly two");
}
