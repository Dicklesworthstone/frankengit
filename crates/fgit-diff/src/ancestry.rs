//! Immutable, exact ancestry derived from a complete commit-parent snapshot.
//!
//! Generations are computed here, never accepted from a cache or a timestamp.
//! The caller must obtain parents from its verified, authority-selected source.
//! An index proves properties of that snapshot; it does not prove that objects
//! remain available, authorize a ref update, or substitute for source selection
//! and admission on a later request.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::{
    CommitGraph, MergeBaseError, MergeBaseLimits, MergeBaseQueryResult, MergeBaseResult,
    load_graph_with_checkpoints,
};

const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const COMMON: u8 = LEFT | RIGHT;
const DOMINATED: u8 = 4;

/// A complete, cycle-checked ancestor closure with dense parent adjacency.
///
/// Commit identities are stored in their canonical `Ord` order. Roots have
/// generation one; every other generation is one plus the maximum parent
/// generation. An edge therefore always moves to a strictly lower generation.
/// Construction and queries are iterative even for very deep histories.
///
/// Keep the index with the exact source snapshot from which it was built. In
/// particular, reusing it across requests requires the caller to establish
/// source identity, availability, and admission independently. This type has
/// no persistent cache format and grants no publication capability.
#[derive(Clone, Debug)]
pub struct CommitAncestryIndex<C> {
    identities: Vec<C>,
    offsets: Vec<usize>,
    parents: Vec<usize>,
    generations: Vec<usize>,
}

/// Work actually consumed by the most recent query, including a refused query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AncestryQueryWork {
    /// Distinct commits discovered by the query, bounded by `max_commits`.
    pub visited_commits: usize,
    /// Parent edges examined by the query, bounded by `max_edges`.
    pub examined_edges: usize,
}

/// Reusable, caller-owned traversal memory; it never stores an authoritative
/// result or reads objects. It is safe to reuse with another index.
///
/// Dense marks need space proportional to the largest index queried with this
/// scratch. Epochs avoid clearing that whole allocation between queries. The
/// stack and frontier grow only with discovered commits. Query limits bound
/// visits and edge examinations, independently of the index's build limits.
#[derive(Debug, Default)]
pub struct AncestryQueryScratch {
    epochs: Vec<u64>,
    flags: Vec<u8>,
    epoch: u64,
    stack: Vec<usize>,
    frontier: BinaryHeap<(usize, Reverse<usize>)>,
    work: AncestryQueryWork,
}

impl AncestryQueryScratch {
    /// Counters reset at the start of every query, including immediate answers.
    #[must_use]
    pub const fn work(&self) -> AncestryQueryWork {
        self.work
    }

    fn reset(&mut self) {
        self.stack.clear();
        self.frontier.clear();
        self.work = AncestryQueryWork::default();
    }

    fn prepare(&mut self, count: usize) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.epochs.fill(0);
            self.epoch = 1;
        }
        if self.epochs.len() < count {
            self.epochs.resize(count, 0);
            self.flags.resize(count, 0);
        }
    }

    fn discover<C, E>(
        &mut self,
        ordinal: usize,
        limits: MergeBaseLimits,
    ) -> Result<bool, MergeBaseError<C, E>> {
        if self.epochs[ordinal] == self.epoch {
            return Ok(false);
        }
        if self.work.visited_commits >= limits.max_commits {
            return Err(MergeBaseError::CommitLimitExceeded {
                limit: limits.max_commits,
            });
        }
        self.work.visited_commits += 1;
        self.epochs[ordinal] = self.epoch;
        self.flags[ordinal] = 0;
        Ok(true)
    }

    fn examine_edge<C, E>(&mut self, limits: MergeBaseLimits) -> Result<(), MergeBaseError<C, E>> {
        if self.work.examined_edges >= limits.max_edges {
            return Err(MergeBaseError::EdgeLimitExceeded {
                limit: limits.max_edges,
            });
        }
        self.work.examined_edges += 1;
        Ok(())
    }
}

impl<C: Clone + Ord> CommitAncestryIndex<C> {
    /// Read and validate the complete ancestor closure of `starts` once.
    /// Duplicate starts are harmless; duplicate parent edges are refused.
    pub fn build<G>(
        graph: &G,
        starts: impl IntoIterator<Item = C>,
        limits: MergeBaseLimits,
    ) -> Result<Self, MergeBaseError<C, G::Error>>
    where
        G: CommitGraph<CommitId = C>,
    {
        Self::build_with_checkpoints(graph, starts, limits, || Ok(()))
    }

    /// Build with caller checkpoints during source discovery, adjacency
    /// construction, cycle detection, and generation computation. A checkpoint
    /// error is preserved as `Source`; no partial index is returned.
    pub fn build_with_checkpoints<G, F>(
        graph: &G,
        starts: impl IntoIterator<Item = C>,
        limits: MergeBaseLimits,
        mut checkpoint: F,
    ) -> Result<Self, MergeBaseError<C, G::Error>>
    where
        G: CommitGraph<CommitId = C>,
        F: FnMut() -> Result<(), G::Error>,
    {
        let snapshot = load_graph_with_checkpoints(graph, starts, limits, &mut checkpoint)?;
        let identities = snapshot.keys().cloned().collect::<Vec<_>>();
        let count = identities.len();
        let mut offsets = Vec::with_capacity(count.saturating_add(1));
        let mut parents = Vec::new();
        let mut children_remaining = vec![0_usize; count];
        offsets.push(0);
        for row in snapshot.values() {
            checkpoint().map_err(MergeBaseError::Source)?;
            for parent in row {
                checkpoint().map_err(MergeBaseError::Source)?;
                let ordinal = identities
                    .binary_search(parent)
                    .map_err(|_| MergeBaseError::GraphClosureViolation)?;
                children_remaining[ordinal] = children_remaining[ordinal]
                    .checked_add(1)
                    .ok_or(MergeBaseError::GraphClosureViolation)?;
                parents.push(ordinal);
            }
            offsets.push(parents.len());
        }
        drop(snapshot);
        checkpoint().map_err(MergeBaseError::Source)?;

        // Kahn's algorithm in descendant-first order. Dense identity order
        // breaks ties, independently of parent input order or hash-map seeds.
        let mut ready = BinaryHeap::new();
        for (ordinal, remaining) in children_remaining.iter().enumerate() {
            checkpoint().map_err(MergeBaseError::Source)?;
            if *remaining == 0 {
                ready.push(Reverse(ordinal));
            }
        }
        let mut order = Vec::with_capacity(count);
        while let Some(Reverse(ordinal)) = ready.pop() {
            checkpoint().map_err(MergeBaseError::Source)?;
            order.push(ordinal);
            for &parent in &parents[offsets[ordinal]..offsets[ordinal + 1]] {
                checkpoint().map_err(MergeBaseError::Source)?;
                children_remaining[parent] -= 1;
                if children_remaining[parent] == 0 {
                    ready.push(Reverse(parent));
                }
            }
        }
        if order.len() != count {
            return Err(MergeBaseError::Cycle);
        }
        let mut generations = vec![0_usize; count];
        for ordinal in order.into_iter().rev() {
            checkpoint().map_err(MergeBaseError::Source)?;
            let mut generation = 1;
            for &parent in &parents[offsets[ordinal]..offsets[ordinal + 1]] {
                checkpoint().map_err(MergeBaseError::Source)?;
                let after_parent = generations[parent]
                    .checked_add(1)
                    .ok_or(MergeBaseError::GraphClosureViolation)?;
                generation = generation.max(after_parent);
            }
            generations[ordinal] = generation;
        }
        checkpoint().map_err(MergeBaseError::Source)?;
        Ok(Self {
            identities,
            offsets,
            parents,
            generations,
        })
    }

    #[must_use]
    pub fn commit_count(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.parents.len()
    }

    /// The exact topological generation, or `None` outside this closure.
    #[must_use]
    pub fn generation(&self, id: &C) -> Option<usize> {
        self.identities
            .binary_search(id)
            .ok()
            .map(|ordinal| self.generations[ordinal])
    }

    fn ordinal<E>(&self, id: &C) -> Result<usize, MergeBaseError<C, E>> {
        self.identities
            .binary_search(id)
            .map_err(|_| MergeBaseError::GraphClosureViolation)
    }

    /// Exact reachability, including equality, within the validated snapshot.
    /// An unknown identity refuses even when both arguments are equal.
    /// Generation pruning uses only generations derived during this build.
    pub fn is_ancestor<E, F>(
        &self,
        ancestor: &C,
        descendant: &C,
        scratch: &mut AncestryQueryScratch,
        limits: MergeBaseLimits,
        mut checkpoint: F,
    ) -> Result<bool, MergeBaseError<C, E>>
    where
        F: FnMut() -> Result<(), E>,
    {
        scratch.reset();
        checkpoint().map_err(MergeBaseError::Source)?;
        let ancestor = self.ordinal(ancestor)?;
        let descendant = self.ordinal(descendant)?;
        if limits.max_commits == 0 {
            return Err(MergeBaseError::CommitLimitExceeded { limit: 0 });
        }
        scratch.prepare(self.commit_count());
        checkpoint().map_err(MergeBaseError::Source)?;
        scratch.discover::<C, E>(descendant, limits)?;
        if ancestor == descendant {
            checkpoint().map_err(MergeBaseError::Source)?;
            return Ok(true);
        }
        let target_generation = self.generations[ancestor];
        if target_generation >= self.generations[descendant] {
            checkpoint().map_err(MergeBaseError::Source)?;
            return Ok(false);
        }
        scratch.stack.push(descendant);
        while let Some(ordinal) = scratch.stack.pop() {
            checkpoint().map_err(MergeBaseError::Source)?;
            for &parent in &self.parents[self.offsets[ordinal]..self.offsets[ordinal + 1]] {
                checkpoint().map_err(MergeBaseError::Source)?;
                scratch.examine_edge::<C, E>(limits)?;
                if self.generations[parent] < target_generation {
                    continue;
                }
                if scratch.discover::<C, E>(parent, limits)? {
                    if parent == ancestor {
                        checkpoint().map_err(MergeBaseError::Source)?;
                        return Ok(true);
                    }
                    // Equal-generation distinct commits cannot reach the
                    // target, so their parents need not enter the frontier.
                    if self.generations[parent] > target_generation {
                        scratch.stack.push(parent);
                    }
                }
            }
        }
        checkpoint().map_err(MergeBaseError::Source)?;
        Ok(false)
    }

    /// Return every best common ancestor in canonical identity order.
    ///
    /// Descending-generation traversal paints left/right reachability once per
    /// vertex. All children are processed before a parent, so its colors are
    /// final when it is popped. A common child's parents are dominated and
    /// cannot be best bases. Each edge of the queried union closure is examined
    /// at most once; unrelated indexed components consume no query budget.
    pub fn merge_bases_all<E, F>(
        &self,
        left: &C,
        right: &C,
        scratch: &mut AncestryQueryScratch,
        limits: MergeBaseLimits,
        mut checkpoint: F,
    ) -> MergeBaseQueryResult<C, E>
    where
        F: FnMut() -> Result<(), E>,
    {
        scratch.reset();
        checkpoint().map_err(MergeBaseError::Source)?;
        let left = self.ordinal(left)?;
        let right = self.ordinal(right)?;
        if limits.max_commits == 0 {
            return Err(MergeBaseError::CommitLimitExceeded { limit: 0 });
        }
        scratch.prepare(self.commit_count());
        checkpoint().map_err(MergeBaseError::Source)?;
        scratch.discover::<C, E>(left, limits)?;
        if left == right {
            checkpoint().map_err(MergeBaseError::Source)?;
            return Ok(MergeBaseResult::Bases(vec![self.identities[left].clone()]));
        }
        scratch.flags[left] = LEFT;
        scratch
            .frontier
            .push((self.generations[left], Reverse(left)));
        scratch.discover::<C, E>(right, limits)?;
        scratch.flags[right] = RIGHT;
        scratch
            .frontier
            .push((self.generations[right], Reverse(right)));
        let mut bases = Vec::new();
        while let Some((_, Reverse(ordinal))) = scratch.frontier.pop() {
            checkpoint().map_err(MergeBaseError::Source)?;
            let flags = scratch.flags[ordinal];
            let common = flags & COMMON == COMMON;
            if common && flags & DOMINATED == 0 {
                bases.push(self.identities[ordinal].clone());
            }
            for &parent in &self.parents[self.offsets[ordinal]..self.offsets[ordinal + 1]] {
                checkpoint().map_err(MergeBaseError::Source)?;
                scratch.examine_edge::<C, E>(limits)?;
                if scratch.discover::<C, E>(parent, limits)? {
                    scratch
                        .frontier
                        .push((self.generations[parent], Reverse(parent)));
                }
                scratch.flags[parent] |= flags & COMMON;
                if common {
                    scratch.flags[parent] |= DOMINATED;
                }
            }
        }
        checkpoint().map_err(MergeBaseError::Source)?;
        bases.sort();
        checkpoint().map_err(MergeBaseError::Source)?;
        Ok(if bases.is_empty() {
            MergeBaseResult::NoCommonAncestor
        } else {
            MergeBaseResult::Bases(bases)
        })
    }
}
