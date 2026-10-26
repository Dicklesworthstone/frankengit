//! Exact best common ancestors that read only the history the answer needs.
//!
//! [`CommitAncestryIndex`](crate::CommitAncestryIndex) and the scalar
//! [`merge_bases_all`](crate::merge_bases_all) first load the complete ancestor
//! closure of both tips, so their cost and their limits scale with the whole
//! history. This traversal reads a commit only when the painting below reaches
//! it, and stops as soon as the remaining frontier cannot change the answer.
//! Its limits therefore bound the commits and parent edges it actually admits.
//!
//! Each commit carries LEFT/RIGHT reachability and a DOMINATED mark meaning
//! "proper ancestor of a common ancestor". A popped commit pushes its marks to
//! its parents; a common, undominated commit is a candidate and also marks its
//! parents dominated. A commit is pushed again whenever it gains a mark, so the
//! marks only grow and the final marks do not depend on the visit order. The
//! order comes from [`CommitGraph::parents_with_order_hint`]; a hint (usually a
//! committer date) is untrusted and can only make the walk cheaper or costlier.
//! A new DOMINATED mark also propagates immediately through already-read parent
//! edges. Otherwise equal dates can leave this proof behind a one-sided queue
//! that keeps reading older commits, even after the recent best base is known.
//! This propagation reads no new objects and does not follow unknown parents;
//! ordinary queued expansion still owns those reads and their resource limits.
//!
//! Why stopping early is exact. A best base `b` is never dominated: domination
//! flows only from commits popped while common, which are true common
//! ancestors, and `b` is a proper ancestor of none. Every commit on a path from
//! a tip down to `b` descends from `b`, so it is undominated too, and the loop
//! runs while any undominated commit is queued. Both marks therefore reach `b`
//! and it is popped as a candidate. The undominated candidates thus contain
//! every best base and only common ancestors. One candidate is the answer. With
//! several, domination is drained further until one remains or the queue is
//! empty; a complete drain marks every proper ancestor of every candidate, so
//! the survivors are exactly the best bases. No candidate means no common
//! ancestor, since nothing was dominated and both closures were read in full.
//!
//! Refusals are observed where the traversal reads. A shallow boundary, a
//! duplicate parent or a cycle among the expanded commits refuses exactly as
//! the full loaders do. Below the stopping frontier nothing is read, so nothing
//! there is checked; content-addressed identities, which the caller's source
//! must verify, already exclude a cycle there.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

use super::{
    AncestryQueryWork, CommitGraph, MergeBaseError, MergeBaseLimits, MergeBaseQueryResult,
    MergeBaseResult, ParentSet,
};

const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const COMMON: u8 = LEFT | RIGHT;
const DOMINATED: u8 = 4;
const PAINT: u8 = COMMON | DOMINATED;
const CANDIDATE: u8 = 8;

/// Return every best common ancestor in canonical identity order, reading only
/// the commits that an exact answer requires.
///
/// The result equals [`merge_bases_all`](crate::merge_bases_all) on every
/// complete, acyclic graph, whatever the order hints. `work` is reset first and
/// reports the commits read and edges admitted, including on a refusal.
/// `limits` bound exactly those counts.
pub fn frontier_merge_bases_all<G, F>(
    graph: &G,
    left: G::CommitId,
    right: G::CommitId,
    limits: MergeBaseLimits,
    work: &mut AncestryQueryWork,
    mut checkpoint: F,
) -> MergeBaseQueryResult<G::CommitId, G::Error>
where
    G: CommitGraph,
    F: FnMut() -> Result<(), G::Error>,
{
    let mut frontier = Frontier::new(graph, limits);
    let result = frontier.query(left, right, &mut checkpoint);
    *work = frontier.work;
    result
}

struct Frontier<'g, G: CommitGraph> {
    graph: &'g G,
    limits: MergeBaseLimits,
    identities: Vec<G::CommitId>,
    ordinals: BTreeMap<G::CommitId, usize>,
    parents: Vec<Vec<G::CommitId>>,
    hints: Vec<i64>,
    marks: Vec<u8>,
    queued: Vec<usize>,
    expanded: Vec<bool>,
    // Highest hint first, then first pushed: equal hints visit breadth-first.
    heap: BinaryHeap<(i64, Reverse<u64>, usize)>,
    pushes: u64,
    // Queue entries whose commit is undominated; the main loop runs while > 0.
    live: usize,
    // Undominated candidates.
    open: usize,
    work: AncestryQueryWork,
}

impl<'g, G: CommitGraph> Frontier<'g, G> {
    fn new(graph: &'g G, limits: MergeBaseLimits) -> Self {
        Self {
            graph,
            limits,
            identities: Vec::new(),
            ordinals: BTreeMap::new(),
            parents: Vec::new(),
            hints: Vec::new(),
            marks: Vec::new(),
            queued: Vec::new(),
            expanded: Vec::new(),
            heap: BinaryHeap::new(),
            pushes: 0,
            live: 0,
            open: 0,
            work: AncestryQueryWork::default(),
        }
    }

    fn query<F>(
        &mut self,
        left: G::CommitId,
        right: G::CommitId,
        checkpoint: &mut F,
    ) -> MergeBaseQueryResult<G::CommitId, G::Error>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        checkpoint().map_err(MergeBaseError::Source)?;
        let left_ordinal = self.discover(&left, checkpoint)?;
        if left == right {
            checkpoint().map_err(MergeBaseError::Source)?;
            return Ok(MergeBaseResult::Bases(vec![left]));
        }
        let right_ordinal = self.discover(&right, checkpoint)?;
        self.mark(left_ordinal, LEFT);
        self.mark(right_ordinal, RIGHT);
        let mut candidates = Vec::new();
        while self.live > 0 {
            checkpoint().map_err(MergeBaseError::Source)?;
            let ordinal = self.pop().ok_or(MergeBaseError::GraphClosureViolation)?;
            let mut paint = self.marks[ordinal] & PAINT;
            if paint == COMMON {
                if self.marks[ordinal] & CANDIDATE == 0 {
                    self.marks[ordinal] |= CANDIDATE;
                    self.open += 1;
                    candidates.push(ordinal);
                }
                paint |= DOMINATED;
            }
            self.expand(ordinal, paint, checkpoint)?;
        }
        // Every queued entry is dominated now and carries DOMINATED onward.
        while self.open > 1 {
            checkpoint().map_err(MergeBaseError::Source)?;
            let Some(ordinal) = self.pop() else {
                break;
            };
            self.expand(ordinal, self.marks[ordinal] & PAINT, checkpoint)?;
        }
        self.refuse_expanded_cycle(checkpoint)?;
        let mut bases = candidates
            .into_iter()
            .filter(|ordinal| self.marks[*ordinal] & DOMINATED == 0)
            .map(|ordinal| self.identities[ordinal].clone())
            .collect::<Vec<_>>();
        bases.sort();
        checkpoint().map_err(MergeBaseError::Source)?;
        Ok(if bases.is_empty() {
            MergeBaseResult::NoCommonAncestor
        } else {
            MergeBaseResult::Bases(bases)
        })
    }

    /// Read a commit once. The read is charged before it starts, so the work
    /// report counts a refused or failed read; its parent edges are charged
    /// before the commit is admitted.
    fn discover<F>(
        &mut self,
        id: &G::CommitId,
        checkpoint: &mut F,
    ) -> Result<usize, MergeBaseError<G::CommitId, G::Error>>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        if let Some(ordinal) = self.ordinals.get(id) {
            return Ok(*ordinal);
        }
        if self.work.visited_commits >= self.limits.max_commits {
            return Err(MergeBaseError::CommitLimitExceeded {
                limit: self.limits.max_commits,
            });
        }
        self.work.visited_commits += 1;
        let (parents, hint) = self
            .graph
            .parents_with_order_hint(id)
            .map_err(MergeBaseError::Source)?;
        checkpoint().map_err(MergeBaseError::Source)?;
        let ParentSet::Complete(parents) = parents else {
            return Err(MergeBaseError::ShallowBoundary { commit: id.clone() });
        };
        let mut sorted = parents.iter().collect::<Vec<_>>();
        sorted.sort();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MergeBaseError::DuplicateParent { commit: id.clone() });
        }
        let edges = self
            .work
            .examined_edges
            .checked_add(parents.len())
            .filter(|edges| *edges <= self.limits.max_edges)
            .ok_or(MergeBaseError::EdgeLimitExceeded {
                limit: self.limits.max_edges,
            })?;
        self.work.examined_edges = edges;
        let ordinal = self.identities.len();
        self.identities.push(id.clone());
        self.ordinals.insert(id.clone(), ordinal);
        self.parents.push(parents);
        self.hints.push(hint);
        self.marks.push(0);
        self.queued.push(0);
        self.expanded.push(false);
        Ok(ordinal)
    }

    fn expand<F>(
        &mut self,
        ordinal: usize,
        paint: u8,
        checkpoint: &mut F,
    ) -> Result<(), MergeBaseError<G::CommitId, G::Error>>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        self.expanded[ordinal] = true;
        for index in 0..self.parents[ordinal].len() {
            checkpoint().map_err(MergeBaseError::Source)?;
            let parent = self.parents[ordinal][index].clone();
            let parent = self.discover(&parent, checkpoint)?;
            if self.mark(parent, paint) {
                self.propagate_known_domination(parent, checkpoint)?;
            }
        }
        Ok(())
    }

    /// Add marks and queue the commit again if that changed anything. Return
    /// whether the commit became dominated for the first time.
    fn mark(&mut self, ordinal: usize, paint: u8) -> bool {
        let before = self.marks[ordinal];
        if before & paint == paint {
            return false;
        }
        let newly_dominated = paint & DOMINATED != 0 && before & DOMINATED == 0;
        if newly_dominated {
            self.live -= self.queued[ordinal];
            if before & CANDIDATE != 0 {
                self.open -= 1;
            }
        }
        self.marks[ordinal] = before | paint;
        self.queued[ordinal] += 1;
        if self.marks[ordinal] & DOMINATED == 0 {
            self.live += 1;
        }
        self.heap
            .push((self.hints[ordinal], Reverse(self.pushes), ordinal));
        self.pushes += 1;
        newly_dominated
    }

    /// Retire obsolete queued work using only ancestry already admitted by
    /// `discover`. Every parent of a dominated commit is itself dominated;
    /// neither its visit-order hint nor another graph read is needed to know
    /// that. A commit enters this stack only when it first becomes dominated,
    /// so the extra work is bounded by the admitted commits and parent edges.
    /// Unknown parents remain on the normal expansion path, including the
    /// complete drain needed to distinguish several surviving best bases.
    fn propagate_known_domination<F>(
        &mut self,
        ordinal: usize,
        checkpoint: &mut F,
    ) -> Result<(), MergeBaseError<G::CommitId, G::Error>>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        let mut pending = vec![ordinal];
        while let Some(ordinal) = pending.pop() {
            checkpoint().map_err(MergeBaseError::Source)?;
            for index in 0..self.parents[ordinal].len() {
                checkpoint().map_err(MergeBaseError::Source)?;
                let Some(parent) = self.ordinals.get(&self.parents[ordinal][index]).copied() else {
                    continue;
                };
                if self.mark(parent, PAINT) {
                    pending.push(parent);
                }
            }
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<usize> {
        let (_, _, ordinal) = self.heap.pop()?;
        self.queued[ordinal] -= 1;
        if self.marks[ordinal] & DOMINATED == 0 {
            self.live -= 1;
        }
        Some(ordinal)
    }

    /// Kahn's algorithm over the expanded commits and the edges between them.
    fn refuse_expanded_cycle<F>(
        &self,
        checkpoint: &mut F,
    ) -> Result<(), MergeBaseError<G::CommitId, G::Error>>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        let count = self.identities.len();
        let mut children = vec![0_usize; count];
        for ordinal in (0..count).filter(|ordinal| self.expanded[*ordinal]) {
            for parent in &self.parents[ordinal] {
                checkpoint().map_err(MergeBaseError::Source)?;
                let parent = self.ordinals[parent];
                if self.expanded[parent] {
                    children[parent] += 1;
                }
            }
        }
        let mut ready = (0..count)
            .filter(|ordinal| self.expanded[*ordinal] && children[*ordinal] == 0)
            .collect::<Vec<_>>();
        let mut ordered = 0_usize;
        while let Some(ordinal) = ready.pop() {
            ordered += 1;
            for parent in &self.parents[ordinal] {
                checkpoint().map_err(MergeBaseError::Source)?;
                let parent = self.ordinals[parent];
                if self.expanded[parent] {
                    children[parent] -= 1;
                    if children[parent] == 0 {
                        ready.push(parent);
                    }
                }
            }
        }
        if ordered == self.expanded.iter().filter(|expanded| **expanded).count() {
            Ok(())
        } else {
            Err(MergeBaseError::Cycle)
        }
    }
}
