//! Deterministic, conflict-free recursive comparison bases.
//!
//! Virtual nodes exist only in this request's graph. Their two parents retain
//! the full ancestry of every previously combined base, so a later fold finds
//! the actual best ancestors of the accumulated result. They are neither Git
//! commit objects nor selected common-ancestor witnesses for publication.

use super::{
    AncestryQueryWork, CommitGraph, GitHashAlgorithm, GitOid, Graph, MergeBaseError,
    MergeBaseLimits, MergeBaseResult, MergeObjectSource, MergeSourceError, ParentSet, Planner,
    PreparationError, PreparationLimits, RecursiveMergeBase, frontier_merge_bases_all,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Node {
    Original(GitOid),
    Virtual(usize),
}

struct VirtualNode {
    tree: GitOid,
    parents: [Node; 2],
}

struct History<'a, S> {
    source: &'a S,
    format: GitHashAlgorithm,
    virtuals: Vec<VirtualNode>,
}

impl<S: MergeObjectSource> History<'_, S> {
    fn tree(&self, node: Node) -> Result<GitOid, PreparationError> {
        self.source.checkpoint()?;
        let tree = match node {
            Node::Original(id) => self.source.commit(id)?.tree,
            Node::Virtual(index) => self.virtuals.get(index).ok_or(PreparationError::InvalidTree)?.tree,
        };
        if tree.is_zero() || tree.algorithm() != self.format {
            return Err(PreparationError::InvalidTree);
        }
        Ok(tree)
    }

    fn combine(
        &mut self,
        tree: GitOid,
        parents: [Node; 2],
        limits: PreparationLimits,
    ) -> Result<Node, PreparationError> {
        self.source.checkpoint()?;
        if parents[0] == parents[1] {
            return Err(PreparationError::InvalidTree);
        }
        // Even a trivial equal-tree fold creates ancestry metadata. Bound it
        // before allocation independently of later graph queries.
        if self.virtuals.len() == limits.max_commits {
            return Err(PreparationError::Budget("virtual merge bases"));
        }
        self.virtuals.try_reserve(1).map_err(|_| PreparationError::Budget("virtual merge-base allocation"))?;
        let node = Node::Virtual(self.virtuals.len());
        self.virtuals.push(VirtualNode { tree, parents });
        Ok(node)
    }
}

impl<S: MergeObjectSource> CommitGraph for History<'_, S> {
    type CommitId = Node;
    type Error = MergeSourceError;

    fn parents_of(&self, id: &Node) -> Result<ParentSet<Node>, MergeSourceError> {
        self.parents_with_order_hint(id).map(|(parents, _)| parents)
    }

    fn parents_with_order_hint(&self, id: &Node) -> Result<(ParentSet<Node>, i64), MergeSourceError> {
        self.source.checkpoint()?;
        match id {
            Node::Original(id) => {
                let (parents, hint) = Graph { source: self.source, format: self.format }.parents_with_order_hint(id)?;
                Ok((
                    match parents {
                        ParentSet::Complete(parents) => ParentSet::Complete(parents.into_iter().map(Node::Original).collect()),
                        ParentSet::ShallowBoundary => ParentSet::ShallowBoundary,
                    },
                    hint,
                ))
            }
            Node::Virtual(index) => {
                let node = self.virtuals.get(*index).ok_or(MergeSourceError::OutsideSelection)?;
                Ok((ParentSet::Complete(node.parents.to_vec()), i64::MAX))
            }
        }
    }
}

/// Select every real best ancestor and construct its effective comparison
/// tree. Graph work includes the initial query and every recursive query;
/// callers may carry the same counters across a complete queue prefix.
pub(super) fn select<H: MergeObjectSource, S: MergeObjectSource>(
    source: &H,
    planner: &mut Planner<'_, S>,
    target: GitOid,
    incoming: GitOid,
    work: &mut AncestryQueryWork,
) -> Result<RecursiveMergeBase, PreparationError> {
    let mut history = History { source, format: planner.format, virtuals: Vec::new() };
    let bases = query(&history, Node::Original(target), Node::Original(incoming), planner.limits, work)?;
    let node = synthesize(&mut history, planner, &bases, work, 0)?;
    Ok(RecursiveMergeBase { bases, tree: history.tree(node)? })
}

fn query<S: MergeObjectSource>(
    history: &History<'_, S>,
    left: Node,
    right: Node,
    limits: PreparationLimits,
    work: &mut AncestryQueryWork,
) -> Result<Vec<GitOid>, PreparationError> {
    let remaining = MergeBaseLimits {
        max_commits: limits.max_commits.checked_sub(work.visited_commits).ok_or(PreparationError::Budget("merge-base commits"))?,
        max_edges: limits.max_edges.checked_sub(work.examined_edges).ok_or(PreparationError::Budget("merge-base edges"))?,
    };
    let mut query_work = AncestryQueryWork::default();
    let result = frontier_merge_bases_all(history, left, right, remaining, &mut query_work, || history.source.checkpoint());
    // Frontier counts never exceed the remaining limits, even on a refusal.
    // Repeated visits through a different query still consume work.
    work.visited_commits += query_work.visited_commits;
    work.examined_edges += query_work.examined_edges;
    let bases = match result.map_err(|error| graph_error(error, limits))? {
        MergeBaseResult::NoCommonAncestor => return Err(PreparationError::NoCommonAncestor),
        MergeBaseResult::Bases(bases) => bases,
    };
    // At least one side of every query is an original commit. Original graph
    // edges cannot refer to our private virtual nodes, so every common ancestor
    // must be original. Reject a violated invariant rather than inventing an
    // original identity for a virtual node.
    bases.into_iter().map(|node| match node {
        Node::Original(id) => Ok(id),
        Node::Virtual(_) => Err(PreparationError::InvalidTree),
    }).collect()
}

fn synthesize<H: MergeObjectSource, S: MergeObjectSource>(
    history: &mut History<'_, H>,
    planner: &mut Planner<'_, S>,
    bases: &[GitOid],
    work: &mut AncestryQueryWork,
    depth: usize,
) -> Result<Node, PreparationError> {
    history.source.checkpoint()?;
    if depth > planner.limits.max_depth {
        return Err(PreparationError::Budget("merge-base recursion depth"));
    }
    let Some(first) = bases.first() else {
        return Err(PreparationError::NoCommonAncestor);
    };
    // The frontier supplies ascending native identities. Folding in that fixed
    // order makes construction independent of source/target or parent ordering.
    let mut current = Node::Original(*first);
    for next in bases.iter().skip(1).copied().map(Node::Original) {
        history.source.checkpoint()?;
        let ours = history.tree(current)?;
        let theirs = history.tree(next)?;
        let tree = if ours == theirs {
            // Identical snapshots are unambiguous independently of their older
            // history. Still retain BOTH parents for the next fold.
            ours
        } else {
            let common = query(history, current, next, planner.limits, work)?;
            let ancestor = synthesize(history, planner, &common, work, depth + 1)?;
            let base_tree = history.tree(ancestor)?;
            let merged = planner.directory(Some(base_tree), ours, theirs, &[], 0, false)?;
            if !planner.conflicts.is_empty() {
                let mut conflicts = std::mem::take(&mut planner.conflicts);
                conflicts.sort_by(|left, right| left.path.cmp(&right.path));
                return Err(PreparationError::RecursiveBaseConflict { bases: bases.to_vec(), conflicts });
            }
            merged.ok_or(PreparationError::InvalidTree)?
        };
        current = history.combine(tree, [current, next], planner.limits)?;
    }
    history.source.checkpoint()?;
    Ok(current)
}

fn graph_error(error: MergeBaseError<Node, MergeSourceError>, limits: PreparationLimits) -> PreparationError {
    use MergeBaseError as Error;
    PreparationError::Graph(match error {
        Error::Source(error) => Error::Source(error),
        Error::ShallowBoundary { commit: Node::Original(commit) } => Error::ShallowBoundary { commit },
        Error::DuplicateParent { commit: Node::Original(commit) } => Error::DuplicateParent { commit },
        Error::GraphClosureViolation | Error::ShallowBoundary { .. } | Error::DuplicateParent { .. } => Error::GraphClosureViolation,
        Error::Cycle => Error::Cycle,
        Error::CommitLimitExceeded { .. } => Error::CommitLimitExceeded { limit: limits.max_commits },
        Error::EdgeLimitExceeded { .. } => Error::EdgeLimitExceeded { limit: limits.max_edges },
    })
}
