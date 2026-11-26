//! An incomparability proof using only parent edges already expanded.
use super::{CANDIDATE, CommitGraph, DOMINATED, Frontier, MergeBaseError};

impl<G: CommitGraph> Frontier<'_, G> {
    /// Walk from each surviving candidate to its first unexpanded ancestors.
    /// If another candidate is reachable along known edges the proof fails.
    /// Otherwise any path to another candidate must cross an unexpanded node.
    /// When each candidate has exactly the same set of such nodes, every one
    /// of them is already its strict ancestor. A path back would be a cycle.
    /// The caller separately checks the expanded graph for cycles.
    pub(super) fn shared_boundary<F>(
        &self,
        candidates: &[usize],
        graph_size: usize,
        checkpoint: &mut F,
    ) -> Result<bool, MergeBaseError<G::CommitId, G::Error>>
    where
        F: FnMut() -> Result<(), G::Error>,
    {
        let mut visited_from = vec![None; self.identities.len()];
        let mut first_boundary = vec![false; self.identities.len()];
        let mut first_count = None;
        let mut stack = Vec::new();
        // Two full walks always fit. More candidates can often be checked
        // within the same allowance, particularly when their bases are recent.
        let mut remaining = graph_size.saturating_mul(2);
        for &start in candidates {
            checkpoint().map_err(MergeBaseError::Source)?;
            if self.marks[start] & DOMINATED != 0 {
                continue;
            }
            let mut count = 0_usize;
            visited_from[start] = Some(start);
            stack.push(start);
            while let Some(node) = stack.pop() {
                checkpoint().map_err(MergeBaseError::Source)?;
                let parents = self.expanded[node].then_some(&self.parents[node]);
                let cost = 1 + parents.map_or(0, Vec::len);
                let Some(left) = remaining.checked_sub(cost) else {
                    return Ok(false);
                };
                remaining = left;
                if node != start && self.marks[node] & (CANDIDATE | DOMINATED) == CANDIDATE {
                    return Ok(false);
                }
                if let Some(parents) = parents {
                    for parent in parents {
                        checkpoint().map_err(MergeBaseError::Source)?;
                        let ordinal = self.ordinals[parent];
                        if visited_from[ordinal] != Some(start) {
                            visited_from[ordinal] = Some(start);
                            stack.push(ordinal);
                        }
                    }
                } else {
                    if first_count.is_some() && !first_boundary[node] {
                        return Ok(false);
                    }
                    first_boundary[node] = true;
                    count += 1;
                }
            }
            if *first_count.get_or_insert(count) != count {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
