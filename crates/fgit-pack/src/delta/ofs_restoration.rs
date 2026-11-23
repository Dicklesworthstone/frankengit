//! Retention for a single ascending pass over a pack with only offset deltas.

use super::*;

/// Only direct parents with an outstanding child remain eligible for retention.
/// The child itself names the parent to expire, so no reverse table or sweep is needed.
pub(super) struct OfsRestoration {
    pub(super) last_child: HashMap<u64, u64>,
    next: usize,
}

impl<L: ExternalBaseLookup, S: CacheSpill> CachedResolver<'_, '_, L, S> {
    /// Optimize an empty resident-recency cache for a single typed pass in
    /// ascending pack-offset order. A mixed/REF pack keeps ordinary recency.
    /// A repeated or skipped lookup abandons the plan. Missing bases, cache
    /// misses and all reconstructed bytes retain normal resolver accounting.
    pub fn prepare_ascending_ofs_restoration(
        &mut self,
        budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<(), PackError> {
        checkpoint(deadline)?;
        if self.recency.is_none()
            || !self.entries.is_empty()
            || self.resident_budget == 0
            || !matches!(self.scalar.by_base.last(), Some(DeltaBase::Ofs(_)))
        {
            return Ok(());
        }
        // The fanout index sorts REF bases after OFS bases, so the preceding
        // check excludes all REF dependencies before allocating or scanning.
        let mut last_child = HashMap::new();
        last_child
            .try_reserve(self.scalar.by_base.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: self.scalar.by_base.len(),
            })?;
        let mut previous = None;
        for object in &self.scalar.by_offset {
            checkpoint(deadline)?;
            budget.charge_work(1, self.scalar.limits)?;
            let offset = object.offset();
            if previous == Some(offset) {
                return Ok(());
            }
            previous = Some(offset);
            if let PackObject::Delta(delta) = object {
                let DeltaBase::Ofs(parent) = delta.base else {
                    return Ok(());
                };
                if parent >= offset {
                    return Ok(());
                }
                last_child.insert(parent, offset);
            }
        }
        self.ofs_restoration = Some(OfsRestoration {
            last_child,
            next: 0,
        });
        Ok(())
    }

    /// Stop recaching a parent during its last direct child's resolution, but
    /// keep its existing bytes available for that final hit. The caller then
    /// releases the entry. A later descendant can still reconstruct an evicted
    /// base by following its original edges and paying the ordinary charges.
    pub(super) fn begin_ofs_entry(&mut self, object: &PackObject) -> Option<u64> {
        let plan = self.ofs_restoration.as_mut()?;
        let offset = object.offset();
        if self.scalar.by_offset.get(plan.next).map(|o| o.offset()) != Some(offset) {
            self.ofs_restoration = None;
            return None;
        }
        plan.next += 1;
        if let PackObject::Delta(delta) = object
            && let DeltaBase::Ofs(parent) = delta.base
            && plan.last_child.get(&parent) == Some(&offset)
        {
            plan.last_child.remove(&parent);
            return Some(parent);
        }
        None
    }
}
