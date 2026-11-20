//! Reusable computations over one private, exact-head cumulative outcome set.
//!
//! Neither the sorted transaction offsets nor the cached Merkle root is an
//! authority source. The original entries remain owned by `CumulativeOutcomes`,
//! and every consumer still authenticates its head and checks the exact token.
//! The ordinary fold remains the independent behavior oracle.

use super::{
    Arc, BTreeMap, CumulativeOutcomes, Digest, DigestBytes, IdentityDomain, OnceLock,
    OutcomeFailure, TerminalOutcome, TxId, merkle_root, ordered_outcome_leaves,
    outcome_index_schema,
};
use crate::DuplicateDecision;

#[derive(Debug)]
pub(super) struct PreparedOutcomeIndex {
    /// Offsets into the unmodified entries, sorted by transaction identity.
    lookup: Vec<usize>,
    /// The exact digest ordering of the existing outcome commitment.
    leaves: Vec<DigestBytes>,
    root: Digest,
}

impl PreparedOutcomeIndex {
    fn from_entries(entries: &[(TxId, TerminalOutcome)]) -> Result<Self, OutcomeFailure> {
        let mut lookup: Vec<_> = (0..entries.len()).collect();
        lookup.sort_unstable_by_key(|index| (entries[*index].0, *index));

        // Preserve the reference fold's first duplicate in source order,
        // including its original and offered outcomes. Sorting must not select
        // the lowest transaction identity as the reported defect instead.
        if let Some(pair) = lookup
            .windows(2)
            .filter(|pair| entries[pair[0]].0 == entries[pair[1]].0)
            .min_by_key(|pair| pair[1])
        {
            return Err(duplicate(
                entries[pair[0]].0,
                entries[pair[0]].1,
                entries[pair[1]].1,
            ));
        }

        let leaves = ordered_outcome_leaves(entries)?;
        let root = root(&leaves);
        Ok(Self {
            lookup,
            leaves,
            root,
        })
    }

    pub(super) const fn root(&self) -> Digest {
        self.root
    }

    pub(super) fn decision_for(
        &self,
        entries: &[(TxId, TerminalOutcome)],
        tx_id: TxId,
    ) -> Option<TerminalOutcome> {
        self.lookup
            .binary_search_by_key(&tx_id, |offset| entries[*offset].0)
            .ok()
            .map(|index| entries[self.lookup[index]].1)
    }

    fn extend(
        &self,
        carried: &[(TxId, TerminalOutcome)],
        stamped: &[(TxId, TerminalOutcome)],
    ) -> Result<Self, OutcomeFailure> {
        // Only the new batch needs a temporary map. Retained decisions are
        // looked up logarithmically without rebuilding a whole-history map.
        let mut added: BTreeMap<TxId, usize> = BTreeMap::new();
        for (offset, (tx_id, outcome)) in stamped.iter().enumerate() {
            let existing = self
                .decision_for(carried, *tx_id)
                .or_else(|| added.get(tx_id).map(|prior| stamped[*prior].1));
            if let Some(existing) = existing {
                return Err(duplicate(*tx_id, existing, *outcome));
            }
            added.insert(*tx_id, offset);
        }

        // Encode only new outcomes. The commitment still requires rebuilding
        // its Merkle interior: this digest-sorted tree is not append-only.
        let new_leaves = ordered_outcome_leaves(stamped)?;
        let mut leaves = Vec::with_capacity(self.leaves.len() + new_leaves.len());
        let mut retained = self.leaves.iter().peekable();
        let mut incoming = new_leaves.iter().peekable();
        while let (Some(left), Some(right)) = (retained.peek(), incoming.peek()) {
            if left.as_bytes() <= right.as_bytes() {
                leaves.push(**left);
                retained.next();
            } else {
                leaves.push(**right);
                incoming.next();
            }
        }
        leaves.extend(retained.copied());
        leaves.extend(incoming.copied());

        let mut lookup = Vec::with_capacity(carried.len() + stamped.len());
        let mut retained = self.lookup.iter().copied().peekable();
        let mut incoming = added.into_iter().peekable();
        while let (Some(left), Some((right_tx, right))) = (retained.peek(), incoming.peek()) {
            if carried[*left].0 < *right_tx {
                lookup.push(*left);
                retained.next();
            } else {
                lookup.push(carried.len() + *right);
                incoming.next();
            }
        }
        lookup.extend(retained);
        lookup.extend(incoming.map(|(_, offset)| carried.len() + offset));

        let root = root(&leaves);
        Ok(Self {
            lookup,
            leaves,
            root,
        })
    }
}

fn root(leaves: &[DigestBytes]) -> Digest {
    Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        merkle_root(outcome_index_schema(), leaves),
    )
}

fn duplicate(tx_id: TxId, existing: TerminalOutcome, offered: TerminalOutcome) -> OutcomeFailure {
    OutcomeFailure::DuplicateTerminalDecision {
        duplicate: Box::new(DuplicateDecision {
            tx_id,
            existing,
            offered,
        }),
    }
}

impl CumulativeOutcomes {
    pub(super) fn prepared_index(&self) -> Result<&PreparedOutcomeIndex, OutcomeFailure> {
        match self
            .prepared
            .get_or_init(|| PreparedOutcomeIndex::from_entries(&self.entries).map(Arc::new))
        {
            Ok(index) => Ok(index),
            Err(error) => Err(error.clone()),
        }
    }

    pub(super) fn prepared_root(&self) -> Result<Digest, OutcomeFailure> {
        Ok(self.prepared_index()?.root())
    }

    pub(super) fn prepare_extension(
        &self,
        stamped: &[(TxId, TerminalOutcome)],
    ) -> Result<PreparedOutcomeIndex, OutcomeFailure> {
        let index = match self.prepared_index() {
            Ok(index) => index,
            Err(error) => {
                // The reference checks every duplicate before encoding any
                // outcome. If a malformed carried value failed encoding, a
                // duplicate in the new batch must still take precedence.
                super::fold_outcome_index(&self.entries, stamped)?;
                return Err(error);
            }
        };
        index.extend(&self.entries, stamped)
    }

    pub(super) fn retain_extension(
        &mut self,
        stamped: Vec<(TxId, TerminalOutcome)>,
        prepared: PreparedOutcomeIndex,
    ) {
        self.entries.extend(stamped);
        self.prepared = OnceLock::from(Ok(Arc::new(prepared)));
    }
}

#[cfg(test)]
mod tests;
