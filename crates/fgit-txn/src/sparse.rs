//! Exact target projection for transaction evaluation.
//!
//! The reference folder copies its entire input before evaluation and diffs
//! that copy afterwards. For a receive microbatch, that previously repeated
//! work proportional to all repository state for every one-ref transaction.
//! Every current intent reads and writes only its named target, so unrelated
//! basis entries cannot affect its result. Selecting the union of those exact
//! targets before invoking the unchanged folder bounds temporary state by the
//! request footprint and retains the one evaluation/absorption implementation.
//!
//! This is not a policy or visibility projection. The caller still checks the
//! complete authenticated snapshot before folding. No selected value comes
//! from the request: present values are copied only from the supplied basis.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::effect::FoldBasis;
use fgit_reference::intent::{
    ForgeStreamId, ForgeStreamPosition, Intent, OutboxDeliveryKey, RefIntent, RetentionIntent,
    RetentionRoot, TransactionRequest,
};
use fgit_types::{Digest, GitOid, RefName};

/// Dense requests need no projection when the full working copy is already
/// bounded by the number of intents. This also avoids an extra copy for empty
/// and tiny repositories. Overflow cannot select an understated basis size.
pub fn full_basis_fits_request(basis: FoldBasis<'_>, request: &TransactionRequest) -> bool {
    let Some(entries) = basis
        .refs
        .len()
        .checked_add(basis.forge_positions.len())
        .and_then(|count| count.checked_add(basis.retention.len()))
        .and_then(|count| count.checked_add(basis.outbox.len()))
    else {
        return false;
    };
    if entries == 0 {
        return true;
    }
    let intents = request.statements.iter().fold(0_usize, |count, statement| {
        count.saturating_add(statement.intents.len())
    });
    entries <= intents
}

#[derive(Default)]
pub struct SparseBasis {
    refs: BTreeMap<RefName, GitOid>,
    forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    retention: BTreeSet<RetentionRoot>,
    outbox: BTreeMap<OutboxDeliveryKey, Digest>,
}

impl SparseBasis {
    /// O(m log n + m log m) work and O(k) entries for m source intents,
    /// n basis entries, and k <= m distinct addressed targets present at basis.
    /// There is no capacity reservation proportional to n or to an untrusted
    /// claimed count. The caller's admitted semantic request bounds m.
    pub(super) fn select(basis: FoldBasis<'_>, request: &TransactionRequest) -> Self {
        let mut selected = Self::default();
        for (_, intent) in request.addressed_intents() {
            // Keep the match exhaustive. A new intent or target-reading ref
            // variant must explicitly establish its footprint before it can
            // enter the production evaluator.
            match intent {
                Intent::Ref(RefIntent::Update { name, .. } | RefIntent::Delete { name, .. }) => {
                    if let Some(value) = basis.refs.get(name) {
                        selected.refs.insert(name.clone(), *value);
                    }
                }
                Intent::Forge(forge) => {
                    if let Some(position) = basis.forge_positions.get(&forge.stream) {
                        selected.forge_positions.insert(forge.stream, *position);
                    }
                }
                Intent::Retention(
                    RetentionIntent::AddRoot(root) | RetentionIntent::RemoveRoot(root),
                ) => {
                    if basis.retention.contains(root) {
                        selected.retention.insert(*root);
                    }
                }
                Intent::Outbox(outbox) => {
                    if let Some(parameters) = basis.outbox.get(&outbox.delivery_key) {
                        selected.outbox.insert(outbox.delivery_key, *parameters);
                    }
                }
            }
        }
        selected
    }

    pub(super) const fn as_basis(&self) -> FoldBasis<'_> {
        FoldBasis {
            refs: &self.refs,
            forge_positions: &self.forge_positions,
            retention: &self.retention,
            outbox: &self.outbox,
        }
    }
}

#[cfg(test)]
mod tests;
