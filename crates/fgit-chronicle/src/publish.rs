//! Publication, and what a losing candidate may conclude about itself.
//!
//! The staging and conditional-replacement protocol belongs to
//! `fgit-authority`; this module does not reimplement it. What it adds is the
//! half the store cannot answer: after a lost race, is this candidate still
//! usable, or has the repository already decided the transactions it carries?

use fgit_authority::{
    AuthorityStore, AuthorityVersionToken, HeadKey, HeadReadReceipt, OutcomeFailure, OutcomeLookup,
    PublicationOutcome, TerminalOutcome, indexed_outcome, publish_decisions,
};
use fgit_types::{RepositoryDecisionBatchId, TenantId, TxId};

use crate::assemble::VerifiedPublication;

/// What happened to a candidate at the head.
#[must_use = "a publication verdict decides whether the caller may report a terminal outcome"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationVerdict {
    /// The conditional replacement landed.
    ///
    /// This is the linearization point: every decision in the batch became
    /// canonical at once, together with the roots the head publishes.
    Published {
        /// The head this publication established.
        head: HeadReadReceipt,
        /// The batch that became canonical.
        batch: RepositoryDecisionBatchId,
        /// Accelerator entries written after the head moved.
        indexed: usize,
    },
    /// The head moved first. Nothing this candidate staged is referenced.
    Lost(LostCandidate),
}

/// What a candidate may conclude after losing the race.
///
/// A lost conditional replacement is ordinary control flow, not an error, and
/// it is never evidence that the transactions did not commit — only that *this
/// attempt* did not publish them.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LostCandidate {
    /// No transaction in the batch has a terminal decision yet.
    ///
    /// The sealed requests are still undecided, so the same requests may be
    /// replanned against the new head. The positions this batch chose are
    /// stale — the winner consumed them — which is why a rebase re-plans
    /// rather than re-submits: sequence is assigned by the plan, never carried.
    Replannable,
    /// At least one transaction already has a terminal decision.
    ///
    /// Those decisions are authoritative and this candidate must not be
    /// retried for them. Re-deciding a sealed transaction would violate the
    /// one-terminal-decision rule.
    Superseded {
        /// The transactions that are already decided, with their outcomes.
        decided: Vec<(TxId, TerminalOutcome)>,
    },
}

/// Stage, replace, and index a verified publication.
///
/// Delegates the protocol to `fgit_authority::publish_decisions`, which stages
/// bodies before the head and writes the accelerator only after the head has
/// moved. On a lost race the candidate is classified against the accelerator
/// so the caller learns whether it may replan.
pub fn publish<S>(
    store: &S,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    publication: &VerifiedPublication,
    tenant_id: TenantId,
) -> Result<PublicationVerdict, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let outcome = publish_decisions(
        store,
        head_key,
        expected,
        publication.batch(),
        publication.head(),
        tenant_id,
    )?;
    match outcome {
        PublicationOutcome::Published {
            head,
            batch_id,
            indexed,
        } => Ok(PublicationVerdict::Published {
            head,
            batch: batch_id,
            indexed,
        }),
        PublicationOutcome::PredecessorMismatch => Ok(PublicationVerdict::Lost(classify_loss(
            store,
            publication,
            tenant_id,
        )?)),
    }
}

/// Ask the accelerator whether any transaction in the candidate is decided.
///
/// The accelerator is a repairable projection, not a second truth, so a miss
/// means "no decision indexed here", never "no decision exists". That is why a
/// clean sweep yields [`LostCandidate::Replannable`] — permission to replan
/// the same sealed requests — and never a claim that they were refused.
fn classify_loss<S>(
    store: &S,
    publication: &VerifiedPublication,
    tenant_id: TenantId,
) -> Result<LostCandidate, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let repository_id = publication.batch().repository_id;
    let mut decided = Vec::new();
    for decision in &publication.batch().decisions {
        if let OutcomeLookup::Decided(outcome) =
            indexed_outcome(store, tenant_id, repository_id, decision.tx_id)?
        {
            decided.push((decision.tx_id, outcome));
        }
    }
    if decided.is_empty() {
        Ok(LostCandidate::Replannable)
    } else {
        Ok(LostCandidate::Superseded { decided })
    }
}
