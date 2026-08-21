//! Publication, and what a losing candidate may conclude about itself.
//!
//! The staging and conditional-replacement protocol belongs to
//! `fgit-authority`; this module does not reimplement it. What it adds is the
//! half the store cannot answer: after a lost race, is this candidate still
//! usable, or has the repository already decided the transactions it carries?

use fgit_authority::{
    AuthorityStore, AuthorityVersionToken, HeadKey, HeadReadReceipt, OutcomeFailure, OutcomeLookup,
    PublicationOutcome, TerminalOutcome, publish_decisions, resolve_outcome,
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
    ///
    /// The payload is boxed because a published head carries canonical bytes
    /// and a domain-pinned identity, while the losing arm carries almost
    /// nothing. Inlining it would make every lost race pay for the width of a
    /// win. `fgit-authority` boxes its own publication payload for the same
    /// reason, so the two layers agree in shape.
    Published(Box<CanonicalBatchReceipt>),
    /// The head moved first. Nothing this candidate staged is referenced.
    Lost(LostCandidate),
}

/// Evidence that one decision batch became canonical.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBatchReceipt {
    /// The head this publication established.
    pub head: HeadReadReceipt,
    /// The batch that became canonical.
    pub batch: RepositoryDecisionBatchId,
    /// Accelerator entries written after the head moved.
    pub indexed: usize,
}

/// What a candidate may conclude after losing the race.
///
/// A lost conditional replacement is ordinary control flow, not an error, and
/// it is never evidence that the transactions did not commit — only that *this
/// attempt* did not publish them.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LostCandidate {
    /// No transaction in the batch has a terminal decision.
    ///
    /// Established by replaying the authenticated decision stream, not by an
    /// accelerator miss, so it survives the crash window between a head
    /// advancing and its accelerator entries being written.
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
///
/// The failure travels unboxed: `fgit-authority` now keeps `OutcomeFailure`
/// inside the workspace error-payload bound, so the indirection this path
/// briefly carried is gone. The crate root asserts that bound, so if the type
/// ever widens again the build says so rather than a lint catching it later.
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
        PublicationOutcome::Published(published) => Ok(PublicationVerdict::Published(Box::new(
            CanonicalBatchReceipt {
                head: published.head,
                batch: published.batch_id,
                indexed: published.indexed,
            },
        ))),
        PublicationOutcome::PredecessorMismatch => Ok(PublicationVerdict::Lost(classify_loss(
            store,
            head_key,
            publication,
            tenant_id,
        )?)),
    }
}

/// Ask the authority whether any transaction in the candidate is decided.
///
/// This resolves through `resolve_outcome`, which replays the authenticated
/// decision stream **and** consults the accelerator, rather than through the
/// accelerator alone.
///
/// The distinction is not academic, and an earlier version of this function
/// got it wrong. The accelerator is written *after* the head moves, so a crash
/// in that window leaves a transaction genuinely decided with no accelerator
/// entry. Asking only the accelerator reads that as undecided and hands back
/// [`LostCandidate::Replannable`] — telling the caller to replan a transaction
/// that already committed, which is exactly how one sealed transaction
/// acquires two terminal decisions. Replay is authoritative precisely because
/// it would give the same answer on a node whose index was wiped.
fn classify_loss<S>(
    store: &S,
    head_key: &HeadKey,
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
            resolve_outcome(store, head_key, tenant_id, repository_id, decision.tx_id)?
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
