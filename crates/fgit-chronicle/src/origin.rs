//! The basis a publication is prepared against, and the roots it results in.

use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_types::{
    DecisionSequence, Digest, HeadGeneration, PolicyEpoch, RepositoryAuthorityHeadId,
    RepositorySequence,
};

use crate::refusal::ChronicleRefusal;

/// One authenticated predecessor head, paired with its identity.
///
/// A basis is the only thing a publication may be built against. Carrying the
/// identity alongside the body is what lets the batch bind to the exact head
/// it succeeds: a body alone cannot prove which head it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationBasis {
    id: RepositoryAuthorityHeadId,
    body: RepositoryAuthorityHeadBody,
}

impl PublicationBasis {
    /// Binds a head body to the identity it was read under.
    #[must_use]
    pub const fn new(id: RepositoryAuthorityHeadId, body: RepositoryAuthorityHeadBody) -> Self {
        Self { id, body }
    }

    /// The predecessor head's identity.
    #[must_use]
    pub const fn id(&self) -> RepositoryAuthorityHeadId {
        self.id
    }

    /// The predecessor head body.
    #[must_use]
    pub const fn body(&self) -> &RepositoryAuthorityHeadBody {
        &self.body
    }

    /// The predecessor generation.
    #[must_use]
    pub const fn generation(&self) -> HeadGeneration {
        self.body.generation
    }

    /// The first decision position this basis leaves open.
    ///
    /// A repository with no decisions yet opens at
    /// [`DecisionSequence::FIRST`]; otherwise the next position after the
    /// head's tail. Gap-freedom across every terminal decision follows from
    /// nobody else being able to choose this number.
    pub fn open_decision_sequence(&self) -> Result<DecisionSequence, ChronicleRefusal> {
        self.body.latest_decision_sequence.map_or_else(
            || Ok(DecisionSequence::FIRST),
            |latest| {
                latest
                    .next()
                    .map_err(|_| ChronicleRefusal::SequenceExhausted {
                        counter: "decision sequence",
                    })
            },
        )
    }

    /// The first committed-transition position this basis leaves open.
    pub fn open_repository_sequence(&self) -> Result<RepositorySequence, ChronicleRefusal> {
        self.body.latest_repository_sequence.map_or_else(
            || Ok(RepositorySequence::FIRST),
            |latest| {
                latest
                    .next()
                    .map_err(|_| ChronicleRefusal::SequenceExhausted {
                        counter: "repository sequence",
                    })
            },
        )
    }

    /// The generation the successor head must carry.
    pub fn successor_generation(&self) -> Result<HeadGeneration, ChronicleRefusal> {
        self.body
            .generation
            .next()
            .map_err(|_| ChronicleRefusal::SequenceExhausted {
                counter: "head generation",
            })
    }
}

/// The non-outcome state a batch's evaluation resulted in.
///
/// These roots are computed by transaction evaluation, not by this crate. The
/// chronicle's job is to refuse a pair whose batch and head disagree about
/// them, and to refuse a batch that committed nothing yet moved the ones a
/// refusal may never move. The cumulative outcome-index root is deliberately
/// absent: it is derived only after sealing from authority-owned carried leaves
/// and the batch's stamped terminal outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultingRoots {
    /// Root over the resulting ref state.
    pub ref_root: Digest,
    /// Root over the resulting forge position.
    pub forge_position_root: Digest,
    /// Root over the resulting retention state.
    pub retention_root: Digest,
    /// Root over the resulting external-effect outbox.
    pub outbox_root: Digest,
    /// Policy epoch after the batch.
    pub policy_epoch: PolicyEpoch,
    /// Compaction generation this publication links, when it publishes one.
    ///
    /// Batch evidence is derived by chronicle sealing from the final decisions
    /// and records; evaluation cannot supply or choose it.
    pub compaction_generation_link: Option<Digest>,
}

impl ResultingRoots {
    /// The non-outcome roots an unchanged repository carries forward from
    /// `basis`.
    ///
    /// A refusal-only batch starts here: it consumes decision sequence and
    /// records evidence, and it moves no committed root. Its outcome index is
    /// still derived at sealing because refusals are terminal outcomes.
    #[must_use]
    pub const fn carried_forward(basis: &PublicationBasis) -> Self {
        let head = basis.body();
        Self {
            ref_root: head.ref_root,
            forge_position_root: head.forge_position_root,
            retention_root: head.retention_root,
            outbox_root: head.outbox_root,
            policy_epoch: head.policy_epoch,
            compaction_generation_link: None,
        }
    }
}
