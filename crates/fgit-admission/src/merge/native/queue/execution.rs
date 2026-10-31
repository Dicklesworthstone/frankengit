//! Closed dispatch between the historical fast-forward and explicit candidate
//! profiles. Sharing guards never erases the selected native merge method.

use fgit_authority::SealAttempt;
use fgit_chronicle::PublicationBasis;
use fgit_forge::{ForgeEvent, ForgeEventBatch};
use fgit_types::{RefusalCode, TxId};

use super::{
    QueueCandidateLandingCommand, QueueLandingCommand, candidate, candidate_landing_proposal,
    landing, landing_proposal,
};
use crate::merge::native::NativeMergeIntent;
use crate::merge::{NativeMergeBasis, PreparedNativeMerge};
use crate::{AdmissionContext, AdmissionError, ValidatedClosure};

#[derive(Clone, Copy)]
pub(in crate::merge) enum Landing<'a> {
    FastForward(&'a QueueLandingCommand),
    Candidate(&'a QueueCandidateLandingCommand),
}

impl Landing<'_> {
    pub(in crate::merge) fn intent(self) -> Result<NativeMergeIntent, AdmissionError> {
        match self {
            Self::FastForward(command) => command.intent(),
            Self::Candidate(command) => command.intent(),
        }
    }

    pub(in crate::merge) fn proposal(
        self,
        context: &AdmissionContext,
    ) -> Result<(ForgeEventBatch, SealAttempt), AdmissionError> {
        match self {
            Self::FastForward(command) => landing_proposal(context, command),
            Self::Candidate(command) => candidate_landing_proposal(context, command),
        }
    }

    pub(super) fn guards(self) -> QueueLandingCommand {
        match self {
            Self::FastForward(command) => command.clone(),
            Self::Candidate(command) => command.guards(),
        }
    }

    pub(super) fn validate_shape<'a>(
        self,
        events: &'a ForgeEventBatch,
    ) -> Result<&'a ForgeEvent, RefusalCode> {
        match self {
            Self::FastForward(_) => landing::validate_landing_shape(events),
            Self::Candidate(_) => candidate::validate_candidate_landing_shape(events),
        }
    }

    pub(in crate::merge) fn prepare(
        self,
        context: &AdmissionContext,
        events: &ForgeEventBatch,
        closure: &ValidatedClosure,
        tx_id: TxId,
        attempt: &SealAttempt,
        basis: &PublicationBasis,
        resolved: &NativeMergeBasis,
    ) -> Result<PreparedNativeMerge, RefusalCode> {
        match self {
            Self::FastForward(command) => landing::prepare_landing(
                context, command, events, closure, tx_id, attempt, basis, resolved,
            ),
            Self::Candidate(command) => candidate::prepare_candidate_landing(
                context, command, events, closure, tx_id, attempt, basis, resolved,
            ),
        }
    }
}

/// Defensive staging/fold check for exactly one supported complete three-event
/// publication. Entry-point validation also verifies its own specific profile.
pub(in crate::merge) fn validate_publication_shape(
    events: &ForgeEventBatch,
) -> Result<&ForgeEvent, RefusalCode> {
    landing::validate_landing_shape(events)
        .or_else(|_| candidate::validate_candidate_landing_shape(events))
}
