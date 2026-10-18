//! Keep an interrupted authority operation distinct from malformed evidence at
//! the projection boundary. These conversions are for preparation only: the
//! publisher retains the full authority error after a possible head CAS.

use fgit_authority::{
    AmbiguityReason, AuthorityFailure, AuthorityRefusal, OutcomeFailure, SealFailure,
};
use fgit_types::RefusalCode;

use crate::{AdmissionError, ProjectionFailure};

impl AdmissionError {
    /// Convert a failed pre-publication dependency into a nonterminal projection
    /// failure while retaining its known infrastructure cause.
    ///
    /// The fallback describes an invalid receipt or evidence at this particular
    /// boundary. It applies only when the error carries no more specific
    /// infrastructure or projection reason. In particular, cancellation and
    /// deadline expiry from a store, including through seal/history wrappers,
    /// are never evidence that the repository is corrupt or an object is absent.
    ///
    /// This does not create a canonical refusal or prove non-commit. A sealed
    /// request remains subject to normal outcome lookup on retry. Do not use
    /// this conversion for the publisher's CAS response: its original
    /// `AuthorityFailure::Ambiguous` must retain effect-unknown guidance.
    #[must_use]
    pub fn into_projection_unavailable(self, fallback: RefusalCode) -> ProjectionFailure {
        let code = match self {
            Self::AsyncProjectionUnavailable(code) | Self::ProjectionUnavailable { code, .. } => {
                code
            }
            Self::Authority(failure) => authority_code(failure, fallback),
            Self::Seal(failure) => seal_code(&failure, fallback),
            Self::Outcome(failure) => match *failure {
                OutcomeFailure::Seal(failure) => seal_code(&failure, fallback),
                OutcomeFailure::ReplayBoundExceeded { .. } => RefusalCode::ResourceBudgetExceeded,
                _ => fallback,
            },
            _ => fallback,
        };
        ProjectionFailure::Unavailable(code)
    }
}

fn seal_code(failure: &SealFailure, fallback: RefusalCode) -> RefusalCode {
    match failure {
        SealFailure::Store(failure) => authority_code(*failure, fallback),
        _ => fallback,
    }
}

const fn authority_code(failure: AuthorityFailure, fallback: RefusalCode) -> RefusalCode {
    match failure {
        AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled | AmbiguityReason::Timeout) => {
            RefusalCode::CancellationInProgress
        }
        AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse) => {
            RefusalCode::ExternalEffectIndeterminate
        }
        AuthorityFailure::Refused(
            AuthorityRefusal::Throttled
            | AuthorityRefusal::CapacityExhausted { .. }
            | AuthorityRefusal::BodyTooLarge { .. },
        ) => RefusalCode::ResourceBudgetExceeded,
        AuthorityFailure::Refused(
            AuthorityRefusal::Unavailable | AuthorityRefusal::OperationUnsupported,
        ) => RefusalCode::DurabilityProfileUnavailable,
        AuthorityFailure::Refused(_) => fallback,
    }
}

#[cfg(test)]
mod tests;
