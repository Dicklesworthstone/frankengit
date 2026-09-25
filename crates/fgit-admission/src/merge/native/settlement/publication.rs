//! A canonical commit and ownership of a dispatch are different facts.
//!
//! Only an acknowledged successful CAS in this invocation may start the send
//! associated with a dispatch marker. Discovering the same committed marker
//! before publication, after losing CAS, or after an uncertain store response
//! is recovery, not ownership. Recovery reloads the marker and probes instead.

use fgit_authority::{AsyncAuthorityStore, AuthorityVersionToken, OutcomeLookup, TerminalOutcome};
use fgit_chronicle::{PublicationVerdict, VerifiedPublication};
use fgit_types::{DecisionOutcome, RefusalCode, TxId};

use super::{AdmissionContext, AdmissionError, unavailable};

/// A previously decided mutation never grants a new dispatch capability.
pub(super) const fn recovered(terminal: TerminalOutcome) -> Result<bool, AdmissionError> {
    match ownership(false, terminal) {
        Ok(owned) => Ok(owned),
        Err(code) => Err(unavailable(code)),
    }
}

/// `Some(true)` belongs exclusively to this invocation's successful CAS.
/// `Some(false)` is an authenticated prior decision; `None` needs a replan.
/// An ambiguous publication error is deliberately not promoted into ownership
/// by looking up its outcome: the persisted marker remains available to probe.
pub(super) async fn publish_owned<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    expected: AuthorityVersionToken,
    publication: &VerifiedPublication,
    tx_id: TxId,
) -> Result<Option<bool>, AdmissionError> {
    let verdict = fgit_chronicle::publish_async(
        store,
        cx,
        &context.head_key,
        expected,
        publication,
        context.tenant_id,
    )
    .await?;
    let published_here = matches!(verdict, PublicationVerdict::Published(_));
    let outcome = fgit_authority::resolve_outcome_async(
        store,
        cx,
        &context.head_key,
        context.tenant_id,
        context.repository_id,
        tx_id,
    )
    .await?;
    match outcome {
        OutcomeLookup::Decided(terminal) => ownership(published_here, terminal)
            .map(Some)
            .map_err(unavailable),
        OutcomeLookup::Undecided if published_here => {
            Err(unavailable(RefusalCode::EvidenceMissing))
        }
        OutcomeLookup::Undecided => Ok(None),
    }
}

const fn ownership(published_here: bool, terminal: TerminalOutcome) -> Result<bool, RefusalCode> {
    match terminal.outcome {
        DecisionOutcome::Committed { .. } => Ok(published_here),
        DecisionOutcome::Refused { code, .. } => Err(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_codec::harness::{commit_id, refusal_record_id};
    use fgit_types::DecisionSequence;

    fn committed() -> TerminalOutcome {
        TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome: DecisionOutcome::Committed {
                repository_commit_id: commit_id(),
            },
        }
    }

    #[test]
    fn fresh_publication_is_the_only_owner_of_an_identical_commit() {
        let terminal = committed();
        assert!(ownership(true, terminal).expect("successful CAS owns this marker"));
        assert!(!ownership(false, terminal).expect("losing CAS only observes the marker"));
        assert!(!recovered(terminal).expect("pre-publication lookup is recovery"));
    }

    #[test]
    fn any_number_of_recovered_markers_grants_no_additional_send() {
        let terminal = committed();
        let mut sends = usize::from(ownership(true, terminal).unwrap());
        for _ in 0..128 {
            sends += usize::from(recovered(terminal).unwrap());
        }
        assert_eq!(sends, 1);
    }

    #[test]
    fn a_lost_ack_does_not_gain_ownership_from_a_later_lookup() {
        // The operation that won CAS did not receive its success response.
        // All later invocations know only the authenticated terminal outcome.
        let terminal = committed();
        assert!(!recovered(terminal).unwrap());
        assert!(!ownership(false, terminal).unwrap());
    }

    #[test]
    fn refusals_never_grant_ownership_on_either_publication_path() {
        for code in [
            RefusalCode::PublicationPolicyRefused,
            RefusalCode::EvidenceStale,
            RefusalCode::ProtectedRefTransitionDenied,
        ] {
            let terminal = TerminalOutcome {
                decision_sequence: DecisionSequence::FIRST,
                outcome: DecisionOutcome::Refused {
                    code,
                    refusal_record_id: refusal_record_id(),
                },
            };
            assert_eq!(ownership(true, terminal), Err(code));
            assert_eq!(ownership(false, terminal), Err(code));
            assert!(recovered(terminal).is_err());
        }
    }
}
