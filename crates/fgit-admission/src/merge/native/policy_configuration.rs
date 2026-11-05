//! Runtime-independent publication seam for an already validated policy event.
//!
//! The metadata owner calls this only after validating and staging its exact
//! singleton protection event. Every CAS replan supplies a newly authenticated
//! basis; no transition proof or placement acknowledgement survives that loop.

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityVersionToken,
    CapabilityRevocationAuthorityFailure, CapabilityRevocationTransitionRefusal,
    CumulativeOutcomes, authority_head_identity,
    prepare_capability_revocation_epoch_transition_async,
};
use fgit_chronicle::{ChronicleRefusal, PublicationPlan, ResultingRoots, VerifiedPublication};
use fgit_codec::CryptoBodyIdentity;
use fgit_types::{Digest, TenantId};

#[cfg(test)]
#[path = "policy_configuration_tests.rs"]
mod tests;

#[derive(Debug)]
pub(super) enum PolicyConfigurationFailure {
    Revocation(CapabilityRevocationTransitionRefusal),
    Chronicle(ChronicleRefusal),
}

impl From<CapabilityRevocationTransitionRefusal> for PolicyConfigurationFailure {
    fn from(value: CapabilityRevocationTransitionRefusal) -> Self {
        Self::Revocation(value)
    }
}

impl From<ChronicleRefusal> for PolicyConfigurationFailure {
    fn from(value: ChronicleRefusal) -> Self {
        Self::Chronicle(value)
    }
}

pub(super) async fn seal_policy_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    tenant: TenantId,
    authenticated: &AuthenticatedHead,
    plan: PublicationPlan,
    roots: ResultingRoots,
    event_root: Digest,
    cumulative: &CumulativeOutcomes,
    expected_head_token: AuthorityVersionToken,
) -> Result<VerifiedPublication, PolicyConfigurationFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    // The explicit no-revocation configuration path must be just as tightly
    // bound as Some(proof); absence from another head cannot bypass carry-forward.
    let head = authenticated
        .body()
        .map_err(CapabilityRevocationAuthorityFailure::from)
        .map_err(CapabilityRevocationTransitionRefusal::from)?;
    let head_id = authority_head_identity(&head)
        .map_err(CapabilityRevocationAuthorityFailure::from)
        .map_err(CapabilityRevocationTransitionRefusal::from)?;
    for (field, matches) in [
        ("predecessor identity", plan.basis().id() == head_id),
        ("predecessor body", plan.basis().body() == &head),
        (
            "predecessor token",
            expected_head_token == authenticated.receipt().token(),
        ),
    ] {
        if !matches {
            return Err(ChronicleRefusal::RevocationTransitionMismatch { field }.into());
        }
    }
    let transition = prepare_capability_revocation_epoch_transition_async(
        store,
        cx,
        tenant,
        authenticated,
        roots.policy_epoch,
        event_root,
    )
    .await?;
    match transition {
        Some(transition) => {
            // Seal first so a mismatched plan cannot cause writes. Immutable
            // dependencies still finish before this candidate can reach CAS.
            let publication = plan.seal_with_revocation_epoch_transition(
                &CryptoBodyIdentity,
                roots,
                cumulative,
                expected_head_token,
                &transition,
            )?;
            transition.stage_async(store, cx).await?;
            Ok(publication)
        }
        None => Ok(plan.seal(&CryptoBodyIdentity, roots, cumulative, expected_head_token)?),
    }
}
