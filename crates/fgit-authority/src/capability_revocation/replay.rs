//! Read-only verification of carried revocation state in authenticated history.

use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_types::Digest;

use super::transition::{
    carried_bodies, read_selected_configuration, read_selected_configuration_async,
    require_next_epoch,
};
use super::{
    CapabilityRevocationTransitionRefusal, capability_revocation_generation_id_from_root,
    read_capability_revocation_generation_by_id, read_capability_revocation_generation_by_id_async,
    validate_selected_generation,
};
use crate::{
    AsyncAuthorityStore, AuthorityStore, RepositoryIncarnationConfiguration,
    RepositoryIncarnationConfigurationEvidence, read_repository_incarnation_configuration,
    read_repository_incarnation_configuration_async,
};

/// Verify immutable carry-forward bodies selected by a historical policy edge.
///
/// Callers must authenticate the head history and independently verify its
/// decision/event shape. This function grants no publication authority, mints no
/// live receipt, and performs no writes. Tenant is preserved byte-for-byte from
/// the old generation; live preparation and current selection separately check
/// it against their authenticated tenant namespace.
///
/// Call this for every policy-epoch advance, including an unchanged configuration
/// root: retaining an old enabled generation at the new epoch is invalid. Only an
/// exactly decoded supported configuration without a revocation root may remain
/// unchanged. Missing, corrupt, and future bodies always fail closed.
pub fn verify_capability_revocation_epoch_transition<S>(
    store: &S,
    predecessor: &RepositoryAuthorityHeadBody,
    successor: &RepositoryAuthorityHeadBody,
    event_root: Digest,
) -> Result<(), CapabilityRevocationTransitionRefusal>
where
    S: AuthorityStore + ?Sized,
{
    require_scope_and_epoch(predecessor, successor)?;
    let configuration = read_selected_configuration(store, predecessor.configuration_root)?;
    let Some((configuration, generation_root)) = selected_generation(configuration) else {
        return require_unchanged_configuration(predecessor, successor);
    };
    let selected = read_capability_revocation_generation_by_id(
        store,
        capability_revocation_generation_id_from_root(&generation_root),
    )?;
    validate_selected_generation(
        &selected,
        selected.body().tenant_id(),
        predecessor.repository_id,
        configuration.repository_incarnation_id,
        predecessor.policy_epoch,
    )?;
    let (generation, expected_configuration, root) =
        carried_bodies(configuration, &selected, successor.policy_epoch, event_root)?;
    if successor.configuration_root != root {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "successor configuration root",
            },
        );
    }
    let observed_configuration =
        read_repository_incarnation_configuration(store, &successor.configuration_root)
            .map_err(super::CapabilityRevocationAuthorityFailure::from)?;
    let observed_generation =
        read_capability_revocation_generation_by_id(store, generation.generation_id()?)?;
    if observed_configuration
        != RepositoryIncarnationConfigurationEvidence::V2_2(expected_configuration).normalized()
        || observed_generation.body() != &generation
    {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "successor immutable bodies",
            },
        );
    }
    Ok(())
}

/// Production asynchronous twin of [`verify_capability_revocation_epoch_transition`].
pub async fn verify_capability_revocation_epoch_transition_async<S>(
    store: &S,
    cx: &S::Context,
    predecessor: &RepositoryAuthorityHeadBody,
    successor: &RepositoryAuthorityHeadBody,
    event_root: Digest,
) -> Result<(), CapabilityRevocationTransitionRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    require_scope_and_epoch(predecessor, successor)?;
    let configuration =
        read_selected_configuration_async(store, cx, predecessor.configuration_root).await?;
    let Some((configuration, generation_root)) = selected_generation(configuration) else {
        return require_unchanged_configuration(predecessor, successor);
    };
    let selected = read_capability_revocation_generation_by_id_async(
        store,
        cx,
        capability_revocation_generation_id_from_root(&generation_root),
    )
    .await?;
    validate_selected_generation(
        &selected,
        selected.body().tenant_id(),
        predecessor.repository_id,
        configuration.repository_incarnation_id,
        predecessor.policy_epoch,
    )?;
    let (generation, expected_configuration, root) =
        carried_bodies(configuration, &selected, successor.policy_epoch, event_root)?;
    if successor.configuration_root != root {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "successor configuration root",
            },
        );
    }
    let observed_configuration =
        read_repository_incarnation_configuration_async(store, cx, &successor.configuration_root)
            .await
            .map_err(super::CapabilityRevocationAuthorityFailure::from)?;
    let observed_generation =
        read_capability_revocation_generation_by_id_async(store, cx, generation.generation_id()?)
            .await?;
    if observed_configuration
        != RepositoryIncarnationConfigurationEvidence::V2_2(expected_configuration).normalized()
        || observed_generation.body() != &generation
    {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "successor immutable bodies",
            },
        );
    }
    Ok(())
}

fn selected_generation(
    configuration: Option<RepositoryIncarnationConfiguration>,
) -> Option<(RepositoryIncarnationConfiguration, Digest)> {
    configuration.and_then(|configuration| {
        configuration
            .capability_revocation_root
            .map(|root| (configuration, root))
    })
}

fn require_scope_and_epoch(
    predecessor: &RepositoryAuthorityHeadBody,
    successor: &RepositoryAuthorityHeadBody,
) -> Result<(), CapabilityRevocationTransitionRefusal> {
    if predecessor.repository_id != successor.repository_id {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "repository identity",
            },
        );
    }
    require_next_epoch(predecessor.policy_epoch, successor.policy_epoch)
}

fn require_unchanged_configuration(
    predecessor: &RepositoryAuthorityHeadBody,
    successor: &RepositoryAuthorityHeadBody,
) -> Result<(), CapabilityRevocationTransitionRefusal> {
    if predecessor.configuration_root != successor.configuration_root {
        return Err(
            CapabilityRevocationTransitionRefusal::CarryForwardMismatch {
                field: "configuration without revocation root",
            },
        );
    }
    Ok(())
}
