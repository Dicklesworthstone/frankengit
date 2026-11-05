//! Exact-basis carry-forward of revocation state during a policy transition.
//!
//! This proof changes no capability membership. It retains the complete selected
//! snapshot and permanent configuration facts while advancing exactly one epoch.
//! Publication must additionally bind the proof to the committed policy event.

use core::fmt;

use fgit_codec::{
    CodecRefusal, CryptoBodyIdentity, RepositoryAuthorityHeadBody,
    RepositoryIncarnationConfigurationBodyV2_2, body_id,
};
use fgit_types::{Digest, PolicyEpoch, RepositoryAuthorityHeadId, TenantId};

use super::{
    CapabilityRevocationAuthorityFailure, CapabilityRevocationGenerationBody,
    CapabilityRevocationGenerationRead, capability_revocation_generation_id_from_root,
    read_capability_revocation_generation_by_id, read_capability_revocation_generation_by_id_async,
    stage_capability_revocation_generation, stage_capability_revocation_generation_async,
    validate_selected_generation,
};
use crate::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityStore, AuthorityVersionToken,
    IdentityDisagreement, OutcomeFailure, RepositoryIncarnationConfiguration,
    authority_head_identity, read_repository_configuration, read_repository_configuration_async,
    read_repository_incarnation_configuration, read_repository_incarnation_configuration_async,
    stage_revocation_aware_repository_incarnation_configuration,
    stage_revocation_aware_repository_incarnation_configuration_async,
};

/// Why the selected revocation snapshot cannot be carried into the next epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRevocationTransitionRefusal {
    /// Authentication, exact-body resolution, or immutable staging failed.
    Authority(Box<CapabilityRevocationAuthorityFailure>),
    /// The proposed epoch is not the immediate successor of the authenticated one.
    EpochNotImmediateSuccessor {
        /// Authenticated predecessor epoch.
        predecessor: PolicyEpoch,
        /// Proposed successor epoch.
        proposed: PolicyEpoch,
    },
    /// The predecessor's policy epoch cannot advance.
    EpochExhausted {
        /// Exhausted authenticated epoch.
        predecessor: PolicyEpoch,
    },
    /// Historical selected bodies do not preserve the exact predecessor facts.
    CarryForwardMismatch {
        /// Scope or configuration/generation fact that disagreed.
        field: &'static str,
    },
}

impl fmt::Display for CapabilityRevocationTransitionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(failure) => write!(formatter, "revocation transition: {failure}"),
            Self::EpochNotImmediateSuccessor {
                predecessor,
                proposed,
            } => write!(
                formatter,
                "revocation transition epoch {} does not immediately follow {}",
                proposed.get(),
                predecessor.get(),
            ),
            Self::EpochExhausted { predecessor } => write!(
                formatter,
                "revocation transition cannot advance policy epoch {}",
                predecessor.get(),
            ),
            Self::CarryForwardMismatch { field } => {
                write!(
                    formatter,
                    "revocation carry-forward disagrees about {field}"
                )
            }
        }
    }
}

impl core::error::Error for CapabilityRevocationTransitionRefusal {}

impl From<CapabilityRevocationAuthorityFailure> for CapabilityRevocationTransitionRefusal {
    fn from(value: CapabilityRevocationAuthorityFailure) -> Self {
        Self::Authority(Box::new(value))
    }
}

/// Opaque evidence that an exact authenticated predecessor's complete revocation
/// set and permanent configuration facts survive one policy-epoch advance.
///
/// A proof does not publish or acknowledge placement. [`Self::stage`] and
/// [`Self::stage_async`] always reauthenticate its retained receipt and perform
/// both immutable writes. A sealer must match the complete predecessor body,
/// identity, CAS token, successor epoch, and committed event evidence root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationEpochTransition {
    predecessor: AuthenticatedHead,
    predecessor_body: RepositoryAuthorityHeadBody,
    predecessor_id: RepositoryAuthorityHeadId,
    generation: CapabilityRevocationGenerationBody,
    configuration: RepositoryIncarnationConfigurationBodyV2_2,
    configuration_root: Digest,
}

impl CapabilityRevocationEpochTransition {
    /// Complete authenticated predecessor; a different body cannot reuse this proof.
    #[must_use]
    pub const fn predecessor_body(&self) -> &RepositoryAuthorityHeadBody {
        &self.predecessor_body
    }

    /// Canonical identity of the complete predecessor.
    #[must_use]
    pub const fn predecessor_id(&self) -> RepositoryAuthorityHeadId {
        self.predecessor_id
    }

    /// Exact original conditional-publication token.
    #[must_use]
    pub const fn expected_head_token(&self) -> AuthorityVersionToken {
        self.predecessor.receipt().token()
    }

    /// Immediate successor epoch retained by the derived generation.
    #[must_use]
    pub const fn successor_epoch(&self) -> PolicyEpoch {
        self.generation.policy_epoch()
    }

    /// Canonical forge-event batch root the committed policy transition must carry.
    #[must_use]
    pub const fn evidence_root(&self) -> Digest {
        self.generation.evidence_root()
    }

    /// New configuration root, derived without accepting caller-selected facts.
    #[must_use]
    pub const fn configuration_root(&self) -> Digest {
        self.configuration_root
    }

    /// Complete carried snapshot, retained for audit and exact-byte verification.
    #[must_use]
    pub const fn generation(&self) -> &CapabilityRevocationGenerationBody {
        &self.generation
    }

    /// Configuration whose only changed fact is the selected revocation generation.
    #[must_use]
    pub const fn configuration(&self) -> &RepositoryIncarnationConfigurationBodyV2_2 {
        &self.configuration
    }

    /// Stage both dependencies without changing the authority head.
    pub fn stage<S>(&self, store: &S) -> Result<(), CapabilityRevocationTransitionRefusal>
    where
        S: AuthorityStore + ?Sized,
    {
        store
            .authenticate_head_receipt(self.predecessor.receipt())
            .map_err(CapabilityRevocationAuthorityFailure::from)?;
        stage_capability_revocation_generation(store, &self.generation)?;
        stage_revocation_aware_repository_incarnation_configuration(store, &self.configuration)
            .map_err(CapabilityRevocationAuthorityFailure::from)?;
        Ok(())
    }

    /// Production asynchronous twin of [`Self::stage`].
    pub async fn stage_async<S>(
        &self,
        store: &S,
        cx: &S::Context,
    ) -> Result<(), CapabilityRevocationTransitionRefusal>
    where
        S: AsyncAuthorityStore + ?Sized,
    {
        store
            .authenticate_head_receipt(cx, self.predecessor.receipt())
            .await
            .map_err(CapabilityRevocationAuthorityFailure::from)?;
        stage_capability_revocation_generation_async(store, cx, &self.generation).await?;
        stage_revocation_aware_repository_incarnation_configuration_async(
            store,
            cx,
            &self.configuration,
        )
        .await
        .map_err(CapabilityRevocationAuthorityFailure::from)?;
        Ok(())
    }
}

/// Prepare a carry-forward proof from exact, reidentified authority-selected bodies.
///
/// `None` means an exactly decoded supported configuration has no revocation root;
/// it does not mean an unavailable, corrupt, future, or stale body was ignored.
/// Such repositories retain their existing configuration and high-value effects
/// continue to require a separately activated explicit revocation generation.
pub fn prepare_capability_revocation_epoch_transition<S>(
    store: &S,
    tenant: TenantId,
    predecessor: &AuthenticatedHead,
    successor_epoch: PolicyEpoch,
    evidence_root: Digest,
) -> Result<Option<CapabilityRevocationEpochTransition>, CapabilityRevocationTransitionRefusal>
where
    S: AuthorityStore + ?Sized,
{
    let predecessor = store
        .authenticate_head_receipt(predecessor.receipt())
        .map_err(CapabilityRevocationAuthorityFailure::from)?;
    let head = predecessor
        .body()
        .map_err(CapabilityRevocationAuthorityFailure::from)?;
    require_next_epoch(head.policy_epoch, successor_epoch)?;
    let Some(configuration) = read_selected_configuration(store, head.configuration_root)? else {
        return Ok(None);
    };
    let Some(root) = configuration.capability_revocation_root else {
        return Ok(None);
    };
    let selected = read_capability_revocation_generation_by_id(
        store,
        capability_revocation_generation_id_from_root(&root),
    )?;
    derive_transition(
        predecessor,
        head,
        tenant,
        configuration,
        selected,
        successor_epoch,
        evidence_root,
    )
    .map(Some)
}

/// Production asynchronous twin of [`prepare_capability_revocation_epoch_transition`].
pub async fn prepare_capability_revocation_epoch_transition_async<S>(
    store: &S,
    cx: &S::Context,
    tenant: TenantId,
    predecessor: &AuthenticatedHead,
    successor_epoch: PolicyEpoch,
    evidence_root: Digest,
) -> Result<Option<CapabilityRevocationEpochTransition>, CapabilityRevocationTransitionRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let predecessor = store
        .authenticate_head_receipt(cx, predecessor.receipt())
        .await
        .map_err(CapabilityRevocationAuthorityFailure::from)?;
    let head = predecessor
        .body()
        .map_err(CapabilityRevocationAuthorityFailure::from)?;
    require_next_epoch(head.policy_epoch, successor_epoch)?;
    let Some(configuration) =
        read_selected_configuration_async(store, cx, head.configuration_root).await?
    else {
        return Ok(None);
    };
    let Some(root) = configuration.capability_revocation_root else {
        return Ok(None);
    };
    let selected = read_capability_revocation_generation_by_id_async(
        store,
        cx,
        capability_revocation_generation_id_from_root(&root),
    )
    .await?;
    derive_transition(
        predecessor,
        head,
        tenant,
        configuration,
        selected,
        successor_epoch,
        evidence_root,
    )
    .map(Some)
}

pub(super) fn require_next_epoch(
    predecessor: PolicyEpoch,
    proposed: PolicyEpoch,
) -> Result<(), CapabilityRevocationTransitionRefusal> {
    let next = predecessor
        .next()
        .map_err(|_| CapabilityRevocationTransitionRefusal::EpochExhausted { predecessor })?;
    if proposed != next {
        return Err(
            CapabilityRevocationTransitionRefusal::EpochNotImmediateSuccessor {
                predecessor,
                proposed,
            },
        );
    }
    Ok(())
}

pub(super) fn read_selected_configuration<S>(
    store: &S,
    root: Digest,
) -> Result<Option<RepositoryIncarnationConfiguration>, CapabilityRevocationAuthorityFailure>
where
    S: AuthorityStore + ?Sized,
{
    match read_repository_incarnation_configuration(store, &root) {
        Ok(configuration) => Ok(Some(configuration)),
        Err(OutcomeFailure::Codec(CodecRefusal::SchemaMajorUnsupported {
            observed: 1, ..
        })) => {
            let legacy = read_repository_configuration(store, &root)?;
            require_configuration_identity(&legacy, root)?;
            Ok(None)
        }
        Err(failure) => Err(failure.into()),
    }
}

pub(super) async fn read_selected_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    root: Digest,
) -> Result<Option<RepositoryIncarnationConfiguration>, CapabilityRevocationAuthorityFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    match read_repository_incarnation_configuration_async(store, cx, &root).await {
        Ok(configuration) => Ok(Some(configuration)),
        Err(OutcomeFailure::Codec(CodecRefusal::SchemaMajorUnsupported {
            observed: 1, ..
        })) => {
            let legacy = read_repository_configuration_async(store, cx, &root).await?;
            require_configuration_identity(&legacy, root)?;
            Ok(None)
        }
        Err(failure) => Err(failure.into()),
    }
}

fn require_configuration_identity<B: fgit_codec::CanonicalBody>(
    body: &B,
    requested_root: Digest,
) -> Result<(), CapabilityRevocationAuthorityFailure> {
    let found = body_id(&CryptoBodyIdentity, body)?;
    let requested = fgit_types::InternalObjectId::new(
        requested_root.algorithm(),
        B::DOMAIN,
        fgit_types::CANONICAL_CODEC_VERSION,
        *requested_root.bytes(),
    );
    if found != requested {
        return Err(OutcomeFailure::BodyIdentityMismatch {
            link: "repository configuration",
            identities: Box::new(IdentityDisagreement { requested, found }),
        }
        .into());
    }
    Ok(())
}

fn derive_transition(
    predecessor: AuthenticatedHead,
    head: RepositoryAuthorityHeadBody,
    tenant: TenantId,
    configuration: RepositoryIncarnationConfiguration,
    selected: CapabilityRevocationGenerationRead,
    successor_epoch: PolicyEpoch,
    evidence_root: Digest,
) -> Result<CapabilityRevocationEpochTransition, CapabilityRevocationTransitionRefusal> {
    validate_selected_generation(
        &selected,
        tenant,
        head.repository_id,
        configuration.repository_incarnation_id,
        head.policy_epoch,
    )?;
    let (generation, configuration, configuration_root) =
        carried_bodies(configuration, &selected, successor_epoch, evidence_root)?;
    let predecessor_id =
        authority_head_identity(&head).map_err(CapabilityRevocationAuthorityFailure::from)?;
    Ok(CapabilityRevocationEpochTransition {
        predecessor,
        predecessor_body: head,
        predecessor_id,
        generation,
        configuration,
        configuration_root,
    })
}

pub(super) fn carried_bodies(
    configuration: RepositoryIncarnationConfiguration,
    selected: &CapabilityRevocationGenerationRead,
    successor_epoch: PolicyEpoch,
    evidence_root: Digest,
) -> Result<
    (
        CapabilityRevocationGenerationBody,
        RepositoryIncarnationConfigurationBodyV2_2,
        Digest,
    ),
    CapabilityRevocationAuthorityFailure,
> {
    let generation = CapabilityRevocationGenerationBody::try_new(
        selected.body().tenant_id(),
        selected.body().repository_id(),
        configuration.repository_incarnation_id,
        successor_epoch,
        Some(selected.generation_id()),
        selected.body().revoked_capability_ids().to_vec(),
        evidence_root,
    )?;
    let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: configuration.root_layout,
        object_format: configuration.object_format,
        repository_incarnation_id: configuration.repository_incarnation_id,
        policy_root: configuration.policy_root,
        capability_revocation_root: Some(generation.generation_root()?),
    };
    let identity = body_id(&CryptoBodyIdentity, &configuration)?;
    Ok((
        generation,
        configuration,
        Digest::new(identity.algorithm(), *identity.digest()),
    ))
}

const _: () = {
    assert!(size_of::<CapabilityRevocationTransitionRefusal>() <= crate::request::MAX_ERROR_BYTES);
};
