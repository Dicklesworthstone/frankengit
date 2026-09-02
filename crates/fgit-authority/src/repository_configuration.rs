//! Strict incarnation-configuration resolution through schema 2.2.
//!
//! The original configuration reader in `outcome` predates capability
//! revocation and recognizes schemas 2.0 and 2.1.  This module is the upgraded
//! public boundary: it preserves those published bytes, admits schema 2.2, and
//! returns one normalized projection while retaining exact-minor evidence for
//! callers that must re-identify the selected body.
//!
//! A read is not accepted merely because bytes were found under a key derived
//! from `configuration_root`.  The exact body is canonically re-identified and
//! its digest must equal the root the authenticated authority head supplied.
//! This closes the same loose-key failure mode that decision-stream reads
//! already refuse.

use fgit_codec::{
    CODEC_MINOR, CanonicalBody, CodecRefusal, DecodeLimits, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
    decode_body, encode_body, read_frame_header,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, InternalObjectId, RepositoryIncarnationId,
    RootLayoutVersion,
};

use crate::{
    AsyncAuthorityStore, AuthorityStore, IdentityDisagreement, ImmutableKey, ImmutableRead,
    OutcomeFailure, PutOutcome, SealFailure, body_key_for_id, canonical_body_id,
};

/// Normalized permanent repository facts across supported incarnation
/// configuration minors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryIncarnationConfiguration {
    /// Authenticated root layout.
    pub root_layout: RootLayoutVersion,
    /// Permanent native Git object identity domain.
    pub object_format: fgit_types::GitHashAlgorithm,
    /// Minted incarnation preventing delete/recreate resurrection.
    pub repository_incarnation_id: RepositoryIncarnationId,
    /// Immutable hidden-ref policy root introduced by schema 2.1.
    pub policy_root: Option<Digest>,
    /// Exact canonical capability-revocation generation introduced by schema
    /// 2.2.  Absence is data and must not be interpreted as an empty set by a
    /// high-value effect reader.
    pub capability_revocation_root: Option<Digest>,
}

/// Exact supported incarnation-configuration body selected by an authority
/// head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryIncarnationConfigurationEvidence {
    /// Historical byte-stable schema 2.0.
    V2_0(RepositoryIncarnationConfigurationBody),
    /// Hidden-ref-policy-aware schema 2.1.
    V2_1(RepositoryIncarnationConfigurationBodyV2_1),
    /// Capability-revocation-aware schema 2.2.
    V2_2(RepositoryIncarnationConfigurationBodyV2_2),
}

impl RepositoryIncarnationConfigurationEvidence {
    /// Normalizes the exact body without inventing fields absent from its
    /// published schema.
    #[must_use]
    pub const fn normalized(self) -> RepositoryIncarnationConfiguration {
        match self {
            Self::V2_0(body) => RepositoryIncarnationConfiguration {
                root_layout: body.root_layout,
                object_format: body.object_format,
                repository_incarnation_id: body.repository_incarnation_id,
                policy_root: None,
                capability_revocation_root: None,
            },
            Self::V2_1(body) => RepositoryIncarnationConfiguration {
                root_layout: body.root_layout,
                object_format: body.object_format,
                repository_incarnation_id: body.repository_incarnation_id,
                policy_root: body.policy_root,
                capability_revocation_root: None,
            },
            Self::V2_2(body) => RepositoryIncarnationConfiguration {
                root_layout: body.root_layout,
                object_format: body.object_format,
                repository_incarnation_id: body.repository_incarnation_id,
                policy_root: body.policy_root,
                capability_revocation_root: body.capability_revocation_root,
            },
        }
    }

    fn canonical_identity(self) -> Result<InternalObjectId, OutcomeFailure> {
        match self {
            Self::V2_0(body) => configuration_identity(&body),
            Self::V2_1(body) => configuration_identity(&body),
            Self::V2_2(body) => configuration_identity(&body),
        }
    }
}

/// Stage one schema-2.2 incarnation configuration and return the exact digest
/// an authority head places in `configuration_root`.
pub fn stage_revocation_aware_repository_incarnation_configuration<S>(
    store: &S,
    configuration: &RepositoryIncarnationConfigurationBodyV2_2,
) -> Result<Digest, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = crate::body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    match store.put_if_absent(&key, &encode_body(configuration)?)? {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => {
            return Err(OutcomeFailure::Seal(Box::new(
                SealFailure::SlotContentUnexpected {
                    slot: "repository configuration",
                },
            )));
        }
    }
    let identity = configuration_identity(configuration)?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// Production asynchronous twin of
/// [`stage_revocation_aware_repository_incarnation_configuration`].
pub async fn stage_revocation_aware_repository_incarnation_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration: &RepositoryIncarnationConfigurationBodyV2_2,
) -> Result<Digest, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = crate::body_key(IdentityDomain::RepositoryConfiguration, configuration)?;
    match store
        .put_if_absent(cx, &key, &encode_body(configuration)?)
        .await?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => {
            return Err(OutcomeFailure::Seal(Box::new(
                SealFailure::SlotContentUnexpected {
                    slot: "repository configuration",
                },
            )));
        }
    }
    let identity = configuration_identity(configuration)?;
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

/// Read and normalize one exact supported incarnation configuration.
pub fn read_repository_incarnation_configuration<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfiguration, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    Ok(
        read_repository_incarnation_configuration_evidence(store, configuration_root)?
            .normalized(),
    )
}

/// Production asynchronous twin of
/// [`read_repository_incarnation_configuration`].
pub async fn read_repository_incarnation_configuration_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfiguration, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    Ok(
        read_repository_incarnation_configuration_evidence_async(
            store,
            cx,
            configuration_root,
        )
        .await?
        .normalized(),
    )
}

/// Read exact-minor incarnation-configuration evidence and require it to
/// re-identify to `configuration_root`.
pub fn read_repository_incarnation_configuration_evidence<S>(
    store: &S,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfigurationEvidence, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(&key)? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    identified_configuration(&bytes, configuration_root)
}

/// Production asynchronous twin of
/// [`read_repository_incarnation_configuration_evidence`].
pub async fn read_repository_incarnation_configuration_evidence_async<S>(
    store: &S,
    cx: &S::Context,
    configuration_root: &Digest,
) -> Result<RepositoryIncarnationConfigurationEvidence, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = configuration_key(configuration_root)?;
    let ImmutableRead::Present(bytes) = store.read_immutable(cx, &key).await? else {
        return Err(OutcomeFailure::ConfigurationUnresolvable);
    };
    identified_configuration(&bytes, configuration_root)
}

fn configuration_key(root: &Digest) -> Result<ImmutableKey, OutcomeFailure> {
    let identity = InternalObjectId::new(
        root.algorithm(),
        IdentityDomain::RepositoryConfiguration.domain_tag(),
        CANONICAL_CODEC_VERSION,
        *root.bytes(),
    );
    Ok(body_key_for_id(&identity)?)
}

fn configuration_identity<B>(body: &B) -> Result<InternalObjectId, OutcomeFailure>
where
    B: CanonicalBody,
{
    Ok(canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        body,
    )?)
}

fn identified_configuration(
    bytes: &[u8],
    requested_root: &Digest,
) -> Result<RepositoryIncarnationConfigurationEvidence, OutcomeFailure> {
    let evidence = decode_repository_incarnation_configuration_evidence(bytes)?;
    let found = evidence.canonical_identity()?;
    let requested = InternalObjectId::new(
        requested_root.algorithm(),
        IdentityDomain::RepositoryConfiguration.domain_tag(),
        CANONICAL_CODEC_VERSION,
        *requested_root.bytes(),
    );
    if found != requested {
        return Err(OutcomeFailure::BodyIdentityMismatch {
            link: "repository configuration",
            identities: Box::new(IdentityDisagreement { requested, found }),
        });
    }
    Ok(evidence)
}

fn decode_repository_incarnation_configuration_evidence(
    bytes: &[u8],
) -> Result<RepositoryIncarnationConfigurationEvidence, OutcomeFailure> {
    let (header, _) = read_frame_header(bytes, DecodeLimits::DEFAULT)?;

    if header.codec_minor != CODEC_MINOR
        || header.domain != RepositoryIncarnationConfigurationBodyV2_2::DOMAIN
        || header.schema.family()
            != RepositoryIncarnationConfigurationBodyV2_2::SCHEMA_FAMILY
        || header.schema.major()
            != RepositoryIncarnationConfigurationBodyV2_2::SCHEMA_MAJOR
    {
        let body: RepositoryIncarnationConfigurationBodyV2_2 =
            decode_body(bytes, DecodeLimits::DEFAULT)?;
        return Ok(RepositoryIncarnationConfigurationEvidence::V2_2(body));
    }

    match header.schema.minor() {
        RepositoryIncarnationConfigurationBody::SCHEMA_MINOR => {
            let body: RepositoryIncarnationConfigurationBody =
                decode_body(bytes, DecodeLimits::DEFAULT)?;
            Ok(RepositoryIncarnationConfigurationEvidence::V2_0(body))
        }
        RepositoryIncarnationConfigurationBodyV2_1::SCHEMA_MINOR => {
            let body: RepositoryIncarnationConfigurationBodyV2_1 =
                decode_body(bytes, DecodeLimits::DEFAULT)?;
            Ok(RepositoryIncarnationConfigurationEvidence::V2_1(body))
        }
        RepositoryIncarnationConfigurationBodyV2_2::SCHEMA_MINOR => {
            let body: RepositoryIncarnationConfigurationBodyV2_2 =
                decode_body(bytes, DecodeLimits::DEFAULT)?;
            Ok(RepositoryIncarnationConfigurationEvidence::V2_2(body))
        }
        observed => Err(CodecRefusal::schema_minor_unsupported(
            RepositoryIncarnationConfigurationBodyV2_2::DOMAIN,
            observed,
            RepositoryIncarnationConfigurationBodyV2_2::SCHEMA_MINOR,
        )
        .into()),
    }
}
