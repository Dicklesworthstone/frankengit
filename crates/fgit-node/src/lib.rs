#![forbid(unsafe_code)]

//! One-process `FrankenGit` node assembly.
//!
//! This crate composes published subsystem boundaries only.  It opens the
//! admitted embedded `FrankenSQLite` authority profile on the node-owned
//! Asupersync runtime and places Git object bodies through the local immutable
//! object-fabric backend. Neither backend is represented by a node-owned map.
//!
//! Database opening and clean shutdown run through the owned runtime during
//! node lifecycle transitions. Authority operations themselves remain async:
//! no synchronous request-path adapter is introduced around the async engine.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use fgit_admission::{
    AdmissionProjection, AdmissionSnapshot, CanonicalAdmissionStore, CanonicalRefState,
    CommitMaterialization, PermittedObjectClosure, RefusalMaterialization, ValidatedClosure,
    canonical_ref_state_root, permitted_object_closure_root,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, HeadInit, HeadKey, HeadRead, ImmutableKey, ImmutableRead, KeyError,
    OutcomeLookup, PublicationOutcome, PutOutcome, StoreInstanceId, initialize_repository_async,
    publish_decisions_async, resolve_outcome_async,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_chronicle::PublicationBasis;
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_codec::{CodecRefusal, CryptoBodyIdentity, body_id, decode_body, encode_body};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, git_payload_commitment};
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_resource::{
    CacheBinding, CacheGrant, CacheGrantRefusal, CachePermit, CacheScope, Grade, LeakDisposition,
    ObligationLedger, OpaqueHandle, RegionCloseOutcome, RegionId, ResourceError, ResourceVector,
};
use fgit_runtime::{BudgetClass, NodeRuntime, RuntimeProfile, RuntimeRefusal};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch,
    RefusalCode, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, LegacyUploadPack, PackPayloadSource, PackRequest,
    Packet, PktLineDecoder, UploadPackRepository, UploadPackVersion, V1Advertisement, WireError,
    WireEvent, WireLimits, encode_packets, sideband_pack_chunk,
};
use fsqlite_types::cx::Cx as FsqliteCx;

const OBJECT_CODEC_NAMESPACE: &[u8] = b"git-object-body/v1";
const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const FABRIC_NAMESPACE_PREFIX: &[u8] = b"frankengit/node/object/";
const ADMISSION_REF_STATE_KEY_PREFIX: &[u8] = b"frankengit/admission/ref-state/v1/";
const ADMISSION_CLOSURE_KEY_PREFIX: &[u8] = b"frankengit/admission/object-closure/v1/";
const ADMISSION_CACHE_SCOPE: &[u8] = b"node/admission-cache/v1";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Immutable upload-pack facts derived from one authenticated admission snapshot.
///
/// This view carries no mutable ref map and does not infer object reachability
/// from the local object fabric.  Its advertised refs come exclusively from a
/// caller-supplied [`AdmissionProjection`] evaluated against an authenticated
/// authority basis.  The first-clone git-daemon transport is legacy V0, whose
/// wants must name an advertised ref; therefore this view deliberately refuses
/// every non-advertised want until the decision-history closure reader is wired
/// as a separate production slice.
#[derive(Clone, Debug)]
pub struct AdmissionUploadPackRepository {
    object_format: GitHashAlgorithm,
    refs: Vec<AdvertisedRef>,
}

impl AdmissionUploadPackRepository {
    /// Creates a bounded upload-pack view from a canonical admission snapshot.
    ///
    /// The snapshot is an owned immutable result of a projection rooted in an
    /// authenticated authority head; it is not a node-local source of truth.
    pub fn from_snapshot(
        snapshot: &AdmissionSnapshot,
        object_format: GitHashAlgorithm,
        limits: &WireLimits,
    ) -> Result<Self, AdmissionUploadPackRefusal> {
        if snapshot.refs.len() > limits.max_advertised_refs {
            return Err(AdmissionUploadPackRefusal::Wire(
                WireError::TooManyAdvertisedRefs {
                    limit: limits.max_advertised_refs,
                },
            ));
        }
        let mut refs = Vec::with_capacity(snapshot.refs.len());
        for (name, oid) in &snapshot.refs {
            if oid.algorithm() != object_format {
                return Err(AdmissionUploadPackRefusal::ObjectFormatMismatch {
                    expected: object_format,
                    observed: oid.algorithm(),
                });
            }
            refs.push(
                AdvertisedRef::new(*oid, name.as_bytes(), limits)
                    .map_err(AdmissionUploadPackRefusal::Wire)?,
            );
        }
        Ok(Self {
            object_format,
            refs,
        })
    }

    /// Evaluates the production admission surface at exactly one authority basis.
    ///
    /// [`fgit_admission::CanonicalAdmissionProjection`] refuses if
    /// `basis` and `authenticated` disagree, so a stale or mixed receipt does
    /// not become a transport snapshot.  The generic signature keeps node
    /// assembly bound to the published projection contract, rather than to a
    /// node-owned representation of canonical refs.
    pub fn from_projection<Projection>(
        projection: &Projection,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        object_format: GitHashAlgorithm,
        limits: &WireLimits,
    ) -> Result<Self, AdmissionUploadPackRefusal>
    where
        Projection: AdmissionProjection + ?Sized,
    {
        let snapshot = projection
            .snapshot(basis, authenticated)
            .map_err(AdmissionUploadPackRefusal::Projection)?;
        Self::from_snapshot(&snapshot, object_format, limits)
    }
}

impl UploadPackRepository for AdmissionUploadPackRepository {
    fn object_format(&self) -> GitHashAlgorithm {
        self.object_format
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.refs.iter().any(|reference| reference.oid == oid)
    }

    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.contains_want(oid)
    }
}

/// Refusal while deriving a transport view from canonical admission state.
#[derive(Debug)]
pub enum AdmissionUploadPackRefusal {
    /// The canonical projection refused the supplied authenticated basis.
    Projection(fgit_types::RefusalCode),
    /// A canonical ref has a native identity domain unlike this repository.
    ObjectFormatMismatch {
        /// The node's declared native object format.
        expected: GitHashAlgorithm,
        /// The format carried by the canonical ref target.
        observed: GitHashAlgorithm,
    },
    /// The wire adapter refused the bounded advertisement representation.
    Wire(WireError),
}

impl Display for AdmissionUploadPackRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Projection(code) => {
                write!(
                    formatter,
                    "admission projection refused upload-pack snapshot: {code:?}"
                )
            }
            Self::ObjectFormatMismatch { expected, observed } => write!(
                formatter,
                "canonical ref object format {observed:?} differs from node format {expected:?}"
            ),
            Self::Wire(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for AdmissionUploadPackRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Projection(_) | Self::ObjectFormatMismatch { .. } => None,
        }
    }
}

/// Refusal while reading the current node head into an upload-pack view.
#[derive(Debug)]
pub enum NodeAdmissionViewRefusal {
    /// The durable authority read or authentication refused.
    Authority(NodeRefusal),
    /// The durable canonical-admission materializer refused the selected head.
    Materialization(AdmissionMaterializationRefusal),
    /// The authenticated receipt did not carry one usable authority-head body.
    HeadBody(fgit_authority::HeadBodyRefusal),
    /// The canonical authority-head body could not be re-identified.
    HeadIdentity(fgit_codec::CodecRefusal),
    /// The re-identified body did not belong to the authority-head domain.
    HeadIdentityDomain(fgit_types::TypeRefusal),
    /// Canonical admission or wire-view construction refused.
    View(AdmissionUploadPackRefusal),
}

impl Display for NodeAdmissionViewRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::Materialization(error) => Display::fmt(error, formatter),
            Self::HeadBody(error) => Display::fmt(error, formatter),
            Self::HeadIdentity(error) => Display::fmt(error, formatter),
            Self::HeadIdentityDomain(error) => Display::fmt(error, formatter),
            Self::View(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeAdmissionViewRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Materialization(error) => Some(error),
            Self::HeadBody(error) => Some(error),
            Self::HeadIdentity(error) => Some(error),
            Self::HeadIdentityDomain(error) => Some(error),
            Self::View(error) => Some(error),
        }
    }
}

/// Authority-backed materialization of the canonical admission state selected
/// by one exact authenticated repository head.
///
/// Canonical ref frames live in immutable authority slots.  The synchronous
/// [`CanonicalAdmissionStore`] view below is deliberately only a cache of one
/// such materialization: it never reads the database, calls `block_on`, or
/// treats its cache as canonical.  A caller must first refresh it through the
/// async authority contract, and its projection refuses a different head,
/// basis, repository, policy epoch, or configuration root.
#[derive(Debug)]
pub struct DurableAdmissionMaterializer {
    materialized: RwLock<Option<MaterializedAdmissionState>>,
    cache_scope: CacheScope,
}

#[derive(Clone, Debug)]
struct MaterializedAdmissionState {
    authenticated: AuthenticatedHead,
    basis: PublicationBasis,
    cache_permit: CachePermit,
    ref_state: CanonicalRefState,
    policy_epoch: PolicyEpoch,
    configuration_root: Digest,
}

/// One immutable admission snapshot paired with the authority receipt that
/// selected it.
///
/// The receipt is intentionally retained with the snapshot.  A user that
/// needs the generic admission interface can pass the same receipt and basis
/// to [`AdmissionProjection::snapshot`]; mixing an otherwise-valid snapshot
/// with another head is a typed refusal.
#[derive(Clone, Debug)]
pub struct MaterializedAdmission {
    authenticated: AuthenticatedHead,
    basis: PublicationBasis,
    snapshot: AdmissionSnapshot,
}

impl MaterializedAdmission {
    /// The exact authenticated receipt whose head selected this snapshot.
    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedHead {
        &self.authenticated
    }

    /// The exact publication basis reconstructed from that receipt.
    #[must_use]
    pub const fn basis(&self) -> &PublicationBasis {
        &self.basis
    }

    /// The immutable ref view selected by the authenticated head.
    #[must_use]
    pub const fn snapshot(&self) -> &AdmissionSnapshot {
        &self.snapshot
    }
}

/// Failure while staging or refreshing canonical admission state through the
/// durable async authority surface.
#[derive(Debug)]
pub enum AdmissionMaterializationRefusal {
    /// The repository head has not been initialized.
    HeadAbsent,
    /// The materializer catch-up scope was cancelled before it could install
    /// a verified cache record.
    Cancelled,
    /// The authority operation refused or became ambiguous.
    Authority(AuthorityFailure),
    /// The authenticated receipt could not be decoded as its typed head.
    HeadBody(fgit_authority::HeadBodyRefusal),
    /// The authenticated head belongs to a different repository.
    RepositoryMismatch {
        /// Repository selected by the caller/node configuration.
        expected: RepositoryId,
        /// Repository encoded in the authenticated head.
        observed: RepositoryId,
    },
    /// Re-identifying the typed authority head failed.
    HeadIdentity(CodecRefusal),
    /// The head identity carried a different domain than an authority head.
    HeadIdentityDomain(fgit_types::TypeRefusal),
    /// A canonical admission frame could not be encoded or decoded.
    CanonicalFrame(CodecRefusal),
    /// A canonical frame did not reproduce the root named by authority.
    CanonicalRoot(RefusalCode),
    /// No immutable canonical frame existed for the authority-selected root.
    ImmutableAbsent(Digest),
    /// A deterministic immutable key was already occupied by different bytes.
    ImmutableConflict,
    /// The caller-derived immutable key exceeded the authority key contract.
    Key(KeyError),
    /// The bounded resource ledger could not fund a cache materialization.
    Resource(ResourceError),
    /// The exact authenticated basis could not accept the cache grant.
    CacheGrant(CacheGrantRefusal),
    /// The cache grant ledger did not reach quiescence after the attempt.
    CacheContainment,
    /// The process-local materialization cache was poisoned.
    CachePoisoned,
}

impl Display for AdmissionMaterializationRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadAbsent => formatter.write_str("canonical admission head is absent"),
            Self::Cancelled => {
                formatter.write_str("canonical admission materialization was cancelled")
            }
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::HeadBody(error) => Display::fmt(error, formatter),
            Self::RepositoryMismatch { expected, observed } => write!(
                formatter,
                "authenticated admission head repository {observed:?} differs from {expected:?}"
            ),
            Self::HeadIdentity(error) | Self::CanonicalFrame(error) => {
                Display::fmt(error, formatter)
            }
            Self::HeadIdentityDomain(error) => Display::fmt(error, formatter),
            Self::CanonicalRoot(code) => write!(
                formatter,
                "canonical admission body did not reproduce its authority root: {code:?}"
            ),
            Self::ImmutableAbsent(root) => {
                write!(formatter, "canonical admission body {root} is absent")
            }
            Self::ImmutableConflict => {
                formatter.write_str("canonical admission immutable slot conflicts")
            }
            Self::Key(error) => Display::fmt(error, formatter),
            Self::Resource(error) => Display::fmt(error, formatter),
            Self::CacheGrant(error) => Display::fmt(error, formatter),
            Self::CacheContainment => {
                formatter.write_str("canonical admission cache grant did not reach quiescence")
            }
            Self::CachePoisoned => formatter.write_str("canonical admission cache is poisoned"),
        }
    }
}

impl Error for AdmissionMaterializationRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::HeadBody(error) => Some(error),
            Self::HeadIdentity(error) | Self::CanonicalFrame(error) => Some(error),
            Self::HeadIdentityDomain(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::CacheGrant(error) => Some(error),
            Self::HeadAbsent
            | Self::Cancelled
            | Self::RepositoryMismatch { .. }
            | Self::CanonicalRoot(_)
            | Self::ImmutableAbsent(_)
            | Self::ImmutableConflict
            | Self::CacheContainment
            | Self::CachePoisoned => None,
        }
    }
}

impl DurableAdmissionMaterializer {
    /// Creates the bounded cache view for one caller-authorized scope.
    ///
    /// The scope cannot grant authority: every served entry is still checked
    /// against an exact authenticated authority head through its cache permit.
    #[must_use]
    pub const fn new(cache_scope: CacheScope) -> Self {
        Self {
            materialized: RwLock::new(None),
            cache_scope,
        }
    }

    /// Stages one immutable canonical ref-state frame through the async
    /// authority contract and returns the root its bytes prove.
    ///
    /// The frame becomes durable (or is proven an identical retry) before any
    /// authority head may name its root.  A collision is refused rather than
    /// overwritten.
    pub async fn stage_ref_state_in<Authority>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        repository_id: RepositoryId,
        state: CanonicalRefState,
    ) -> Result<Digest, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
    {
        let root = canonical_ref_state_root(&state)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let frame = encode_body(&state).map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        let key = admission_immutable_key(ADMISSION_REF_STATE_KEY_PREFIX, repository_id, root)
            .map_err(AdmissionMaterializationRefusal::Key)?;
        stage_immutable_frame(authority, cx, &key, &frame).await?;
        Ok(root)
    }

    /// Stages one immutable validated object-closure frame through authority.
    ///
    /// This deliberately does not make the closure current: only the selected
    /// RCR can do that, and a head does not carry a closure root.  Until the
    /// chronicle reader is composed, synchronous closure resolution remains a
    /// typed absence rather than an invented association.
    pub async fn stage_permitted_object_closure_in<Authority>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        repository_id: RepositoryId,
        closure: PermittedObjectClosure,
    ) -> Result<Digest, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
    {
        let root = permitted_object_closure_root(&closure)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let frame =
            encode_body(&closure).map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        let key = admission_immutable_key(ADMISSION_CLOSURE_KEY_PREFIX, repository_id, root)
            .map_err(AdmissionMaterializationRefusal::Key)?;
        stage_immutable_frame(authority, cx, &key, &frame).await?;
        Ok(root)
    }

    /// Reads, authenticates, and materializes the authority-selected canonical
    /// ref frame for one repository.
    ///
    /// The one mutable field in this type is only a bounded decoded cache.
    /// It is replaced after the immutable frame and every binding have been
    /// validated, and is never consulted as an authority source.
    pub async fn materialize_current_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        head_key: &HeadKey,
        repository_id: RepositoryId,
        is_cancelled: &IsCancelled,
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        ensure_materializer_catch_up_live(is_cancelled)?;
        let HeadRead::Present(receipt) = authority
            .read_head(cx, head_key)
            .await
            .map_err(AdmissionMaterializationRefusal::Authority)?
        else {
            return Err(AdmissionMaterializationRefusal::HeadAbsent);
        };
        ensure_materializer_catch_up_live(is_cancelled)?;
        let authenticated = authority
            .authenticate_head_receipt(cx, &receipt)
            .await
            .map_err(AdmissionMaterializationRefusal::Authority)?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        let body = authenticated
            .body()
            .map_err(AdmissionMaterializationRefusal::HeadBody)?;
        if body.repository_id != repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: repository_id,
                observed: body.repository_id,
            });
        }
        let head_id = body_id(&CryptoBodyIdentity, &body)
            .map_err(AdmissionMaterializationRefusal::HeadIdentity)
            .and_then(|identity| {
                RepositoryAuthorityHeadId::from_internal_object_id(identity)
                    .map_err(AdmissionMaterializationRefusal::HeadIdentityDomain)
            })?;
        let basis = PublicationBasis::new(head_id, body.clone());
        let cache_binding =
            CacheBinding::new(repository_id, head_id, body.generation, self.cache_scope);
        ensure_materializer_catch_up_live(is_cancelled)?;
        let cache_resources = admission_cache_resources();
        let cache_ledger = ObligationLedger::root(
            RegionId::new(body.generation.get()),
            LeakDisposition::RecordAndContinue,
            cache_resources,
        );
        let cache_budget = cache_ledger
            .grant(cache_resources)
            .map_err(AdmissionMaterializationRefusal::Resource)?;
        let cache_result = async {
            // The reservation comes before the immutable read, decode, and
            // resident snapshot construction it funds. Any error or
            // cancellation drops/discards it and leaves no permit to install.
            let cache_grant = CacheGrant::reserve(cache_binding, cache_budget)
                .map_err(AdmissionMaterializationRefusal::CacheGrant)?;
            ensure_materializer_catch_up_live(is_cancelled)?;
            let key = admission_immutable_key(
                ADMISSION_REF_STATE_KEY_PREFIX,
                repository_id,
                body.ref_root,
            )
            .map_err(AdmissionMaterializationRefusal::Key)?;
            let ImmutableRead::Present(frame) = authority
                .read_immutable(cx, &key)
                .await
                .map_err(AdmissionMaterializationRefusal::Authority)?
            else {
                return Err(AdmissionMaterializationRefusal::ImmutableAbsent(
                    body.ref_root,
                ));
            };
            ensure_materializer_catch_up_live(is_cancelled)?;
            let ref_state =
                decode_body::<CanonicalRefState>(&frame, fgit_codec::DecodeLimits::DEFAULT)
                    .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
            if canonical_ref_state_root(&ref_state)
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?
                != body.ref_root
            {
                return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                    RefusalCode::InternalInvariantBreach,
                ));
            }
            let snapshot = AdmissionSnapshot {
                refs: ref_state.refs().clone(),
                forge_positions: BTreeMap::new(),
                retention: BTreeSet::new(),
                outbox: BTreeMap::new(),
            };
            let cache_permit = cache_grant
                .accept(cache_binding)
                .map_err(AdmissionMaterializationRefusal::CacheGrant)?;
            ensure_materializer_catch_up_live(is_cancelled)?;
            let materialized = MaterializedAdmission {
                authenticated: authenticated.clone(),
                basis: basis.clone(),
                snapshot,
            };
            let state = MaterializedAdmissionState {
                authenticated,
                basis,
                cache_permit,
                ref_state,
                policy_epoch: body.policy_epoch,
                configuration_root: body.configuration_root,
            };
            Ok((materialized, state))
        }
        .await;
        let cache_close = cache_ledger.close();
        if !cache_close.is_quiescent() {
            return Err(AdmissionMaterializationRefusal::CacheContainment);
        }
        let (materialized, state) = cache_result?;
        // No await follows this final catch-up checkpoint. A cancelled scope
        // therefore cannot install a readable partial materialization.
        ensure_materializer_catch_up_live(is_cancelled)?;
        *self
            .materialized
            .write()
            .map_err(|_| AdmissionMaterializationRefusal::CachePoisoned)? = Some(state);
        Ok(materialized)
    }

    fn snapshot_for(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        let authenticated_body = authenticated
            .body()
            .map_err(|_| RefusalCode::AuthorityReceiptInvalid)?;
        if authenticated_body != *basis.body() {
            self.discard_materialized_cache()?;
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let cache_binding = CacheBinding::new(
            authenticated_body.repository_id,
            basis.id(),
            authenticated_body.generation,
            self.cache_scope,
        );
        let mut guard = self
            .materialized
            .write()
            .map_err(|_| RefusalCode::InternalInvariantBreach)?;
        let Some(materialized) = guard.as_ref() else {
            return Err(RefusalCode::EvidenceMissing);
        };
        let mismatched = materialized.authenticated != *authenticated
            || materialized.basis != *basis
            || materialized.basis.body().repository_id != authenticated_body.repository_id
            || materialized.policy_epoch != authenticated_body.policy_epoch
            || materialized.configuration_root != authenticated_body.configuration_root
            || canonical_ref_state_root(&materialized.ref_state)? != authenticated_body.ref_root
            || CachePermit::require_matching(Some(&materialized.cache_permit), cache_binding)
                .is_err();
        if mismatched {
            // CALM-015: an absent or mismatched authenticated basis cannot
            // leave a reusable derived view behind.
            *guard = None;
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let refs = guard
            .as_ref()
            .ok_or(RefusalCode::EvidenceMissing)?
            .ref_state
            .refs()
            .clone();
        drop(guard);
        Ok(AdmissionSnapshot {
            refs,
            forge_positions: BTreeMap::new(),
            retention: BTreeSet::new(),
            outbox: BTreeMap::new(),
        })
    }

    fn discard_materialized_cache(&self) -> Result<(), RefusalCode> {
        let mut guard = self
            .materialized
            .write()
            .map_err(|_| RefusalCode::InternalInvariantBreach)?;
        *guard = None;
        Ok(())
    }
}

impl CanonicalAdmissionStore for DurableAdmissionMaterializer {
    fn resolve_ref_state(&self, root: Digest) -> Result<CanonicalRefState, RefusalCode> {
        let mut guard = self
            .materialized
            .write()
            .map_err(|_| RefusalCode::InternalInvariantBreach)?;
        let Some(materialized) = guard.as_ref() else {
            return Err(RefusalCode::EvidenceMissing);
        };
        let binding = CacheBinding::new(
            materialized.basis.body().repository_id,
            materialized.basis.id(),
            materialized.basis.generation(),
            self.cache_scope,
        );
        if CachePermit::require_matching(Some(&materialized.cache_permit), binding).is_err() {
            *guard = None;
            return Err(RefusalCode::EvidenceMissing);
        }
        if materialized.basis.body().ref_root != root {
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let ref_state = materialized.ref_state.clone();
        drop(guard);
        Ok(ref_state)
    }

    fn stage_ref_state(&self, _root: Digest, _state: CanonicalRefState) -> Result<(), RefusalCode> {
        Err(RefusalCode::DurabilityProfileUnavailable)
    }

    fn resolve_permitted_object_closure(
        &self,
        _root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
        Err(RefusalCode::EvidenceMissing)
    }

    fn stage_permitted_object_closure(
        &self,
        _root: Digest,
        _closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        Err(RefusalCode::DurabilityProfileUnavailable)
    }
}

impl AdmissionProjection for DurableAdmissionMaterializer {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        self.snapshot_for(basis, authenticated)
    }

    fn materialize_commit(
        &self,
        _basis: &PublicationBasis,
        _request: &fgit_reference::intent::TransactionRequest,
        _fold: &fgit_txn::TransactionFoldReport,
        _closure: &ValidatedClosure,
    ) -> Result<CommitMaterialization, RefusalCode> {
        Err(RefusalCode::DurabilityProfileUnavailable)
    }

    fn materialize_refusal(
        &self,
        _basis: &PublicationBasis,
        _tx_id: fgit_types::TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        Err(RefusalCode::DurabilityProfileUnavailable)
    }
}

async fn stage_immutable_frame<Authority>(
    authority: &Authority,
    cx: &Authority::Context,
    key: &ImmutableKey,
    frame: &[u8],
) -> Result<(), AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
{
    match authority
        .put_if_absent(cx, key, frame)
        .await
        .map_err(AdmissionMaterializationRefusal::Authority)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
        PutOutcome::Conflict => Err(AdmissionMaterializationRefusal::ImmutableConflict),
    }
}

fn ensure_materializer_catch_up_live(
    is_cancelled: &impl Fn() -> bool,
) -> Result<(), AdmissionMaterializationRefusal> {
    if is_cancelled() {
        Err(AdmissionMaterializationRefusal::Cancelled)
    } else {
        Ok(())
    }
}

fn admission_immutable_key(
    namespace: &[u8],
    repository_id: RepositoryId,
    root: Digest,
) -> Result<ImmutableKey, KeyError> {
    let mut bytes = Vec::with_capacity(
        namespace.len() + repository_id.as_bytes().len() + size_of::<u16>() + root.bytes().len(),
    );
    bytes.extend_from_slice(namespace);
    bytes.extend_from_slice(repository_id.as_bytes());
    bytes.extend_from_slice(&root.algorithm().code_point().to_be_bytes());
    bytes.extend_from_slice(root.bytes().as_bytes());
    ImmutableKey::new(bytes)
}

/// Typed refusal from the node assembly boundary.
#[derive(Debug)]
pub enum NodeRefusal {
    /// An empty filesystem root would make the storage target ambiguous.
    EmptyStorageRoot,
    /// A caller-selected worker count was outside this slice's finite profile.
    InvalidWorkerCount,
    /// The runtime could not establish its finite production profile.
    Runtime(RuntimeRefusal),
    /// Authority-head staging or initialization refused or was ambiguous.
    Authority(fgit_authority::OutcomeFailure),
    /// Durable canonical-admission staging or refresh refused.
    AdmissionMaterialization(AdmissionMaterializationRefusal),
    /// A non-initializing open found no canonical authority head.
    AuthorityHeadAbsent,
    /// A supplied authority materialization names another repository.
    RepositoryMismatch,
    /// The operator-selected storage root cannot name the embedded database.
    StoragePathEncoding,
    /// The derived authority-head key was outside the bounded key vocabulary.
    HeadKey(fgit_authority::KeyError),
    /// A newly constructed durable authority unexpectedly held another head.
    HeadInitializationConflict,
    /// Authority initialization failed and its explicit worker cleanup failed too.
    AuthorityInitializationCleanup {
        /// The initialization failure observed before cleanup.
        initialization: Box<Self>,
        /// The failure while awaiting the authority worker's close.
        cleanup: Box<Self>,
    },
    /// A non-initializing open failed and then could not prove clean teardown.
    ExistingOpenCleanup {
        /// The refusal observed while opening or authenticating the head.
        opening: Box<Self>,
        /// The refusal while draining the partially opened node.
        cleanup: Box<Self>,
    },
    /// The local immutable object fabric refused the requested operation.
    Fabric(StoreRefusal),
    /// Object bytes exceeded this node's configured storage bound.
    ObjectTooLarge { offered: u64, maximum: u64 },
    /// A platform-sized object length could not be represented canonically.
    ObjectLengthOverflow,
    /// Resource custody could not issue the bounded placement grant.
    Resource(ResourceError),
    /// A storage effect failed to settle its obligation region.
    ResourceContainment,
    /// The node root did not quiesce within its bounded shutdown interval.
    RuntimeContainment,
    /// A fixed node identity handle failed its bounded representation.
    Identity(fgit_resource::IdentityError),
}

impl Display for NodeRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStorageRoot => formatter.write_str("node storage root is empty"),
            Self::InvalidWorkerCount => formatter.write_str("node worker count must be non-zero"),
            Self::Runtime(error) => Display::fmt(error, formatter),
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::AdmissionMaterialization(error) => Display::fmt(error, formatter),
            Self::AuthorityHeadAbsent => {
                formatter.write_str("node authority head is absent; run fg init before doctor")
            }
            Self::RepositoryMismatch => formatter
                .write_str("authority materialization does not belong to this node repository"),
            Self::StoragePathEncoding => formatter.write_str(
                "node storage root cannot be represented as a UTF-8 embedded authority path",
            ),
            Self::HeadKey(error) => Display::fmt(error, formatter),
            Self::HeadInitializationConflict => {
                formatter.write_str("durable authority head conflicts during initialization")
            }
            Self::AuthorityInitializationCleanup {
                initialization,
                cleanup,
            } => write!(
                formatter,
                "authority initialization failed ({initialization}) and explicit cleanup failed ({cleanup})"
            ),
            Self::ExistingOpenCleanup { opening, cleanup } => write!(
                formatter,
                "non-initializing node open failed ({opening}) and explicit cleanup failed ({cleanup})"
            ),
            Self::Fabric(error) => Display::fmt(error, formatter),
            Self::ObjectTooLarge { offered, maximum } => {
                write!(
                    formatter,
                    "object is {offered} bytes but node limit is {maximum}"
                )
            }
            Self::ObjectLengthOverflow => {
                formatter.write_str("object length exceeds canonical range")
            }
            Self::Resource(error) => Display::fmt(error, formatter),
            Self::ResourceContainment => {
                formatter.write_str("object placement region did not reach quiescence")
            }
            Self::RuntimeContainment => {
                formatter.write_str("node runtime did not reach quiescence during shutdown")
            }
            Self::Identity(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::AdmissionMaterialization(error) => Some(error),
            Self::HeadKey(error) => Some(error),
            Self::AuthorityInitializationCleanup { initialization, .. } => Some(initialization),
            Self::ExistingOpenCleanup { opening, .. } => Some(opening),
            Self::Fabric(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::EmptyStorageRoot
            | Self::InvalidWorkerCount
            | Self::AuthorityHeadAbsent
            | Self::RepositoryMismatch
            | Self::HeadInitializationConflict
            | Self::StoragePathEncoding
            | Self::ObjectTooLarge { .. }
            | Self::ObjectLengthOverflow
            | Self::ResourceContainment
            | Self::RuntimeContainment => None,
        }
    }
}

/// A repository path accepted by the git-daemon transport boundary.
///
/// This is an opaque authority lookup key, never a filesystem path.  The
/// daemon grammar requires an absolute slash-prefixed path, while the path
/// validator rejects empty, dot, parent, and control-byte components before a
/// future authority-backed resolver sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonRepositoryPath(Vec<u8>);

impl GitDaemonRepositoryPath {
    /// Returns the exact wire bytes of the validated authority lookup key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn parse(path: &[u8]) -> Result<Self, GitDaemonTransportRefusal> {
        if path.is_empty() {
            return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                reason: GitDaemonPathRefusal::Empty,
            });
        }
        if !path.starts_with(b"/") {
            return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                reason: GitDaemonPathRefusal::NotAbsolute,
            });
        }
        for component in path[1..].split(|byte| *byte == b'/') {
            if component.is_empty() {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::EmptyComponent,
                });
            }
            if component == b"." {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::DotComponent,
                });
            }
            if component == b".." {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::ParentComponent,
                });
            }
            if component.iter().any(|byte| byte.is_ascii_control()) {
                return Err(GitDaemonTransportRefusal::InvalidRepositoryPath {
                    reason: GitDaemonPathRefusal::ControlByte,
                });
            }
        }
        Ok(Self(path.to_vec()))
    }
}

/// Why a git-daemon repository lookup key was refused before authority lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitDaemonPathRefusal {
    /// The service request did not name a repository.
    Empty,
    /// Git-daemon requires the repository name to begin with `/`.
    NotAbsolute,
    /// A repeated slash or trailing slash created an empty path component.
    EmptyComponent,
    /// A `.` component would admit an alternate spelling of the same key.
    DotComponent,
    /// A `..` component could be interpreted as a filesystem traversal.
    ParentComponent,
    /// A path component included an ASCII control byte.
    ControlByte,
}

impl Display for GitDaemonPathRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("repository path is empty"),
            Self::NotAbsolute => formatter.write_str("repository path is not absolute"),
            Self::EmptyComponent => formatter.write_str("repository path has an empty component"),
            Self::DotComponent => formatter.write_str("repository path has a dot component"),
            Self::ParentComponent => formatter.write_str("repository path has a parent component"),
            Self::ControlByte => formatter.write_str("repository path has a control byte"),
        }
    }
}

impl Error for GitDaemonPathRefusal {}

/// The parsed git-daemon opening request for the supported upload-pack lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonRequest {
    repository_path: GitDaemonRepositoryPath,
}

impl GitDaemonRequest {
    /// Returns the canonical authority lookup key requested by the client.
    #[must_use]
    pub const fn repository_path(&self) -> &GitDaemonRepositoryPath {
        &self.repository_path
    }
}

/// Typed failure at the git-daemon transport boundary.
#[derive(Debug)]
pub enum GitDaemonTransportRefusal {
    /// The byte stream could not be read or written at a named transport step.
    Io {
        /// The operation that encountered the I/O failure.
        operation: &'static str,
        /// The source I/O failure.
        source: io::Error,
    },
    /// The service-request pkt-line had malformed length syntax.
    InvalidGreetingLength,
    /// The service-request pkt-line used a control record instead of data.
    GreetingControlPacket,
    /// The service-request pkt-line was shorter than its four-byte framing header.
    GreetingPacketTooSmall { declared: usize },
    /// The service-request pkt-line exceeds the declared bounded wire profile.
    GreetingPacketTooLarge { declared: usize, maximum: usize },
    /// The complete request did not decode to exactly one pkt-line data record.
    InvalidGreetingPacketSequence { packets: usize },
    /// The service request omitted the NUL separator after the command and path.
    MissingGreetingTerminator,
    /// The command/path record had no ASCII-space separator.
    MalformedServiceRequest,
    /// The requested daemon service is not upload-pack.
    UnsupportedService { service_bytes: usize },
    /// The client requested a protocol generation outside this V0 milestone.
    UnsupportedProtocolVersion { version_bytes: usize },
    /// More than one version parameter appeared in the service request.
    DuplicateProtocolVersion,
    /// The path cannot name a canonical repository lookup key.
    InvalidRepositoryPath {
        /// The precise lexical refusal.
        reason: GitDaemonPathRefusal,
    },
    /// A complete pkt-line negotiation was not supplied before transport EOF.
    IncompleteNegotiation,
    /// The existing wire state machine rejected a bounded protocol input/output.
    Wire(WireError),
}

impl Display for GitDaemonTransportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "git-daemon {operation}: {source}"),
            Self::InvalidGreetingLength => {
                formatter.write_str("git-daemon greeting has a non-hex pkt-line length")
            }
            Self::GreetingControlPacket => {
                formatter.write_str("git-daemon greeting must be one data pkt-line")
            }
            Self::GreetingPacketTooSmall { declared } => {
                write!(
                    formatter,
                    "git-daemon greeting packet is too short: {declared}"
                )
            }
            Self::GreetingPacketTooLarge { declared, maximum } => write!(
                formatter,
                "git-daemon greeting packet is {declared} bytes, above {maximum}"
            ),
            Self::InvalidGreetingPacketSequence { packets } => write!(
                formatter,
                "git-daemon greeting must contain one data packet, found {packets}"
            ),
            Self::MissingGreetingTerminator => {
                formatter.write_str("git-daemon greeting lacks the NUL service terminator")
            }
            Self::MalformedServiceRequest => {
                formatter.write_str("git-daemon greeting lacks a command/path separator")
            }
            Self::UnsupportedService { service_bytes } => write!(
                formatter,
                "git-daemon requested an unsupported service ({service_bytes} bytes)"
            ),
            Self::UnsupportedProtocolVersion { version_bytes } => write!(
                formatter,
                "git-daemon requested an unsupported protocol version ({version_bytes} bytes)"
            ),
            Self::DuplicateProtocolVersion => {
                formatter.write_str("git-daemon greeting specifies protocol version more than once")
            }
            Self::InvalidRepositoryPath { reason } => Display::fmt(reason, formatter),
            Self::IncompleteNegotiation => formatter
                .write_str("git-daemon transport ended before a complete upload-pack request"),
            Self::Wire(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for GitDaemonTransportRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidRepositoryPath { reason } => Some(reason),
            Self::Wire(error) => Some(error),
            Self::InvalidGreetingLength
            | Self::GreetingControlPacket
            | Self::GreetingPacketTooSmall { .. }
            | Self::GreetingPacketTooLarge { .. }
            | Self::InvalidGreetingPacketSequence { .. }
            | Self::MissingGreetingTerminator
            | Self::MalformedServiceRequest
            | Self::UnsupportedService { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::DuplicateProtocolVersion
            | Self::IncompleteNegotiation => None,
        }
    }
}

/// A transport or canonical-pack-construction failure from one served session.
#[derive(Debug)]
pub enum GitDaemonServeError<PackError> {
    /// The socket/stdin transport or wire protocol was refused.
    Transport(GitDaemonTransportRefusal),
    /// The authority-backed canonical pack builder declined the selected request.
    Pack(PackError),
}

impl<PackError: Display> Display for GitDaemonServeError<PackError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
        }
    }
}

impl<PackError: Error + 'static> Error for GitDaemonServeError<PackError> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Pack(error) => Some(error),
        }
    }
}

/// Evidence that one legacy upload-pack request was completely emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonSessionReceipt {
    request: GitDaemonRequest,
    pack_request: PackRequest,
}

impl GitDaemonSessionReceipt {
    /// Returns the parsed git-daemon service request.
    #[must_use]
    pub const fn request(&self) -> &GitDaemonRequest {
        &self.request
    }

    /// Returns the exact wire-validated fetch request sent to the pack builder.
    #[must_use]
    pub const fn pack_request(&self) -> &PackRequest {
        &self.pack_request
    }
}

/// Parses one complete git-daemon opening pkt-line.
///
/// Only legacy V0 `git-upload-pack` is accepted for the first-clone vertical
/// slice. Service selection and repository path validation belong here; pkt
/// line syntax remains owned by `fgit-wire`'s published decoder.
pub fn parse_git_daemon_request(
    frame: &[u8],
    limits: WireLimits,
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let mut decoder = PktLineDecoder::new(limits).map_err(GitDaemonTransportRefusal::Wire)?;
    let packets = decoder
        .push(frame)
        .map_err(GitDaemonTransportRefusal::Wire)?;
    decoder.finish().map_err(GitDaemonTransportRefusal::Wire)?;
    let [Packet::Data(payload)] = packets.as_slice() else {
        if packets
            .iter()
            .any(|packet| !matches!(packet, Packet::Data(_)))
        {
            return Err(GitDaemonTransportRefusal::GreetingControlPacket);
        }
        return Err(GitDaemonTransportRefusal::InvalidGreetingPacketSequence {
            packets: packets.len(),
        });
    };
    parse_git_daemon_request_payload(payload)
}

/// Serves one bounded legacy V0 git-daemon upload-pack session.
///
/// The caller supplies an authority-backed `UploadPackRepository` snapshot and
/// constructs the pack only after the verified wire machine emits
/// [`WireEvent::PackRequested`]. This adapter deliberately owns neither a ref
/// map nor an object catalog: a future `OneNode` binding must resolve the
/// requested path through the authenticated authority head and use the
/// canonical pack planner/writer for `build_pack`.
///
/// The first-clone lane advertises exactly the supplied capabilities. Its
/// intended caller passes an empty capability set, yielding raw `PACK` bytes
/// after the final negotiated ACK/NAK. When a later caller explicitly enables
/// `side-band-64k`, this adapter preserves the wire crate's bounded
/// pull/write ordering and emits a terminal flush after the payload.
pub fn serve_git_daemon_upload_pack<R, W, BuildPack, Payload, PackError>(
    reader: &mut R,
    writer: &mut W,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionReceipt, GitDaemonServeError<PackError>>
where
    R: Read,
    W: Write,
    BuildPack: FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, PackError>,
    Payload: PackPayloadSource,
{
    let request =
        read_git_daemon_request(reader, &limits).map_err(GitDaemonServeError::Transport)?;
    let advertisement = V1Advertisement::new(
        repository.advertised_refs().to_vec(),
        capabilities.clone(),
        repository.object_format(),
        &limits,
    )
    .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    write_packet_group(
        writer,
        &advertisement.encode(&limits).map_err(|error| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
        })?,
        &limits,
    )
    .map_err(GitDaemonServeError::Transport)?;

    let mut machine = LegacyUploadPack::new(UploadPackVersion::V0, capabilities, limits.clone())
        .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    let mut input = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut input).map_err(|source| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
                operation: "read upload-pack negotiation",
                source,
            })
        })?;
        if read == 0 {
            machine.finish().map_err(|error| {
                GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
            })?;
            return Err(GitDaemonServeError::Transport(
                GitDaemonTransportRefusal::IncompleteNegotiation,
            ));
        }

        let transition = machine
            .push_bytes(&input[..read], repository)
            .map_err(|error| {
                GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
            })?;
        write_packet_group(writer, &transition.output, &limits)
            .map_err(GitDaemonServeError::Transport)?;

        for event in transition.events {
            let WireEvent::PackRequested(pack_request) = event else {
                continue;
            };
            if !machine.is_complete() {
                return Err(GitDaemonServeError::Transport(
                    GitDaemonTransportRefusal::IncompleteNegotiation,
                ));
            }
            let mut payload =
                build_pack(&request, &pack_request).map_err(GitDaemonServeError::Pack)?;
            emit_pack_payload(writer, &mut payload, &pack_request, &limits)
                .map_err(GitDaemonServeError::Transport)?;
            return Ok(GitDaemonSessionReceipt {
                request,
                pack_request,
            });
        }
    }
}

/// Accepts and completes one git-daemon upload-pack connection.
///
/// A node-owned listener loop owns repetition, shutdown requests, and the
/// in-flight-session drain. This one-shot primitive performs the protocol
/// session and sends the server write-half EOF after raw V0 pack bytes, which
/// is the completion marker required by legacy clients.
pub fn serve_git_daemon_tcp_once<BuildPack, Payload, PackError>(
    listener: &TcpListener,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    build_pack: BuildPack,
) -> Result<GitDaemonSessionReceipt, GitDaemonServeError<PackError>>
where
    BuildPack: FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, PackError>,
    Payload: PackPayloadSource,
{
    let (mut stream, _) = listener.accept().map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "accept git-daemon connection",
            source,
        })
    })?;
    let mut writer = stream.try_clone().map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "duplicate git-daemon connection for response writes",
            source,
        })
    })?;
    let receipt = serve_git_daemon_upload_pack(
        &mut stream,
        &mut writer,
        repository,
        capabilities,
        limits,
        build_pack,
    )?;
    writer.shutdown(Shutdown::Write).map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "send git-daemon response EOF",
            source,
        })
    })?;
    Ok(receipt)
}

fn parse_git_daemon_request_payload(
    payload: &[u8],
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let Some(terminator) = payload.iter().position(|byte| *byte == 0) else {
        return Err(GitDaemonTransportRefusal::MissingGreetingTerminator);
    };
    let service_and_path = &payload[..terminator];
    let parameters = &payload[terminator + 1..];
    if !parameters.is_empty() && !parameters.ends_with(&[0]) {
        return Err(GitDaemonTransportRefusal::MissingGreetingTerminator);
    }
    let Some(separator) = service_and_path.iter().position(|byte| *byte == b' ') else {
        return Err(GitDaemonTransportRefusal::MalformedServiceRequest);
    };
    let service = &service_and_path[..separator];
    if service != b"git-upload-pack" {
        return Err(GitDaemonTransportRefusal::UnsupportedService {
            service_bytes: service.len(),
        });
    }
    let repository_path = GitDaemonRepositoryPath::parse(&service_and_path[separator + 1..])?;

    let mut requested_version_bytes = None;
    for parameter in parameters.split(|byte| *byte == 0) {
        if parameter.is_empty() {
            continue;
        }
        let Some(version) = parameter.strip_prefix(b"version=") else {
            continue;
        };
        if requested_version_bytes.is_some() {
            return Err(GitDaemonTransportRefusal::DuplicateProtocolVersion);
        }
        requested_version_bytes = Some(version.len());
    }
    if let Some(version_bytes) = requested_version_bytes {
        return Err(GitDaemonTransportRefusal::UnsupportedProtocolVersion { version_bytes });
    }
    Ok(GitDaemonRequest { repository_path })
}

fn read_git_daemon_request(
    reader: &mut impl Read,
    limits: &WireLimits,
) -> Result<GitDaemonRequest, GitDaemonTransportRefusal> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "read git-daemon greeting header",
            source,
        })?;
    let declared = git_daemon_packet_length(header)?;
    if declared < 4 {
        return Err(GitDaemonTransportRefusal::GreetingControlPacket);
    }
    if declared > limits.max_packet_bytes {
        return Err(GitDaemonTransportRefusal::GreetingPacketTooLarge {
            declared,
            maximum: limits.max_packet_bytes,
        });
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(declared)
        .map_err(|_| GitDaemonTransportRefusal::Wire(WireError::AllocationFailure))?;
    frame.extend_from_slice(&header);
    let payload_length = declared
        .checked_sub(header.len())
        .ok_or(GitDaemonTransportRefusal::GreetingPacketTooSmall { declared })?;
    let original_length = frame.len();
    frame.resize(declared, 0);
    reader
        .read_exact(&mut frame[original_length..original_length + payload_length])
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "read git-daemon greeting payload",
            source,
        })?;
    parse_git_daemon_request(&frame, limits.clone())
}

fn git_daemon_packet_length(header: [u8; 4]) -> Result<usize, GitDaemonTransportRefusal> {
    let mut declared = 0_usize;
    for byte in header {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' => usize::from(byte - b'a') + 10,
            b'A'..=b'F' => usize::from(byte - b'A') + 10,
            _ => return Err(GitDaemonTransportRefusal::InvalidGreetingLength),
        };
        declared = declared
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or(GitDaemonTransportRefusal::InvalidGreetingLength)?;
    }
    Ok(declared)
}

fn write_packet_group(
    writer: &mut impl Write,
    packets: &[Packet],
    limits: &WireLimits,
) -> Result<(), GitDaemonTransportRefusal> {
    let bytes = encode_packets(packets, limits).map_err(GitDaemonTransportRefusal::Wire)?;
    writer
        .write_all(&bytes)
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "write git-daemon pkt-line response",
            source,
        })?;
    writer
        .flush()
        .map_err(|source| GitDaemonTransportRefusal::Io {
            operation: "flush git-daemon pkt-line response",
            source,
        })
}

fn emit_pack_payload(
    writer: &mut impl Write,
    payload: &mut impl PackPayloadSource,
    request: &PackRequest,
    limits: &WireLimits,
) -> Result<(), GitDaemonTransportRefusal> {
    let maximum_chunk_bytes = if request.options.sideband_64k() {
        limits
            .max_packet_bytes
            .checked_sub(5)
            .ok_or(GitDaemonTransportRefusal::Wire(WireError::InvalidLimit {
                field: "max_packet_bytes for sideband pack source",
            }))?
    } else {
        limits.max_packet_bytes
    };
    while let Some(chunk) = payload
        .next_chunk(maximum_chunk_bytes)
        .map_err(GitDaemonTransportRefusal::Wire)?
    {
        if chunk.len() > maximum_chunk_bytes {
            return Err(GitDaemonTransportRefusal::Wire(
                WireError::PackChunkTooLarge {
                    observed: chunk.len(),
                    limit: maximum_chunk_bytes,
                },
            ));
        }
        if request.options.sideband_64k() {
            let packets =
                sideband_pack_chunk(&chunk, limits).map_err(GitDaemonTransportRefusal::Wire)?;
            write_packet_group(writer, &packets, limits)?;
        } else {
            writer
                .write_all(&chunk)
                .map_err(|source| GitDaemonTransportRefusal::Io {
                    operation: "write raw git pack payload",
                    source,
                })?;
            writer
                .flush()
                .map_err(|source| GitDaemonTransportRefusal::Io {
                    operation: "flush raw git pack payload",
                    source,
                })?;
        }
    }
    if request.options.sideband_64k() {
        write_packet_group(writer, &[Packet::Flush], limits)?;
    }
    Ok(())
}

/// Explicit inputs for initializing one embedded node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    storage_root: PathBuf,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    store_instance: StoreInstanceId,
    worker_threads: usize,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
}

impl NodeConfig {
    /// Creates the bounded SHA-1 Git compatibility profile used in this slice.
    #[must_use]
    pub fn new(storage_root: PathBuf, tenant_id: TenantId, repository_id: RepositoryId) -> Self {
        Self {
            storage_root,
            tenant_id,
            repository_id,
            store_instance: StoreInstanceId::from_raw(1),
            worker_threads: 1,
            object_format: GitHashAlgorithm::Sha1,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            segment_limits: SegmentLimits::default(),
        }
    }

    /// Selects the explicit one-process authority instance identity.
    #[must_use]
    pub const fn with_store_instance(mut self, store_instance: StoreInstanceId) -> Self {
        self.store_instance = store_instance;
        self
    }

    /// Selects a finite production runtime worker count.
    #[must_use]
    pub const fn with_worker_threads(mut self, worker_threads: usize) -> Self {
        self.worker_threads = worker_threads;
        self
    }

    /// Selects the native Git object identity domain.
    #[must_use]
    pub const fn with_object_format(mut self, object_format: GitHashAlgorithm) -> Self {
        self.object_format = object_format;
        self
    }

    /// Selects the pre-allocation object byte ceiling.
    #[must_use]
    pub const fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }
}

/// The idempotent result of creating the initial authority head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeInitialization {
    /// The head slot was absent and this call created it.
    Created,
    /// The requested genesis head was already installed byte-for-byte.
    IdenticalRetry,
}

/// Bounded, authenticated observations made by [`OneNode::doctor`].
///
/// This is deliberately narrower than a replay proof. It authenticates the
/// current authority receipt and, when the caller names one native object,
/// re-verifies that object's immutable envelope, native identity, and payload
/// commitment. It neither enumerates physical storage nor reconstructs an RCR
/// chain; those capabilities remain owned by the future materializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    authority_head: AuthenticatedHead,
    sampled_object: Option<GitOid>,
}

/// Request-owned authority context for one node operation.
///
/// The embedded authority binding requires `FrankenSQLite`'s capability context,
/// while node request cancellation and budget ownership come from the
/// node-owned Asupersync runtime. This wrapper keeps that bridge alive for the
/// whole request without storing it on [`FsqliteAuthorityStore`] or reusing a
/// node-lifetime database context for request work.
///
/// It intentionally exposes no direct database operation: node operations
/// take this value explicitly, so a future raw-socket gateway can carry the
/// same bounded request context through authenticated authority reads and the
/// canonical admission projection. It does not itself materialize refs.
pub struct NodeRequestContext {
    authority: FsqliteCx,
}

impl NodeRequestContext {
    const fn authority(&self) -> &FsqliteCx {
        &self.authority
    }
}

impl DoctorReport {
    /// The current authority receipt authenticated by the embedded store.
    #[must_use]
    pub const fn authority_head(&self) -> &AuthenticatedHead {
        &self.authority_head
    }

    /// The exact object independently re-verified by this invocation, if any.
    #[must_use]
    pub const fn sampled_object(&self) -> Option<GitOid> {
        self.sampled_object
    }
}

/// In-process authority/fabric bootstrap for the future one-node server assembly.
///
/// This type deliberately does not claim a transport service: the currently
/// published wire crate is SANS-I/O and the canonical ref projection required
/// for receive admission has not yet been published as a production surface.
#[derive(Debug)]
pub struct OneNode {
    authority: FsqliteAuthorityStore,
    admission_materializer: DurableAdmissionMaterializer,
    head_key: HeadKey,
    fabric: LocalFilesystemFabric,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    namespace: Vec<u8>,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
    runtime: NodeRuntime,
}

impl OneNode {
    /// Opens the durable authority store and initializes its first head when absent.
    ///
    /// Runtime blocking here is only node lifecycle work. Request operations
    /// such as [`Self::read_authority_head`] remain async over the runtime-owned
    /// database context.
    pub fn init(config: NodeConfig) -> Result<(Self, NodeInitialization), NodeRefusal> {
        let repository_id = config.repository_id;
        let node = Self::open_components(config)?;
        let initialization_cx = node.authority_context();
        let ref_root = match node
            .runtime
            .block_on(node.admission_materializer.stage_ref_state_in(
                &node.authority,
                &initialization_cx,
                repository_id,
                CanonicalRefState::default(),
            )) {
            Ok(root) => root,
            Err(staging) => {
                let initialization = NodeRefusal::AdmissionMaterialization(staging);
                return match node.shutdown() {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
        };
        let genesis = genesis_head(repository_id, ref_root);
        let initialization = match initialize_embedded_repository(
            &node.runtime,
            &node.authority,
            &initialization_cx,
            &node.head_key,
            &genesis,
        ) {
            Ok(HeadInit::Created(_)) => Ok(NodeInitialization::Created),
            Ok(HeadInit::IdenticalRetry(_)) => Ok(NodeInitialization::IdenticalRetry),
            Ok(HeadInit::Conflict) => Err(NodeRefusal::HeadInitializationConflict),
            Err(error) => Err(error),
        };
        match initialization {
            Ok(initialization) => Ok((node, initialization)),
            Err(initialization) => {
                let cleanup = node.shutdown();
                match cleanup {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }
        }
    }

    /// Opens an already initialized node without synthesizing a canonical head.
    ///
    /// The embedded engine must establish its fixed local schema before it can
    /// read, but this method never calls `initialize_head`: an absent head is a
    /// typed refusal. A successful return has authenticated the current head
    /// receipt against the store's issuance record.
    pub fn open_existing(config: NodeConfig) -> Result<Self, NodeRefusal> {
        let node = Self::open_components(config)?;
        let opened = node.runtime().block_on(node.authenticate_authority_head());
        match opened {
            Ok(_) => Ok(node),
            Err(opening) => Err(close_after_existing_open_failure(node, opening)),
        }
    }

    fn open_components(config: NodeConfig) -> Result<Self, NodeRefusal> {
        if config.storage_root.as_os_str().is_empty() {
            return Err(NodeRefusal::EmptyStorageRoot);
        }
        if config.worker_threads == 0 {
            return Err(NodeRefusal::InvalidWorkerCount);
        }

        let runtime = RuntimeProfile::production(config.worker_threads)
            .build()
            .map_err(NodeRefusal::Runtime)?;
        let authority_path = authority_database_path(&config.storage_root)?;
        let namespace = object_namespace(config.repository_id);
        let failure_domain = fgit_resource::OpaqueHandle::new(b"node-local-filesystem")
            .map_err(NodeRefusal::Identity)?;
        let encryption_dependency =
            fgit_resource::OpaqueHandle::new(b"node-local-key").map_err(NodeRefusal::Identity)?;
        let fabric = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            config.storage_root,
            namespace.clone(),
            failure_domain,
            encryption_dependency,
            config.max_object_bytes,
            config.segment_limits.clone(),
        ))
        .map_err(NodeRefusal::Fabric)?;

        let head_key = head_key(config.repository_id)?;
        let admission_cache_scope = admission_cache_scope().map_err(NodeRefusal::Identity)?;
        let opening_cx = authority_context_for(&runtime);
        let authority = runtime
            .block_on(FsqliteAuthorityStore::open(
                &opening_cx,
                authority_path,
                config.store_instance,
                AuthorityLimits::default(),
            ))
            .map_err(authority_engine_refusal)?;
        Ok(Self {
            runtime,
            authority,
            admission_materializer: DurableAdmissionMaterializer::new(admission_cache_scope),
            head_key,
            fabric,
            tenant_id: config.tenant_id,
            repository_id: config.repository_id,
            namespace,
            object_format: config.object_format,
            max_object_bytes: config.max_object_bytes,
            segment_limits: config.segment_limits,
        })
    }

    /// Returns the runtime responsible for request contexts and lifecycle.
    #[must_use]
    pub const fn runtime(&self) -> &NodeRuntime {
        &self.runtime
    }

    /// Returns the repository tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the repository identity governed by this node's authority head.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Mints the bounded authority context for one node request.
    ///
    /// Each call creates a new `FrankenSQLite` context attached to a fresh
    /// `BudgetClass::Database` Asupersync context. The returned value must stay
    /// alive while its matching node operations are awaited; it is never saved
    /// in the authority store or shared with another request.
    #[must_use]
    pub fn request_context(&self) -> NodeRequestContext {
        NodeRequestContext {
            authority: self.authority_context(),
        }
    }

    /// Reads the current authority-selected head in `request`.
    ///
    /// The authority call is made through the production async contract. The
    /// object fabric is not authority, and this does not decode the head body
    /// into refs or provide an upload-pack repository.
    pub async fn read_authority_head_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<HeadRead, NodeRefusal> {
        AsyncAuthorityStore::read_head(&self.authority, request.authority(), &self.head_key)
            .await
            .map_err(authority_failure_refusal)
    }

    /// Reads the current authority-selected head with a fresh bounded context.
    ///
    /// Services that execute more than one authority operation for the same
    /// request should call [`Self::request_context`] once and use
    /// [`Self::read_authority_head_in`] instead.
    pub async fn read_authority_head(&self) -> Result<HeadRead, NodeRefusal> {
        let request = self.request_context();
        self.read_authority_head_in(&request).await
    }

    /// Re-reads and authenticates the current authority-head receipt.
    ///
    /// Authentication proves the store issued the exact key, token,
    /// generation, and body presented in the read receipt. It does not prove
    /// that this receipt is current after the read, so callers still need CAS
    /// for publication.
    pub async fn authenticate_authority_head_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<AuthenticatedHead, NodeRefusal> {
        let HeadRead::Present(receipt) = self.read_authority_head_in(request).await? else {
            return Err(NodeRefusal::AuthorityHeadAbsent);
        };
        AsyncAuthorityStore::authenticate_head_receipt(
            &self.authority,
            request.authority(),
            &receipt,
        )
        .await
        .map_err(authority_failure_refusal)
    }

    /// Re-reads and authenticates the current authority-head receipt with a
    /// fresh bounded request context.
    pub async fn authenticate_authority_head(&self) -> Result<AuthenticatedHead, NodeRefusal> {
        let request = self.request_context();
        self.authenticate_authority_head_in(&request).await
    }

    /// Materializes the canonical ref state selected by the current durable
    /// head into the node's bounded, exact-head cache.
    ///
    /// This is the production bridge from the asynchronous authority store to
    /// the synchronous admission trait.  It performs no request-path blocking:
    /// the authority head and immutable ref frame are both awaited before the
    /// cache is updated, and a missing or mismatched frame refuses the read.
    pub async fn materialize_admission_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal> {
        // The child is the materializer-catch-up ownership scope. Parent
        // request cancellation propagates to it; its checkpoints fence cache
        // installation without making the cache an authority source.
        let catch_up = request.authority().create_child();
        let is_cancelled = || catch_up.checkpoint().is_err();
        self.admission_materializer
            .materialize_current_in(
                &self.authority,
                &catch_up,
                &self.head_key,
                self.repository_id,
                &is_cancelled,
            )
            .await
    }

    /// Materializes canonical admission state with a fresh bounded context.
    pub async fn materialize_admission(
        &self,
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal> {
        let request = self.request_context();
        self.materialize_admission_in(&request).await
    }

    /// Returns the read-only canonical admission projection backed by this
    /// node's last successful async materialization.
    ///
    /// A caller must materialize the exact head first.  Until then, and for a
    /// different authenticated basis thereafter, this projection returns a
    /// typed refusal instead of consulting any connection-local ref map.
    #[must_use]
    pub const fn admission_projection(&self) -> &DurableAdmissionMaterializer {
        &self.admission_materializer
    }

    /// Opens a V0 upload-pack view directly from the durable materialization.
    ///
    /// Unlike a local ref map, this path accepts only a frame whose canonical
    /// root is named by an authenticated authority head.  The materialized
    /// snapshot retains the exact receipt and basis, so a caller can also pass
    /// it through the generic admission projection boundary without mixing
    /// generations.
    pub async fn durable_admission_upload_pack_repository_in(
        &self,
        request: &NodeRequestContext,
        limits: &WireLimits,
    ) -> Result<AdmissionUploadPackRepository, NodeAdmissionViewRefusal> {
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(NodeAdmissionViewRefusal::Materialization)?;
        AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::View)
    }

    /// Opens the current durable authority state as a bounded V0 upload-pack view.
    ///
    /// This reads and authenticates the head through the node's production
    /// async authority contract, derives the exact [`PublicationBasis`] from
    /// that receipt, then delegates ref resolution to the supplied admission
    /// projection.  The resulting view is safe only for the legacy V0
    /// first-clone transport: non-advertised closure wants are deliberately
    /// refused until the decision-history closure reader is composed.
    pub async fn admission_upload_pack_repository_in<Projection>(
        &self,
        request: &NodeRequestContext,
        projection: &Projection,
        limits: &WireLimits,
    ) -> Result<AdmissionUploadPackRepository, NodeAdmissionViewRefusal>
    where
        Projection: AdmissionProjection + Sync + ?Sized,
    {
        let authenticated = self
            .authenticate_authority_head_in(request)
            .await
            .map_err(NodeAdmissionViewRefusal::Authority)?;
        let body = authenticated
            .body()
            .map_err(NodeAdmissionViewRefusal::HeadBody)?;
        let id = body_id(&CryptoBodyIdentity, &body)
            .map_err(NodeAdmissionViewRefusal::HeadIdentity)
            .and_then(|identity| {
                RepositoryAuthorityHeadId::from_internal_object_id(identity)
                    .map_err(NodeAdmissionViewRefusal::HeadIdentityDomain)
            })?;
        let basis = PublicationBasis::new(id, body);
        AdmissionUploadPackRepository::from_projection(
            projection,
            &basis,
            &authenticated,
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::View)
    }

    /// Resolves one sealed transaction outcome through authoritative durable state.
    ///
    /// This reconciles the authenticated decision stream with its derived
    /// outcome accelerator. In particular, an absent accelerator row is not
    /// treated as an undecided transaction without replaying the current
    /// authority-selected history first.
    pub async fn resolve_outcome_in(
        &self,
        request: &NodeRequestContext,
        transaction_id: fgit_types::TxId,
    ) -> Result<OutcomeLookup, NodeRefusal> {
        resolve_outcome_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            self.tenant_id,
            self.repository_id,
            transaction_id,
        )
        .await
        .map_err(NodeRefusal::Authority)
    }

    /// Resolves one sealed transaction outcome with a fresh bounded context.
    pub async fn resolve_outcome(
        &self,
        transaction_id: fgit_types::TxId,
    ) -> Result<OutcomeLookup, NodeRefusal> {
        let request = self.request_context();
        self.resolve_outcome_in(&request, transaction_id).await
    }

    /// Publishes one already-materialized decision batch through this node's
    /// durable production authority path.
    ///
    /// `batch` and `successor` must come from the canonical transaction/ref
    /// materializer. This boundary never synthesizes them from connection-local
    /// state: the shared authority core verifies their binding, walks the
    /// authenticated decision history, and atomically publishes the terminal
    /// outcomes with the successor head. `expected` is the token from the
    /// materializer's authenticated predecessor read. Materializations for a
    /// different repository are refused before any immutable staging work.
    pub async fn publish_decisions_in(
        &self,
        request: &NodeRequestContext,
        expected: AuthorityVersionToken,
        batch: &RepositoryDecisionBatchBody,
        successor: &RepositoryAuthorityHeadBody,
    ) -> Result<PublicationOutcome, NodeRefusal> {
        if batch.repository_id != self.repository_id
            || successor.repository_id != self.repository_id
        {
            return Err(NodeRefusal::RepositoryMismatch);
        }
        publish_decisions_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            expected,
            batch,
            successor,
            self.tenant_id,
        )
        .await
        .map_err(NodeRefusal::Authority)
    }

    /// Performs the currently published bounded doctor checks.
    ///
    /// `sampled_object` is caller-selected rather than discovered from a
    /// directory listing. It is accepted only in this node's declared native
    /// Git identity domain, then read through fabric's verified-whole-read
    /// boundary. No sample means authority-head authentication only.
    pub async fn doctor_in(
        &self,
        request: &NodeRequestContext,
        sampled_object: Option<GitOid>,
    ) -> Result<DoctorReport, NodeRefusal> {
        let authority_head = self.authenticate_authority_head_in(request).await?;
        if let Some(identity) = sampled_object {
            let _ = self.read_git_object(identity)?;
        }
        Ok(DoctorReport {
            authority_head,
            sampled_object,
        })
    }

    /// Performs the currently published bounded doctor checks with a fresh
    /// bounded request context.
    pub async fn doctor(
        &self,
        sampled_object: Option<GitOid>,
    ) -> Result<DoctorReport, NodeRefusal> {
        let request = self.request_context();
        self.doctor_in(&request, sampled_object).await
    }

    /// Awaits authority-worker closure and then joins the owning runtime.
    ///
    /// Callers that obtain a node must use this before dropping it so a clean
    /// stop has an observed quiescence result instead of relying on the
    /// database driver's drop-time backstop.
    pub fn shutdown(mut self) -> Result<(), NodeRefusal> {
        let shutdown_cx = self.authority_context();
        self.runtime
            .block_on(self.authority.close(&shutdown_cx))
            .map_err(authority_engine_refusal)?;
        if self.runtime.join_root(SHUTDOWN_TIMEOUT) {
            Ok(())
        } else {
            Err(NodeRefusal::RuntimeContainment)
        }
    }

    fn authority_context(&self) -> FsqliteCx {
        authority_context_for(&self.runtime)
    }

    /// Validates and immutably places one native Git object through object fabric.
    pub fn put_git_object(
        &self,
        object_type: ObjectType,
        body: Vec<u8>,
    ) -> Result<StoredObject, NodeRefusal> {
        let offered = u64::try_from(body.len()).map_err(|_| NodeRefusal::ObjectLengthOverflow)?;
        if offered > self.max_object_bytes {
            return Err(NodeRefusal::ObjectTooLarge {
                offered,
                maximum: self.max_object_bytes,
            });
        }
        let object_kind = fabric_object_kind(object_type);
        let crypto_kind = crypto_object_kind(object_type);
        let identity = git_object_id(self.object_format, crypto_kind, &body);
        let commitment = git_payload_commitment(crypto_kind, &body, CANONICAL_CODEC_VERSION);
        let mut commitment_bytes = [0_u8; 32];
        commitment_bytes.copy_from_slice(commitment.digest().as_bytes());
        let envelope = ObjectEnvelope::new(
            self.namespace.clone(),
            identity,
            object_kind,
            offered,
            commitment_bytes,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            commitment_bytes,
            None,
            &self.segment_limits,
        )
        .map_err(|error| NodeRefusal::Fabric(StoreRefusal::Fabric(error)))?;
        let verified = VerifiedObject::new(envelope, body).map_err(NodeRefusal::Fabric)?;
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            placement_resources(offered),
        );
        let grant = ledger
            .grant(placement_resources(offered))
            .map_err(NodeRefusal::Resource)?;
        let outcome = self
            .fabric
            .put_if_absent(verified, PlacementAdmission::new(&ledger, grant));
        let closed = ledger.close();
        if !matches!(closed, RegionCloseOutcome::Quiescent(_)) {
            return Err(NodeRefusal::ResourceContainment);
        }
        match outcome.map_err(NodeRefusal::Fabric)? {
            PutIfAbsent::Created { .. } => Ok(StoredObject::Created(identity)),
            PutIfAbsent::AlreadyPresent { .. } => Ok(StoredObject::AlreadyPresent(identity)),
        }
    }

    /// Reads one exact immutable Git object from the local fabric.
    pub fn read_git_object(&self, identity: GitOid) -> Result<VerifiedObject, NodeRefusal> {
        if identity.algorithm() != self.object_format {
            return Err(NodeRefusal::Fabric(
                StoreRefusal::NativeObjectIdentityMismatch,
            ));
        }
        self.fabric
            .read_whole(identity)
            .map(|read| read.object)
            .map_err(NodeRefusal::Fabric)
    }
}

fn close_after_existing_open_failure(node: OneNode, opening: NodeRefusal) -> NodeRefusal {
    match node.shutdown() {
        Ok(()) => opening,
        Err(cleanup) => NodeRefusal::ExistingOpenCleanup {
            opening: Box::new(opening),
            cleanup: Box::new(cleanup),
        },
    }
}

/// Observable immutable-placement outcome; neither case is an authority publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredObject {
    /// The exact immutable object was newly placed.
    Created(GitOid),
    /// An identical immutable object was already present.
    AlreadyPresent(GitOid),
}

impl StoredObject {
    /// The native object identity named by either placement outcome.
    #[must_use]
    pub const fn identity(self) -> GitOid {
        match self {
            Self::Created(identity) | Self::AlreadyPresent(identity) => identity,
        }
    }
}

fn head_key(repository_id: RepositoryId) -> Result<HeadKey, NodeRefusal> {
    let mut bytes = Vec::with_capacity(HEAD_KEY_PREFIX.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(HEAD_KEY_PREFIX);
    bytes.extend_from_slice(repository_id.as_bytes());
    HeadKey::new(bytes).map_err(NodeRefusal::HeadKey)
}

fn authority_database_path(storage_root: &Path) -> Result<String, NodeRefusal> {
    storage_root
        .join(AUTHORITY_DATABASE_FILE)
        .into_os_string()
        .into_string()
        .map_err(|_| NodeRefusal::StoragePathEncoding)
}

fn authority_context_for(runtime: &NodeRuntime) -> FsqliteCx {
    let authority = FsqliteCx::new();
    authority.set_native_cx(runtime.request_cx(BudgetClass::Database));
    authority
}

fn authority_engine_refusal(error: EngineError) -> NodeRefusal {
    NodeRefusal::Authority(error.into_failure().into())
}

fn authority_failure_refusal(error: fgit_authority::AuthorityFailure) -> NodeRefusal {
    NodeRefusal::Authority(error.into())
}

fn initialize_embedded_repository(
    runtime: &NodeRuntime,
    authority: &FsqliteAuthorityStore,
    authority_cx: &FsqliteCx,
    head_key: &HeadKey,
    genesis: &RepositoryAuthorityHeadBody,
) -> Result<HeadInit, NodeRefusal> {
    runtime
        .block_on(initialize_repository_async(
            authority,
            authority_cx,
            head_key,
            genesis,
        ))
        .map_err(NodeRefusal::Authority)
}

fn object_namespace(repository_id: RepositoryId) -> Vec<u8> {
    let mut namespace =
        Vec::with_capacity(FABRIC_NAMESPACE_PREFIX.len() + repository_id.as_bytes().len());
    namespace.extend_from_slice(FABRIC_NAMESPACE_PREFIX);
    namespace.extend_from_slice(repository_id.as_bytes());
    namespace
}

fn genesis_head(repository_id: RepositoryId, ref_root: Digest) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root,
        forge_position_root: genesis_root(repository_id, b"forge-position"),
        outcome_index_root: genesis_root(repository_id, b"outcome-index"),
        retention_root: genesis_root(repository_id, b"retention"),
        outbox_root: genesis_root(repository_id, b"outbox"),
        configuration_root: genesis_root(repository_id, b"configuration"),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn genesis_root(repository_id: RepositoryId, label: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(label.len() + repository_id.as_bytes().len());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(repository_id.as_bytes());
    let commitment = git_payload_commitment(GitObjectKind::Blob, &bytes, CANONICAL_CODEC_VERSION);
    Digest::new(
        IdentityDomain::GitPayloadCommitment.algorithm().id(),
        *commitment.digest(),
    )
}

const fn fabric_object_kind(object_type: ObjectType) -> ObjectKind {
    match object_type {
        ObjectType::Commit => ObjectKind::Commit,
        ObjectType::Tree => ObjectKind::Tree,
        ObjectType::Blob => ObjectKind::Blob,
        ObjectType::Tag => ObjectKind::Tag,
    }
}

const fn crypto_object_kind(object_type: ObjectType) -> GitObjectKind {
    match object_type {
        ObjectType::Commit => GitObjectKind::Commit,
        ObjectType::Tree => GitObjectKind::Tree,
        ObjectType::Blob => GitObjectKind::Blob,
        ObjectType::Tag => GitObjectKind::Tag,
    }
}

fn placement_resources(object_bytes: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, object_bytes.max(1)), (Grade::Objects, 1)])
}

fn admission_cache_scope() -> Result<CacheScope, fgit_resource::IdentityError> {
    OpaqueHandle::new(ADMISSION_CACHE_SCOPE).map(CacheScope::new)
}

fn admission_cache_resources() -> ResourceVector {
    let frame_bytes = fgit_codec::DecodeLimits::DEFAULT.frame_bytes;
    ResourceVector::from_grades(&[
        (Grade::Bytes, frame_bytes),
        (Grade::Objects, 1),
        (Grade::CpuMicros, frame_bytes),
        (Grade::MemoryBytes, frame_bytes),
    ])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::fs;
    use std::io::{Cursor, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use fgit_admission::{
        AdmissionProjection, AdmissionSnapshot, CanonicalAdmissionStore, CanonicalRefState,
        PermittedObjectClosure, canonical_ref_state_root,
    };
    use fgit_authority::{AsyncAuthorityStore, HeadInit, HeadRead, ImmutableRead, OutcomeLookup};
    use fgit_chronicle::PublicationBasis;
    use fgit_codec::harness::{advanced_head, decision_batch, tx_id};
    use fgit_codec::{CryptoBodyIdentity, body_id, decode_body};
    use fgit_types::{
        GitHashAlgorithm, GitOid, RefName, RefusalCode, RepositoryAuthorityHeadId, RepositoryId,
        TenantId,
    };
    use fgit_wire::{
        AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, PackPayloadSource, Packet,
        UploadPackRepository, WireError, WireLimits, encode_packets,
    };

    use super::{
        ADMISSION_CLOSURE_KEY_PREFIX, AdmissionMaterializationRefusal, AdmissionUploadPackRefusal,
        AdmissionUploadPackRepository, GitDaemonServeError, GitDaemonTransportRefusal, NodeConfig,
        NodeInitialization, NodeRefusal, OneNode, admission_immutable_key, genesis_head,
        genesis_root, initialize_embedded_repository, parse_git_daemon_request,
        serve_git_daemon_tcp_once, serve_git_daemon_upload_pack,
    };

    static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct ScratchDirectory {
        root: PathBuf,
    }

    impl ScratchDirectory {
        fn new() -> Self {
            let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "frankengit-node-authority-{}-{sequence}",
                std::process::id()
            ));
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn test_config(root: PathBuf) -> NodeConfig {
        NodeConfig::new(
            root,
            TenantId::from_bytes([0x11; 16]),
            RepositoryId::from_bytes([0x22; 16]),
        )
    }

    #[derive(Clone, Debug)]
    struct FixtureRepository {
        refs: Vec<AdvertisedRef>,
    }

    impl FixtureRepository {
        fn single_main_ref() -> Self {
            let limits = WireLimits::default();
            let oid = AnyGitOid::from_hex(
                GitObjectFormat::Sha1,
                "1111111111111111111111111111111111111111",
            )
            .expect("fixed SHA-1 object id");
            let reference =
                AdvertisedRef::new(oid, b"refs/heads/main", &limits).expect("fixed valid ref");
            Self {
                refs: vec![reference],
            }
        }
    }

    impl UploadPackRepository for FixtureRepository {
        fn object_format(&self) -> GitObjectFormat {
            GitObjectFormat::Sha1
        }

        fn advertised_refs(&self) -> &[AdvertisedRef] {
            &self.refs
        }

        fn contains_want(&self, oid: AnyGitOid) -> bool {
            self.refs.iter().any(|reference| reference.oid == oid)
        }

        fn is_common(&self, _oid: AnyGitOid) -> bool {
            false
        }
    }

    #[test]
    fn admission_snapshot_view_advertises_exact_canonical_refs_in_order() {
        let main = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed SHA-1 object id");
        let release = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "2222222222222222222222222222222222222222",
        )
        .expect("fixed SHA-1 object id");
        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/main").expect("fixed valid ref"),
            main,
        );
        refs.insert(
            RefName::try_new(b"refs/tags/v1.0").expect("fixed valid ref"),
            release,
        );
        let snapshot = AdmissionSnapshot {
            refs,
            ..AdmissionSnapshot::default()
        };

        let repository = AdmissionUploadPackRepository::from_snapshot(
            &snapshot,
            GitHashAlgorithm::Sha1,
            &WireLimits::default(),
        )
        .expect("canonical SHA-1 snapshot becomes an upload-pack view");

        assert_eq!(
            repository
                .advertised_refs()
                .iter()
                .map(|reference| reference.name.as_slice())
                .collect::<Vec<_>>(),
            vec![b"refs/heads/main".as_slice(), b"refs/tags/v1.0".as_slice()],
        );
        assert!(repository.contains_want(main));
        assert!(repository.is_common(release));
        assert!(
            !repository.contains_want(
                GitOid::from_hex(
                    GitHashAlgorithm::Sha1,
                    "3333333333333333333333333333333333333333",
                )
                .expect("fixed SHA-1 object id"),
            )
        );
    }

    #[test]
    fn admission_snapshot_view_refuses_cross_domain_ref_targets() {
        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/main").expect("fixed valid ref"),
            GitOid::from_hex(
                GitHashAlgorithm::Sha256,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("fixed SHA-256 object id"),
        );
        let snapshot = AdmissionSnapshot {
            refs,
            ..AdmissionSnapshot::default()
        };

        let refusal = AdmissionUploadPackRepository::from_snapshot(
            &snapshot,
            GitHashAlgorithm::Sha1,
            &WireLimits::default(),
        )
        .expect_err("a mixed hash-domain advertisement is not Git-compatible");

        assert!(matches!(
            refusal,
            AdmissionUploadPackRefusal::ObjectFormatMismatch {
                expected: GitHashAlgorithm::Sha1,
                observed: GitHashAlgorithm::Sha256,
            }
        ));
    }

    #[test]
    fn admission_snapshot_view_checks_advertisement_bound_before_copying_refs() {
        let main = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed SHA-1 object id");
        let release = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "2222222222222222222222222222222222222222",
        )
        .expect("fixed SHA-1 object id");
        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/main").expect("fixed valid ref"),
            main,
        );
        refs.insert(
            RefName::try_new(b"refs/tags/v1.0").expect("fixed valid ref"),
            release,
        );
        let snapshot = AdmissionSnapshot {
            refs,
            ..AdmissionSnapshot::default()
        };
        let limits = WireLimits {
            max_advertised_refs: 1,
            ..WireLimits::default()
        };

        let refusal = AdmissionUploadPackRepository::from_snapshot(
            &snapshot,
            GitHashAlgorithm::Sha1,
            &limits,
        )
        .expect_err("the adapter must reject before allocating a second advertisement copy");

        assert!(matches!(
            refusal,
            AdmissionUploadPackRefusal::Wire(WireError::TooManyAdvertisedRefs { limit: 1 })
        ));
    }

    struct FixturePack {
        bytes: Option<Vec<u8>>,
    }

    impl PackPayloadSource for FixturePack {
        fn next_chunk(&mut self, maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
            let Some(chunk) = self.bytes.take() else {
                return Ok(None);
            };
            if chunk.len() > maximum_chunk_bytes {
                return Err(WireError::PackChunkTooLarge {
                    observed: chunk.len(),
                    limit: maximum_chunk_bytes,
                });
            }
            Ok(Some(chunk))
        }
    }

    struct FragmentedReader {
        bytes: Vec<u8>,
        offset: usize,
        fragment_bytes: usize,
    }

    impl FragmentedReader {
        fn new(bytes: Vec<u8>, fragment_bytes: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                fragment_bytes,
            }
        }
    }

    impl Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let available = self.bytes.len() - self.offset;
            let length = available.min(self.fragment_bytes).min(buffer.len());
            buffer[..length].copy_from_slice(&self.bytes[self.offset..self.offset + length]);
            self.offset += length;
            Ok(length)
        }
    }

    fn daemon_greeting(payload: &[u8]) -> Vec<u8> {
        encode_packets(&[Packet::Data(payload.to_vec())], &WireLimits::default())
            .expect("fixed greeting encodes")
    }

    #[test]
    fn git_daemon_parser_accepts_a_v0_upload_pack_path() {
        let greeting = daemon_greeting(b"git-upload-pack /demo.git\0host=example.test\0");
        let request = parse_git_daemon_request(&greeting, WireLimits::default())
            .expect("v0 upload-pack greeting is accepted");

        assert_eq!(request.repository_path().as_bytes(), b"/demo.git");
    }

    #[test]
    fn git_daemon_parser_refuses_a_non_upload_pack_service() {
        let greeting = daemon_greeting(b"git-receive-pack /demo.git\0host=example.test\0");

        assert!(matches!(
            parse_git_daemon_request(&greeting, WireLimits::default()),
            Err(GitDaemonTransportRefusal::UnsupportedService { .. })
        ));
    }

    #[test]
    fn git_daemon_parser_refuses_a_truncated_pkt_line() {
        assert!(matches!(
            parse_git_daemon_request(b"0033git-upload-pack /demo.git", WireLimits::default()),
            Err(GitDaemonTransportRefusal::Wire(
                WireError::TruncatedPacket { .. }
            ))
        ));
    }

    #[test]
    fn git_daemon_session_writes_advertisement_ack_then_raw_pack_after_done() {
        let repository = FixtureRepository::single_main_ref();
        let want = repository.refs[0].oid.to_string();
        let mut client_bytes = daemon_greeting(b"git-upload-pack /demo.git\0host=example.test\0");
        client_bytes.extend(
            encode_packets(
                &[
                    Packet::Data(format!("want {want}\n").into_bytes()),
                    Packet::Flush,
                    Packet::Data(b"done\n".to_vec()),
                ],
                &WireLimits::default(),
            )
            .expect("fixed upload-pack negotiation encodes"),
        );
        let mut reader = FragmentedReader::new(client_bytes, 3);
        let mut writer = Cursor::new(Vec::new());

        let receipt = serve_git_daemon_upload_pack(
            &mut reader,
            &mut writer,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            |request, pack_request| -> Result<FixturePack, Infallible> {
                assert_eq!(request.repository_path().as_bytes(), b"/demo.git");
                assert_eq!(pack_request.wants, vec![repository.refs[0].oid]);
                Ok(FixturePack {
                    bytes: Some(b"PACK\0fixture".to_vec()),
                })
            },
        )
        .expect("complete V0 negotiation emits the canonical-pack payload");

        assert_eq!(receipt.request().repository_path().as_bytes(), b"/demo.git");
        assert_eq!(receipt.pack_request().wants, vec![repository.refs[0].oid]);
        let bytes = writer.into_inner();
        let pack_offset = bytes
            .windows(b"PACK".len())
            .position(|window| window == b"PACK")
            .expect("raw pack follows the upload-pack negotiation");
        assert_eq!(&bytes[pack_offset..], b"PACK\0fixture");
        assert_eq!(
            bytes[..pack_offset]
                .windows(b"NAK\n".len())
                .filter(|window| *window == b"NAK\n")
                .count(),
            1,
            "the want-phase flush emits the sole negotiated NAK before raw pack bytes; the final done transition delegates fgit-wire's non-duplicating Git 2.54 behavior"
        );
    }

    #[test]
    fn git_daemon_session_refuses_eof_before_done_without_constructing_a_pack() {
        let repository = FixtureRepository::single_main_ref();
        let mut reader = Cursor::new(daemon_greeting(b"git-upload-pack /demo.git\0"));
        let mut writer = Cursor::new(Vec::new());

        let result = serve_git_daemon_upload_pack(
            &mut reader,
            &mut writer,
            &repository,
            Capabilities::default(),
            WireLimits::default(),
            |_request, _pack_request| -> Result<FixturePack, Infallible> {
                panic!("a pack must not be constructed before a complete request")
            },
        );

        assert!(matches!(
            result,
            Err(GitDaemonServeError::Transport(
                GitDaemonTransportRefusal::IncompleteNegotiation
            ))
        ));
    }

    #[test]
    fn git_daemon_tcp_once_signals_eof_after_the_raw_pack_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener address is available");
        let repository = FixtureRepository::single_main_ref();
        let server = thread::spawn(move || {
            serve_git_daemon_tcp_once(
                &listener,
                &repository,
                Capabilities::default(),
                WireLimits::default(),
                |_request, _pack_request| -> Result<FixturePack, Infallible> {
                    Ok(FixturePack {
                        bytes: Some(b"PACK\0tcp".to_vec()),
                    })
                },
            )
        });

        let mut client = TcpStream::connect(address).expect("loopback client connects");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let want = "1111111111111111111111111111111111111111";
        let mut request = daemon_greeting(b"git-upload-pack /demo.git\0host=loopback\0");
        request.extend(
            encode_packets(
                &[
                    Packet::Data(format!("want {want}\n").into_bytes()),
                    Packet::Flush,
                    Packet::Data(b"done\n".to_vec()),
                ],
                &WireLimits::default(),
            )
            .expect("fixed TCP negotiation encodes"),
        );
        std::io::Write::write_all(&mut client, &request).expect("client request writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes request half after done");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("server response reaches write-half EOF");
        let receipt = server
            .join()
            .expect("server thread joins")
            .expect("server accepts the complete V0 request");
        assert_eq!(receipt.request().repository_path().as_bytes(), b"/demo.git");
        assert!(response.ends_with(b"PACK\0tcp"));
    }

    #[test]
    fn clean_restart_uses_the_same_durable_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        let (first, first_init) = OneNode::init(config.clone()).expect("first node opens");
        assert_eq!(first_init, NodeInitialization::Created);
        let first_request = first.request_context();
        let first_head = first
            .runtime()
            .block_on(first.read_authority_head_in(&first_request))
            .expect("first head reads");
        assert!(matches!(&first_head, HeadRead::Present(_)));
        first.shutdown().expect("first node closes cleanly");

        let (second, second_init) = OneNode::init(config).expect("reopened node opens");
        assert_eq!(second_init, NodeInitialization::IdenticalRetry);
        let second_request = second.request_context();
        let second_head = second
            .runtime()
            .block_on(second.read_authority_head_in(&second_request))
            .expect("reopened head reads");
        assert_eq!(second_head, first_head);
        second.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn durable_admission_materialization_is_head_bound_and_never_sync_stages() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node initializes canonical empty refs first");
        let request = node.request_context();

        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .expect("authority-selected empty ref frame materializes");
        assert!(materialized.snapshot().refs.is_empty());
        assert_eq!(
            CanonicalAdmissionStore::resolve_ref_state(
                &node.admission_materializer,
                materialized.basis().body().ref_root,
            )
            .expect("only the materialized authority root resolves"),
            CanonicalRefState::default()
        );
        assert_eq!(
            CanonicalAdmissionStore::stage_ref_state(
                &node.admission_materializer,
                materialized.basis().body().ref_root,
                CanonicalRefState::default(),
            ),
            Err(RefusalCode::DurabilityProfileUnavailable),
            "the synchronous trait cannot claim durable staging"
        );

        let projection_snapshot = AdmissionProjection::snapshot(
            &node.admission_materializer,
            materialized.basis(),
            materialized.authenticated(),
        )
        .expect("the exact authenticated basis resolves");
        assert_eq!(projection_snapshot, *materialized.snapshot());

        let closure = PermittedObjectClosure::default();
        let closure_root = node
            .runtime()
            .block_on(
                node.admission_materializer
                    .stage_permitted_object_closure_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        closure.clone(),
                    ),
            )
            .expect("closure frame stages through durable authority");
        let closure_key = admission_immutable_key(
            ADMISSION_CLOSURE_KEY_PREFIX,
            node.repository_id(),
            closure_root,
        )
        .expect("fixed closure key is bounded");
        let ImmutableRead::Present(closure_frame) = node
            .runtime()
            .block_on(AsyncAuthorityStore::read_immutable(
                &node.authority,
                request.authority(),
                &closure_key,
            ))
            .expect("staged closure reads through durable authority")
        else {
            panic!("successful closure staging created an immutable frame");
        };
        assert_eq!(
            decode_body::<PermittedObjectClosure>(
                &closure_frame,
                fgit_codec::DecodeLimits::DEFAULT
            )
            .expect("durable closure frame decodes"),
            closure
        );
        assert_eq!(
            CanonicalAdmissionStore::resolve_permitted_object_closure(
                &node.admission_materializer,
                closure_root,
            ),
            Err(RefusalCode::EvidenceMissing),
            "a staged closure is not current without an authenticated RCR"
        );

        let mut other_body = materialized.basis().body().clone();
        other_body.configuration_root = genesis_root(node.repository_id(), b"different-policy");
        let other_id = body_id(&CryptoBodyIdentity, &other_body)
            .map_err(|_| ())
            .and_then(|identity| {
                RepositoryAuthorityHeadId::from_internal_object_id(identity).map_err(|_| ())
            })
            .expect("fixed alternate test body identifies");
        let other_basis = PublicationBasis::new(other_id, other_body);
        assert_eq!(
            AdmissionProjection::snapshot(
                &node.admission_materializer,
                &other_basis,
                materialized.authenticated(),
            ),
            Err(RefusalCode::AuthorityReceiptStale),
            "a cache entry never answers for a different basis"
        );
        assert_eq!(
            CanonicalAdmissionStore::resolve_ref_state(
                &node.admission_materializer,
                materialized.basis().body().ref_root,
            ),
            Err(RefusalCode::EvidenceMissing),
            "a mismatched authenticated basis discards the derived cache view"
        );

        let upload_pack = node
            .runtime()
            .block_on(
                node.durable_admission_upload_pack_repository_in(&request, &WireLimits::default()),
            )
            .expect("first-clone view comes from durable admission materialization");
        assert!(upload_pack.advertised_refs().is_empty());
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn cancelled_materializer_catch_up_never_installs_a_cache_record() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node initializes canonical refs");
        let request = node.request_context();
        let polls = AtomicUsize::new(0);

        let result = node
            .runtime()
            .block_on(node.admission_materializer.materialize_current_in(
                &node.authority,
                request.authority(),
                &node.head_key,
                node.repository_id(),
                &|| polls.fetch_add(1, Ordering::AcqRel) >= 6,
            ));
        assert!(
            matches!(result, Err(AdmissionMaterializationRefusal::Cancelled)),
            "the cancellation is observed after the cache permit but before cache installation"
        );
        let cancelled_request = node.request_context();
        cancelled_request.authority().cancel();
        assert!(
            matches!(
                node.runtime()
                    .block_on(node.materialize_admission_in(&cancelled_request)),
                Err(AdmissionMaterializationRefusal::Cancelled)
            ),
            "the production child catch-up context inherits request cancellation"
        );
        assert_eq!(
            CanonicalAdmissionStore::resolve_ref_state(
                &node.admission_materializer,
                canonical_ref_state_root(&CanonicalRefState::default())
                    .expect("empty canonical ref root computes"),
            ),
            Err(RefusalCode::EvidenceMissing),
            "a cancelled catch-up scope leaves no readable partial cache record"
        );
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn admission_materializer_request_future_is_send() {
        fn require_send(value: impl Send) {
            drop(value);
        }

        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node initializes canonical refs");
        let request = node.request_context();
        let limits = WireLimits::default();

        require_send(node.materialize_admission_in(&request));
        require_send(node.admission_upload_pack_repository_in(
            &request,
            node.admission_projection(),
            &limits,
        ));
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn durable_admission_materializer_refuses_a_head_without_its_ref_frame() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let node = OneNode::open_components(config).expect("components open");
        let missing_root = genesis_root(node.repository_id(), b"unstaged-canonical-refs");
        let head = genesis_head(node.repository_id(), missing_root);
        let initialization_cx = node.authority_context();
        let initialized = initialize_embedded_repository(
            node.runtime(),
            &node.authority,
            &initialization_cx,
            &node.head_key,
            &head,
        );
        assert!(matches!(initialized, Ok(HeadInit::Created(_))));

        let request = node.request_context();
        let result = node
            .runtime()
            .block_on(node.materialize_admission_in(&request));
        assert!(matches!(
            result,
            Err(AdmissionMaterializationRefusal::ImmutableAbsent(root)) if root == missing_root
        ));
        assert_eq!(
            CanonicalAdmissionStore::resolve_ref_state(&node.admission_materializer, missing_root),
            Err(RefusalCode::EvidenceMissing),
            "an absent durable frame never falls back to a node-local map"
        );
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn doctor_authenticates_the_head_and_rechecks_a_named_object() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config.clone()).expect("node opens");
        let stored = node
            .put_git_object(fgit_git_object::ObjectType::Blob, b"doctor sample".to_vec())
            .expect("sample stores");
        let request = node.request_context();
        let report = node
            .runtime()
            .block_on(node.doctor_in(&request, Some(stored.identity())))
            .expect("doctor authenticates and verifies the named sample");
        assert_eq!(report.sampled_object(), Some(stored.identity()));
        assert_eq!(
            report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        node.shutdown().expect("node closes cleanly");

        let reopened = OneNode::open_existing(config).expect("existing head opens");
        let reopened_request = reopened.request_context();
        let reopened_report = reopened
            .runtime()
            .block_on(reopened.doctor_in(&reopened_request, None))
            .expect("doctor authenticates reopened head");
        assert_eq!(
            reopened_report.authority_head().receipt().generation(),
            fgit_types::HeadGeneration::FIRST
        );
        reopened.shutdown().expect("reopened node closes cleanly");
    }

    #[test]
    fn node_resolves_an_undecided_transaction_through_async_authority() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node opens");
        let request = node.request_context();

        let outcome = node
            .runtime()
            .block_on(node.resolve_outcome_in(&request, tx_id()))
            .expect("fresh authority has no terminal outcome for fixture transaction");
        assert_eq!(outcome, OutcomeLookup::Undecided);
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn durable_publication_refuses_another_repository_before_staging() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node opens");
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("genesis head reads");
        let HeadRead::Present(before_receipt) = before else {
            panic!("node initialization creates its authority head");
        };

        let other_repository = RepositoryId::from_bytes([0x44; 16]);
        let mut batch = decision_batch();
        batch.repository_id = other_repository;
        let mut successor = advanced_head();
        successor.repository_id = other_repository;

        let refusal = node.runtime().block_on(node.publish_decisions_in(
            &request,
            before_receipt.token(),
            &batch,
            &successor,
        ));
        assert!(matches!(refusal, Err(NodeRefusal::RepositoryMismatch)));

        let after = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("rejected publication leaves head readable");
        assert_eq!(after, HeadRead::Present(before_receipt));
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn open_existing_refuses_an_absent_authority_head() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());

        assert!(matches!(
            OneNode::open_existing(config),
            Err(NodeRefusal::AuthorityHeadAbsent)
        ));
    }
}
