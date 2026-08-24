#![forbid(unsafe_code)]
#![feature(random)]

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
use std::future::Future;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use fgit_admission::evidence::{
    DURABLE_REFUSAL_EVIDENCE_DETAIL, DecisionEvidenceBodies, ForgeEventBatch, InvariantEvidence,
    OutboxEffectBatch, PolicyDecisionEvidence, PrincipalSnapshot, RefusalEvidenceBodies,
    RetentionDelta, evidence_root, principal_snapshot_id,
};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionLimits, AdmissionResult,
    AdmissionSnapshot, AdmissionSnapshotProjection, AsyncAdmissionProjection,
    AsyncProjectionFailure, CanonicalAdmissionStore, CanonicalRefState, CommitEvidence,
    CommitMaterialization, PermittedObjectClosure, RefusalMaterialization, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, ValidatedReceive,
    ValidatedSourceImport, admit_validated_receive_async, admit_validated_source_import_async,
    canonical_ref_state_root, permitted_object_closure_root, prepare_canonical_commit,
    validate_source_import,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityVersionToken, HeadInit, HeadKey, HeadRead, IdempotencyKey, ImmutableKey,
    ImmutableRead, KeyError, OutcomeLookup, PutOutcome, StoreInstanceId,
    initialize_repository_async, outcome_index_root, read_authority_head_body_async,
    read_decision_batch_body_async, read_repository_incarnation_configuration_async,
    resolve_outcome_async, stage_repository_incarnation_configuration_async,
};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore};
use fgit_chronicle::{
    PublicationBasis, PublicationVerdict, VerifiedPublication, publish_async, verify_pair,
};
use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryIncarnationConfigurationBody,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, body_id, decode_body, encode_body,
};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, git_payload_commitment};
use fgit_git_object::ObjectType;
use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, PlacementAdmission, PutIfAbsent, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackError, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriteReceipt, PackWriter,
};
use fgit_reference::intent::TransactionRequest;
use fgit_resource::{
    CacheBinding, CacheGrant, CacheGrantRefusal, CachePermit, CacheScope, Grade, LeakDisposition,
    ObligationLedger, OpaqueHandle, RegionCloseOutcome, RegionId, ResourceError, ResourceVector,
};
use fgit_runtime::{BudgetClass, NodeRuntime, RuntimeProfile, RuntimeRefusal};
use fgit_txn::TransactionFoldReport;
use fgit_types::cell::{
    CellReadiness, CellRefusal, CellState, CellTransition, CellTransitionCause, ReadLabel,
    ServingCell, admits_read,
};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256,
    HeadGeneration, PolicyEpoch, PrincipalId, RefName, RefusalCode, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId, RepositoryIncarnationId, TenantId,
    TxId,
};
use fgit_wire::stale_disclosure::{LabelledAdvertisement, advertise_under_read_label_served_by};
use fgit_wire::visibility::{RefVisibility, filter_advertised_refs};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, LegacyUploadPack, PackPayloadSource, PackRequest,
    Packet, PktLineDecoder, UploadPackRepository, UploadPackVersion, V1Advertisement, V2UploadPack,
    WireError, WireEvent, WireLimits, encode_packets, sideband_pack_chunk,
};
use fsqlite_types::cx::Cx as FsqliteCx;

mod loose_import;
mod quarantine_validator;

pub use loose_import::{LooseGitImportRefusal, StagedLooseGitImport};
pub use quarantine_validator::ProductionQuarantineValidator;

const OBJECT_CODEC_NAMESPACE: &[u8] = b"git-object-body/v1";
const HEAD_KEY_PREFIX: &[u8] = b"frankengit/node/head/";
const FABRIC_NAMESPACE_PREFIX: &[u8] = b"frankengit/node/object/";
const ADMISSION_REF_STATE_KEY_PREFIX: &[u8] = b"frankengit/admission/ref-state/v1/";
const ADMISSION_CLOSURE_KEY_PREFIX: &[u8] = b"frankengit/admission/object-closure/v1/";
const ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX: &[u8] =
    b"frankengit/admission/principal-snapshot/v1/";
const ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX: &[u8] = b"frankengit/admission/refusal-evidence/v1/";
const ADMISSION_POLICY_DECISION_KEY_PREFIX: &[u8] = b"frankengit/admission/policy-decision/v1/";
const ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX: &[u8] =
    b"frankengit/admission/invariant-evidence/v1/";
const ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
const ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX: &[u8] =
    b"frankengit/admission/outbox-effect-batch/v1/";
const ADMISSION_RETENTION_DELTA_KEY_PREFIX: &[u8] = b"frankengit/admission/retention-delta/v1/";
const ADMISSION_CACHE_SCOPE: &[u8] = b"node/admission-cache/v1";
const DEFAULT_MAX_OBJECT_BYTES: u64 = 32 * 1024 * 1024;
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// The git-daemon profile always advertises an `agent` capability. Besides
// identifying the deterministic server profile, this keeps an authenticated
// empty repository on Git's `capabilities^{}` advertisement form rather than
// degenerating to a bare pkt-line flush.
const GIT_DAEMON_CAPABILITIES: &[u8] = b"agent=frankengit-node";

/// The git-daemon capability advertisement for one repository object format.
///
/// Measured against pinned git-2.54.0 through the sandboxed oracle: upstream
/// advertises `object-format` for EVERY format, sha1 included, and on v0/v1 it
/// orders that token BEFORE `agent=`. This reproduces upstream exactly, because
/// §6 makes advertisement behaviour compatibility semantics rather than a
/// stylistic choice. An earlier revision omitted the token for SHA-1 on the
/// reasoning that a client seeing none selects sha1 anyway; that is compatible
/// but it is not what Git does, and the differential lane caught it.
///
/// The token is unconditional, so a future object format is advertised correctly
/// by construction: `as_str()` names it and no arm exists that could silently
/// omit it.
///
/// Anyone extending this node to protocol v2 must NOT carry the order across.
/// The same oracle run shows v2 emitting `agent=` first and `object-format=`
/// last, so the v0/v1 order is not a global Git convention.
fn git_daemon_capabilities(object_format: GitHashAlgorithm, head_target: Option<&[u8]>) -> Vec<u8> {
    let mut tokens = b"object-format=".to_vec();
    tokens.extend_from_slice(object_format.as_str().as_bytes());
    if let Some(target) = head_target {
        tokens.extend_from_slice(b" symref=HEAD:");
        tokens.extend_from_slice(target);
    }
    tokens.push(b' ');
    tokens.extend_from_slice(GIT_DAEMON_CAPABILITIES);
    tokens
}

/// Immutable upload-pack facts derived from one authenticated admission snapshot.
///
/// This view carries no mutable ref map and does not infer object reachability
/// from the local object fabric.  Its advertised refs come exclusively from a
/// caller-supplied [`AdmissionSnapshotProjection`] evaluated against an authenticated
/// authority basis.  The first-clone git-daemon transport serves the legacy
/// V0/V1 packet grammar, whose wants must name an advertised ref; therefore
/// this view deliberately refuses every non-advertised want until the
/// decision-history closure reader is wired as a separate production slice.
#[derive(Clone, Debug)]
pub struct AdmissionUploadPackRepository {
    object_format: GitHashAlgorithm,
    refs: Vec<AdvertisedRef>,
    head_target: Option<RefName>,
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
        let head_target = snapshot.head_target.clone();
        let head_oid = match head_target.as_ref() {
            Some(target) => match snapshot.refs.get(target) {
                Some(oid) => Some(*oid),
                None if snapshot.refs.is_empty() => None,
                None => {
                    return Err(AdmissionUploadPackRefusal::HeadTargetNotAdvertised(
                        target.clone(),
                    ));
                }
            },
            None => None,
        };
        let advertised_count = snapshot.refs.len() + usize::from(head_oid.is_some());
        if advertised_count > limits.max_advertised_refs {
            return Err(AdmissionUploadPackRefusal::Wire(
                WireError::TooManyAdvertisedRefs {
                    limit: limits.max_advertised_refs,
                },
            ));
        }
        let mut refs = Vec::with_capacity(advertised_count);
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
        if let Some(oid) = head_oid {
            refs.insert(
                0,
                AdvertisedRef::new(oid, b"HEAD", limits)
                    .map_err(AdmissionUploadPackRefusal::Wire)?,
            );
        }
        Ok(Self {
            object_format,
            refs,
            head_target,
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
        Projection: AdmissionSnapshotProjection + ?Sized,
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

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        (name == b"HEAD"
            && self
                .refs
                .first()
                .is_some_and(|reference| reference.name == b"HEAD"))
        .then_some(self.head_target.as_ref())
        .flatten()
        .map(RefName::as_bytes)
    }

    fn unborn_symref_target(&self) -> Option<&[u8]> {
        self.refs
            .is_empty()
            .then_some(self.head_target.as_ref())
            .flatten()
            .map(RefName::as_bytes)
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
    /// A non-empty canonical snapshot names a `HEAD` target it does not expose.
    HeadTargetNotAdvertised(RefName),
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
            Self::HeadTargetNotAdvertised(target) => write!(
                formatter,
                "canonical HEAD target {} is absent from a non-empty snapshot",
                String::from_utf8_lossy(target.as_bytes())
            ),
            Self::Wire(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for AdmissionUploadPackRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Projection(_)
            | Self::ObjectFormatMismatch { .. }
            | Self::HeadTargetNotAdvertised(_) => None,
        }
    }
}

/// The receive-pack advertisement one principal may see, derived from an
/// authenticated admission snapshot and an authority-supplied visibility policy.
///
/// # Why this is not [`AdmissionUploadPackRepository`] with a filter bolted on
///
/// Fetch and push are separate service and capability matrices
/// (`docs/AGENT_PROTOCOL.md` §6), and the fetch view deliberately advertises the
/// whole canonical ref set. A push advertisement must additionally hide what the
/// principal may not see, because §8's rule that authorization filters precede
/// disclosure applies to the ref namespace itself: a name a principal cannot push
/// to must also be a name it cannot learn exists.
///
/// # The bound is evaluated on the VISIBLE count, and that ordering is the point
///
/// [`AdmissionUploadPackRepository::from_snapshot`] checks
/// `limits.max_advertised_refs` against the whole snapshot before copying. That
/// was correct when this was written, because the fetch view had no policy to
/// consult; it is now a GAP rather than a design choice, since a repository can
/// carry hide rules that the fetch path still ignores. Whoever closes it must
/// count the visible set BEFORE applying the bound, for exactly the reason
/// below -- and must give the HEAD resolution the same treatment, since
/// `HeadTargetNotAdvertised` would otherwise disclose a hidden HEAD target.
/// Tracked on `frankengit-jkbo`. Reused verbatim here it would leak: a principal could learn that hidden refs exist by
/// receiving [`WireError::TooManyAdvertisedRefs`] for a repository whose visible
/// ref count is far below the limit. The refusal would itself become the
/// enumeration oracle this type exists to prevent.
///
/// So the visible set is counted first, the bound is applied to that count, and
/// only visible refs are ever turned into an [`AdvertisedRef`] — which also keeps
/// the crate's existing bound-before-copying discipline rather than trading one
/// property for the other.
#[derive(Clone, Debug)]
pub struct AdmissionReceivePackAdvertisement {
    object_format: GitHashAlgorithm,
    refs: Vec<AdvertisedRef>,
}

impl AdmissionReceivePackAdvertisement {
    /// Builds the filtered push advertisement for one authenticated snapshot.
    ///
    /// The visibility policy is supplied by the caller rather than derived here:
    /// this type consumes an authority-bound decision, it does not make one.
    ///
    /// # Errors
    ///
    /// [`AdmissionUploadPackRefusal::ObjectFormatMismatch`] when a visible ref
    /// carries a foreign identity domain, and [`AdmissionUploadPackRefusal::Wire`]
    /// when the visible set exceeds `limits.max_advertised_refs` or a visible name
    /// is not wire-representable.
    pub fn from_snapshot(
        snapshot: &AdmissionSnapshot,
        visibility: &RefVisibility,
        object_format: GitHashAlgorithm,
        limits: &WireLimits,
    ) -> Result<Self, AdmissionUploadPackRefusal> {
        let visible_count = snapshot
            .refs
            .keys()
            .filter(|name| !visibility.hides(name.as_bytes()))
            .count();
        if visible_count > limits.max_advertised_refs {
            return Err(AdmissionUploadPackRefusal::Wire(
                WireError::TooManyAdvertisedRefs {
                    limit: limits.max_advertised_refs,
                },
            ));
        }
        let mut visible = Vec::with_capacity(visible_count);
        for (name, oid) in &snapshot.refs {
            if visibility.hides(name.as_bytes()) {
                continue;
            }
            if oid.algorithm() != object_format {
                return Err(AdmissionUploadPackRefusal::ObjectFormatMismatch {
                    expected: object_format,
                    observed: oid.algorithm(),
                });
            }
            visible.push(
                AdvertisedRef::new(*oid, name.as_bytes(), limits)
                    .map_err(AdmissionUploadPackRefusal::Wire)?,
            );
        }
        Ok(Self {
            object_format,
            refs: filter_advertised_refs(&visible, visibility),
        })
    }

    /// The refs this principal may see for push, in canonical snapshot order.
    #[must_use]
    pub fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    /// The repository's native object format.
    #[must_use]
    pub const fn object_format(&self) -> GitHashAlgorithm {
        self.object_format
    }
}

/// Refusal while reading the current node head into an upload-pack view.
#[derive(Debug)]
pub enum NodeAdmissionViewRefusal {
    /// The durable authority read or authentication refused.
    Authority(Box<NodeRefusal>),
    /// The durable canonical-admission materializer refused the selected head.
    Materialization(Box<AdmissionMaterializationRefusal>),
    /// The authenticated receipt did not carry one usable authority-head body.
    HeadBody(Box<fgit_authority::HeadBodyRefusal>),
    /// The canonical authority-head body could not be re-identified.
    HeadIdentity(Box<fgit_codec::CodecRefusal>),
    /// The re-identified body did not belong to the authority-head domain.
    HeadIdentityDomain(Box<fgit_types::TypeRefusal>),
    /// Canonical admission or wire-view construction refused.
    View(Box<AdmissionUploadPackRefusal>),
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
            Self::Authority(error) => Some(error.as_ref()),
            Self::Materialization(error) => Some(error.as_ref()),
            Self::HeadBody(error) => Some(error.as_ref()),
            Self::HeadIdentity(error) => Some(error.as_ref()),
            Self::HeadIdentityDomain(error) => Some(error.as_ref()),
            Self::View(error) => Some(error.as_ref()),
        }
    }
}

impl From<NodeRefusal> for NodeAdmissionViewRefusal {
    fn from(value: NodeRefusal) -> Self {
        Self::Authority(Box::new(value))
    }
}

impl From<AdmissionMaterializationRefusal> for NodeAdmissionViewRefusal {
    fn from(value: AdmissionMaterializationRefusal) -> Self {
        Self::Materialization(Box::new(value))
    }
}

impl From<fgit_authority::HeadBodyRefusal> for NodeAdmissionViewRefusal {
    fn from(value: fgit_authority::HeadBodyRefusal) -> Self {
        Self::HeadBody(Box::new(value))
    }
}

impl From<fgit_codec::CodecRefusal> for NodeAdmissionViewRefusal {
    fn from(value: fgit_codec::CodecRefusal) -> Self {
        Self::HeadIdentity(Box::new(value))
    }
}

impl From<fgit_types::TypeRefusal> for NodeAdmissionViewRefusal {
    fn from(value: fgit_types::TypeRefusal) -> Self {
        Self::HeadIdentityDomain(Box::new(value))
    }
}

impl From<AdmissionUploadPackRefusal> for NodeAdmissionViewRefusal {
    fn from(value: AdmissionUploadPackRefusal) -> Self {
        Self::View(Box::new(value))
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

/// An [`AdmissionEvidence`] provider whose roots have been read from the
/// durable immutable authority store and re-derived from their decoded bodies.
///
/// The fields stay private deliberately.  A caller may receive this provider
/// only from [`DurableAdmissionMaterializer::stage_decision_evidence_in`] or
/// [`DurableAdmissionMaterializer::read_decision_evidence_in`]; neither path
/// accepts a caller-minted evidence root.
#[derive(Clone, Debug)]
pub struct DurableAdmissionEvidence {
    context: AdmissionContext,
    basis_id: RepositoryAuthorityHeadId,
    request_tx_id: TxId,
    request_digest: Digest,
    bodies: DecisionEvidenceBodies,
    evidence: CommitEvidence,
}

impl DurableAdmissionEvidence {
    fn from_bodies(
        context: AdmissionContext,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        bodies: DecisionEvidenceBodies,
    ) -> Result<Self, AdmissionMaterializationRefusal> {
        let evidence = CommitEvidence {
            principal_snapshot_id: principal_snapshot_id(bodies.principal_snapshot())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
            forge_event_batch_root: evidence_root(bodies.forge_event_batch())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
            policy_decision_root: evidence_root(bodies.policy_decision())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
            invariant_evidence_root: evidence_root(bodies.invariant_evidence())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
            outbox_effect_root: evidence_root(bodies.outbox_effect_batch())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
            retention_delta_root: evidence_root(bodies.retention_delta())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
        };
        Ok(Self {
            context,
            basis_id: basis.id(),
            request_tx_id: request.tx_id,
            request_digest: request.canonical_request_digest,
            bodies,
            evidence,
        })
    }

    /// Returns the RCR fields proved by this durable evidence provider.
    #[must_use]
    pub const fn commit_evidence_record(&self) -> CommitEvidence {
        self.evidence
    }
}

impl AdmissionEvidence for DurableAdmissionEvidence {
    fn commit_evidence(
        &self,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
    ) -> Result<CommitEvidence, RefusalCode> {
        if basis.id() != self.basis_id
            || request.tx_id != self.request_tx_id
            || request.canonical_request_digest != self.request_digest
            || !request_matches_admission_context(request, &self.context)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let derived = DecisionEvidenceBodies::derive(&self.context, basis, request, fold)?;
        if derived != self.bodies {
            return Err(RefusalCode::EvidenceMissing);
        }
        Ok(self.evidence)
    }

    fn refusal_evidence(
        &self,
        _basis: &PublicationBasis,
        _tx_id: TxId,
        _code: RefusalCode,
    ) -> Result<RefusalMaterialization, RefusalCode> {
        // This provider proves a committing record only. A refusal requires
        // authority-backed staging and is produced by DurableAsyncAdmissionProjection.
        Err(RefusalCode::DurabilityProfileUnavailable)
    }
}

#[derive(Clone, Debug)]
struct MaterializedAdmissionState {
    authenticated: AuthenticatedHead,
    basis: PublicationBasis,
    cache_permit: CachePermit,
    ref_state: CanonicalRefState,
    selected_closure: AuthoritySelectedClosure,
    policy_epoch: PolicyEpoch,
    configuration_root: Digest,
    /// The hide policy this repository's configuration named, already built.
    ///
    /// Resolved once when the basis was materialized rather than on every
    /// snapshot. `snapshot_for` already compares `configuration_root` against
    /// the authenticated head and drops this whole state on mismatch, so a
    /// policy cached beside that root cannot outlive the configuration it came
    /// from -- a stale projection therefore cannot expand disclosure, and no
    /// new guard is needed to say so.
    hidden_refs: RefVisibility,
}

/// The canonical record through which an authority head selected a closure.
///
/// The empty genesis state has no RCR by protocol design.  Its empty closure
/// is therefore selected only when the authenticated genesis ref state is
/// empty; imports with objects must first publish an RCR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureSelectionSource {
    /// The empty closure paired with the empty genesis ref state.
    EmptyGenesis,
    /// The latest committed RCR found by replaying the authenticated head chain.
    RepositoryCommit(RepositoryCommitId),
}

/// A permitted object set selected from authenticated authority history.
///
/// This is not a local reachability cache: `root` is re-derived from `closure`,
/// and `source` names the genesis rule or exact RCR that selected it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySelectedClosure {
    root: Digest,
    closure: PermittedObjectClosure,
    source: ClosureSelectionSource,
}

impl AuthoritySelectedClosure {
    /// The RCR commitment root reproduced by the decoded closure bytes.
    #[must_use]
    pub const fn root(&self) -> Digest {
        self.root
    }

    /// The immutable native Git object identities permitted by that root.
    #[must_use]
    pub const fn closure(&self) -> &PermittedObjectClosure {
        &self.closure
    }

    /// The exact authority-history source that selected the closure.
    #[must_use]
    pub const fn source(&self) -> ClosureSelectionSource {
        self.source
    }
}

/// One immutable admission snapshot paired with the authority receipt that
/// selected it.
///
/// The receipt is intentionally retained with the snapshot.  A user that
/// needs the generic admission interface can pass the same receipt and basis
/// to [`AdmissionSnapshotProjection::snapshot`]; mixing an otherwise-valid snapshot
/// with another head is a typed refusal.
#[derive(Clone, Debug)]
pub struct MaterializedAdmission {
    authenticated: AuthenticatedHead,
    basis: PublicationBasis,
    snapshot: AdmissionSnapshot,
    selected_closure: AuthoritySelectedClosure,
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

    /// The exact authority-selected object closure available to a pack writer.
    #[must_use]
    pub const fn selected_closure(&self) -> &AuthoritySelectedClosure {
        &self.selected_closure
    }
}

/// A bounded Git pack derived from one authority-selected object closure.
///
/// The payload is consumable only after the `fgit-pack` writer finished its
/// temporary artifact and checksum.  Its evidence retains both the exact
/// authority head basis and the RCR/genesis source that selected the objects.
#[derive(Debug)]
pub struct AuthoritySelectedPackPayload {
    basis: PublicationBasis,
    closure: AuthoritySelectedClosure,
    receipt: PackWriteReceipt,
    bytes: Vec<u8>,
    offset: usize,
}

impl AuthoritySelectedPackPayload {
    /// The authenticated authority basis that selected the payload closure.
    #[must_use]
    pub const fn basis(&self) -> &PublicationBasis {
        &self.basis
    }

    /// The closure root and RCR/genesis source that authorized every entry.
    #[must_use]
    pub const fn closure(&self) -> &AuthoritySelectedClosure {
        &self.closure
    }

    /// The completed deterministic pack-writer receipt.
    #[must_use]
    pub const fn receipt(&self) -> &PackWriteReceipt {
        &self.receipt
    }

    /// Consumes this completed payload and returns the exact Git pack bytes.
    ///
    /// This does not re-materialize the closure or consult the object fabric:
    /// the returned bytes are the already completed pack whose receipt remains
    /// available until this call consumes the payload.  A file-export caller
    /// may therefore publish only this immutable, authority-selected result.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl PackPayloadSource for AuthoritySelectedPackPayload {
    fn next_chunk(&mut self, maximum_chunk_bytes: usize) -> Result<Option<Vec<u8>>, WireError> {
        if maximum_chunk_bytes == 0 {
            return Err(WireError::InvalidLimit {
                field: "pack payload chunk bytes",
            });
        }
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let remaining = self.bytes.len().saturating_sub(self.offset);
        let length = remaining.min(maximum_chunk_bytes);
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::AllocationFailure)?;
        let mut chunk = Vec::new();
        chunk
            .try_reserve_exact(length)
            .map_err(|_| WireError::AllocationFailure)?;
        chunk.extend_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(Some(chunk))
    }
}

/// Refusal while turning an authority-selected closure into a Git pack.
#[derive(Debug)]
pub enum NodePackMaterializationRefusal {
    /// The exact-head admission materialization was unavailable or invalid.
    Admission(Box<AdmissionMaterializationRefusal>),
    /// The bounded deterministic pack planner or writer refused the closure.
    Pack(Box<PackWriteError>),
}

impl Display for NodePackMaterializationRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodePackMaterializationRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error.as_ref()),
            Self::Pack(error) => Some(error.as_ref()),
        }
    }
}

impl From<AdmissionMaterializationRefusal> for NodePackMaterializationRefusal {
    fn from(value: AdmissionMaterializationRefusal) -> Self {
        Self::Admission(Box::new(value))
    }
}

impl From<PackWriteError> for NodePackMaterializationRefusal {
    fn from(value: PackWriteError) -> Self {
        Self::Pack(Box::new(value))
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
    /// The authenticated receipt and requested publication basis did not name
    /// the same authority head.
    ExactBasisMismatch,
    /// Reading an authority-addressed head or decision body refused.
    DecisionHistory(Box<fgit_authority::OutcomeFailure>),
    /// A decoded head and batch did not satisfy the chronicle successor rules.
    DecisionHistoryVerification(fgit_chronicle::ChronicleRefusal),
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
    /// Re-identifying a committed RCR failed.
    CommitIdentity(CodecRefusal),
    /// The re-identified RCR carried a different derived-identity domain.
    CommitIdentityDomain(fgit_types::TypeRefusal),
    /// A head named a decision batch but omitted the predecessor needed to verify it.
    DecisionHistoryUnbound,
    /// A re-identified RCR did not agree with the successor head's latest record.
    LatestCommitMismatch {
        /// RCR identity recomputed from the selected record.
        expected: Box<RepositoryCommitId>,
        /// RCR identity carried by the selected authority head.
        observed: Option<Box<RepositoryCommitId>>,
    },
    /// The selected RCR did not describe the successor head's repository state.
    SelectedCommitStateMismatch { field: &'static str },
    /// A no-decision genesis head named a non-empty ref state without an RCR closure.
    NonEmptyGenesisWithoutClosure,
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
            Self::ExactBasisMismatch => formatter.write_str(
                "authenticated authority receipt disagrees with requested publication basis",
            ),
            Self::DecisionHistory(error) => Display::fmt(error, formatter),
            Self::DecisionHistoryVerification(error) => Display::fmt(error, formatter),
            Self::RepositoryMismatch { expected, observed } => write!(
                formatter,
                "authenticated admission head repository {observed:?} differs from {expected:?}"
            ),
            Self::HeadIdentity(error)
            | Self::CommitIdentity(error)
            | Self::CanonicalFrame(error) => Display::fmt(error, formatter),
            Self::HeadIdentityDomain(error) | Self::CommitIdentityDomain(error) => {
                Display::fmt(error, formatter)
            }
            Self::DecisionHistoryUnbound => formatter
                .write_str("authority decision history omitted a required predecessor head"),
            Self::LatestCommitMismatch { expected, observed } => write!(
                formatter,
                "authority head latest RCR {observed:?} differs from selected record {expected:?}"
            ),
            Self::SelectedCommitStateMismatch { field } => write!(
                formatter,
                "selected RCR does not bind successor authority {field}"
            ),
            Self::NonEmptyGenesisWithoutClosure => {
                formatter.write_str("non-empty genesis has no authority-selected RCR closure")
            }
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
            Self::DecisionHistory(error) => Some(error.as_ref()),
            Self::DecisionHistoryVerification(error) => Some(error),
            Self::HeadIdentity(error)
            | Self::CommitIdentity(error)
            | Self::CanonicalFrame(error) => Some(error),
            Self::HeadIdentityDomain(error) | Self::CommitIdentityDomain(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::CacheGrant(error) => Some(error),
            Self::HeadAbsent
            | Self::Cancelled
            | Self::ExactBasisMismatch
            | Self::RepositoryMismatch { .. }
            | Self::DecisionHistoryUnbound
            | Self::LatestCommitMismatch { .. }
            | Self::SelectedCommitStateMismatch { .. }
            | Self::NonEmptyGenesisWithoutClosure
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

    /// Derives and stages every immutable body that an admitted committing
    /// decision must quote, then returns the provider bound to those exact
    /// durable bytes.
    ///
    /// Staging happens before a provider exists, so an RCR cannot name a root
    /// that was only computed in memory.  A cancellation may leave harmless
    /// immutable pre-staged frames, but never returns a provider that could be
    /// used to publish them.
    pub async fn stage_decision_evidence_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        context: AdmissionContext,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        is_cancelled: &IsCancelled,
    ) -> Result<DurableAdmissionEvidence, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        if context.repository_id != basis.body().repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: context.repository_id,
                observed: basis.body().repository_id,
            });
        }
        if !request_matches_admission_context(request, &context) {
            return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::EvidenceInvalid,
            ));
        }
        ensure_materializer_catch_up_live(is_cancelled)?;
        let bodies = DecisionEvidenceBodies::derive(&context, basis, request, fold)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let provider = DurableAdmissionEvidence::from_bodies(context, basis, request, bodies)?;
        self.stage_evidence_bodies_in(authority, cx, &provider.bodies, is_cancelled)
            .await?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        Ok(provider)
    }

    /// Derives and stages the immutable evidence body quoted by one terminal
    /// refusal record.
    ///
    /// A refusal has no committing decision provider to carry its root.  Its
    /// principal snapshot and refusal witness are therefore staged here from
    /// the exact authenticated basis, transaction identity, and evaluated
    /// refusal code before the async admission driver can publish the record.
    pub async fn stage_refusal_evidence_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
        is_cancelled: &IsCancelled,
    ) -> Result<RefusalMaterialization, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        if context.repository_id != basis.body().repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: context.repository_id,
                observed: basis.body().repository_id,
            });
        }
        ensure_materializer_catch_up_live(is_cancelled)?;
        let bodies = RefusalEvidenceBodies::derive(context, basis, tx_id, code)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        self.stage_refusal_evidence_bodies_in(authority, cx, &bodies, is_cancelled)
            .await?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: DURABLE_REFUSAL_EVIDENCE_DETAIL.to_owned(),
            evidence_root: evidence_root(bodies.refusal_evidence())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
        })
    }

    /// Reads every named evidence body from immutable authority storage,
    /// verifies its content root, and rebuilds the provider only if those
    /// decoded bodies are exactly the bodies the supplied decision requires.
    pub async fn read_decision_evidence_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        context: AdmissionContext,
        basis: &PublicationBasis,
        request: &TransactionRequest,
        fold: &TransactionFoldReport,
        evidence: CommitEvidence,
        is_cancelled: &IsCancelled,
    ) -> Result<DurableAdmissionEvidence, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        if context.repository_id != basis.body().repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: context.repository_id,
                observed: basis.body().repository_id,
            });
        }
        if !request_matches_admission_context(request, &context) {
            return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::EvidenceInvalid,
            ));
        }
        ensure_materializer_catch_up_live(is_cancelled)?;
        let principal_snapshot =
            read_evidence_body_in::<Authority, PrincipalSnapshot, IsCancelled>(
                authority,
                cx,
                context.repository_id,
                ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
                Digest::new(
                    evidence
                        .principal_snapshot_id
                        .as_internal_object_id()
                        .algorithm(),
                    *evidence
                        .principal_snapshot_id
                        .as_internal_object_id()
                        .digest(),
                ),
                is_cancelled,
            )
            .await?;
        let policy_decision =
            read_evidence_body_in::<Authority, PolicyDecisionEvidence, IsCancelled>(
                authority,
                cx,
                context.repository_id,
                ADMISSION_POLICY_DECISION_KEY_PREFIX,
                evidence.policy_decision_root,
                is_cancelled,
            )
            .await?;
        let invariant_evidence =
            read_evidence_body_in::<Authority, InvariantEvidence, IsCancelled>(
                authority,
                cx,
                context.repository_id,
                ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
                evidence.invariant_evidence_root,
                is_cancelled,
            )
            .await?;
        let forge_event_batch = read_evidence_body_in::<Authority, ForgeEventBatch, IsCancelled>(
            authority,
            cx,
            context.repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            evidence.forge_event_batch_root,
            is_cancelled,
        )
        .await?;
        let outbox_effect_batch =
            read_evidence_body_in::<Authority, OutboxEffectBatch, IsCancelled>(
                authority,
                cx,
                context.repository_id,
                ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
                evidence.outbox_effect_root,
                is_cancelled,
            )
            .await?;
        let retention_delta = read_evidence_body_in::<Authority, RetentionDelta, IsCancelled>(
            authority,
            cx,
            context.repository_id,
            ADMISSION_RETENTION_DELTA_KEY_PREFIX,
            evidence.retention_delta_root,
            is_cancelled,
        )
        .await?;
        let bodies = DecisionEvidenceBodies::from_decoded(
            principal_snapshot,
            policy_decision,
            invariant_evidence,
            forge_event_batch,
            outbox_effect_batch,
            retention_delta,
        );
        let provider =
            DurableAdmissionEvidence::from_bodies(context.clone(), basis, request, bodies)?;
        if provider.evidence != evidence {
            return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::InternalInvariantBreach,
            ));
        }
        let derived = DecisionEvidenceBodies::derive(&context, basis, request, fold)
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        if provider.bodies != derived {
            return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::InternalInvariantBreach,
            ));
        }
        ensure_materializer_catch_up_live(is_cancelled)?;
        Ok(provider)
    }

    async fn stage_evidence_bodies_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        bodies: &DecisionEvidenceBodies,
        is_cancelled: &IsCancelled,
    ) -> Result<(), AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        let repository_id = bodies.principal_snapshot().repository_id();
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            bodies.principal_snapshot(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_POLICY_DECISION_KEY_PREFIX,
            bodies.policy_decision(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
            bodies.invariant_evidence(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            bodies.forge_event_batch(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
            bodies.outbox_effect_batch(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_RETENTION_DELTA_KEY_PREFIX,
            bodies.retention_delta(),
            is_cancelled,
        )
        .await
    }

    async fn stage_refusal_evidence_bodies_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        bodies: &RefusalEvidenceBodies,
        is_cancelled: &IsCancelled,
    ) -> Result<(), AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        let repository_id = bodies.principal_snapshot().repository_id();
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            bodies.principal_snapshot(),
            is_cancelled,
        )
        .await?;
        stage_evidence_body_in(
            authority,
            cx,
            repository_id,
            ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX,
            bodies.refusal_evidence(),
            is_cancelled,
        )
        .await
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
    /// RCR (or the empty-genesis rule) can do that.  The current resolver
    /// reads that association back from authenticated authority history rather
    /// than treating this staged frame as a node-local catalog entry.
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
        let basis = PublicationBasis::new(authority_head_id(&body)?, body);
        self.materialize_exact_in(
            authority,
            cx,
            repository_id,
            &basis,
            &authenticated,
            is_cancelled,
        )
        .await
    }

    /// Materializes exactly the already authenticated authority head selected
    /// by an admission attempt.
    ///
    /// Unlike [`Self::materialize_current_in`], this method never rereads the
    /// head. That distinction is load-bearing for a CAS replan: a newer head
    /// observed during cache refresh must be handled by the admission driver's
    /// next attempt, not mistaken for a terminal refusal of the prior basis.
    pub async fn materialize_exact_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        repository_id: RepositoryId,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        is_cancelled: &IsCancelled,
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        let authenticated_body = authenticated
            .body()
            .map_err(AdmissionMaterializationRefusal::HeadBody)?;
        if authenticated_body != *basis.body()
            || authority_head_id(&authenticated_body)? != basis.id()
        {
            return Err(AdmissionMaterializationRefusal::ExactBasisMismatch);
        }
        self.materialize_selected_in(
            authority,
            cx,
            repository_id,
            basis,
            authenticated,
            is_cancelled,
        )
        .await
    }

    async fn materialize_selected_in<Authority, IsCancelled>(
        &self,
        authority: &Authority,
        cx: &Authority::Context,
        repository_id: RepositoryId,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        is_cancelled: &IsCancelled,
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal>
    where
        Authority: AsyncAuthorityStore + ?Sized,
        IsCancelled: Fn() -> bool + Sync,
    {
        let body = basis.body().clone();
        if body.repository_id != repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: repository_id,
                observed: body.repository_id,
            });
        }
        let cache_binding =
            CacheBinding::new(repository_id, basis.id(), body.generation, self.cache_scope);
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
            let (closure_root, selection_source) =
                select_authority_closure_in(authority, cx, body.clone(), &ref_state, is_cancelled)
                    .await?;
            ensure_materializer_catch_up_live(is_cancelled)?;
            let closure_key =
                admission_immutable_key(ADMISSION_CLOSURE_KEY_PREFIX, repository_id, closure_root)
                    .map_err(AdmissionMaterializationRefusal::Key)?;
            let ImmutableRead::Present(closure_frame) = authority
                .read_immutable(cx, &closure_key)
                .await
                .map_err(AdmissionMaterializationRefusal::Authority)?
            else {
                return Err(AdmissionMaterializationRefusal::ImmutableAbsent(
                    closure_root,
                ));
            };
            ensure_materializer_catch_up_live(is_cancelled)?;
            let closure = decode_body::<PermittedObjectClosure>(
                &closure_frame,
                fgit_codec::DecodeLimits::DEFAULT,
            )
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
            if permitted_object_closure_root(&closure)
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?
                != closure_root
            {
                return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                    RefusalCode::InternalInvariantBreach,
                ));
            }
            let selected_closure = AuthoritySelectedClosure {
                root: closure_root,
                closure,
                source: selection_source,
            };
            // The repository's own hide policy, read from the configuration the
            // authenticated head selects. A rule that will not parse refuses the
            // materialization rather than being skipped: skipping would serve
            // refs the repository means to hide, which is the failure this slice
            // exists to prevent. EvidenceInvalid and never RefNameInvalid -- the
            // latter reaches a pushing client as "invalid ref name" and would
            // blame it for a defect in stored configuration.
            let hidden_refs = match fgit_authority::read_repository_configuration_async(
                authority,
                cx,
                &body.configuration_root,
            )
            .await
            {
                Ok(configuration) => {
                    let mut policy = RefVisibility::new();
                    for rule in &configuration.hidden_ref_rules {
                        policy
                            .push_rule(rule, &WireLimits::default())
                            .map_err(|_| {
                                AdmissionMaterializationRefusal::CanonicalRoot(
                                    RefusalCode::EvidenceInvalid,
                                )
                            })?;
                    }
                    policy
                }
                // A head selecting the incarnation-aware configuration carries no
                // hide rules: schema major 2 is policy-free by design (fg059), so
                // such a repository hides nothing. That is a KNOWN LIMITATION
                // recorded on frankengit-jkbo, not an oversight, and it is why
                // this arm is as narrow as it is -- only the exact major-2 case
                // is read as "no policy" and every other failure still refuses.
                //
                // The migration hazard is worth naming: moving a repository from
                // the major-1 body to the incarnation body silently drops its
                // hide rules. Closing that needs a policy field on the major-2
                // body, which is its owner's call and is not this slice.
                Err(fgit_authority::OutcomeFailure::Codec(
                    fgit_codec::CodecRefusal::SchemaMajorUnsupported { observed: 2, .. },
                )) => RefVisibility::new(),
                Err(error) => {
                    return Err(AdmissionMaterializationRefusal::DecisionHistory(Box::new(
                        error,
                    )));
                }
            };
            let snapshot = AdmissionSnapshot {
                refs: ref_state.refs().clone(),
                head_target: ref_state.head_target().cloned(),
                forge_positions: BTreeMap::new(),
                retention: BTreeSet::new(),
                outbox: BTreeMap::new(),
                hidden_refs: hidden_refs.clone(),
            };
            let cache_permit = cache_grant
                .accept(cache_binding)
                .map_err(AdmissionMaterializationRefusal::CacheGrant)?;
            ensure_materializer_catch_up_live(is_cancelled)?;
            let materialized = MaterializedAdmission {
                authenticated: authenticated.clone(),
                basis: basis.clone(),
                snapshot,
                selected_closure: selected_closure.clone(),
            };
            let state = MaterializedAdmissionState {
                authenticated: authenticated.clone(),
                basis: basis.clone(),
                cache_permit,
                ref_state,
                selected_closure,
                policy_epoch: body.policy_epoch,
                configuration_root: body.configuration_root,
                hidden_refs,
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
            || permitted_object_closure_root(&materialized.selected_closure.closure)?
                != materialized.selected_closure.root
            || CachePermit::require_matching(Some(&materialized.cache_permit), cache_binding)
                .is_err();
        if mismatched {
            // CALM-015: an absent or mismatched authenticated basis cannot
            // leave a reusable derived view behind.
            *guard = None;
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let ref_state = &guard
            .as_ref()
            .ok_or(RefusalCode::EvidenceMissing)?
            .ref_state;
        let refs = ref_state.refs().clone();
        let head_target = ref_state.head_target().cloned();
        // Cloned from the cache rather than rebuilt: the mismatch check above
        // already discarded this state if its configuration_root disagreed with
        // the authenticated head, so what is cached here is the policy of the
        // basis being served and cannot be a stale one.
        let hidden_refs = guard
            .as_ref()
            .ok_or(RefusalCode::EvidenceMissing)?
            .hidden_refs
            .clone();
        drop(guard);
        Ok(AdmissionSnapshot {
            refs,
            head_target,
            forge_positions: BTreeMap::new(),
            retention: BTreeSet::new(),
            outbox: BTreeMap::new(),
            hidden_refs,
        })
    }

    fn discard_materialized_cache(&self) -> Result<(), RefusalCode> {
        let mut guard = self
            .materialized
            .write()
            .map_err(|_| RefusalCode::InternalInvariantBreach)?;
        *guard = None;
        drop(guard);
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
        root: Digest,
    ) -> Result<PermittedObjectClosure, RefusalCode> {
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
        if materialized.selected_closure.root != root {
            return Err(RefusalCode::AuthorityReceiptStale);
        }
        let closure = materialized.selected_closure.closure.clone();
        drop(guard);
        Ok(closure)
    }

    fn stage_permitted_object_closure(
        &self,
        _root: Digest,
        _closure: PermittedObjectClosure,
    ) -> Result<(), RefusalCode> {
        Err(RefusalCode::DurabilityProfileUnavailable)
    }
}

impl AdmissionSnapshotProjection for DurableAdmissionMaterializer {
    fn snapshot(
        &self,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, RefusalCode> {
        self.snapshot_for(basis, authenticated)
    }
}

/// One exact state loaded while an asynchronous admission attempt was prepared.
///
/// This is request-scoped derived data, not a second authority store. It is
/// replaced on every async snapshot and consumed by its matching commit
/// materialization, so a CAS replan cannot reuse a predecessor's ref state.
#[derive(Clone, Debug)]
struct AsyncMaterializedBasis {
    basis: PublicationBasis,
    ref_state: CanonicalRefState,
}

/// Asynchronous durable projection for an embedded `Fsqlite` authority node.
///
/// The projection deliberately implements only
/// [`AsyncAdmissionProjection`], never [`fgit_admission::AdmissionProjection`].
/// Passing it to a blocking entrypoint is therefore a type error rather than a
/// canonical terminal refusal. Each snapshot reloads the exact basis selected
/// by the async driver, then the matching materialization stages successor
/// bodies before `fgit-admission` can attempt the authority-head CAS.
///
/// The node owns the authenticated admission context.  It derives a committing
/// provider only after the driver supplies the exact fold and stages refusal
/// evidence directly through authority; it never accepts caller-minted roots.
#[derive(Debug)]
pub struct DurableAsyncAdmissionProjection<'materializer> {
    materializer: &'materializer DurableAdmissionMaterializer,
    context: AdmissionContext,
    prepared: Mutex<Option<AsyncMaterializedBasis>>,
}

impl<'materializer> DurableAsyncAdmissionProjection<'materializer> {
    /// Connects the durable frame materializer to one node-owned admission context.
    #[must_use]
    pub const fn new(
        materializer: &'materializer DurableAdmissionMaterializer,
        context: AdmissionContext,
    ) -> Self {
        Self {
            materializer,
            context,
            prepared: Mutex::new(None),
        }
    }
}

impl AsyncAdmissionProjection<FsqliteAuthorityStore> for DurableAsyncAdmissionProjection<'_> {
    #[expect(
        clippy::manual_async_fn,
        reason = "the explicit + Send future is the cross-thread async projection contract"
    )]
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, AsyncProjectionFailure>> + Send + 'a {
        async move {
            let catch_up = cx.create_child();
            let is_cancelled = || catch_up.checkpoint().is_err();
            let materialized = self
                .materializer
                .materialize_exact_in(
                    authority,
                    &catch_up,
                    self.context.repository_id,
                    basis,
                    authenticated,
                    &is_cancelled,
                )
                .await
                .map_err(async_projection_unavailable)?;
            let prepared = AsyncMaterializedBasis {
                basis: basis.clone(),
                ref_state: CanonicalRefState::new(materialized.snapshot().refs.clone()),
            };
            *self.prepared.lock().map_err(|_| {
                AsyncProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach)
            })? = Some(prepared);
            Ok(materialized.snapshot().clone())
        }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "the explicit + Send future is the cross-thread async projection contract"
    )]
    fn materialize_commit_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, AsyncProjectionFailure>> + Send + 'a
    {
        async move {
            let prepared_basis = self
                .prepared
                .lock()
                .map_err(|_| {
                    AsyncProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach)
                })?
                .take()
                .ok_or(AsyncProjectionFailure::Unavailable(
                    RefusalCode::EvidenceMissing,
                ))?;
            if prepared_basis.basis != *basis {
                return Err(AsyncProjectionFailure::Unavailable(
                    RefusalCode::AuthorityReceiptStale,
                ));
            }
            let stage_context = cx.create_child();
            let is_cancelled = || stage_context.checkpoint().is_err();
            let provider = self
                .materializer
                .stage_decision_evidence_in(
                    authority,
                    &stage_context,
                    self.context.clone(),
                    basis,
                    request,
                    fold,
                    &is_cancelled,
                )
                .await
                .map_err(async_projection_unavailable)?;
            let evidence = provider
                .commit_evidence(basis, request, fold)
                .map_err(AsyncProjectionFailure::Unavailable)?;
            let prepared = prepare_canonical_commit(
                basis,
                request,
                fold,
                closure,
                prepared_basis.ref_state,
                evidence,
            )
            .map_err(AsyncProjectionFailure::Refuse)?;
            let ref_root = self
                .materializer
                .stage_ref_state_in(
                    authority,
                    cx,
                    self.context.repository_id,
                    prepared.next_ref_state().clone(),
                )
                .await
                .map_err(async_projection_unavailable)?;
            if ref_root != prepared.ref_root() {
                return Err(AsyncProjectionFailure::Unavailable(
                    RefusalCode::InternalInvariantBreach,
                ));
            }
            let closure_root = self
                .materializer
                .stage_permitted_object_closure_in(
                    authority,
                    cx,
                    self.context.repository_id,
                    prepared.object_closure().clone(),
                )
                .await
                .map_err(async_projection_unavailable)?;
            if closure_root != prepared.object_closure_root() {
                return Err(AsyncProjectionFailure::Unavailable(
                    RefusalCode::InternalInvariantBreach,
                ));
            }
            Ok(prepared.into_materialization())
        }
    }

    async fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a FsqliteCx,
        basis: &'a PublicationBasis,
        tx_id: fgit_types::TxId,
        code: RefusalCode,
    ) -> Result<RefusalMaterialization, AsyncProjectionFailure> {
        let stage_context = cx.create_child();
        let is_cancelled = || stage_context.checkpoint().is_err();
        self.materializer
            .stage_refusal_evidence_in(
                authority,
                &stage_context,
                &self.context,
                basis,
                tx_id,
                code,
                &is_cancelled,
            )
            .await
            .map_err(async_projection_unavailable)
    }
}

fn async_projection_unavailable(
    refusal: AdmissionMaterializationRefusal,
) -> AsyncProjectionFailure {
    let code = match refusal {
        AdmissionMaterializationRefusal::Cancelled => RefusalCode::CancellationInProgress,
        AdmissionMaterializationRefusal::CanonicalRoot(code) => code,
        AdmissionMaterializationRefusal::CanonicalFrame(_) => RefusalCode::CanonicalFramingInvalid,
        AdmissionMaterializationRefusal::Resource(_)
        | AdmissionMaterializationRefusal::CacheGrant(_)
        | AdmissionMaterializationRefusal::CacheContainment => RefusalCode::ResourceBudgetExceeded,
        AdmissionMaterializationRefusal::ExactBasisMismatch
        | AdmissionMaterializationRefusal::RepositoryMismatch { .. } => {
            RefusalCode::AuthorityReceiptStale
        }
        AdmissionMaterializationRefusal::HeadAbsent
        | AdmissionMaterializationRefusal::Authority(_)
        | AdmissionMaterializationRefusal::HeadBody(_)
        | AdmissionMaterializationRefusal::DecisionHistory(_)
        | AdmissionMaterializationRefusal::DecisionHistoryVerification(_)
        | AdmissionMaterializationRefusal::HeadIdentity(_)
        | AdmissionMaterializationRefusal::HeadIdentityDomain(_)
        | AdmissionMaterializationRefusal::CommitIdentity(_)
        | AdmissionMaterializationRefusal::CommitIdentityDomain(_)
        | AdmissionMaterializationRefusal::DecisionHistoryUnbound
        | AdmissionMaterializationRefusal::LatestCommitMismatch { .. }
        | AdmissionMaterializationRefusal::SelectedCommitStateMismatch { .. }
        | AdmissionMaterializationRefusal::NonEmptyGenesisWithoutClosure
        | AdmissionMaterializationRefusal::ImmutableAbsent(_)
        | AdmissionMaterializationRefusal::Key(_)
        | AdmissionMaterializationRefusal::ImmutableConflict
        | AdmissionMaterializationRefusal::CachePoisoned => RefusalCode::EvidenceMissing,
    };
    AsyncProjectionFailure::Unavailable(code)
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

async fn stage_evidence_body_in<Authority, Body, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    repository_id: RepositoryId,
    namespace: &[u8],
    body: &Body,
    is_cancelled: &IsCancelled,
) -> Result<(), AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    Body: CanonicalBody + Sync,
    IsCancelled: Fn() -> bool + Sync,
{
    ensure_materializer_catch_up_live(is_cancelled)?;
    let root = evidence_root(body).map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
    let frame = encode_body(body).map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    let key = admission_immutable_key(namespace, repository_id, root)
        .map_err(AdmissionMaterializationRefusal::Key)?;
    ensure_materializer_catch_up_live(is_cancelled)?;
    stage_immutable_frame(authority, cx, &key, &frame).await?;
    ensure_materializer_catch_up_live(is_cancelled)
}

async fn read_evidence_body_in<Authority, Body, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    repository_id: RepositoryId,
    namespace: &[u8],
    root: Digest,
    is_cancelled: &IsCancelled,
) -> Result<Body, AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    Body: CanonicalBody,
    IsCancelled: Fn() -> bool + Sync,
{
    ensure_materializer_catch_up_live(is_cancelled)?;
    let key = admission_immutable_key(namespace, repository_id, root)
        .map_err(AdmissionMaterializationRefusal::Key)?;
    let ImmutableRead::Present(frame) = authority
        .read_immutable(cx, &key)
        .await
        .map_err(AdmissionMaterializationRefusal::Authority)?
    else {
        return Err(AdmissionMaterializationRefusal::ImmutableAbsent(root));
    };
    ensure_materializer_catch_up_live(is_cancelled)?;
    let body = decode_body::<Body>(&frame, fgit_codec::DecodeLimits::DEFAULT)
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    if evidence_root(&body).map_err(AdmissionMaterializationRefusal::CanonicalRoot)? != root {
        return Err(AdmissionMaterializationRefusal::CanonicalRoot(
            RefusalCode::InternalInvariantBreach,
        ));
    }
    Ok(body)
}

fn request_matches_admission_context(
    request: &TransactionRequest,
    context: &AdmissionContext,
) -> bool {
    request.tenant == context.tenant_id
        && request.repository == context.repository_id
        && request.principal == context.principal_id
}

fn ensure_materializer_catch_up_live(
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> Result<(), AdmissionMaterializationRefusal> {
    if is_cancelled() {
        Err(AdmissionMaterializationRefusal::Cancelled)
    } else {
        Ok(())
    }
}

fn authority_head_id(
    body: &RepositoryAuthorityHeadBody,
) -> Result<RepositoryAuthorityHeadId, AdmissionMaterializationRefusal> {
    body_id(&CryptoBodyIdentity, body)
        .map_err(AdmissionMaterializationRefusal::HeadIdentity)
        .and_then(|identity| {
            RepositoryAuthorityHeadId::from_internal_object_id(identity)
                .map_err(AdmissionMaterializationRefusal::HeadIdentityDomain)
        })
}

fn repository_commit_id(
    record: &RepositoryCommitRecord,
) -> Result<RepositoryCommitId, AdmissionMaterializationRefusal> {
    body_id(&CryptoBodyIdentity, record)
        .map_err(AdmissionMaterializationRefusal::CommitIdentity)
        .and_then(|identity| {
            RepositoryCommitId::from_internal_object_id(identity)
                .map_err(AdmissionMaterializationRefusal::CommitIdentityDomain)
        })
}

/// Selects the last committed closure from one authenticated head chain.
///
/// A refusal-only batch advances the head but does not change the object
/// closure, so this deliberately walks predecessors until it finds an RCR.
/// Every hop re-identifies the predecessor, verifies the batch/successor pair,
/// and is bounded by the authority replay ceiling before another immutable read.
async fn select_authority_closure_in<Authority>(
    authority: &Authority,
    cx: &Authority::Context,
    current_head: RepositoryAuthorityHeadBody,
    current_refs: &CanonicalRefState,
    is_cancelled: &(impl Fn() -> bool + Sync),
) -> Result<(Digest, ClosureSelectionSource), AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
{
    let mut successor = current_head;
    let mut walked = 0_usize;

    loop {
        ensure_materializer_catch_up_live(is_cancelled)?;
        let Some(batch_id) = fgit_authority::next_batch_to_replay(&successor, &mut walked)
            .map_err(|error| AdmissionMaterializationRefusal::DecisionHistory(Box::new(error)))?
        else {
            if successor.predecessor_head_id.is_some() {
                return Err(AdmissionMaterializationRefusal::DecisionHistoryUnbound);
            }
            if !current_refs.refs().is_empty() {
                return Err(AdmissionMaterializationRefusal::NonEmptyGenesisWithoutClosure);
            }
            let closure = PermittedObjectClosure::default();
            let root = permitted_object_closure_root(&closure)
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
            return Ok((root, ClosureSelectionSource::EmptyGenesis));
        };
        let predecessor_id = successor
            .predecessor_head_id
            .ok_or(AdmissionMaterializationRefusal::DecisionHistoryUnbound)?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        let predecessor = read_authority_head_body_async(authority, cx, predecessor_id)
            .await
            .map_err(|error| AdmissionMaterializationRefusal::DecisionHistory(Box::new(error)))?;
        ensure_materializer_catch_up_live(is_cancelled)?;
        let batch = read_decision_batch_body_async(authority, cx, batch_id)
            .await
            .map_err(|error| AdmissionMaterializationRefusal::DecisionHistory(Box::new(error)))?;
        let basis = PublicationBasis::new(predecessor_id, predecessor.clone());
        verify_pair(&CryptoBodyIdentity, &basis, &batch, &successor)
            .map_err(AdmissionMaterializationRefusal::DecisionHistoryVerification)?;

        if let Some(record) = batch.committed_rcrs.last() {
            let record_id = repository_commit_id(record)?;
            if successor.latest_committed_rcr_id != Some(record_id) {
                return Err(AdmissionMaterializationRefusal::LatestCommitMismatch {
                    expected: Box::new(record_id),
                    observed: successor.latest_committed_rcr_id.map(Box::new),
                });
            }
            if record.repository_id != successor.repository_id {
                return Err(
                    AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                        field: "repository_id",
                    },
                );
            }
            if record.resulting_ref_root != successor.ref_root {
                return Err(
                    AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                        field: "ref_root",
                    },
                );
            }
            if record.policy_epoch != successor.policy_epoch {
                return Err(
                    AdmissionMaterializationRefusal::SelectedCommitStateMismatch {
                        field: "policy_epoch",
                    },
                );
            }
            return Ok((
                record.object_closure_root,
                ClosureSelectionSource::RepositoryCommit(record_id),
            ));
        }

        successor = predecessor;
    }
}

struct VerifiedFabricPackSource<'a> {
    fabric: &'a LocalFilesystemFabric,
    maximum_object_bytes: usize,
}

impl CanonicalObjectSource for VerifiedFabricPackSource<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let verified = self
            .fabric
            .read_whole(*id)
            .map_err(|_| PackWriteError::MissingCanonicalObject(*id))?;
        let object_type = match verified.object.envelope().object_kind() {
            ObjectKind::Commit => ObjectType::Commit,
            ObjectKind::Tree => ObjectType::Tree,
            ObjectKind::Blob => ObjectType::Blob,
            ObjectKind::Tag => ObjectType::Tag,
            ObjectKind::Internal => return Err(PackError::InvalidEntryType(5).into()),
        };
        let payload = verified.object.payload();
        if payload.len() > self.maximum_object_bytes {
            return Err(PackError::ObjectSizeLimit {
                actual: payload.len(),
                limit: self.maximum_object_bytes,
            }
            .into());
        }
        let mut body = Vec::new();
        body.try_reserve_exact(payload.len())
            .map_err(|_| PackError::AllocationFailed {
                requested: payload.len(),
            })?;
        body.extend_from_slice(payload);
        Ok(CanonicalPackObject::new(
            *id,
            object_type,
            body,
            Vec::new(),
            0,
            0,
        ))
    }
}

fn selected_pack_ids(
    closure: &PermittedObjectClosure,
    client_haves: &[GitOid],
    limits: &PackLimits,
) -> Result<Vec<GitOid>, PackWriteError> {
    // `PackRequest` has already bounded and de-duplicated `have` lines at
    // the wire boundary.  Copy and sort them here so selected-closure
    // planning does not trust map order or use an unbounded allocation path.
    // A client have can only remove an already authority-permitted object; it
    // cannot add disclosure or alter the authenticated closure retained in
    // the pack receipt.
    let mut haves = Vec::new();
    haves
        .try_reserve_exact(client_haves.len())
        .map_err(|_| PackError::AllocationFailed {
            requested: client_haves.len(),
        })?;
    haves.extend_from_slice(client_haves);
    haves.sort_unstable();
    haves.dedup();

    let maximum = usize::try_from(limits.max_entries).unwrap_or(usize::MAX);
    let mut ids = Vec::new();
    ids.try_reserve_exact(closure.objects().len().min(maximum))
        .map_err(|_| PackError::AllocationFailed {
            requested: closure.objects().len().min(maximum),
        })?;
    for &id in closure.objects() {
        if haves.binary_search(&id).is_ok() {
            continue;
        }
        if ids.len() == maximum {
            return Err(PackError::EntryCountLimit {
                actual: u32::try_from(ids.len().saturating_add(1)).unwrap_or(u32::MAX),
                limit: limits.max_entries,
            }
            .into());
        }
        ids.push(id);
    }
    Ok(ids)
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
    Runtime(Box<RuntimeRefusal>),
    /// Authority-head staging or initialization refused or was ambiguous.
    Authority(Box<fgit_authority::OutcomeFailure>),
    /// Durable canonical-admission staging or refresh refused.
    AdmissionMaterialization(Box<AdmissionMaterializationRefusal>),
    /// A non-initializing open found no canonical authority head.
    AuthorityHeadAbsent,
    /// A supplied authority materialization names another repository.
    RepositoryMismatch,
    /// A caller's explicit format expectation disagrees with the authenticated
    /// repository configuration.
    ObjectFormatMismatch {
        /// The canonical native Git object identity domain stored by the repository.
        stored: GitHashAlgorithm,
        /// The incompatible explicit expectation supplied to this node open.
        supplied: GitHashAlgorithm,
    },
    /// A caller addressed a superseded repository incarnation.
    RepositoryIncarnationMismatch {
        /// The incarnation named by the caller's stale location or token.
        expected: RepositoryIncarnationId,
        /// The incarnation the authenticated authority head currently selects.
        observed: RepositoryIncarnationId,
    },
    /// The operator-selected storage root cannot name the embedded database.
    StoragePathEncoding,
    /// The derived authority-head key was outside the bounded key vocabulary.
    HeadKey(Box<fgit_authority::KeyError>),
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
    Fabric(Box<StoreRefusal>),
    /// Object bytes exceeded this node's configured storage bound.
    ObjectTooLarge { offered: u64, maximum: u64 },
    /// A platform-sized object length could not be represented canonically.
    ObjectLengthOverflow,
    /// Resource custody could not issue the bounded placement grant.
    Resource(Box<ResourceError>),
    /// A storage effect failed to settle its obligation region.
    ResourceContainment,
    /// The node root did not quiesce within its bounded shutdown interval.
    RuntimeContainment,
    /// A publication's basis did not bind the store-authenticated current head.
    PublicationBasisUnbound,
    /// A fixed node identity handle failed its bounded representation.
    Identity(Box<fgit_resource::IdentityError>),
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
            Self::ObjectFormatMismatch { stored, supplied } => write!(
                formatter,
                "caller requested {supplied} objects but authenticated repository configuration requires {stored}"
            ),
            Self::RepositoryIncarnationMismatch { expected, observed } => write!(
                formatter,
                "caller addressed repository incarnation {expected}, but the authenticated head selects {observed}"
            ),
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
            Self::PublicationBasisUnbound => formatter
                .write_str("publication basis does not bind the store-authenticated current head"),
            Self::Identity(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error.as_ref()),
            Self::Authority(error) => Some(error.as_ref()),
            Self::AdmissionMaterialization(error) => Some(error.as_ref()),
            Self::HeadKey(error) => Some(error.as_ref()),
            Self::AuthorityInitializationCleanup { initialization, .. } => Some(initialization),
            Self::ExistingOpenCleanup { opening, .. } => Some(opening),
            Self::Fabric(error) => Some(error.as_ref()),
            Self::Resource(error) => Some(error.as_ref()),
            Self::Identity(error) => Some(error.as_ref()),
            Self::EmptyStorageRoot
            | Self::InvalidWorkerCount
            | Self::AuthorityHeadAbsent
            | Self::RepositoryMismatch
            | Self::ObjectFormatMismatch { .. }
            | Self::RepositoryIncarnationMismatch { .. }
            | Self::HeadInitializationConflict
            | Self::StoragePathEncoding
            | Self::ObjectTooLarge { .. }
            | Self::ObjectLengthOverflow
            | Self::ResourceContainment
            | Self::PublicationBasisUnbound
            | Self::RuntimeContainment => None,
        }
    }
}

impl From<RuntimeRefusal> for NodeRefusal {
    fn from(value: RuntimeRefusal) -> Self {
        Self::Runtime(Box::new(value))
    }
}

impl From<fgit_authority::OutcomeFailure> for NodeRefusal {
    fn from(value: fgit_authority::OutcomeFailure) -> Self {
        Self::Authority(Box::new(value))
    }
}

impl From<AdmissionMaterializationRefusal> for NodeRefusal {
    fn from(value: AdmissionMaterializationRefusal) -> Self {
        Self::AdmissionMaterialization(Box::new(value))
    }
}

impl From<fgit_authority::KeyError> for NodeRefusal {
    fn from(value: fgit_authority::KeyError) -> Self {
        Self::HeadKey(Box::new(value))
    }
}

impl From<StoreRefusal> for NodeRefusal {
    fn from(value: StoreRefusal) -> Self {
        Self::Fabric(Box::new(value))
    }
}

impl From<ResourceError> for NodeRefusal {
    fn from(value: ResourceError) -> Self {
        Self::Resource(Box::new(value))
    }
}

impl From<fgit_resource::IdentityError> for NodeRefusal {
    fn from(value: fgit_resource::IdentityError) -> Self {
        Self::Identity(Box::new(value))
    }
}

/// Typed refusal while converting a verified local Git directory into a
/// durable source-import decision.
///
/// The variants preserve the boundary that produced the failure: source
/// staging is not admission, source-import validation is not authority
/// publication, and an infrastructure failure while driving the async
/// admission core does not become a terminal source-import decision.
#[derive(Debug)]
pub enum NodeSourceImportRefusal {
    /// The caller's retry key cannot name one stable seal identity.
    Idempotency(Box<fgit_authority::IdentityRefusal>),
    /// The local source could not be verified and staged as immutable objects.
    Staging(Box<LooseGitImportRefusal>),
    /// The bounded staging profile produced an object count outside the
    /// canonical source-import receipt vocabulary.
    ObjectCountOutOfRange { count: usize },
    /// The immutable closure body could not derive its canonical commitment.
    ClosureRoot(RefusalCode),
    /// The staged refs and closure did not form an admissible source import.
    Validation(RefusalCode),
    /// The shared async admission driver could not publish or resolve a
    /// terminal outcome.
    Admission(Box<AdmissionError>),
}

impl Display for NodeSourceImportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idempotency(error) => Display::fmt(error, formatter),
            Self::Staging(error) => Display::fmt(error, formatter),
            Self::ObjectCountOutOfRange { count } => write!(
                formatter,
                "source import object count {count} exceeds the receipt vocabulary"
            ),
            Self::ClosureRoot(code) => {
                write!(
                    formatter,
                    "cannot derive source-import closure root: {code:?}"
                )
            }
            Self::Validation(code) => {
                write!(formatter, "source import validation refused: {code:?}")
            }
            Self::Admission(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeSourceImportRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Idempotency(error) => Some(error.as_ref()),
            Self::Staging(error) => Some(error.as_ref()),
            Self::Admission(error) => Some(error.as_ref()),
            Self::ObjectCountOutOfRange { .. } | Self::ClosureRoot(_) | Self::Validation(_) => None,
        }
    }
}

/// Authenticated client identity carried by the receive transport boundary.
///
/// The authentication boundary supplies both fields. In particular, the
/// idempotency key is a client retry identity; it is never derived from a
/// receive request, connection identifier, or other mutable transport data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReceiveSession {
    principal_id: PrincipalId,
    client_idempotency_key: IdempotencyKey,
}

impl AuthenticatedReceiveSession {
    /// Forms an authenticated receive session from authority-bound identity.
    #[must_use]
    pub const fn new(principal_id: PrincipalId, client_idempotency_key: IdempotencyKey) -> Self {
        Self {
            principal_id,
            client_idempotency_key,
        }
    }

    /// Returns the principal authenticated for this transport session.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the client-supplied retry identity bound to this session.
    #[must_use]
    pub const fn client_idempotency_key(&self) -> &IdempotencyKey {
        &self.client_idempotency_key
    }
}

/// Authentication state exposed by the loopback receive transport.
///
/// The anonymous form exists so a transport adapter can refuse it explicitly;
/// it cannot be converted into an admission context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoopbackReceiveSession {
    /// A session whose principal and retry key came from authentication.
    Authenticated(AuthenticatedReceiveSession),
    /// A connection that has not authenticated a principal.
    Anonymous,
}

impl LoopbackReceiveSession {
    /// Creates an authenticated loopback session from caller-authenticated data.
    #[must_use]
    pub const fn authenticated(
        principal_id: PrincipalId,
        client_idempotency_key: IdempotencyKey,
    ) -> Self {
        Self::Authenticated(AuthenticatedReceiveSession::new(
            principal_id,
            client_idempotency_key,
        ))
    }

    /// Creates an anonymous session that the mutation transport will refuse.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self::Anonymous
    }

    const fn authenticated_session(&self) -> Option<&AuthenticatedReceiveSession> {
        match self {
            Self::Authenticated(session) => Some(session),
            Self::Anonymous => None,
        }
    }
}

/// Typed refusal emitted by the authenticated loopback receive transport.
#[derive(Debug)]
pub enum NodeReceiveTransportRefusal {
    /// The transport supplied no authenticated principal or client retry key.
    Unauthenticated,
    /// The authenticated request was refused by canonical admission.
    Admission(Box<AdmissionError>),
}

impl Display for NodeReceiveTransportRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => {
                formatter.write_str("receive transport did not authenticate a principal")
            }
            Self::Admission(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for NodeReceiveTransportRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unauthenticated => None,
            Self::Admission(error) => Some(error.as_ref()),
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
    upload_pack_version: UploadPackVersion,
}

/// A finite wall-clock budget for one accepted git-daemon session.
///
/// The value is an absolute session budget, not a per-read idle interval: a
/// peer that drips one byte before each socket timeout still reaches the same
/// deadline.  It is part of the node configuration so a deployment chooses
/// its compatibility/resource profile explicitly rather than inheriting an
/// unbounded socket default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitDaemonSessionTimeout(Duration);

impl GitDaemonSessionTimeout {
    /// Conservative bounded profile for the embedded one-session daemon.
    pub const DEFAULT: Self = Self(Duration::from_secs(30));

    /// Constructs a non-zero session budget.
    pub const fn try_new(timeout: Duration) -> Result<Self, GitDaemonSessionTimeoutRefusal> {
        if timeout.is_zero() {
            return Err(GitDaemonSessionTimeoutRefusal::Zero);
        }
        Ok(Self(timeout))
    }

    /// Returns the configured session budget.
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Why a git-daemon session budget could not be configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitDaemonSessionTimeoutRefusal {
    /// A zero duration cannot bound an I/O operation.
    Zero,
}

impl Display for GitDaemonSessionTimeoutRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("git-daemon session timeout must be non-zero"),
        }
    }
}

impl Error for GitDaemonSessionTimeoutRefusal {}

/// Absolute elapsed-time accounting for one accepted git-daemon connection.
///
/// The deadline is shared by the read and write halves. Each socket operation
/// installs only the remaining duration, so a peer cannot turn an idle timeout
/// into an unbounded session by periodically sending a single byte.
#[derive(Clone, Copy, Debug)]
struct GitDaemonSessionDeadline {
    started: Instant,
    timeout: GitDaemonSessionTimeout,
}

impl GitDaemonSessionDeadline {
    fn new(timeout: GitDaemonSessionTimeout) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    fn remaining(self) -> io::Result<Duration> {
        let remaining = self
            .timeout
            .duration()
            .saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "git-daemon session deadline elapsed",
            ));
        }
        Ok(remaining)
    }

    fn expired(self) -> bool {
        self.remaining().is_err()
    }

    fn check(self, operation: &'static str) -> Result<(), GitDaemonTransportRefusal> {
        self.remaining()
            .map(|_| ())
            .map_err(|_| GitDaemonTransportRefusal::SessionDeadlineExceeded { operation })
    }
}

fn check_session_deadline(
    deadline: Option<GitDaemonSessionDeadline>,
    operation: &'static str,
) -> Result<(), GitDaemonTransportRefusal> {
    deadline.map_or(Ok(()), |deadline| deadline.check(operation))
}

/// A socket half whose every operation observes a shared absolute deadline.
struct DeadlineTcpStream<'stream> {
    stream: &'stream mut TcpStream,
    deadline: GitDaemonSessionDeadline,
}

impl<'stream> DeadlineTcpStream<'stream> {
    const fn new(stream: &'stream mut TcpStream, deadline: GitDaemonSessionDeadline) -> Self {
        Self { stream, deadline }
    }

    fn prepare_read(&self) -> io::Result<()> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))
    }

    fn prepare_write(&self) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))
    }
}

impl Read for DeadlineTcpStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.prepare_read()?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineTcpStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.prepare_write()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.prepare_write()?;
        self.stream.flush()
    }
}

impl GitDaemonRequest {
    /// Returns the canonical authority lookup key requested by the client.
    #[must_use]
    pub const fn repository_path(&self) -> &GitDaemonRepositoryPath {
        &self.repository_path
    }

    /// Returns the legacy upload-pack grammar selected by the greeting.
    ///
    /// The git-daemon lane admits the implicit V0 default and an explicit
    /// `version=1` parameter. V2 remains a typed greeting refusal until its
    /// distinct ls-refs serving path is attached.
    #[must_use]
    pub const fn upload_pack_version(&self) -> UploadPackVersion {
        self.upload_pack_version
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
    /// The configured absolute session budget elapsed during one I/O step.
    SessionDeadlineExceeded {
        /// The read or write operation that exceeded the budget.
        operation: &'static str,
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
    /// The client requested a protocol generation not served by this daemon lane.
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
            Self::SessionDeadlineExceeded { operation } => {
                write!(
                    formatter,
                    "git-daemon session deadline exceeded while {operation}"
                )
            }
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
            | Self::SessionDeadlineExceeded { .. }
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

fn classify_session_deadline(error: GitDaemonTransportRefusal) -> GitDaemonTransportRefusal {
    match error {
        GitDaemonTransportRefusal::Io { operation, source }
            if matches!(
                source.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            GitDaemonTransportRefusal::SessionDeadlineExceeded { operation }
        }
        other => other,
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

fn classify_session_serve_error<PackError>(
    error: GitDaemonServeError<PackError>,
) -> GitDaemonServeError<PackError> {
    match error {
        GitDaemonServeError::Transport(error) => {
            GitDaemonServeError::Transport(classify_session_deadline(error))
        }
        GitDaemonServeError::Pack(error) => GitDaemonServeError::Pack(error),
    }
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

/// Evidence that a client received the complete advertisement for an empty
/// repository.
///
/// Empty repositories have no reachable objects to negotiate, so a flush after
/// the standard zero-identity advertisement is the complete upload-pack
/// response.  Recording this separately prevents callers from claiming a pack
/// was emitted when no pack was required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDaemonAdvertisementReceipt {
    request: GitDaemonRequest,
}

impl GitDaemonAdvertisementReceipt {
    /// Returns the parsed git-daemon service request that selected the empty
    /// repository advertisement.
    #[must_use]
    pub const fn request(&self) -> &GitDaemonRequest {
        &self.request
    }
}

/// The complete observable result of one legacy git-daemon session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitDaemonSessionOutcome {
    /// The repository was canonically empty, so advertisement plus EOF was
    /// the complete fetch response and no pack builder was called.
    EmptyRepository(GitDaemonAdvertisementReceipt),
    /// Negotiation selected a request and a canonical pack payload was emitted.
    Pack(GitDaemonSessionReceipt),
}

impl GitDaemonSessionOutcome {
    /// Returns the request that selected this session's authenticated view.
    #[must_use]
    pub const fn request(&self) -> &GitDaemonRequest {
        match self {
            Self::EmptyRepository(receipt) => receipt.request(),
            Self::Pack(receipt) => receipt.request(),
        }
    }
}

/// Failure while composing one node-owned git-daemon session.
#[derive(Debug)]
pub enum NodeGitDaemonServeRefusal {
    /// The daemon socket or protocol framing was refused.
    Transport(Box<GitDaemonTransportRefusal>),
    /// The authenticated authority-backed admission view could not be read.
    Admission(Box<NodeAdmissionViewRefusal>),
    /// The authority-selected closure could not become a bounded pack payload.
    Pack(Box<NodePackMaterializationRefusal>),
    /// The request selected another repository endpoint before authority work.
    RepositoryPathMismatch,
}

impl Display for NodeGitDaemonServeRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => Display::fmt(error, formatter),
            Self::Admission(error) => Display::fmt(error, formatter),
            Self::Pack(error) => Display::fmt(error, formatter),
            Self::RepositoryPathMismatch => {
                formatter.write_str("git-daemon request does not select this node repository")
            }
        }
    }
}

impl Error for NodeGitDaemonServeRefusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error.as_ref()),
            Self::Admission(error) => Some(error.as_ref()),
            Self::Pack(error) => Some(error.as_ref()),
            Self::RepositoryPathMismatch => None,
        }
    }
}

impl From<GitDaemonTransportRefusal> for NodeGitDaemonServeRefusal {
    fn from(value: GitDaemonTransportRefusal) -> Self {
        Self::Transport(Box::new(value))
    }
}

impl From<NodeAdmissionViewRefusal> for NodeGitDaemonServeRefusal {
    fn from(value: NodeAdmissionViewRefusal) -> Self {
        Self::Admission(Box::new(value))
    }
}

impl From<NodePackMaterializationRefusal> for NodeGitDaemonServeRefusal {
    fn from(value: NodePackMaterializationRefusal) -> Self {
        Self::Pack(Box::new(value))
    }
}

fn node_git_daemon_serve_error(
    error: GitDaemonServeError<NodePackMaterializationRefusal>,
) -> NodeGitDaemonServeRefusal {
    match error {
        GitDaemonServeError::Transport(error) => NodeGitDaemonServeRefusal::from(error),
        GitDaemonServeError::Pack(error) => NodeGitDaemonServeRefusal::from(error),
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

/// Serves one bounded legacy V0/V1 git-daemon upload-pack session.
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
/// after the final negotiated ACK/NAK. An authenticated empty repository is
/// complete without negotiation or a pack, so its advertisement returns an
/// [`GitDaemonSessionOutcome::EmptyRepository`] immediately. When a later
/// caller explicitly enables `side-band-64k`, this adapter preserves the wire
/// crate's bounded pull/write ordering and emits a terminal flush after the
/// payload.
pub fn serve_git_daemon_upload_pack<R, W, BuildPack, Payload, PackError>(
    reader: &mut R,
    writer: &mut W,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionOutcome, GitDaemonServeError<PackError>>
where
    R: Read,
    W: Write,
    BuildPack: FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, PackError>,
    Payload: PackPayloadSource,
{
    let request =
        read_git_daemon_request(reader, &limits).map_err(GitDaemonServeError::Transport)?;
    serve_git_daemon_upload_pack_after_greeting(
        reader,
        writer,
        request,
        repository,
        capabilities,
        limits,
        None,
        |request, pack_request| {
            build_pack(request, pack_request).map_err(GitDaemonServeError::Pack)
        },
    )
}

/// Best-effort consumption of the client's want-less request after an
/// empty-repository advertisement.
///
/// A real client answers the zero-identity `capabilities^{}` advertisement by
/// sending its request and waiting; closing the read side with those bytes
/// still queued makes the kernel answer with RST instead of a clean FIN, so a
/// cloning client can observe a connection reset where upstream completes
/// gracefully. The drain reads until the request flush, stream end, or any
/// bounded refusal, and never changes the session outcome. A client that
/// drips framing forever is the unbounded-session problem a transport
/// deadline owns, not this drain's.
fn drain_client_request(reader: &mut impl Read, limits: &WireLimits) {
    let Ok(mut decoder) = PktLineDecoder::new(limits.clone()) else {
        return;
    };
    let mut input = [0_u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut input) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        match decoder.push(&input[..read]) {
            Ok(packets) if packets.iter().any(|packet| matches!(packet, Packet::Flush)) => {
                return;
            }
            Ok(_) => {}
            // A bounded framing refusal ends the politeness drain the same
            // way a stream end does: the outcome is already decided.
            Err(_) => return,
        }
    }
}

/// Completes one upload-pack session after its git-daemon greeting was read.
///
/// Keeping this half of the session beside [`serve_git_daemon_upload_pack`]
/// lets a node validate the parsed opaque repository key before it refreshes
/// authority-backed state, without duplicating any advertisement, negotiation,
/// or pack-emission behavior from `fgit-wire`.
fn serve_git_daemon_upload_pack_after_greeting<R, W, BuildPack, Payload, PackError>(
    reader: &mut R,
    writer: &mut W,
    request: GitDaemonRequest,
    repository: &impl UploadPackRepository,
    capabilities: Capabilities,
    limits: WireLimits,
    session_deadline: Option<GitDaemonSessionDeadline>,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionOutcome, GitDaemonServeError<PackError>>
where
    R: Read,
    W: Write,
    BuildPack:
        FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, GitDaemonServeError<PackError>>,
    Payload: PackPayloadSource,
{
    if matches!(request.upload_pack_version(), UploadPackVersion::V2) {
        return serve_v2_upload_pack_after_greeting(
            reader,
            writer,
            request,
            repository,
            limits,
            session_deadline,
            build_pack,
        );
    }
    check_session_deadline(session_deadline, "prepare upload-pack advertisement")
        .map_err(GitDaemonServeError::Transport)?;
    let mut advertisement = V1Advertisement::new(
        repository.advertised_refs().to_vec(),
        capabilities.clone(),
        repository.object_format(),
        &limits,
    )
    .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    advertisement.version_one_prelude =
        matches!(request.upload_pack_version(), UploadPackVersion::V1);
    write_packet_group(
        writer,
        &advertisement.encode(&limits).map_err(|error| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
        })?,
        &limits,
    )
    .map_err(GitDaemonServeError::Transport)?;

    if repository.advertised_refs().is_empty() {
        drain_client_request(reader, &limits);
        return Ok(GitDaemonSessionOutcome::EmptyRepository(
            GitDaemonAdvertisementReceipt { request },
        ));
    }

    let mut machine =
        LegacyUploadPack::new(request.upload_pack_version(), capabilities, limits.clone())
            .map_err(|error| {
                GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error))
            })?;
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
            check_session_deadline(session_deadline, "build selected git pack")
                .map_err(GitDaemonServeError::Transport)?;
            let mut payload = build_pack(&request, &pack_request)?;
            check_session_deadline(session_deadline, "build selected git pack")
                .map_err(GitDaemonServeError::Transport)?;
            emit_pack_payload(
                writer,
                &mut payload,
                &pack_request,
                &limits,
                session_deadline,
            )
            .map_err(GitDaemonServeError::Transport)?;
            return Ok(GitDaemonSessionOutcome::Pack(GitDaemonSessionReceipt {
                request,
                pack_request,
            }));
        }
    }
}

/// Serves one bounded protocol-v2 upload-pack session after a `version=2`
/// daemon greeting selected this lane.
///
/// The server capability advertisement is built here rather than reusing the
/// legacy capability set because protocol v2 advertises command names and
/// feature values (`ls-refs`, `fetch`, `object-format`) instead of the v0/v1
/// keyword set. Each v2 command request is a complete machine run: after
/// `ls-refs` completes the loop installs a fresh machine so the same
/// connection can carry the follow-up `fetch`; after `fetch` emits its pack
/// the session is done.
fn serve_v2_upload_pack_after_greeting<R, W, BuildPack, Payload, PackError>(
    reader: &mut R,
    writer: &mut W,
    request: GitDaemonRequest,
    repository: &impl UploadPackRepository,
    limits: WireLimits,
    session_deadline: Option<GitDaemonSessionDeadline>,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionOutcome, GitDaemonServeError<PackError>>
where
    R: Read,
    W: Write,
    BuildPack:
        FnMut(&GitDaemonRequest, &PackRequest) -> Result<Payload, GitDaemonServeError<PackError>>,
    Payload: PackPayloadSource,
{
    check_session_deadline(session_deadline, "prepare protocol-v2 advertisement")
        .map_err(GitDaemonServeError::Transport)?;
    let object_format = match repository.object_format() {
        fgit_wire::GitObjectFormat::Sha1 => "sha1",
        fgit_wire::GitObjectFormat::Sha256 => "sha256",
    };
    let advertisement_packets = vec![
        Packet::Data(b"version 2\n".to_vec()),
        Packet::Data(b"ls-refs\n".to_vec()),
        Packet::Data(b"fetch\n".to_vec()),
        Packet::Data(format!("object-format={object_format}\n").into_bytes()),
        Packet::Flush,
    ];
    let server_capabilities = Capabilities::parse_v2_advertisement(&advertisement_packets, &limits)
        .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))?;
    write_packet_group(writer, &advertisement_packets, &limits)
        .map_err(GitDaemonServeError::Transport)?;

    let fresh_machine = || -> Result<V2UploadPack, GitDaemonServeError<PackError>> {
        V2UploadPack::new(server_capabilities.clone(), limits.clone())
            .map_err(|error| GitDaemonServeError::Transport(GitDaemonTransportRefusal::Wire(error)))
    };
    let mut machine = fresh_machine()?;
    let mut ls_refs_completed = false;
    let mut input = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut input).map_err(|source| {
            GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
                operation: "read protocol-v2 command stream",
                source,
            })
        })?;
        if read == 0 {
            if ls_refs_completed {
                // The client obtained everything it needed from ls-refs (the
                // empty-repository shape) and closed the session cleanly.
                return Ok(GitDaemonSessionOutcome::EmptyRepository(
                    GitDaemonAdvertisementReceipt { request },
                ));
            }
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

        let mut next_command = false;
        for event in transition.events {
            match event {
                WireEvent::LsRefs { .. } => {
                    ls_refs_completed = true;
                    next_command = true;
                }
                WireEvent::PackRequested(pack_request) => {
                    check_session_deadline(session_deadline, "build selected git pack")
                        .map_err(GitDaemonServeError::Transport)?;
                    let mut payload = build_pack(&request, &pack_request)?;
                    check_session_deadline(session_deadline, "build selected git pack")
                        .map_err(GitDaemonServeError::Transport)?;
                    emit_pack_payload(
                        writer,
                        &mut payload,
                        &pack_request,
                        &limits,
                        session_deadline,
                    )
                    .map_err(GitDaemonServeError::Transport)?;
                    return Ok(GitDaemonSessionOutcome::Pack(GitDaemonSessionReceipt {
                        request,
                        pack_request,
                    }));
                }
                WireEvent::Common(_) => {}
            }
        }
        if next_command {
            machine = fresh_machine()?;
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
    session_timeout: GitDaemonSessionTimeout,
    mut build_pack: BuildPack,
) -> Result<GitDaemonSessionOutcome, GitDaemonServeError<PackError>>
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
    let mut response_stream = stream.try_clone().map_err(|source| {
        GitDaemonServeError::Transport(GitDaemonTransportRefusal::Io {
            operation: "duplicate git-daemon connection for response writes",
            source,
        })
    })?;
    let deadline = GitDaemonSessionDeadline::new(session_timeout);
    let mut reader = DeadlineTcpStream::new(&mut stream, deadline);
    let mut writer = DeadlineTcpStream::new(&mut response_stream, deadline);
    let request = read_git_daemon_request(&mut reader, &limits)
        .map_err(classify_session_deadline)
        .map_err(GitDaemonServeError::Transport)?;
    let receipt = serve_git_daemon_upload_pack_after_greeting(
        &mut reader,
        &mut writer,
        request,
        repository,
        capabilities,
        limits,
        Some(deadline),
        |request, pack_request| {
            build_pack(request, pack_request).map_err(GitDaemonServeError::Pack)
        },
    )
    .map_err(classify_session_serve_error)?;
    response_stream
        .shutdown(Shutdown::Write)
        .map_err(|source| {
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

    let mut requested_version = None;
    for parameter in parameters.split(|byte| *byte == 0) {
        if parameter.is_empty() {
            continue;
        }
        let Some(version) = parameter.strip_prefix(b"version=") else {
            continue;
        };
        if requested_version.is_some() {
            return Err(GitDaemonTransportRefusal::DuplicateProtocolVersion);
        }
        requested_version = Some(version);
    }
    let upload_pack_version = match requested_version {
        None => UploadPackVersion::V0,
        Some(b"1") => UploadPackVersion::V1,
        Some(b"2") => UploadPackVersion::V2,
        Some(version) => {
            return Err(GitDaemonTransportRefusal::UnsupportedProtocolVersion {
                version_bytes: version.len(),
            });
        }
    };
    Ok(GitDaemonRequest {
        repository_path,
        upload_pack_version,
    })
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
    session_deadline: Option<GitDaemonSessionDeadline>,
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
    loop {
        check_session_deadline(session_deadline, "read materialized git pack payload")?;
        let chunk = payload
            .next_chunk(maximum_chunk_bytes)
            .map_err(GitDaemonTransportRefusal::Wire)?;
        check_session_deadline(session_deadline, "read materialized git pack payload")?;
        let Some(chunk) = chunk else {
            break;
        };
        if chunk.len() > maximum_chunk_bytes {
            return Err(GitDaemonTransportRefusal::Wire(
                WireError::PackChunkTooLarge {
                    observed: chunk.len(),
                    limit: maximum_chunk_bytes,
                },
            ));
        }
        if request.options.sideband_64k() {
            check_session_deadline(session_deadline, "write sideband git pack payload")?;
            let packets =
                sideband_pack_chunk(&chunk, limits).map_err(GitDaemonTransportRefusal::Wire)?;
            write_packet_group(writer, &packets, limits)?;
        } else {
            check_session_deadline(session_deadline, "write raw git pack payload")?;
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
    creation_repository_incarnation_id: RepositoryIncarnationId,
    expected_repository_incarnation_id: Option<RepositoryIncarnationId>,
    git_daemon_repository_path: GitDaemonRepositoryPath,
    store_instance: StoreInstanceId,
    worker_threads: usize,
    /// An explicit creation/open expectation. An unspecified value defers to
    /// the authenticated repository configuration when opening an existing
    /// repository, while initialization selects the conservative SHA-1
    /// compatibility profile and persists that selection canonically.
    object_format: Option<GitHashAlgorithm>,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
    git_daemon_session_timeout: GitDaemonSessionTimeout,
    /// Which cell this process is, for answers it serves.
    ///
    /// `frankengit-1egm`. Unset by default and typed as such: a deployment that
    /// does not name its cells is a real configuration, not a mistake, and
    /// `ServingCell::Unidentified` says so where a `None` would not.
    ///
    /// Deliberately NOT `store_instance`. That names the authority STORE, and
    /// `establish()` hands every cell sharing one backend the same value --
    /// which is exactly why an authenticated read could not say which cell
    /// served it.
    serving_cell: ServingCell,
}

impl NodeConfig {
    /// Creates a node configuration with no caller-supplied object-format
    /// expectation.
    ///
    /// Existing repositories select their native object domain from the
    /// authenticated configuration body. New repositories use the bounded
    /// SHA-1 compatibility profile unless [`Self::with_object_format`] names a
    /// deliberate creation format.
    #[must_use]
    pub fn new(storage_root: PathBuf, tenant_id: TenantId, repository_id: RepositoryId) -> Self {
        Self {
            storage_root,
            tenant_id,
            repository_id,
            creation_repository_incarnation_id: mint_repository_incarnation_id(),
            expected_repository_incarnation_id: None,
            git_daemon_repository_path: default_git_daemon_repository_path(repository_id),
            store_instance: StoreInstanceId::from_raw(1),
            serving_cell: ServingCell::Unidentified,
            worker_threads: 1,
            object_format: None,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            segment_limits: SegmentLimits::default(),
            git_daemon_session_timeout: GitDaemonSessionTimeout::DEFAULT,
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
        self.object_format = Some(object_format);
        self
    }

    /// Binds this operation to one caller-observed repository incarnation.
    ///
    /// A location record, capability, or cache that carries an incarnation
    /// must use this builder before opening a repository. The node compares it
    /// to the v2 body selected by the authenticated authority head before any
    /// object operation can proceed.
    #[must_use]
    pub const fn with_expected_repository_incarnation(
        mut self,
        repository_incarnation_id: RepositoryIncarnationId,
    ) -> Self {
        self.creation_repository_incarnation_id = repository_incarnation_id;
        self.expected_repository_incarnation_id = Some(repository_incarnation_id);
        self
    }

    /// Selects the pre-allocation object byte ceiling.
    #[must_use]
    pub const fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }

    /// Selects the absolute resource budget for one accepted git-daemon session.
    #[must_use]
    /// Name the cell this process is.
    ///
    /// The identity is carried as a hint because a cell's claim about its own
    /// name is a claim (§5.1). It labels answers so an operator can find the
    /// cell that drifted; it grants nothing.
    pub const fn with_serving_cell(mut self, serving_cell: ServingCell) -> Self {
        self.serving_cell = serving_cell;
        self
    }

    pub const fn with_git_daemon_session_timeout(
        mut self,
        session_timeout: GitDaemonSessionTimeout,
    ) -> Self {
        self.git_daemon_session_timeout = session_timeout;
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
    /// What this cell may currently serve, with the audit of how it got there.
    ///
    /// Held by value rather than behind a lock on purpose. Every mutator takes
    /// `&mut self`, so a capability change cannot race a read in flight -- which
    /// is the property you want from a transition that decides what the cell is
    /// allowed to answer. It also keeps the audit out of lock-poisoning
    /// semantics, where the honest recovery is unclear.
    readiness: CellReadiness,
    authority: FsqliteAuthorityStore,
    admission_materializer: DurableAdmissionMaterializer,
    head_key: HeadKey,
    fabric: LocalFilesystemFabric,
    git_daemon_repository_path: GitDaemonRepositoryPath,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    storage_root: PathBuf,
    namespace: Vec<u8>,
    object_format: GitHashAlgorithm,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
    git_daemon_session_timeout: GitDaemonSessionTimeout,
    /// Which cell this process is, stamped onto answers it serves.
    serving_cell: ServingCell,
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
        let configuration = RepositoryIncarnationConfigurationBody {
            root_layout: RootLayoutVersion::LegacyWholeBody,
            object_format: node.object_format,
            repository_incarnation_id: node.repository_incarnation_id,
        };
        let configuration_root =
            match node
                .runtime
                .block_on(stage_repository_incarnation_configuration_async(
                    &node.authority,
                    &initialization_cx,
                    &configuration,
                )) {
                Ok(root) => root,
                Err(staging) => {
                    let initialization = NodeRefusal::from(staging);
                    return match node.shutdown() {
                        Ok(()) => Err(initialization),
                        Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                            initialization: Box::new(initialization),
                            cleanup: Box::new(cleanup),
                        }),
                    };
                }
            };
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
                let initialization = NodeRefusal::from(staging);
                return match node.shutdown() {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
        };
        if let Err(staging) = node.runtime.block_on(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    &initialization_cx,
                    repository_id,
                    PermittedObjectClosure::default(),
                ),
        ) {
            let initialization = NodeRefusal::from(staging);
            return match node.shutdown() {
                Ok(()) => Err(initialization),
                Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                    initialization: Box::new(initialization),
                    cleanup: Box::new(cleanup),
                }),
            };
        }
        let genesis = match genesis_head(repository_id, ref_root, configuration_root) {
            Ok(genesis) => genesis,
            Err(initialization) => {
                return match node.shutdown() {
                    Ok(()) => Err(initialization),
                    Err(cleanup) => Err(NodeRefusal::AuthorityInitializationCleanup {
                        initialization: Box::new(initialization),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }
        };
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
        let supplied_object_format = config.object_format;
        let expected_repository_incarnation_id = config.expected_repository_incarnation_id;
        let mut node = Self::open_components(config)?;
        let configuration_cx = node.authority_context();
        let opened = node.runtime().block_on(async {
            let authenticated = node.authenticate_authority_head().await?;
            let head = authenticated
                .body()
                .map_err(fgit_authority::OutcomeFailure::from)?;
            let configuration = read_repository_incarnation_configuration_async(
                &node.authority,
                &configuration_cx,
                &head.configuration_root,
            )
            .await?;
            if let Some(supplied) = supplied_object_format
                && supplied != configuration.object_format
            {
                return Err(NodeRefusal::ObjectFormatMismatch {
                    stored: configuration.object_format,
                    supplied,
                });
            }
            if let Some(expected) = expected_repository_incarnation_id
                && expected != configuration.repository_incarnation_id
            {
                return Err(NodeRefusal::RepositoryIncarnationMismatch {
                    expected,
                    observed: configuration.repository_incarnation_id,
                });
            }
            Ok((
                configuration.object_format,
                configuration.repository_incarnation_id,
            ))
        });
        match opened {
            Ok((object_format, repository_incarnation_id)) => {
                if let Err(rebind) = node.rebind_object_fabric(repository_incarnation_id) {
                    return Err(close_after_existing_open_failure(node, rebind));
                }
                node.object_format = object_format;
                node.repository_incarnation_id = repository_incarnation_id;
                Ok(node)
            }
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
            .map_err(NodeRefusal::from)?;
        let authority_path = authority_database_path(&config.storage_root)?;
        let namespace = object_namespace(
            config.repository_id,
            config.creation_repository_incarnation_id,
        );
        let fabric = open_local_fabric(
            config.storage_root.clone(),
            namespace.clone(),
            config.max_object_bytes,
            config.segment_limits.clone(),
        )?;

        let head_key = head_key(config.repository_id)?;
        let admission_cache_scope = admission_cache_scope().map_err(NodeRefusal::from)?;
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
            readiness: CellReadiness::bootstrapping(),
            runtime,
            authority,
            admission_materializer: DurableAdmissionMaterializer::new(admission_cache_scope),
            head_key,
            fabric,
            git_daemon_repository_path: config.git_daemon_repository_path,
            tenant_id: config.tenant_id,
            repository_id: config.repository_id,
            repository_incarnation_id: config.creation_repository_incarnation_id,
            storage_root: config.storage_root,
            namespace,
            object_format: config.object_format.unwrap_or(GitHashAlgorithm::Sha1),
            max_object_bytes: config.max_object_bytes,
            segment_limits: config.segment_limits,
            git_daemon_session_timeout: config.git_daemon_session_timeout,
            serving_cell: config.serving_cell,
        })
    }

    /// Which cell this process is, as stamped onto answers it serves.
    ///
    /// `frankengit-1egm`. Distinct from the store instance: every cell sharing
    /// one authority backend reports the same store id, which is why an
    /// authenticated read could not say which cell produced it.
    #[must_use]
    pub const fn serving_cell(&self) -> ServingCell {
        self.serving_cell
    }

    /// What this cell may currently serve.
    #[must_use]
    pub const fn cell_state(&self) -> CellState {
        self.readiness.state()
    }

    /// Every readiness transition this cell has made, oldest first.
    #[must_use]
    pub fn readiness_audit(&self) -> &[CellTransition] {
        self.readiness.audit()
    }

    /// Move this cell to `next`, recording why in the same call.
    ///
    /// Takes `&mut self` so a capability change cannot overlap a read: plan
    /// §37.3 requires transitions to be audited AND to enforce capability
    /// changes, and a transition that could land mid-read would enforce a
    /// capability the in-flight answer did not respect.
    ///
    /// # Errors
    ///
    /// [`CellRefusal::IllegalTransition`] when the edge is not admitted.
    pub fn transition_cell_state(
        &mut self,
        next: CellState,
        cause: CellTransitionCause,
        at_generation: HeadGeneration,
    ) -> Result<&CellTransition, CellRefusal> {
        self.readiness.transition_to(next, cause, at_generation)
    }

    /// Serve a ref advertisement carrying the read mode it was served under.
    ///
    /// Two rules meet here, and both are the point of the method:
    ///
    /// * the cell's state decides whether this mode may be served at all, so a
    ///   cell in [`CellState::DegradedRead`] refuses a
    ///   [`fgit_types::cell::ReadMode::Current`] answer rather than producing a
    ///   fresh-looking one it cannot back;
    /// * disclosure is narrowed by the policy passed here, which must be the
    ///   CURRENT one. Plan §22.5: a stale projection never expands disclosure.
    ///   Routing through [`advertise_under_read_label`] rather than filtering
    ///   inline makes that one choke point instead of a rule each caller has to
    ///   remember.
    ///
    /// # Errors
    ///
    /// [`LabelledReadRefusal::State`] when the cell's state admits no such read,
    /// and the materialization or advertisement refusals otherwise.
    pub async fn labelled_advertisement_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        limits: &WireLimits,
        label: ReadLabel,
    ) -> Result<LabelledAdvertisement, LabelledReadRefusal> {
        admits_read(self.cell_state(), label.mode()).map_err(LabelledReadRefusal::State)?;
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(|refusal| LabelledReadRefusal::View(Box::new(refusal.into())))?;
        let advertisement = AdmissionReceivePackAdvertisement::from_snapshot(
            materialized.snapshot(),
            visibility,
            self.object_format,
            limits,
        )
        .map_err(|refusal| LabelledReadRefusal::Advertisement(Box::new(refusal)))?;
        Ok(advertise_under_read_label_served_by(
            advertisement.advertised_refs(),
            visibility,
            label,
            self.serving_cell,
        ))
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

    /// Returns the exact incarnation selected by the authenticated
    /// configuration body.
    #[must_use]
    pub const fn repository_incarnation_id(&self) -> RepositoryIncarnationId {
        self.repository_incarnation_id
    }

    /// Returns the one canonical git-daemon lookup path this node serves.
    ///
    /// The path is an opaque transport lookup key, rather than a filesystem
    /// location.  Matching it before any authority read prevents a listener
    /// for one repository from answering under an alternate repository name.
    #[must_use]
    pub const fn git_daemon_repository_path(&self) -> &GitDaemonRepositoryPath {
        &self.git_daemon_repository_path
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
        let always_live = || true;
        self.materialize_admission_while_in(request, &always_live)
            .await
    }

    /// Materializes canonical admission state while an enclosing bounded
    /// operation remains live.
    ///
    /// The materializer's own checkpoint predicate remains authoritative for
    /// request cancellation. This outer predicate lets transport-owned bounds
    /// stop work before the derived cache may be installed.
    async fn materialize_admission_while_in(
        &self,
        request: &NodeRequestContext,
        is_live: &(impl Fn() -> bool + Sync),
    ) -> Result<MaterializedAdmission, AdmissionMaterializationRefusal> {
        // The child is the materializer-catch-up ownership scope. Parent
        // request cancellation propagates to it; its checkpoints fence cache
        // installation without making the cache an authority source.
        let catch_up = request.authority().create_child();
        let is_cancelled = || !is_live() || catch_up.checkpoint().is_err();
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

    fn durable_admission_projection(
        &self,
        context: &AdmissionContext,
    ) -> Result<DurableAsyncAdmissionProjection<'_>, AdmissionError> {
        if context.head_key != self.head_key
            || context.tenant_id != self.tenant_id
            || context.repository_id != self.repository_id
            || context.object_format != self.object_format
        {
            return Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid,
            ));
        }
        Ok(DurableAsyncAdmissionProjection::new(
            &self.admission_materializer,
            context.clone(),
        ))
    }

    /// Admits one verified receive-pack session through the node-owned durable
    /// asynchronous materialization boundary.
    ///
    /// The projection creates evidence only after the driver has supplied the
    /// exact authenticated basis and fold. A refused decision gets its own
    /// canonical, authority-staged witness before publication. Source import
    /// uses the same projection in [`Self::admit_validated_source_import_durable_in`].
    pub async fn admit_validated_receive_durable_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        validated: &ValidatedReceive,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, AdmissionError> {
        let projection = self.durable_admission_projection(context)?;
        admit_validated_receive_async(
            &self.authority,
            request.authority(),
            context,
            validated,
            limits,
            &projection,
        )
        .await
    }

    /// Admits a verified receive through the authenticated loopback transport.
    ///
    /// This composition boundary forms its [`AdmissionContext`] only from the
    /// node authority coordinates and a principal plus idempotency key supplied
    /// by the caller's authentication boundary. It does not derive either value
    /// from receive bytes, a socket, or a request identifier. Anonymous
    /// sessions are refused before admission, sealing, or publication begins.
    ///
    /// This is a loopback composition slice, not a claim that the raw
    /// git-daemon transport accepts push. Object-bearing receives still require
    /// a pack/object-store quarantine validator before they reach this method.
    pub async fn admit_loopback_receive_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &ValidatedReceive,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        self.admit_validated_receive_durable_in(request, &context, validated, limits)
            .await
            .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))
    }

    /// Admits one verified source import through the same durable projection
    /// used for receive-pack.
    ///
    /// This shares the async admission driver, exact-basis snapshot loading,
    /// successor-frame staging, and unavailable-evidence refusal boundary with
    /// [`Self::admit_validated_receive_durable_in`]. It deliberately does not
    /// claim a selected durability epoch; staged frames become visible only
    /// when the authority-head publication completes its selected profile.
    pub async fn admit_validated_source_import_durable_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        validated: &ValidatedSourceImport,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, AdmissionError> {
        let projection = self.durable_admission_projection(context)?;
        admit_validated_source_import_async(
            &self.authority,
            request.authority(),
            context,
            validated,
            limits,
            &projection,
        )
        .await
    }

    /// Verifies a bounded loose Git source and publishes its direct refs
    /// through the node-owned asynchronous source-import admission path.
    ///
    /// Every staged source ref is lowered with the native all-zero
    /// expected-old identity. This makes the command an establish-if-absent
    /// import rather than a node-local ref-map merge, and preserves the same
    /// sealed request identity if a caller retries after an ambiguous response.
    /// A pre-existing source ref therefore receives the canonical
    /// `ExpectedOldRefMismatch` terminal decision; this initial import profile
    /// never silently overwrites or deletes an authority-selected ref.
    ///
    /// `principal_id` must come from the caller's authentication boundary, and
    /// `idempotency_key` is explicit rather than derived from a source path or
    /// mutable filesystem metadata. The method itself accepts neither
    /// caller-supplied closure roots nor a caller-supplied publication basis.
    pub async fn import_loose_git_directory_durable_in(
        &self,
        request: &NodeRequestContext,
        source: &Path,
        principal_id: PrincipalId,
        idempotency_key: &[u8],
    ) -> Result<AdmissionResult, NodeSourceImportRefusal> {
        let idempotency_key = IdempotencyKey::new(idempotency_key.to_vec())
            .map_err(|error| NodeSourceImportRefusal::Idempotency(Box::new(error)))?;
        let limits = AdmissionLimits::default();
        let staged = self
            .stage_loose_git_import_with_ref_limit(source, limits.max_commands)
            .map_err(|error| NodeSourceImportRefusal::Staging(Box::new(error)))?;
        let object_count = u32::try_from(staged.object_count()).map_err(|_| {
            NodeSourceImportRefusal::ObjectCountOutOfRange {
                count: staged.object_count(),
            }
        })?;
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(staged.closure())
                .map_err(NodeSourceImportRefusal::ClosureRoot)?,
            objects: staged.closure().objects().clone(),
        };
        let absent = match self.object_format {
            GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::ZERO),
            GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::ZERO),
        };
        let updates = staged
            .refs()
            .refs()
            .iter()
            .map(|(name, new)| SourceRefUpdate {
                old: absent,
                new: *new,
                ref_name: name.as_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        let receipt = SourceImportReceipt {
            object_format: self.object_format,
            object_count,
            delete_only: updates.iter().all(|update| update.new.is_zero()),
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let validated = validate_source_import(&updates, &receipt, closure)
            .map_err(NodeSourceImportRefusal::Validation)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id,
            idempotency_key,
            object_format: self.object_format,
        };
        self.admit_validated_source_import_durable_in(request, &context, &validated, limits)
            .await
            .map_err(|error| NodeSourceImportRefusal::Admission(Box::new(error)))
    }

    /// Materializes a bounded Git pack from exactly one authority-selected closure.
    ///
    /// The closure is read through the authenticated head/RCR chain before any
    /// fabric read.  The fabric provides only verified native object bodies;
    /// `fgit-pack` applies the deterministic selected-set planner and writes a
    /// temporary artifact before this payload becomes consumable.
    pub async fn authority_selected_pack_payload_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<AuthoritySelectedPackPayload, NodePackMaterializationRefusal> {
        let materialized = self
            .materialize_admission_in(request)
            .await
            .map_err(NodePackMaterializationRefusal::from)?;
        let pack_context = request.authority().create_child();
        let mut is_live = || pack_context.checkpoint().is_ok();
        self.materialize_selected_pack(&materialized, &[], &mut is_live)
    }

    /// Materializes an authority-selected pack with a fresh request context.
    pub async fn authority_selected_pack_payload(
        &self,
    ) -> Result<AuthoritySelectedPackPayload, NodePackMaterializationRefusal> {
        let request = self.request_context();
        self.authority_selected_pack_payload_in(&request).await
    }

    fn materialize_selected_pack(
        &self,
        materialized: &MaterializedAdmission,
        client_haves: &[GitOid],
        is_live: &mut impl FnMut() -> bool,
    ) -> Result<AuthoritySelectedPackPayload, NodePackMaterializationRefusal> {
        let limits = PackLimits::default();
        let configured_limit = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            maximum_object_bytes: limits.max_object_bytes.min(configured_limit),
        };
        let ids = selected_pack_ids(
            materialized.selected_closure().closure(),
            client_haves,
            &limits,
        )
        .map_err(NodePackMaterializationRefusal::from)?;
        let planner = PackPlanner::new(
            self.object_format,
            PackWriteProfile::COMPRESSED_V1,
            limits.clone(),
        );
        let plan = planner
            .plan_selected(&source, &ids, is_live)
            .map_err(NodePackMaterializationRefusal::from)?;
        let (bytes, receipt) = PackWriter::new(limits)
            .write(&plan, is_live)
            .map_err(NodePackMaterializationRefusal::from)?;
        Ok(AuthoritySelectedPackPayload {
            basis: materialized.basis().clone(),
            closure: materialized.selected_closure().clone(),
            receipt,
            bytes,
            offset: 0,
        })
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
            .map_err(NodeAdmissionViewRefusal::from)?;
        AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::from)
    }

    /// Accepts and completes one legacy git-daemon upload-pack session.
    ///
    /// The accepted socket first supplies its bounded greeting and must name
    /// this node's configured repository lookup path.  Only then does this
    /// method drive the request-owned asynchronous materialization through the
    /// node's owned runtime, producing the exact authenticated-head snapshot
    /// used for the V0 advertisement.  This is not a synchronous
    /// `CanonicalAdmissionStore` adapter: the admission cache remains a
    /// derived view refreshed by the async authority contract.
    ///
    /// Empty state still completes at advertisement.  A non-empty state
    /// advertises only after its immutable refs and permitted object closure
    /// were selected by the same authenticated authority head; the wire crate
    /// remains the sole owner of negotiation and bounded payload framing.
    pub fn serve_git_daemon_once(
        &self,
        listener: &TcpListener,
    ) -> Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal> {
        self.serve_git_daemon_once_with_limits(listener, WireLimits::default())
    }

    /// Variant of [`Self::serve_git_daemon_once`] with an explicit bounded
    /// transport profile for callers that own a narrower protocol policy.
    pub fn serve_git_daemon_once_with_limits(
        &self,
        listener: &TcpListener,
        limits: WireLimits,
    ) -> Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal> {
        let (mut stream, _) = listener.accept().map_err(|source| {
            NodeGitDaemonServeRefusal::from(GitDaemonTransportRefusal::Io {
                operation: "accept git-daemon connection",
                source,
            })
        })?;
        let mut response_stream = stream.try_clone().map_err(|source| {
            NodeGitDaemonServeRefusal::from(GitDaemonTransportRefusal::Io {
                operation: "duplicate git-daemon connection for response writes",
                source,
            })
        })?;
        let deadline = GitDaemonSessionDeadline::new(self.git_daemon_session_timeout);
        let mut reader = DeadlineTcpStream::new(&mut stream, deadline);
        let greeting = read_git_daemon_request(&mut reader, &limits)
            .map_err(classify_session_deadline)
            .map_err(NodeGitDaemonServeRefusal::from)?;
        if greeting.repository_path() != &self.git_daemon_repository_path {
            return Err(NodeGitDaemonServeRefusal::RepositoryPathMismatch);
        }

        let request = self.request_context();
        deadline
            .check("materialize authenticated admission")
            .map_err(NodeGitDaemonServeRefusal::from)?;
        let admission_deadline_expired = AtomicBool::new(false);
        let admission_is_live = || {
            if deadline.expired() {
                admission_deadline_expired.store(true, Ordering::Relaxed);
                return false;
            }
            true
        };
        let admission = self
            .runtime
            .block_on(self.materialize_admission_while_in(&request, &admission_is_live));
        if admission_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
            return Err(NodeGitDaemonServeRefusal::from(
                GitDaemonTransportRefusal::SessionDeadlineExceeded {
                    operation: "materialize authenticated admission",
                },
            ));
        }
        let materialized = admission.map_err(|error| {
            NodeGitDaemonServeRefusal::from(NodeAdmissionViewRefusal::from(error))
        })?;
        let repository = AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            &limits,
        )
        .map_err(|error| NodeGitDaemonServeRefusal::from(NodeAdmissionViewRefusal::from(error)))?;
        let advertised_capabilities =
            git_daemon_capabilities(self.object_format, repository.symref_target(b"HEAD"));
        let capabilities = Capabilities::parse_v1(&advertised_capabilities, &limits)
            .map_err(GitDaemonTransportRefusal::Wire)
            .map_err(NodeGitDaemonServeRefusal::from)?;
        let mut writer = DeadlineTcpStream::new(&mut response_stream, deadline);
        let served = serve_git_daemon_upload_pack_after_greeting(
            &mut reader,
            &mut writer,
            greeting,
            &repository,
            capabilities,
            limits,
            Some(deadline),
            |_request, pack_request| {
                let pack_context = request.authority().create_child();
                let pack_deadline_expired = AtomicBool::new(false);
                let mut is_live = || {
                    if deadline.expired() {
                        pack_deadline_expired.store(true, Ordering::Relaxed);
                        return false;
                    }
                    pack_context.checkpoint().is_ok()
                };
                let pack = self.materialize_selected_pack(
                    &materialized,
                    &pack_request.haves,
                    &mut is_live,
                );
                if pack_deadline_expired.load(Ordering::Relaxed) || deadline.expired() {
                    Err(GitDaemonServeError::Transport(
                        GitDaemonTransportRefusal::SessionDeadlineExceeded {
                            operation: "materialize selected git pack",
                        },
                    ))
                } else {
                    pack.map_err(GitDaemonServeError::Pack)
                }
            },
        )
        .map_err(classify_session_serve_error)
        .map_err(node_git_daemon_serve_error)?;
        response_stream
            .shutdown(Shutdown::Write)
            .map_err(|source| {
                NodeGitDaemonServeRefusal::from(GitDaemonTransportRefusal::Io {
                    operation: "send git-daemon response EOF",
                    source,
                })
            })?;
        Ok(served)
    }

    /// Opens the current durable authority state as a bounded V0 upload-pack view.
    ///
    /// This reads and authenticates the head through the node's production
    /// async authority contract, derives the exact [`PublicationBasis`] from
    /// that receipt, then delegates ref resolution to the supplied admission
    /// projection.  The resulting view is safe only for the legacy V0
    /// first-clone transport: this generic projection view does not itself
    /// carry a closure, so non-advertised wants remain refused.  The durable
    /// authority-selected pack path supplies closure evidence for the node's
    /// served transport.
    pub async fn admission_upload_pack_repository_in<Projection>(
        &self,
        request: &NodeRequestContext,
        projection: &Projection,
        limits: &WireLimits,
    ) -> Result<AdmissionUploadPackRepository, NodeAdmissionViewRefusal>
    where
        Projection: AdmissionSnapshotProjection + Sync + ?Sized,
    {
        let authenticated = self
            .authenticate_authority_head_in(request)
            .await
            .map_err(NodeAdmissionViewRefusal::from)?;
        let body = authenticated
            .body()
            .map_err(NodeAdmissionViewRefusal::from)?;
        let id = body_id(&CryptoBodyIdentity, &body)
            .map_err(NodeAdmissionViewRefusal::from)
            .and_then(|identity| {
                RepositoryAuthorityHeadId::from_internal_object_id(identity)
                    .map_err(NodeAdmissionViewRefusal::from)
            })?;
        let basis = PublicationBasis::new(id, body);
        AdmissionUploadPackRepository::from_projection(
            projection,
            &basis,
            &authenticated,
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::from)
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
        .map_err(NodeRefusal::from)
    }

    /// Resolves one sealed transaction outcome with a fresh bounded context.
    pub async fn resolve_outcome(
        &self,
        transaction_id: fgit_types::TxId,
    ) -> Result<OutcomeLookup, NodeRefusal> {
        let request = self.request_context();
        self.resolve_outcome_in(&request, transaction_id).await
    }

    /// Publishes one chronicle-verified decision batch through this node's
    /// durable production authority path.
    ///
    /// The public boundary accepts only a [`VerifiedPublication`]: the
    /// unforgeable evidence that the batch and successor head passed every
    /// chronicle invariant against the basis they name. Before any immutable
    /// staging work, this boundary re-authenticates the store's current head
    /// receipt and requires the publication's basis to bind that head exactly,
    /// with the caller's `expected` token agreeing with the authenticated
    /// receipt; a publication assembled against any other predecessor is
    /// refused here rather than after winning the conditional replacement.
    /// Raw batch and head bodies remain publishable only through the
    /// lower-layer authority surface reserved for fault injection.
    pub async fn publish_decisions_in(
        &self,
        request: &NodeRequestContext,
        expected: AuthorityVersionToken,
        publication: &VerifiedPublication,
    ) -> Result<PublicationVerdict, NodeRefusal> {
        if publication.batch().repository_id != self.repository_id
            || publication.head().repository_id != self.repository_id
        {
            return Err(NodeRefusal::RepositoryMismatch);
        }
        let authenticated = self.authenticate_authority_head_in(request).await?;
        let receipt = authenticated.receipt();
        let current_body: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), fgit_codec::DecodeLimits::DEFAULT)
                .map_err(|_| NodeRefusal::PublicationBasisUnbound)?;
        // The basis id is re-identified from the authenticated body rather than
        // trusted: PublicationBasis::new accepts any id/body pairing, and
        // verify_pair checks the batch against basis.id without recomputing it.
        let canonical_head_id =
            authority_head_id(&current_body).map_err(|_| NodeRefusal::PublicationBasisUnbound)?;
        let bound = receipt.token() == expected
            && *publication.basis().body() == current_body
            && publication.basis().id() == canonical_head_id;
        if !bound {
            return Err(NodeRefusal::PublicationBasisUnbound);
        }
        publish_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            expected,
            publication,
            self.tenant_id,
        )
        .await
        .map_err(NodeRefusal::from)
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

    /// Switches from the unopened candidate namespace to the one the
    /// authenticated configuration selects.
    ///
    /// `open_existing` has not exposed the preliminary fabric to a caller: it
    /// authenticates the head and checks any caller-supplied expectation before
    /// reaching this point. Reopening the local fabric here therefore prevents
    /// an unlabelled open from resolving objects in a stale or random creation
    /// namespace.
    fn rebind_object_fabric(
        &mut self,
        repository_incarnation_id: RepositoryIncarnationId,
    ) -> Result<(), NodeRefusal> {
        let namespace = object_namespace(self.repository_id, repository_incarnation_id);
        if self.namespace == namespace {
            return Ok(());
        }
        let fabric = open_local_fabric(
            self.storage_root.clone(),
            namespace.clone(),
            self.max_object_bytes,
            self.segment_limits.clone(),
        )?;
        self.fabric = fabric;
        self.namespace = namespace;
        Ok(())
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
        .map_err(|error| NodeRefusal::from(StoreRefusal::Fabric(error)))?;
        let verified = VerifiedObject::new(envelope, body).map_err(NodeRefusal::from)?;
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            placement_resources(offered),
        );
        let grant = ledger
            .grant(placement_resources(offered))
            .map_err(NodeRefusal::from)?;
        let outcome = self
            .fabric
            .put_if_absent(verified, PlacementAdmission::new(&ledger, grant));
        let closed = ledger.close();
        if !matches!(closed, RegionCloseOutcome::Quiescent(_)) {
            return Err(NodeRefusal::ResourceContainment);
        }
        match outcome.map_err(NodeRefusal::from)? {
            PutIfAbsent::Created { .. } => Ok(StoredObject::Created(identity)),
            PutIfAbsent::AlreadyPresent { .. } => Ok(StoredObject::AlreadyPresent(identity)),
        }
    }

    /// Reads one exact immutable Git object from the local fabric.
    pub fn read_git_object(&self, identity: GitOid) -> Result<VerifiedObject, NodeRefusal> {
        if identity.algorithm() != self.object_format {
            return Err(NodeRefusal::from(
                StoreRefusal::NativeObjectIdentityMismatch,
            ));
        }
        self.fabric
            .read_whole(identity)
            .map(|read| read.object)
            .map_err(NodeRefusal::from)
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

/// Why a labelled read could not be served.
///
/// Separate from [`NodeRefusal`] because the first variant is not a node fault
/// at all: a cell refusing a mode its state does not admit is behaving
/// correctly, and folding that into the same enum as storage and runtime
/// failures would make "the cell is draining" indistinguishable from "the disk
/// is gone" at every call site that matches on it.
#[derive(Debug)]
pub enum LabelledReadRefusal {
    /// The cell's readiness state admits no read in the requested mode.
    State(CellRefusal),
    /// The admission view could not be materialized.
    View(Box<NodeAdmissionViewRefusal>),
    /// The advertisement could not be built from the snapshot.
    Advertisement(Box<AdmissionUploadPackRefusal>),
}

impl Display for LabelledReadRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(refusal) => write!(formatter, "the cell cannot serve this read: {refusal}"),
            Self::View(refusal) => {
                write!(formatter, "the admission view is unavailable: {refusal}")
            }
            Self::Advertisement(refusal) => {
                write!(formatter, "the advertisement could not be built: {refusal}")
            }
        }
    }
}

impl Error for LabelledReadRefusal {}

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
    HeadKey::new(bytes).map_err(NodeRefusal::from)
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
    let failure: fgit_authority::OutcomeFailure = error.into_failure().into();
    NodeRefusal::from(failure)
}

fn authority_failure_refusal(error: fgit_authority::AuthorityFailure) -> NodeRefusal {
    let failure: fgit_authority::OutcomeFailure = error.into();
    NodeRefusal::from(failure)
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
        .map_err(NodeRefusal::from)
}

fn mint_repository_incarnation_id() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes(std::random::random::<u128>(..).to_be_bytes())
}

fn open_local_fabric(
    storage_root: PathBuf,
    namespace: Vec<u8>,
    max_object_bytes: u64,
    segment_limits: SegmentLimits,
) -> Result<LocalFilesystemFabric, NodeRefusal> {
    let failure_domain =
        fgit_resource::OpaqueHandle::new(b"node-local-filesystem").map_err(NodeRefusal::from)?;
    let encryption_dependency =
        fgit_resource::OpaqueHandle::new(b"node-local-key").map_err(NodeRefusal::from)?;
    LocalFilesystemFabric::open(LocalFilesystemConfig::new(
        storage_root,
        namespace,
        failure_domain,
        encryption_dependency,
        max_object_bytes,
        segment_limits,
    ))
    .map_err(NodeRefusal::from)
}

fn object_namespace(
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
) -> Vec<u8> {
    let mut namespace = Vec::with_capacity(
        FABRIC_NAMESPACE_PREFIX.len()
            + repository_id.as_bytes().len()
            + repository_incarnation_id.as_bytes().len(),
    );
    namespace.extend_from_slice(FABRIC_NAMESPACE_PREFIX);
    namespace.extend_from_slice(repository_id.as_bytes());
    namespace.extend_from_slice(repository_incarnation_id.as_bytes());
    namespace
}

fn default_git_daemon_repository_path(repository_id: RepositoryId) -> GitDaemonRepositoryPath {
    let text = format!("/{repository_id}.git");
    // A `RepositoryId` display value is canonical lowercase hexadecimal, so
    // this fixed prefix/suffix construction satisfies the daemon path grammar
    // without accepting a caller-provided filesystem spelling.
    GitDaemonRepositoryPath(text.into_bytes())
}

fn genesis_head(
    repository_id: RepositoryId,
    ref_root: Digest,
    configuration_root: Digest,
) -> Result<RepositoryAuthorityHeadBody, NodeRefusal> {
    Ok(RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root,
        forge_position_root: genesis_root(repository_id, b"forge-position"),
        outcome_index_root: outcome_index_root(&[]).map_err(NodeRefusal::from)?,
        retention_root: genesis_root(repository_id, b"retention"),
        outbox_root: genesis_root(repository_id, b"outbox"),
        configuration_root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    })
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::Infallible;
    use std::fs;
    use std::io::{Cursor, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use fgit_admission::evidence::{
        DURABLE_REFUSAL_EVIDENCE_DETAIL, ForgeEventBatch, InvariantEvidence, OutboxEffectBatch,
        PolicyDecisionEvidence, PrincipalSnapshot, RefusalEvidence, RefusalEvidenceBodies,
        RetentionDelta, evidence_root,
    };
    use fgit_admission::{
        AdmissionContext, AdmissionError, AdmissionEvidence, AdmissionLimits, AdmissionSnapshot,
        AdmissionSnapshotProjection, AsyncAdmissionProjection, CanonicalAdmissionStore,
        CanonicalRefState, CommitEvidence, PermittedObjectClosure, QuarantineValidator,
        SourceImportOrigin, SourceImportReceipt, SourceRefUpdate, ValidatedClosure,
        canonical_ref_state_root, permitted_object_closure_root, validate_receive,
        validate_source_import,
    };
    use fgit_authority::{
        AsyncAuthorityStore, HeadInit, HeadRead, ImmutableRead, OutcomeLookup,
        collect_cumulative_outcomes_async, publish_decisions_async, read_decision_batch_body_async,
    };
    use fgit_chronicle::{
        ChronicleRefusal, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
        batch_identity,
    };
    use fgit_codec::harness::{commit_record, digest_of, refusal_record_id, tx_id};
    use fgit_codec::{
        CanonicalBody, CryptoBodyIdentity, RepositoryAuthorityHeadBody, body_id, decode_body,
    };
    use fgit_object_fabric::fabric::StoreRefusal;
    use fgit_reference::effect::{FoldOutcome, FoldReport, NetEffects};
    use fgit_reference::intent::TransactionRequest;
    use fgit_reference::intent::{DurabilityProfile, IdempotencyKey as ModelIdempotencyKey};
    use fgit_txn::TransactionFoldReport;
    use fgit_types::{
        CANONICAL_CODEC_VERSION, DecisionOutcome, Digest, DigestBytes, GitHashAlgorithm, GitOid,
        InternalObjectId, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId,
        RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId, TxId,
    };
    use fgit_wire::receive::{QuarantineReceipt, ReceiveCommand, ReceiveRequest};
    use fgit_wire::{
        AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, ObjectType, PackPayloadSource,
        Packet, UploadPackRepository, V2UploadPack, WireError, WireEvent, WireLimits,
        encode_packets,
    };

    use super::{
        ADMISSION_CLOSURE_KEY_PREFIX, ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
        ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX, ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
        ADMISSION_POLICY_DECISION_KEY_PREFIX, ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
        ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX, ADMISSION_RETENTION_DELTA_KEY_PREFIX,
        AdmissionMaterializationRefusal, AdmissionUploadPackRefusal, AdmissionUploadPackRepository,
        ClosureSelectionSource, GitDaemonServeError, GitDaemonSessionOutcome,
        GitDaemonSessionTimeout, GitDaemonTransportRefusal, NodeConfig, NodeGitDaemonServeRefusal,
        NodeInitialization, NodeRefusal, NodeRequestContext, OneNode, admission_immutable_key,
        authority_head_id, genesis_head, genesis_root, git_daemon_capabilities,
        initialize_embedded_repository, object_namespace, parse_git_daemon_request,
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

    #[test]
    fn genesis_head_commits_to_the_canonical_empty_outcome_index() {
        let repository_id = RepositoryId::from_bytes([0x22; 16]);
        let ref_root = genesis_root(repository_id, b"fixed-genesis-refs");

        let head = genesis_head(
            repository_id,
            ref_root,
            genesis_root(repository_id, b"fixed-genesis-configuration"),
        )
        .expect("the canonical empty outcome index derives without input entries");

        assert_eq!(
            head.outcome_index_root,
            fgit_authority::outcome_index_root(&[])
                .expect("the authority empty-outcome derivation is defined"),
            "the live genesis head uses the authority-owned empty index commitment"
        );
    }

    fn distinct_tx_id() -> TxId {
        TxId::from_internal_object_id(InternalObjectId::new(
            fgit_codec::harness::algorithm(),
            TxId::DOMAIN_TAG,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x9a; 32]).expect("fixed test digest has canonical length"),
        ))
        .expect("fixed transaction identity uses its own domain")
    }

    fn evidence_request(
        node: &OneNode,
    ) -> (AdmissionContext, TransactionRequest, TransactionFoldReport) {
        let context = AdmissionContext {
            head_key: node.head_key.clone(),
            tenant_id: node.tenant_id(),
            repository_id: node.repository_id(),
            principal_id: PrincipalId::from_bytes([0x44; 16]),
            idempotency_key: fgit_authority::IdempotencyKey::new(b"node-evidence".to_vec())
                .expect("fixed bounded authority idempotency key"),
            object_format: node.object_format,
        };
        let request = TransactionRequest {
            tx_id: distinct_tx_id(),
            tenant: context.tenant_id,
            repository: context.repository_id,
            principal: context.principal_id,
            schema: SchemaId::new(SchemaFamily::from_static("node-evidence"), 1, 0),
            idempotency_key: ModelIdempotencyKey::new(
                fgit_types::AsciiSlug::try_new("test", b"node-evidence-request")
                    .expect("fixed model idempotency key"),
            ),
            canonical_request_digest: digest_of(0x7a),
            statements: Vec::new(),
            promised_closure: BTreeSet::new(),
            atomic: true,
            durability: DurabilityProfile::CanonicalSource,
        };
        let fold = FoldReport {
            outcome: FoldOutcome::Folded(NetEffects::default()),
            mappings: Vec::new(),
        };
        (context, request, fold)
    }

    fn assert_published_evidence_body<Body>(
        node: &OneNode,
        request: &NodeRequestContext,
        namespace: &[u8],
        root: Digest,
    ) where
        Body: CanonicalBody,
    {
        let key = admission_immutable_key(namespace, node.repository_id(), root)
            .expect("published evidence key is bounded");
        let ImmutableRead::Present(frame) = node
            .runtime()
            .block_on(AsyncAuthorityStore::read_immutable(
                &node.authority,
                request.authority(),
                &key,
            ))
            .expect("published RCR evidence reads through durable authority")
        else {
            panic!("every evidence root named by the published RCR has a durable frame");
        };
        let body = decode_body::<Body>(&frame, fgit_codec::DecodeLimits::DEFAULT)
            .expect("published evidence frame decodes canonically");
        assert_eq!(
            evidence_root(&body).expect("decoded evidence re-identifies"),
            root,
            "the published RCR root is derived from the decoded authority frame"
        );
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
        let main_ref = RefName::try_new(b"refs/heads/main").expect("fixed valid ref");
        refs.insert(main_ref.clone(), main);
        refs.insert(
            RefName::try_new(b"refs/tags/v1.0").expect("fixed valid ref"),
            release,
        );
        let snapshot = AdmissionSnapshot {
            refs,
            head_target: Some(main_ref),
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
            vec![
                b"HEAD".as_slice(),
                b"refs/heads/main".as_slice(),
                b"refs/tags/v1.0".as_slice(),
            ],
        );
        assert_eq!(
            repository.symref_target(b"HEAD"),
            Some(b"refs/heads/main".as_slice())
        );
        assert_eq!(repository.unborn_symref_target(), None);
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
    fn admission_snapshot_view_emits_unborn_head_only_for_a_v2_unborn_request() {
        let default_branch =
            RefName::try_new(b"refs/heads/main").expect("fixed valid default branch");
        let snapshot = AdmissionSnapshot {
            head_target: Some(default_branch),
            ..AdmissionSnapshot::default()
        };
        let repository = AdmissionUploadPackRepository::from_snapshot(
            &snapshot,
            GitHashAlgorithm::Sha1,
            &WireLimits::default(),
        )
        .expect("an empty repository may have an unborn symbolic HEAD");

        assert!(repository.advertised_refs().is_empty());
        assert_eq!(repository.symref_target(b"HEAD"), None);
        assert_eq!(
            repository.unborn_symref_target(),
            Some(b"refs/heads/main".as_slice())
        );

        let capabilities =
            Capabilities::parse_v1(b"ls-refs", &WireLimits::default()).expect("ls-refs exists");
        let mut machine = V2UploadPack::new(capabilities, WireLimits::default())
            .expect("v2 ls-refs machine constructs");
        machine
            .push_packet(&Packet::Data(b"command=ls-refs\n".to_vec()), &repository)
            .expect("ls-refs command is accepted");
        machine
            .push_packet(&Packet::Delimiter, &repository)
            .expect("ls-refs argument section opens");
        machine
            .push_packet(&Packet::Data(b"unborn\n".to_vec()), &repository)
            .expect("client asks for unborn HEAD state");
        let transition = machine
            .push_packet(&Packet::Flush, &repository)
            .expect("unborn ls-refs completes");

        assert_eq!(
            transition.output,
            vec![
                Packet::Data(b"unborn HEAD symref-target:refs/heads/main\n".to_vec()),
                Packet::Flush,
            ]
        );
        assert!(matches!(
            transition.events.as_slice(),
            [WireEvent::LsRefs { unborn: true, .. }]
        ));
    }

    #[test]
    fn admission_snapshot_view_refuses_a_dangling_head_for_a_nonempty_repository() {
        let main = RefName::try_new(b"refs/heads/main").expect("fixed valid branch");
        let topic = RefName::try_new(b"refs/heads/topic").expect("fixed valid branch");
        let snapshot = AdmissionSnapshot {
            refs: BTreeMap::from([(
                topic,
                GitOid::from_hex(
                    GitHashAlgorithm::Sha1,
                    "1111111111111111111111111111111111111111",
                )
                .expect("fixed SHA-1 object id"),
            )]),
            head_target: Some(main.clone()),
            ..AdmissionSnapshot::default()
        };

        assert!(matches!(
            AdmissionUploadPackRepository::from_snapshot(
                &snapshot,
                GitHashAlgorithm::Sha1,
                &WireLimits::default(),
            ),
            Err(AdmissionUploadPackRefusal::HeadTargetNotAdvertised(target)) if target == main
        ));
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

        let outcome = serve_git_daemon_upload_pack(
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
        let GitDaemonSessionOutcome::Pack(receipt) = outcome else {
            panic!("a non-empty repository must negotiate and emit a pack");
        };

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
        let fixture_pack_worker = thread::spawn(move || {
            serve_git_daemon_tcp_once(
                &listener,
                &repository,
                Capabilities::default(),
                WireLimits::default(),
                GitDaemonSessionTimeout::DEFAULT,
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
        let outcome = fixture_pack_worker
            .join()
            .expect("server thread joins")
            .expect("server accepts the complete V0 request");
        let GitDaemonSessionOutcome::Pack(receipt) = outcome else {
            panic!("a non-empty repository must negotiate and emit a pack");
        };
        assert_eq!(receipt.request().repository_path().as_bytes(), b"/demo.git");
        assert!(response.ends_with(b"PACK\0tcp"));
    }

    #[test]
    fn one_node_serves_its_authenticated_empty_repository_without_a_fixture_pack() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes a canonical empty repository");
        let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener reports its bound loopback address");
        let empty_repository_worker = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });

        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let greeting_payload = [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            b"\0host=loopback\0".as_slice(),
        ]
        .concat();
        let greeting = daemon_greeting(&greeting_payload);
        std::io::Write::write_all(&mut client, &greeting).expect("client greeting writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes its greeting half");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("empty repository advertisement reaches EOF");

        let (session_result, shutdown) = empty_repository_worker
            .join()
            .expect("node server thread joins");
        shutdown.expect("node drains and shuts down after the one session");
        let empty_repository_session =
            session_result.expect("empty canonical admission state serves");
        assert!(matches!(
            empty_repository_session,
            GitDaemonSessionOutcome::EmptyRepository(_)
        ));
        assert_eq!(
            empty_repository_session
                .request()
                .repository_path()
                .as_bytes(),
            repository_path
        );
        let mut expected = format!(
            "{:04x}",
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 agent=frankengit-node\n"
                .len()
                + 4
        )
        .into_bytes();
        expected.extend_from_slice(
            b"0000000000000000000000000000000000000000 capabilities^{}\0object-format=sha1 agent=frankengit-node\n0000",
        );
        assert_eq!(
            response, expected,
            "the empty V0 advertisement carries Git's zero-identity capability pseudo-ref and no pack"
        );
    }

    #[test]
    fn git_daemon_capabilities_advertise_the_object_format_for_every_repository_format() {
        let limits = WireLimits::default();

        // SHA-1 carries its OWN object-format token, because pinned git-2.54.0
        // advertises one for every format. Measured, not assumed: the oracle
        // shows `object-format=sha1` on an empty --object-format=sha1 repository.
        let sha1 = git_daemon_capabilities(GitHashAlgorithm::Sha1, None);
        assert_eq!(sha1.as_slice(), b"object-format=sha1 agent=frankengit-node");
        assert!(
            Capabilities::parse_v1(&sha1, &limits)
                .expect("the SHA-1 daemon capability list stays wire-valid")
                .contains(b"object-format"),
            "upstream advertises object-format for sha1 too; omitting it is a declared divergence, not a default",
        );

        // SHA-256 gains exactly one token, in Git's own spelling, and the bytes
        // are asserted through the parser the daemon actually feeds them to --
        // a string comparison alone would not prove they are wire-valid.
        let sha256 = git_daemon_capabilities(GitHashAlgorithm::Sha256, None);
        assert_eq!(
            sha256.as_slice(),
            b"object-format=sha256 agent=frankengit-node"
        );
        let parsed = Capabilities::parse_v1(&sha256, &limits)
            .expect("the SHA-256 daemon capability list is wire-valid");
        assert!(
            parsed.contains(b"object-format"),
            "without this capability a stock client keeps the SHA-1 default and cannot parse a 64-hex advertisement",
        );
        assert!(
            parsed.contains(b"agent"),
            "the object-format token must be added to the agent profile, not replace it",
        );

        let with_head = git_daemon_capabilities(GitHashAlgorithm::Sha1, Some(b"refs/heads/main"));
        assert_eq!(
            with_head.as_slice(),
            b"object-format=sha1 symref=HEAD:refs/heads/main agent=frankengit-node"
        );
        assert!(
            Capabilities::parse_v1(&with_head, &limits)
                .expect("the symbolic HEAD capability stays wire-valid")
                .contains(b"symref"),
            "a resolved canonical HEAD must reach the v0/v1 capability record",
        );
    }

    #[test]
    fn one_node_advertises_object_format_sha256_for_its_empty_sha256_repository() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(
            test_config(scratch.path().to_path_buf()).with_object_format(GitHashAlgorithm::Sha256),
        )
        .expect("node initializes a canonical empty SHA-256 repository");
        let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener reports its bound loopback address");
        let worker = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });

        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let greeting_payload = [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            b"\0host=loopback\0".as_slice(),
        ]
        .concat();
        let greeting = daemon_greeting(&greeting_payload);
        std::io::Write::write_all(&mut client, &greeting).expect("client greeting writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes its greeting half");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("empty SHA-256 advertisement reaches EOF");

        let (session_result, shutdown) = worker.join().expect("node server thread joins");
        shutdown.expect("node drains and shuts down after the one session");
        let session = session_result.expect("empty canonical SHA-256 admission state serves");
        assert!(matches!(
            session,
            GitDaemonSessionOutcome::EmptyRepository(_)
        ));

        // The zero identity is 64 hex digits here, not 40, which is precisely
        // why the capability must be present: without it a stock client keeps
        // the SHA-1 domain and cannot parse this advertisement.
        let identity = "0".repeat(GitHashAlgorithm::Sha256.digest_len() * 2);
        let line =
            format!("{identity} capabilities^{{}}\0object-format=sha256 agent=frankengit-node\n");
        let mut expected = format!("{:04x}", line.len() + 4).into_bytes();
        expected.extend_from_slice(line.as_bytes());
        expected.extend_from_slice(b"0000");
        assert_eq!(
            response, expected,
            "the empty SHA-256 V0 advertisement must carry a 64-zero identity AND the object-format capability that lets a client select the domain",
        );
    }

    #[test]
    fn one_node_advertises_object_format_sha256_on_protocol_v1_as_well_as_v0() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(
            test_config(scratch.path().to_path_buf()).with_object_format(GitHashAlgorithm::Sha256),
        )
        .expect("node initializes a canonical empty SHA-256 repository");
        let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener reports its bound loopback address");
        let worker = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });

        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        // The only difference from the V0 twin: the greeting names protocol v1,
        // which adds a prelude packet. The capability list is derived once from
        // the repository object format and handed to both versions unchanged,
        // so this pins that the version selection cannot drop it.
        let greeting_payload = [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            b"\0host=loopback\0version=1\0".as_slice(),
        ]
        .concat();
        let greeting = daemon_greeting(&greeting_payload);
        std::io::Write::write_all(&mut client, &greeting).expect("client greeting writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes its greeting half");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("empty SHA-256 V1 advertisement reaches EOF");

        let (session_result, shutdown) = worker.join().expect("node server thread joins");
        shutdown.expect("node drains and shuts down after the one session");
        let session = session_result.expect("empty canonical SHA-256 admission state serves");
        assert!(matches!(
            session,
            GitDaemonSessionOutcome::EmptyRepository(_)
        ));

        let identity = "0".repeat(GitHashAlgorithm::Sha256.digest_len() * 2);
        let advertisement =
            format!("{identity} capabilities^{{}}\0object-format=sha256 agent=frankengit-node\n");
        let packet = |payload: &str| {
            let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
            out.extend_from_slice(payload.as_bytes());
            out
        };
        let mut expected = packet("version 1\n");
        expected.extend_from_slice(&packet(&advertisement));
        expected.extend_from_slice(b"0000");
        assert_eq!(
            response, expected,
            "protocol v1 adds its prelude and must still carry object-format=sha256",
        );
    }

    /// Publishes one real ref into a SHA-256 node through the owned import and
    /// authority APIs, so the non-empty advertisement below is produced by the
    /// node's own admission path rather than by hand-built state. The object id
    /// is whatever `put_git_object` derives under the node's configured format,
    /// which is what makes this a SHA-256 advertisement rather than a fixture
    /// asserting its own input.
    fn sha256_node_with_one_published_ref(scratch: &ScratchDirectory) -> (OneNode, String) {
        let (node, _) = OneNode::init(
            test_config(scratch.path().to_path_buf()).with_object_format(GitHashAlgorithm::Sha256),
        )
        .expect("node initializes a canonical empty SHA-256 repository");
        let authority_request = node.request_context();
        let stored = node
            .put_git_object(
                ObjectType::Blob,
                b"fg058 sha256 advertisement subject".to_vec(),
            )
            .expect("the node places a verified native object in its configured format");
        let objects = BTreeSet::from([stored.identity()]);
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))
            .expect("the import closure root derives"),
            objects,
        };
        let absent = AnyGitOid::from_hex(GitObjectFormat::Sha256, &"0".repeat(64))
            .expect("the SHA-256 absent-ref sentinel parses");
        let updates = [SourceRefUpdate {
            old: absent,
            new: stored.identity(),
            ref_name: b"refs/heads/sha256-main".to_vec(),
        }];
        let receipt = SourceImportReceipt {
            object_format: GitObjectFormat::Sha256,
            object_count: 1,
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let validated = validate_source_import(&updates, &receipt, closure)
            .expect("a covering SHA-256 source-import closure is admissible");
        let (context, _, _) = evidence_request(&node);
        node.runtime()
            .block_on(node.admit_validated_source_import_durable_in(
                &authority_request,
                &context,
                &validated,
                AdmissionLimits::default(),
            ))
            .expect("the node publishes the SHA-256 source-import RCR");
        let identity = stored.identity().to_string();
        (node, identity)
    }

    /// Serves exactly one git-daemon session and returns the bytes the client
    /// saw. The session outcome is deliberately not asserted here: a client that
    /// closes after the greeting leaves a NON-EMPTY negotiation incomplete, and
    /// these tests are about the advertisement that was already written.
    fn read_one_daemon_advertisement(node: OneNode, greeting_tail: &[u8]) -> Vec<u8> {
        let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener reports its bound loopback address");
        let worker = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });
        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let greeting_payload = [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            greeting_tail,
        ]
        .concat();
        let greeting = daemon_greeting(&greeting_payload);
        std::io::Write::write_all(&mut client, &greeting).expect("client greeting writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes its greeting half");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("the advertisement reaches EOF");
        let (_served, shutdown) = worker.join().expect("node server thread joins");
        shutdown.expect("node drains and shuts down after the one session");
        response
    }

    fn packet(payload: &str) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload.as_bytes());
        out
    }

    #[test]
    fn one_node_advertises_object_format_sha256_for_a_non_empty_sha256_repository() {
        let scratch = ScratchDirectory::new();
        let (node, identity) = sha256_node_with_one_published_ref(&scratch);
        assert_eq!(
            identity.len(),
            GitHashAlgorithm::Sha256.digest_len() * 2,
            "the published ref must carry a 64-hex SHA-256 identity, which is the whole reason a client needs the capability",
        );

        let response = read_one_daemon_advertisement(node, b"\0host=loopback\0");

        let mut expected = packet(&format!(
            "{identity} refs/heads/sha256-main\0object-format=sha256 agent=frankengit-node\n"
        ));
        expected.extend_from_slice(b"0000");
        assert_eq!(
            response, expected,
            "a non-empty SHA-256 v0 advertisement must carry the real 64-hex ref AND object-format=sha256",
        );
    }

    #[test]
    fn one_node_advertises_object_format_sha256_for_a_non_empty_repository_on_protocol_v1() {
        let scratch = ScratchDirectory::new();
        let (node, identity) = sha256_node_with_one_published_ref(&scratch);

        let response = read_one_daemon_advertisement(node, b"\0host=loopback\0version=1\0");

        let mut expected = packet("version 1\n");
        expected.extend_from_slice(&packet(&format!(
            "{identity} refs/heads/sha256-main\0object-format=sha256 agent=frankengit-node\n"
        )));
        expected.extend_from_slice(b"0000");
        assert_eq!(
            response, expected,
            "protocol v1 on a non-empty SHA-256 repository must carry its prelude, the real ref, and object-format=sha256",
        );
    }

    #[test]
    fn one_node_refuses_a_different_daemon_path_before_authority_materialization() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes a canonical empty repository");
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("listener reports its bound loopback address");
        let server = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });

        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let greeting = daemon_greeting(b"git-upload-pack /other.git\0host=loopback\0");
        std::io::Write::write_all(&mut client, &greeting).expect("client greeting writes");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes its greeting half");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("rejected session reaches EOF");

        let (path_rejection, shutdown) = server.join().expect("node server thread joins");
        shutdown.expect("node drains and shuts down after rejecting the session");
        assert!(matches!(
            path_rejection,
            Err(NodeGitDaemonServeRefusal::RepositoryPathMismatch)
        ));
        assert!(response.is_empty(), "no repository state is advertised");
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
    fn open_existing_accepts_the_current_incarnation_and_refuses_a_stale_twin() {
        let scratch = ScratchDirectory::new();
        let current = RepositoryIncarnationId::from_bytes([0x59; 16]);
        let stale = RepositoryIncarnationId::from_bytes([0x5A; 16]);
        let config =
            test_config(scratch.path().to_path_buf()).with_expected_repository_incarnation(current);

        let (created, _) = OneNode::init(config.clone())
            .expect("a creation stages the current incarnation configuration");
        assert_eq!(created.repository_incarnation_id(), current);
        assert_ne!(
            object_namespace(created.repository_id(), current),
            object_namespace(created.repository_id(), stale),
            "object location records are scoped by both repository and incarnation"
        );
        created.shutdown().expect("creator node closes cleanly");

        let permitted =
            OneNode::open_existing(config.clone()).expect("the matching current incarnation opens");
        assert_eq!(permitted.repository_incarnation_id(), current);
        permitted.shutdown().expect("permitted node closes cleanly");

        assert!(
            matches!(
                OneNode::open_existing(config.with_expected_repository_incarnation(stale)),
                Err(NodeRefusal::RepositoryIncarnationMismatch {
                    expected,
                    observed,
                }) if expected == stale && observed == current
            ),
            "a stale location must fail before the node can serve its object namespace"
        );
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
        let is_live = || false;
        let exact = node
            .runtime()
            .block_on(node.admission_materializer.materialize_exact_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                materialized.basis(),
                materialized.authenticated(),
                &is_live,
            ))
            .expect("the supplied authenticated basis materializes without rereading the head");
        assert_eq!(
            exact.snapshot(),
            materialized.snapshot(),
            "exact-basis materialization must reproduce the same immutable snapshot"
        );
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

        let projection_snapshot = AdmissionSnapshotProjection::snapshot(
            &node.admission_materializer,
            materialized.basis(),
            materialized.authenticated(),
        )
        .expect("the exact authenticated basis resolves");
        assert_eq!(projection_snapshot, *materialized.snapshot());
        let (context, evidence_request, fold) = evidence_request(&node);
        let async_projection = node
            .durable_admission_projection(&context)
            .expect("one node owns the durable evidence projection for its authority slot");
        let mut wrong_tenant = context.clone();
        wrong_tenant.tenant_id = TenantId::from_bytes([0x99; 16]);
        assert!(matches!(
            node.durable_admission_projection(&wrong_tenant),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::EvidenceInvalid
            ))
        ));
        let async_snapshot = node
            .runtime()
            .block_on(AsyncAdmissionProjection::snapshot_async(
                &async_projection,
                &node.authority,
                request.authority(),
                materialized.basis(),
                materialized.authenticated(),
            ))
            .expect("the async-only projection reloads the driver-selected basis");
        assert_eq!(async_snapshot, *materialized.snapshot());
        let empty_closure = PermittedObjectClosure::default();
        let validated_closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&empty_closure)
                .expect("empty closure root derives"),
            objects: BTreeSet::new(),
        };
        let committing = node
            .runtime()
            .block_on(AsyncAdmissionProjection::materialize_commit_async(
                &async_projection,
                &node.authority,
                request.authority(),
                materialized.basis(),
                &evidence_request,
                &fold,
                &validated_closure,
            ))
            .expect("the fold-bound projection stages and quotes real decision evidence");
        let committed_evidence = CommitEvidence {
            principal_snapshot_id: committing.record.principal_snapshot_id,
            forge_event_batch_root: committing.record.forge_event_batch_root,
            policy_decision_root: committing.record.policy_decision_root,
            invariant_evidence_root: committing.record.invariant_evidence_root,
            outbox_effect_root: committing.record.outbox_effect_root,
            retention_delta_root: committing.record.retention_delta_root,
        };
        let rederived = node
            .runtime()
            .block_on(node.admission_materializer.read_decision_evidence_in(
                &node.authority,
                request.authority(),
                context.clone(),
                materialized.basis(),
                &evidence_request,
                &fold,
                committed_evidence,
                &is_live,
            ))
            .expect("the evidence quoted by the proposed RCR re-derives from durable frames");
        assert_eq!(
            rederived
                .commit_evidence(materialized.basis(), &evidence_request, &fold)
                .expect("re-derived provider remains bound to the exact fold"),
            committed_evidence
        );
        let refusal_tx_id = distinct_tx_id();
        let refusal = node
            .runtime()
            .block_on(AsyncAdmissionProjection::materialize_refusal_async(
                &async_projection,
                &node.authority,
                request.authority(),
                materialized.basis(),
                refusal_tx_id,
                RefusalCode::ExpectedOldRefMismatch,
            ))
            .expect("the production projection stages canonical refusal evidence");
        let expected_refusal = RefusalEvidenceBodies::derive(
            &context,
            materialized.basis(),
            refusal_tx_id,
            RefusalCode::ExpectedOldRefMismatch,
        )
        .expect("fixed terminal refusal has canonical evidence");
        assert_eq!(
            refusal.policy_epoch,
            materialized.basis().body().policy_epoch
        );
        assert_eq!(refusal.detail, DURABLE_REFUSAL_EVIDENCE_DETAIL);
        assert_eq!(
            refusal.evidence_root,
            evidence_root(expected_refusal.refusal_evidence())
                .expect("expected refusal evidence root derives"),
            "the terminal materialization quotes the root of its canonical body"
        );
        let refusal_key = admission_immutable_key(
            ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX,
            node.repository_id(),
            refusal.evidence_root,
        )
        .expect("fixed refusal evidence key is bounded");
        let ImmutableRead::Present(refusal_frame) = node
            .runtime()
            .block_on(AsyncAuthorityStore::read_immutable(
                &node.authority,
                request.authority(),
                &refusal_key,
            ))
            .expect("staged refusal evidence reads through durable authority")
        else {
            panic!("successful refusal materialization created an immutable evidence frame");
        };
        assert_eq!(
            decode_body::<RefusalEvidence>(&refusal_frame, fgit_codec::DecodeLimits::DEFAULT)
                .expect("durable refusal evidence frame decodes"),
            expected_refusal.refusal_evidence().clone(),
            "the stored body exactly re-derives the root quoted by the terminal refusal"
        );

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
            )
            .expect("the empty genesis rule selects only its canonical empty closure"),
            closure,
            "a matching staged root resolves only because the authenticated head is empty genesis"
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
        assert!(
            matches!(
                node.runtime()
                    .block_on(node.admission_materializer.materialize_exact_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        &other_basis,
                        materialized.authenticated(),
                        &is_live,
                    )),
                Err(AdmissionMaterializationRefusal::ExactBasisMismatch)
            ),
            "an async replan must never load a frame under a basis different from its authenticated receipt"
        );
        assert_eq!(
            AdmissionSnapshotProjection::snapshot(
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
        assert_eq!(upload_pack.advertised_refs(), []);
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn durable_async_projection_never_uses_a_synchronous_runtime_bridge() {
        let source = include_str!("lib.rs");
        let marker = "impl AsyncAdmissionProjection<FsqliteAuthorityStore> for DurableAsyncAdmissionProjection<'_> {";
        let (_, projection_and_rest) = source
            .split_once(marker)
            .expect("the durable async projection implementation remains present");
        let (projection, _) = projection_and_rest
            .split_once("\nfn async_projection_unavailable")
            .expect("the durable async projection has its explicit refusal mapper boundary");
        assert!(
            projection.contains(".await"),
            "the durable projection reaches authority staging through its asynchronous contract"
        );
        assert!(
            !projection.contains("block_on"),
            "a projection must not hide a synchronous runtime bridge inside async admission"
        );
    }

    #[test]
    fn node_owned_projection_publishes_source_receive_and_refusal_rcrs_with_rederivable_evidence() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes the canonical empty repository");
        let authority_request = node.request_context();
        let stored = node
            .put_git_object(ObjectType::Blob, b"source-import evidence object".to_vec())
            .expect("the import path places its verified native object first");
        let objects = BTreeSet::from([stored.identity()]);
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))
            .expect("the import closure root derives"),
            objects,
        };
        let zero = AnyGitOid::from_hex(
            GitObjectFormat::Sha1,
            "0000000000000000000000000000000000000000",
        )
        .expect("the SHA-1 absent-ref sentinel parses");
        let updates = [SourceRefUpdate {
            old: zero,
            new: stored.identity(),
            ref_name: b"refs/heads/evidence".to_vec(),
        }];
        let receipt = SourceImportReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 1,
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let validated = validate_source_import(&updates, &receipt, closure.clone())
            .expect("a covering source-import closure is admissible");
        let (context, _, _) = evidence_request(&node);
        let admission = node
            .runtime()
            .block_on(node.admit_validated_source_import_durable_in(
                &authority_request,
                &context,
                &validated,
                AdmissionLimits::default(),
            ))
            .expect("the node-owned projection publishes the source-import RCR");
        assert_eq!(
            admission.commands.len(),
            1,
            "the one imported ref receives one authenticated terminal outcome"
        );

        let HeadRead::Present(head) = node
            .runtime()
            .block_on(node.read_authority_head_in(&authority_request))
            .expect("published successor head reads")
        else {
            panic!("the admitted source import advances the repository head");
        };
        let successor: RepositoryAuthorityHeadBody =
            decode_body(head.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("published successor head decodes");
        let expected_source_refs = CanonicalRefState::new(BTreeMap::from([(
            RefName::try_new(b"refs/heads/evidence").expect("fixed source-import ref is valid"),
            stored.identity(),
        )]));
        assert_eq!(
            successor.ref_root,
            canonical_ref_state_root(&expected_source_refs)
                .expect("the imported ref state has one canonical root"),
            "the authority head carries the source-import successor ref root rather than a staged hint"
        );
        let batch_id = successor
            .decision_tail_id
            .expect("the successor head names its committed decision batch");
        let batch = node
            .runtime()
            .block_on(read_decision_batch_body_async(
                &node.authority,
                authority_request.authority(),
                batch_id,
            ))
            .expect("the published decision batch reads through authority");
        let [record] = batch.committed_rcrs.as_slice() else {
            panic!("the one admitted import publishes exactly one RCR");
        };
        let principal_identity = record.principal_snapshot_id.as_internal_object_id();
        let principal_snapshot_root =
            Digest::new(principal_identity.algorithm(), *principal_identity.digest());
        assert_published_evidence_body::<PrincipalSnapshot>(
            &node,
            &authority_request,
            ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            principal_snapshot_root,
        );
        assert_published_evidence_body::<PolicyDecisionEvidence>(
            &node,
            &authority_request,
            ADMISSION_POLICY_DECISION_KEY_PREFIX,
            record.policy_decision_root,
        );
        assert_published_evidence_body::<InvariantEvidence>(
            &node,
            &authority_request,
            ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
            record.invariant_evidence_root,
        );
        assert_published_evidence_body::<ForgeEventBatch>(
            &node,
            &authority_request,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            record.forge_event_batch_root,
        );
        assert_published_evidence_body::<OutboxEffectBatch>(
            &node,
            &authority_request,
            ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
            record.outbox_effect_root,
        );
        assert_published_evidence_body::<RetentionDelta>(
            &node,
            &authority_request,
            ADMISSION_RETENTION_DELTA_KEY_PREFIX,
            record.retention_delta_root,
        );

        let stale_old = AnyGitOid::from_hex(
            GitObjectFormat::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed stale expected-old OID parses");
        let stale_updates = [SourceRefUpdate {
            old: stale_old,
            new: stored.identity(),
            ref_name: b"refs/heads/evidence".to_vec(),
        }];
        let stale_validated = validate_source_import(&stale_updates, &receipt, closure)
            .expect("a complete stale source import remains structurally admissible");
        let mut stale_context = context.clone();
        stale_context.idempotency_key =
            fgit_authority::IdempotencyKey::new(b"node-evidence-stale".to_vec())
                .expect("the stale import has its own bounded idempotency key");
        let basis_before_refusal = node
            .runtime()
            .block_on(node.materialize_admission_in(&authority_request))
            .expect("the current source-import basis materializes before refusal publication");
        let refusal = node
            .runtime()
            .block_on(node.admit_validated_source_import_durable_in(
                &authority_request,
                &stale_context,
                &stale_validated,
                AdmissionLimits::default(),
            ))
            .expect("the durable source-import surface publishes a terminal refusal");
        assert_eq!(refusal.commands.len(), 1);
        let refusal_command = refusal.commands[0];
        let DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            ..
        } = refusal_command.terminal.outcome
        else {
            panic!("the stale expected-old assertion receives its authenticated terminal refusal");
        };
        let expected_refusal = RefusalEvidenceBodies::derive(
            &stale_context,
            basis_before_refusal.basis(),
            refusal_command.tx_id,
            RefusalCode::ExpectedOldRefMismatch,
        )
        .expect("the terminal refusal derives its basis-bound evidence");
        assert_published_evidence_body::<RefusalEvidence>(
            &node,
            &authority_request,
            ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX,
            evidence_root(expected_refusal.refusal_evidence())
                .expect("the staged refusal evidence root derives"),
        );

        struct DeleteOnlyValidator {
            closure: ValidatedClosure,
        }

        impl QuarantineValidator for DeleteOnlyValidator {
            fn validate(
                &self,
                _request: &ReceiveRequest,
                _pack: Option<&fgit_pack::QuarantinedPack>,
                _receipt: &QuarantineReceipt,
                _deadline: &mut impl fgit_pack::Deadline,
            ) -> Result<ValidatedClosure, RefusalCode> {
                Ok(self.closure.clone())
            }
        }

        let delete_request = ReceiveRequest {
            commands: vec![ReceiveCommand {
                old: stored.identity(),
                new: zero,
                ref_name: b"refs/heads/evidence".to_vec(),
            }],
            capabilities: Vec::new(),
            push_options: Vec::new(),
            certificate: None,
        };
        let delete_receipt = QuarantineReceipt {
            object_format: GitObjectFormat::Sha1,
            object_count: 0,
            pack_bytes: 0,
            delete_only: true,
        };
        let empty_closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::default())
                .expect("the delete-only closure root derives"),
            objects: BTreeSet::new(),
        };
        let mut deadline = || true;
        let validated_delete = validate_receive(
            &delete_request,
            None,
            &delete_receipt,
            &DeleteOnlyValidator {
                closure: empty_closure,
            },
            &mut deadline,
        )
        .expect("a pack-free delete-only receive remains a validated receive input");
        let mut receive_context = context;
        receive_context.idempotency_key =
            fgit_authority::IdempotencyKey::new(b"node-evidence-receive-delete".to_vec())
                .expect("the receive delete has its own bounded idempotency key");
        let receive = node
            .runtime()
            .block_on(node.admit_validated_receive_durable_in(
                &authority_request,
                &receive_context,
                &validated_delete,
                AdmissionLimits::default(),
            ))
            .expect("the same durable projection publishes the receive-pack RCR");
        assert_eq!(receive.commands.len(), 1);
        assert!(matches!(
            receive.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after_receive = node
            .runtime()
            .block_on(node.materialize_admission_in(&authority_request))
            .expect("the receive successor materializes from the authority head");
        assert!(
            after_receive.snapshot().refs.is_empty(),
            "the receive-pack delete and source import both mutate the one authority-selected ref state"
        );
        assert_eq!(
            after_receive.basis().body().ref_root,
            canonical_ref_state_root(&CanonicalRefState::default())
                .expect("the empty successor ref state has one canonical root"),
            "the receive-pack successor head carries the shared materializer's ref root"
        );
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn refusal_tail_replays_to_the_committed_rcr_closure_and_materializes_a_pack() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes empty canonical state");
        let request = node.request_context();
        let stored = node
            .put_git_object(
                fgit_git_object::ObjectType::Blob,
                b"authority selected blob".to_vec(),
            )
            .expect("fixture blob enters verified fabric");
        let client_have = node
            .put_git_object(
                fgit_git_object::ObjectType::Blob,
                b"client already has this authority-selected blob".to_vec(),
            )
            .expect("fixture client-have blob enters verified fabric");

        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/main").expect("fixed ref name is valid"),
            stored.identity(),
        );
        let ref_state = CanonicalRefState::new(refs);
        let ref_root = node
            .runtime()
            .block_on(node.admission_materializer.stage_ref_state_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                ref_state,
            ))
            .expect("future RCR ref state stages before head publication");
        let closure = PermittedObjectClosure::new(BTreeSet::from([
            stored.identity(),
            client_have.identity(),
        ]));
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
            .expect("future RCR closure stages before head publication");

        let HeadRead::Present(genesis_read) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("genesis head reads")
        else {
            panic!("node initialization publishes genesis");
        };
        let genesis_body: fgit_codec::RepositoryAuthorityHeadBody =
            decode_body(genesis_read.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("authenticated fixture head decodes");
        let genesis_basis = PublicationBasis::new(
            authority_head_id(&genesis_body).expect("genesis head re-identifies"),
            genesis_body,
        );
        let mut record = commit_record();
        record.repository_id = node.repository_id();
        record.resulting_ref_root = ref_root;
        record.object_closure_root = closure_root;
        record.resulting_forge_position_root = genesis_basis.body().forge_position_root;
        record.policy_epoch = genesis_basis.body().policy_epoch;
        let mut roots = ResultingRoots::carried_forward(&genesis_basis);
        roots.ref_root = ref_root;
        let mut commit_plan = PublicationPlan::open(genesis_basis).expect("genesis opens a plan");
        commit_plan.commit(record);
        let genesis_outcomes = node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
            ))
            .expect("genesis outcomes collect from the authority");
        let committed = commit_plan
            .seal(
                &CryptoBodyIdentity,
                roots,
                &genesis_outcomes,
                genesis_read.token(),
            )
            .expect("committed RCR produces a verified head pair");
        let record_id = super::repository_commit_id(
            committed
                .batch()
                .committed_rcrs
                .first()
                .expect("committed batch carries the selected RCR"),
        )
        .expect("the final stamped RCR re-identifies");
        let committed_verdict = node
            .runtime()
            .block_on(node.publish_decisions_in(&request, genesis_read.token(), &committed))
            .expect("committed RCR publishes through authority");
        assert!(matches!(
            committed_verdict,
            PublicationVerdict::Published(_)
        ));

        let HeadRead::Present(successor_read) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("committed head reads")
        else {
            panic!("committed RCR advances head");
        };
        let successor_body: fgit_codec::RepositoryAuthorityHeadBody =
            decode_body(successor_read.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("committed fixture head decodes");
        let successor_basis = PublicationBasis::new(
            authority_head_id(&successor_body).expect("committed head re-identifies"),
            successor_body,
        );
        let refusal_result_roots = ResultingRoots::carried_forward(&successor_basis);
        let mut refusal_publication =
            PublicationPlan::open(successor_basis).expect("committed head opens");
        refusal_publication.refuse(
            distinct_tx_id(),
            RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id(),
        );
        let successor_outcomes = node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
            ))
            .expect("successor outcomes collect from the authority");
        let refusal_pair = refusal_publication
            .seal(
                &CryptoBodyIdentity,
                refusal_result_roots,
                &successor_outcomes,
                successor_read.token(),
            )
            .expect("refusal-only successor preserves committed roots");
        let refusal_verdict = node
            .runtime()
            .block_on(node.publish_decisions_in(&request, successor_read.token(), &refusal_pair))
            .expect("refusal-only successor publishes through authority");
        assert!(matches!(refusal_verdict, PublicationVerdict::Published(_)));

        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .expect("reader verifies tail then walks to the committed RCR");
        assert_eq!(materialized.selected_closure().root(), closure_root);
        assert_eq!(materialized.selected_closure().closure(), &closure);
        assert_eq!(
            materialized.selected_closure().source(),
            ClosureSelectionSource::RepositoryCommit(record_id),
            "the derived view names the exact RCR rather than a local catalog"
        );
        assert_eq!(
            CanonicalAdmissionStore::resolve_permitted_object_closure(
                &node.admission_materializer,
                closure_root,
            )
            .expect("only the exact authority-selected closure resolves"),
            closure
        );

        let mut payload = node
            .runtime()
            .block_on(node.authority_selected_pack_payload_in(&request))
            .expect("selected verified object becomes a bounded deterministic pack");
        assert_eq!(payload.basis(), materialized.basis());
        assert_eq!(
            payload.closure().source(),
            ClosureSelectionSource::RepositoryCommit(record_id)
        );
        let first_chunk = payload
            .next_chunk(4)
            .expect("payload honors bounded chunk requests")
            .expect("non-empty closure emits a pack header");
        assert_eq!(first_chunk, b"PACK");

        let repository_path = node.git_daemon_repository_path().as_bytes().to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("loopback listener reports its address");
        let server = thread::spawn(move || {
            let served = node.serve_git_daemon_once_with_limits(&listener, WireLimits::default());
            let shutdown = node.shutdown();
            (served, shutdown)
        });
        let mut client = TcpStream::connect(address).expect("client connects to node listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout configures");
        let greeting_payload = [
            b"git-upload-pack ".as_slice(),
            repository_path.as_slice(),
            b"\0host=loopback\0".as_slice(),
        ]
        .concat();
        let mut client_request = daemon_greeting(&greeting_payload);
        client_request.extend(
            encode_packets(
                &[
                    Packet::Data(format!("want {}\n", stored.identity()).into_bytes()),
                    Packet::Flush,
                    Packet::Data(format!("have {}\n", client_have.identity()).into_bytes()),
                    Packet::Data(b"done\n".to_vec()),
                ],
                &WireLimits::default(),
            )
            .expect("authority-selected want negotiation encodes"),
        );
        std::io::Write::write_all(&mut client, &client_request)
            .expect("client sends greeting and negotiation");
        client
            .shutdown(Shutdown::Write)
            .expect("client closes request half after done");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("server completes authority-selected pack response");
        let (pack_session_result, shutdown) = server.join().expect("node server thread joins");
        shutdown.expect("node drains after authority-selected pack session");
        assert!(matches!(
            pack_session_result,
            Ok(GitDaemonSessionOutcome::Pack(_))
        ));
        assert!(
            response
                .windows(b"PACK".len())
                .any(|window| window == b"PACK"),
            "non-empty refs are advertised only with an emitted authority-selected pack"
        );
        let pack_offset = response
            .windows(b"PACK".len())
            .position(|window| window == b"PACK")
            .expect("the completed session contains one raw pack");
        let mut deadline = || true;
        let pack = fgit_pack::read_verified_pack(
            &response[pack_offset..],
            GitHashAlgorithm::Sha1,
            &fgit_pack::PackLimits::default(),
            &mut deadline,
            &fgit_pack::NativeChecksumVerifier,
        )
        .expect("the daemon's compressed pack has a valid native checksum");
        assert_eq!(
            pack.entries().len(),
            1,
            "an exact client have removes its object from the authority-selected pack"
        );
        assert_eq!(
            pack.entries()[0].inflated,
            b"authority selected blob",
            "the permitted twin not named as a client have remains in the emitted pack"
        );
    }

    #[test]
    fn materializer_refuses_a_head_with_a_pre_stamp_rcr_identity() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes empty canonical state");
        let request = node.request_context();
        let oid = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed object identity parses");
        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/main").expect("fixed ref name is valid"),
            oid,
        );
        let ref_root = node
            .runtime()
            .block_on(node.admission_materializer.stage_ref_state_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                CanonicalRefState::new(refs),
            ))
            .expect("future RCR ref state stages before head publication");

        let HeadRead::Present(genesis_read) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("genesis head reads")
        else {
            panic!("node initialization publishes genesis");
        };
        let genesis_body: fgit_codec::RepositoryAuthorityHeadBody =
            decode_body(genesis_read.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("authenticated fixture head decodes");
        let genesis_basis = PublicationBasis::new(
            authority_head_id(&genesis_body).expect("genesis head re-identifies"),
            genesis_body,
        );
        let mut record = commit_record();
        record.repository_id = node.repository_id();
        record.resulting_ref_root = ref_root;
        record.object_closure_root = digest_of(0xb1);
        record.resulting_forge_position_root = genesis_basis.body().forge_position_root;
        record.policy_epoch = genesis_basis.body().policy_epoch;
        let stale_record_id =
            super::repository_commit_id(&record).expect("pre-stamp RCR re-identifies");

        let mut roots = ResultingRoots::carried_forward(&genesis_basis);
        roots.ref_root = ref_root;
        let mut plan = PublicationPlan::open(genesis_basis).expect("genesis opens a plan");
        plan.commit(record);
        let genesis_outcomes = node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
            ))
            .expect("genesis outcomes collect from the authority");
        let committed = plan
            .seal(
                &CryptoBodyIdentity,
                roots,
                &genesis_outcomes,
                genesis_read.token(),
            )
            .expect("the plan derives the committed RCR identity after stamping");
        let mut mismatched_batch = committed.batch().clone();
        mismatched_batch
            .decisions
            .first_mut()
            .expect("the committed batch carries its decision")
            .outcome = DecisionOutcome::Committed {
            repository_commit_id: stale_record_id,
        };
        let mut mismatched_successor = committed.head().clone();
        mismatched_successor.latest_committed_rcr_id = Some(stale_record_id);
        mismatched_successor.decision_tail_id = Some(
            batch_identity(&CryptoBodyIdentity, &mismatched_batch)
                .expect("the deliberately stale batch re-identifies"),
        );
        // Fault-injection surface: the lower-layer authority path still accepts
        // raw bodies exactly so tests can prove derived state catches what the
        // public node boundary refuses to carry.
        node.runtime()
            .block_on(publish_decisions_async(
                &node.authority,
                request.authority(),
                &node.head_key,
                genesis_read.token(),
                &mismatched_batch,
                &mismatched_successor,
                node.tenant_id,
            ))
            .expect("schema-valid stale fixture publishes through fault injection");

        assert!(matches!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request)),
            Err(
                AdmissionMaterializationRefusal::DecisionHistoryVerification(
                    ChronicleRefusal::CommitRecordIdentityMismatch { index: 0 }
                )
            )
        ));

        // The public boundary binds every publication to the authenticated
        // current head: the otherwise-valid genesis publication is stale now
        // that the injected successor occupies the head slot.
        let stale = node.runtime().block_on(node.publish_decisions_in(
            &request,
            genesis_read.token(),
            &committed,
        ));
        assert!(
            matches!(stale, Err(NodeRefusal::PublicationBasisUnbound)),
            "the public boundary must refuse publications whose basis no longer binds"
        );
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn publication_basis_id_is_reidentified_against_the_authenticated_head() {
        let scratch = ScratchDirectory::new();
        let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf()))
            .expect("node initializes empty canonical state");
        let request = node.request_context();

        let HeadRead::Present(genesis_read) = node
            .runtime()
            .block_on(node.read_authority_head_in(&request))
            .expect("genesis head reads")
        else {
            panic!("node initialization publishes genesis");
        };
        let genesis_body: fgit_codec::RepositoryAuthorityHeadBody =
            decode_body(genesis_read.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("authenticated fixture head decodes");

        // Forge a basis that pairs the REAL current head body with an id that
        // does not identify it. PublicationBasis::new accepts the pairing and
        // seal/verify_pair trust the id field, so only the publication
        // boundary's re-identification can catch the forgery.
        let forged_id = RepositoryAuthorityHeadId::from_internal_object_id(InternalObjectId::new(
            fgit_codec::harness::algorithm(),
            RepositoryAuthorityHeadId::DOMAIN_TAG,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x7f; 32]).expect("fixed test digest has canonical length"),
        ))
        .expect("forged head id derives from its own internal object id");
        assert_ne!(
            forged_id,
            authority_head_id(&genesis_body).expect("real genesis head identifies"),
            "the forged id must differ from the canonical one"
        );
        let forged_basis = PublicationBasis::new(forged_id, genesis_body);

        let roots = ResultingRoots::carried_forward(&forged_basis);

        let mut plan = PublicationPlan::open(forged_basis).expect("forged basis opens a plan");
        plan.refuse(
            distinct_tx_id(),
            RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id(),
        );
        let outcomes = node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &node.authority,
                request.authority(),
                &node.head_key,
            ))
            .expect("outcomes collect from the authority");
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &outcomes, genesis_read.token())
            .expect("seal trusts the basis id, which is exactly the hole");

        let refused = node.runtime().block_on(node.publish_decisions_in(
            &request,
            genesis_read.token(),
            &publication,
        ));
        assert!(
            matches!(refused, Err(NodeRefusal::PublicationBasisUnbound)),
            "the boundary must re-identify the basis id against the authenticated head"
        );
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn nonempty_genesis_refuses_even_when_a_closure_frame_is_staged() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let node = OneNode::open_components(config).expect("node components open before genesis");
        let request = node.request_context();
        let oid = GitOid::from_hex(
            GitHashAlgorithm::Sha1,
            "1111111111111111111111111111111111111111",
        )
        .expect("fixed object identity parses");
        let mut refs = BTreeMap::new();
        refs.insert(
            RefName::try_new(b"refs/heads/imported").expect("fixed ref name is valid"),
            oid,
        );
        let ref_root = node
            .runtime()
            .block_on(node.admission_materializer.stage_ref_state_in(
                &node.authority,
                request.authority(),
                node.repository_id(),
                CanonicalRefState::new(refs),
            ))
            .expect("non-empty frame stages before genesis publication");
        node.runtime()
            .block_on(
                node.admission_materializer
                    .stage_permitted_object_closure_in(
                        &node.authority,
                        request.authority(),
                        node.repository_id(),
                        PermittedObjectClosure::new(BTreeSet::from([oid])),
                    ),
            )
            .expect("a staged closure alone remains non-authoritative");
        let genesis = genesis_head(
            node.repository_id(),
            ref_root,
            genesis_root(node.repository_id(), b"test-configuration"),
        )
        .expect("schema-valid test genesis derives the empty outcome root");
        initialize_embedded_repository(
            node.runtime(),
            &node.authority,
            request.authority(),
            &node.head_key,
            &genesis,
        )
        .expect("test publishes a schema-valid but closure-unbound genesis head");

        assert!(matches!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request)),
            Err(AdmissionMaterializationRefusal::NonEmptyGenesisWithoutClosure)
        ));
        assert_eq!(
            CanonicalAdmissionStore::resolve_permitted_object_closure(
                &node.admission_materializer,
                canonical_ref_state_root(&CanonicalRefState::default())
                    .expect("empty ref root computes"),
            ),
            Err(RefusalCode::EvidenceMissing),
            "the unbound staged closure never becomes a local fallback"
        );
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
    fn durable_decision_evidence_stages_reads_and_rejects_forged_or_cancelled_lookup() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let (node, _) = OneNode::init(config).expect("node initializes canonical refs");
        let authority_request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&authority_request))
            .expect("the initialized head materializes");
        let (context, request, fold) = evidence_request(&node);
        let is_live = || false;

        let staged = node
            .runtime()
            .block_on(node.admission_materializer.stage_decision_evidence_in(
                &node.authority,
                authority_request.authority(),
                context.clone(),
                materialized.basis(),
                &request,
                &fold,
                &is_live,
            ))
            .expect("all committing evidence bodies stage before provider construction");
        let evidence = staged.commit_evidence_record();
        assert_eq!(
            staged
                .commit_evidence(materialized.basis(), &request, &fold)
                .expect("staged provider is bound to its exact inputs"),
            evidence
        );

        let loaded = node
            .runtime()
            .block_on(node.admission_materializer.read_decision_evidence_in(
                &node.authority,
                authority_request.authority(),
                context.clone(),
                materialized.basis(),
                &request,
                &fold,
                evidence,
                &is_live,
            ))
            .expect("the durable frames re-read through the async authority contract");
        assert_eq!(
            loaded
                .commit_evidence(materialized.basis(), &request, &fold)
                .expect("decoded provider preserves the exact binding"),
            evidence
        );

        let forged = CommitEvidence {
            policy_decision_root: evidence.forge_event_batch_root,
            ..evidence
        };
        assert!(matches!(
            node.runtime()
                .block_on(node.admission_materializer.read_decision_evidence_in(
                    &node.authority,
                    authority_request.authority(),
                    context.clone(),
                    materialized.basis(),
                    &request,
                    &fold,
                    forged,
                    &is_live,
                )),
            Err(AdmissionMaterializationRefusal::ImmutableAbsent(root))
                if root == forged.policy_decision_root
        ));

        let cancelled = || true;
        assert!(matches!(
            node.runtime()
                .block_on(node.admission_materializer.stage_decision_evidence_in(
                    &node.authority,
                    authority_request.authority(),
                    context.clone(),
                    materialized.basis(),
                    &request,
                    &fold,
                    &cancelled,
                )),
            Err(AdmissionMaterializationRefusal::Cancelled)
        ));
        assert!(matches!(
            node.runtime()
                .block_on(node.admission_materializer.stage_refusal_evidence_in(
                    &node.authority,
                    authority_request.authority(),
                    &context,
                    materialized.basis(),
                    distinct_tx_id(),
                    RefusalCode::ExpectedOldRefMismatch,
                    &cancelled,
                )),
            Err(AdmissionMaterializationRefusal::Cancelled)
        ));

        let mut cross_principal = request;
        cross_principal.principal = PrincipalId::from_bytes([0x55; 16]);
        assert!(matches!(
            node.runtime()
                .block_on(node.admission_materializer.stage_decision_evidence_in(
                    &node.authority,
                    authority_request.authority(),
                    context,
                    materialized.basis(),
                    &cross_principal,
                    &fold,
                    &is_live,
                )),
            Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::EvidenceInvalid
            ))
        ));
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
        let is_cancelled = || false;

        require_send(node.admission_materializer.stage_ref_state_in(
            &node.authority,
            request.authority(),
            node.repository_id(),
            CanonicalRefState::default(),
        ));
        require_send(
            node.admission_materializer
                .stage_permitted_object_closure_in(
                    &node.authority,
                    request.authority(),
                    node.repository_id(),
                    PermittedObjectClosure::default(),
                ),
        );
        require_send(node.admission_materializer.materialize_current_in(
            &node.authority,
            request.authority(),
            &node.head_key,
            node.repository_id(),
            &is_cancelled,
        ));
        require_send(node.read_authority_head_in(&request));
        require_send(node.read_authority_head());
        require_send(node.authenticate_authority_head_in(&request));
        require_send(node.authenticate_authority_head());
        require_send(node.materialize_admission_in(&request));
        require_send(node.materialize_admission());
        require_send(node.admission_upload_pack_repository_in(
            &request,
            node.admission_projection(),
            &limits,
        ));
        require_send(node.authority_selected_pack_payload_in(&request));
        require_send(node.authority_selected_pack_payload());
        require_send(node.durable_admission_upload_pack_repository_in(&request, &limits));
        require_send(node.resolve_outcome_in(&request, distinct_tx_id()));
        require_send(node.resolve_outcome(distinct_tx_id()));
        require_send(node.doctor_in(&request, None));
        require_send(node.doctor(None));
        node.shutdown().expect("node closes cleanly");
    }

    #[test]
    fn durable_admission_materializer_refuses_a_head_without_its_ref_frame() {
        let scratch = ScratchDirectory::new();
        let config = test_config(scratch.path().to_path_buf());
        let node = OneNode::open_components(config).expect("components open");
        let missing_root = genesis_root(node.repository_id(), b"unstaged-canonical-refs");
        let head = genesis_head(
            node.repository_id(),
            missing_root,
            genesis_root(node.repository_id(), b"test-configuration"),
        )
        .expect("schema-valid test genesis derives the empty outcome root");
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
    fn doctor_reports_a_seeded_immutable_object_corruption() {
        let scratch = ScratchDirectory::new();
        let (node, _) =
            OneNode::init(test_config(scratch.path().to_path_buf())).expect("node opens");
        let stored = node
            .put_git_object(
                fgit_git_object::ObjectType::Blob,
                b"doctor corruption sample".to_vec(),
            )
            .expect("sample stores");

        let namespace_directory = only_directory_entry(&scratch.path().join("objects"));
        let algorithm_directory = only_directory_entry(&namespace_directory);
        let object_path = only_directory_entry(&algorithm_directory);
        let mut bytes = fs::read(&object_path).expect("stored immutable body reads for fault seed");
        let last = bytes
            .last_mut()
            .expect("stored immutable body includes the sample payload");
        *last ^= 0x01;
        fs::write(&object_path, bytes).expect("fault seed flips one immutable payload byte");

        let request = node.request_context();
        let report = node
            .runtime()
            .block_on(node.doctor_in(&request, Some(stored.identity())));
        assert!(matches!(
            report,
            Err(NodeRefusal::Fabric(error)) if *error == StoreRefusal::PayloadCommitmentMismatch
        ));
        node.shutdown()
            .expect("node drains and shuts down after a corruption finding");
    }

    fn only_directory_entry(directory: &Path) -> PathBuf {
        let mut entries = fs::read_dir(directory)
            .expect("fault drill directory opens")
            .map(|entry| entry.expect("fault drill directory entry reads"));
        let entry = entries.next().expect("fault drill has one expected entry");
        assert!(
            entries.next().is_none(),
            "fault drill isolates one node-owned immutable body"
        );
        entry.path()
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

        let other_scratch = ScratchDirectory::new();
        let mut other_config = test_config(other_scratch.path().to_path_buf());
        // A genuinely different repository: identical deterministic ids would
        // make both nodes the same repository and defeat the refusal under test.
        other_config.tenant_id = TenantId::from_bytes([0x33; 16]);
        other_config.repository_id = RepositoryId::from_bytes([0x44; 16]);
        let (other_node, _) = OneNode::init(other_config)
            .expect("second node opens with its own repository identity");
        let other_request = other_node.request_context();
        let HeadRead::Present(other_read) = other_node
            .runtime()
            .block_on(other_node.read_authority_head_in(&other_request))
            .expect("second node genesis head reads")
        else {
            panic!("second node initialization creates its authority head");
        };
        let other_body: RepositoryAuthorityHeadBody =
            decode_body(other_read.body(), fgit_codec::DecodeLimits::DEFAULT)
                .expect("second node fixture head decodes");
        let other_basis = PublicationBasis::new(
            authority_head_id(&other_body).expect("second node head re-identifies"),
            other_body,
        );
        let roots = ResultingRoots::carried_forward(&other_basis);
        let mut plan = PublicationPlan::open(other_basis).expect("second node genesis opens");
        plan.refuse(
            distinct_tx_id(),
            RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id(),
        );
        let outcomes = other_node
            .runtime()
            .block_on(collect_cumulative_outcomes_async(
                &other_node.authority,
                other_request.authority(),
                &other_node.head_key,
            ))
            .expect("second node outcomes collect from its authority");
        let publication = plan
            .seal(&CryptoBodyIdentity, roots, &outcomes, other_read.token())
            .expect("refusal-only publication seals for the second repository");

        let refusal = node.runtime().block_on(node.publish_decisions_in(
            &node.request_context(),
            before_receipt.token(),
            &publication,
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
#[cfg(test)]
mod drain_politeness_tests {
    use super::*;

    /// A reader that yields fixed chunks and records how many reads happened,
    /// so a drain can be pinned to the exact read it must stop on.
    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        next: usize,
        reads: usize,
    }

    impl ChunkedReader {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                next: 0,
                reads: 0,
            }
        }
    }

    impl std::io::Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let Some(chunk) = self.chunks.get(self.next) else {
                return Ok(0);
            };
            self.next += 1;
            let taken = chunk.len().min(buf.len());
            buf[..taken].copy_from_slice(&chunk[..taken]);
            Ok(taken)
        }
    }

    #[test]
    fn drain_consumes_a_want_less_request_through_its_flush() {
        // The request flush completes in the SECOND chunk; a correct drain
        // stops there and never asks for a third.
        let mut client = ChunkedReader::new(&[b"000ePACK-request\n", b"0000"]);
        drain_client_request(&mut client, &WireLimits::default());
        assert_eq!(
            client.reads, 2,
            "the drain must stop reading once the request flush arrives"
        );
    }

    #[test]
    fn drain_returns_at_stream_end_without_a_flush() {
        let mut client = ChunkedReader::new(&[b"0009half-framed"]);
        drain_client_request(&mut client, &WireLimits::default());
        assert_eq!(client.reads, 1, "a truncated request ends the drain at EOF");
    }

    #[test]
    fn drain_stops_at_a_framing_refusal_without_hanging() {
        let mut client = ChunkedReader::new(&[b"zzzznot-a-packet-length"]);
        drain_client_request(&mut client, &WireLimits::default());
        assert_eq!(
            client.reads, 1,
            "a framing refusal ends the drain without another read"
        );
    }
}
