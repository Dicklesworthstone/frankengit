#![forbid(unsafe_code)]
//! Conservative ATP-Git inventory, planning, and quarantine reconstruction.
//!
//! This crate owns the first complete ATP-Git planning slice.  It authenticates
//! peer-capability records through a caller-supplied verifier, turns bounded
//! receiver inventories into deterministic whole-object plans, and verifies
//! the entire manifest closure before passing newly reconstructed objects to a
//! quarantine-only sink.  It deliberately does not select an adaptive block,
//! chunk, pack, or compaction profile: ADR-0004 requires measurement before
//! those numeric choices can become a durable policy.
//!
//! Probabilistic inventories are hints only.  Their false positives can omit
//! an object from an initial plan, but [`ReconstructionPipeline`] checks the
//! exact closure and returns an [`ExactRepairRequest`] before staging anything.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fgit_crypto::git_object_id;
use fgit_object_fabric::fabric::{StoreRefusal, VerifiedObject};
use fgit_object_fabric::{
    Commitment, CryptoDigest, DigestAlgorithm, DigestDomain, FabricError, ObjectEnvelope,
    ObjectKind, SegmentLimits,
};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, SegmentManifestId};

/// The only presently implemented ATP-Git profile.
///
/// It transfers complete verified objects.  Chunk, pack-view, coded, and
/// adaptive plans remain typed fallback cases until the ADR-0004 measurement
/// campaign admits an evidence-backed profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AtpGitProfile {
    /// Whole-object conservative interim profile from ADR-0004.
    ConservativeInterimV1,
}

impl AtpGitProfile {
    /// Stable profile label carried in capability records and plan receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConservativeInterimV1 => "conservative-interim-v1",
        }
    }
}

impl fmt::Display for AtpGitProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A non-secret peer identity fingerprint bound by the capability verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerIdentity([u8; 32]);

impl PeerIdentity {
    /// Builds a peer identity from the verifier's canonical fingerprint.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A peer capability record before authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilities {
    peer: PeerIdentity,
    repository: RepositoryId,
    profiles: BTreeSet<AtpGitProfile>,
    supports_exact_closure_verification: bool,
}

impl PeerCapabilities {
    /// Builds one peer's declared ATP-Git capabilities.
    #[must_use]
    pub fn new(
        peer: PeerIdentity,
        repository: RepositoryId,
        profiles: impl IntoIterator<Item = AtpGitProfile>,
        supports_exact_closure_verification: bool,
    ) -> Self {
        Self {
            peer,
            repository,
            profiles: profiles.into_iter().collect(),
            supports_exact_closure_verification,
        }
    }

    /// Identity the verifier authenticated.
    #[must_use]
    pub const fn peer(&self) -> PeerIdentity {
        self.peer
    }

    /// Repository namespace the record applies to.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// Declared ATP-Git profiles in canonical order.
    pub fn profiles(&self) -> impl Iterator<Item = AtpGitProfile> + '_ {
        self.profiles.iter().copied()
    }

    /// Whether this peer can perform the mandatory exact final closure check.
    #[must_use]
    pub const fn supports_exact_closure_verification(&self) -> bool {
        self.supports_exact_closure_verification
    }

    fn supports(&self, profile: AtpGitProfile) -> bool {
        self.profiles.contains(&profile)
    }
}

/// Boundary that authenticates a peer capability record.
///
/// Production deployments bind this to their mutually authenticated transport
/// or capability system.  ATP-Git cannot treat a deserialized record as an
/// authorization fact merely because it has well-formed fields.
pub trait PeerCapabilityVerifier {
    /// Verifies the complete record, including its peer and repository scope.
    fn verify(&self, offered: &PeerCapabilities) -> Result<(), AtpRefusal>;
}

/// Capability record accepted by a [`PeerCapabilityVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeerCapabilities(PeerCapabilities);

impl AuthenticatedPeerCapabilities {
    /// Authenticates a complete capability record before it can influence a plan.
    pub fn verify<V: PeerCapabilityVerifier>(
        offered: PeerCapabilities,
        verifier: &V,
    ) -> Result<Self, AtpRefusal> {
        verifier.verify(&offered)?;
        Ok(Self(offered))
    }

    /// Returns the authenticated record.
    #[must_use]
    pub const fn record(&self) -> &PeerCapabilities {
        &self.0
    }
}

/// Bound applied before ATP-Git accepts an untrusted inventory or payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    objects: u32,
    payload_bytes: u64,
    reconstruction_bytes: u64,
    probabilistic_summary_bytes: usize,
}

impl TransferLimits {
    /// Creates explicit caller-owned bounds for one ATP-Git request.
    pub const fn new(
        max_objects: u32,
        max_payload_bytes: u64,
        max_total_reconstruction_bytes: u64,
        max_probabilistic_summary_bytes: usize,
    ) -> Result<Self, AtpRefusal> {
        if max_objects == 0
            || max_payload_bytes == 0
            || max_total_reconstruction_bytes == 0
            || max_probabilistic_summary_bytes == 0
        {
            return Err(AtpRefusal::InvalidLimits);
        }
        Ok(Self {
            objects: max_objects,
            payload_bytes: max_payload_bytes,
            reconstruction_bytes: max_total_reconstruction_bytes,
            probabilistic_summary_bytes: max_probabilistic_summary_bytes,
        })
    }

    /// Maximum objects in one manifest closure.
    #[must_use]
    pub const fn max_objects(&self) -> u32 {
        self.objects
    }

    /// Maximum bytes in one transferred payload.
    #[must_use]
    pub const fn max_payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Maximum cumulative bytes copied into verified reconstruction objects.
    #[must_use]
    pub const fn max_total_reconstruction_bytes(&self) -> u64 {
        self.reconstruction_bytes
    }

    /// Maximum wire bytes in a probabilistic inventory summary.
    #[must_use]
    pub const fn max_probabilistic_summary_bytes(&self) -> usize {
        self.probabilistic_summary_bytes
    }
}

/// A logical Git object named by an immutable ATP-Git manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferObjectEntry {
    identity: GitOid,
    object_kind: ObjectKind,
    logical_size: u64,
    payload_identity: Commitment,
    payload_commitment: Commitment,
    segment: Option<SegmentManifestId>,
}

impl TransferObjectEntry {
    /// Describes a complete canonical Git object after checking its identities.
    ///
    /// The payload is used only to derive and verify this immutable descriptor;
    /// it is not retained by the manifest.
    pub fn from_payload(
        identity: GitOid,
        object_kind: ObjectKind,
        payload: &[u8],
        segment: Option<SegmentManifestId>,
    ) -> Result<Self, AtpRefusal> {
        let expected = git_object_id(identity.algorithm(), crypto_kind(object_kind)?, payload);
        if expected != identity {
            return Err(AtpRefusal::NativeObjectIdentityMismatch { identity });
        }
        let logical_size = u64::try_from(payload.len()).map_err(|_| AtpRefusal::LengthOverflow)?;
        let payload_identity = content_identity(payload)?;
        let payload_commitment = payload_commitment(object_kind, payload)?;
        Ok(Self {
            identity,
            object_kind,
            logical_size,
            payload_identity,
            payload_commitment,
            segment,
        })
    }

    /// Native Git object identity.
    #[must_use]
    pub const fn identity(&self) -> GitOid {
        self.identity
    }

    /// Canonical Git object kind.
    #[must_use]
    pub const fn object_kind(&self) -> ObjectKind {
        self.object_kind
    }

    /// Exact logical Git payload length.
    #[must_use]
    pub const fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Content-only identity used for unique-payload planning.
    #[must_use]
    pub const fn payload_identity(&self) -> Commitment {
        self.payload_identity
    }

    /// Type- and length-bound strong native Git payload commitment.
    #[must_use]
    pub const fn payload_commitment(&self) -> Commitment {
        self.payload_commitment
    }

    /// Optional immutable segment that exactly contains this object.
    #[must_use]
    pub const fn segment(&self) -> Option<SegmentManifestId> {
        self.segment
    }
}

/// Immutable logical closure requested by one ATP-Git transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifest {
    repository: RepositoryId,
    object_format: GitHashAlgorithm,
    requested_roots: Vec<GitOid>,
    objects: Vec<TransferObjectEntry>,
}

impl TransferManifest {
    /// Creates a canonical manifest over a caller-supplied, already computed closure.
    pub fn new(
        repository: RepositoryId,
        object_format: GitHashAlgorithm,
        requested_roots: Vec<GitOid>,
        objects: Vec<TransferObjectEntry>,
        limits: TransferLimits,
    ) -> Result<Self, AtpRefusal> {
        if u32::try_from(objects.len()).map_err(|_| AtpRefusal::TooManyObjects)? > limits.objects {
            return Err(AtpRefusal::TooManyObjects);
        }
        ensure_strictly_sorted(
            &requested_roots,
            AtpRefusal::NonCanonicalRootOrder,
            AtpRefusal::DuplicateRequestedRoot,
        )?;
        let mut prior: Option<GitOid> = None;
        let mut payload_sizes = BTreeMap::new();
        let mut total_logical_bytes = 0_u64;
        for entry in &objects {
            if entry.identity.algorithm() != object_format {
                return Err(AtpRefusal::ObjectFormatMismatch {
                    identity: entry.identity,
                    expected: object_format,
                });
            }
            if entry.logical_size > limits.payload_bytes {
                return Err(AtpRefusal::PayloadTooLarge {
                    offered: entry.logical_size,
                    maximum: limits.payload_bytes,
                });
            }
            total_logical_bytes = total_logical_bytes
                .checked_add(entry.logical_size)
                .ok_or(AtpRefusal::LengthOverflow)?;
            if total_logical_bytes > limits.reconstruction_bytes {
                return Err(AtpRefusal::ReconstructionBudgetExceeded {
                    offered: total_logical_bytes,
                    maximum: limits.reconstruction_bytes,
                });
            }
            if let Some(previous) = prior {
                match previous.cmp(&entry.identity) {
                    std::cmp::Ordering::Greater => return Err(AtpRefusal::NonCanonicalObjectOrder),
                    std::cmp::Ordering::Equal => return Err(AtpRefusal::DuplicateObjectIdentity),
                    std::cmp::Ordering::Less => {}
                }
            }
            prior = Some(entry.identity);
            if payload_sizes
                .insert(entry.payload_identity, entry.logical_size)
                .is_some_and(|previous_size| previous_size != entry.logical_size)
            {
                return Err(AtpRefusal::PayloadIdentitySizeMismatch);
            }
        }
        for root in &requested_roots {
            if root.algorithm() != object_format {
                return Err(AtpRefusal::ObjectFormatMismatch {
                    identity: *root,
                    expected: object_format,
                });
            }
            if objects
                .binary_search_by_key(root, TransferObjectEntry::identity)
                .is_err()
            {
                return Err(AtpRefusal::RequestedRootAbsent { identity: *root });
            }
        }
        Ok(Self {
            repository,
            object_format,
            requested_roots,
            objects,
        })
    }

    /// Repository namespace this closure belongs to.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// Declared native Git object format.
    #[must_use]
    pub const fn object_format(&self) -> GitHashAlgorithm {
        self.object_format
    }

    /// Requested roots in canonical identity order.
    #[must_use]
    pub fn requested_roots(&self) -> &[GitOid] {
        &self.requested_roots
    }

    /// Exact required object closure in canonical identity order.
    #[must_use]
    pub fn objects(&self) -> &[TransferObjectEntry] {
        &self.objects
    }
}

/// Bounded receiver inventory supplied during planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaveSummary {
    /// Exact verified object identities.
    ExactObjects(Vec<GitOid>),
    /// Exact verified immutable segment identities.
    ExactSegments(Vec<SegmentManifestId>),
    /// A bounded Bloom-style hint whose positive answer proves nothing.
    Probabilistic(BloomHaveSummary),
}

impl HaveSummary {
    /// Creates a canonical exact-object inventory.
    pub fn exact_objects(objects: Vec<GitOid>, limits: TransferLimits) -> Result<Self, AtpRefusal> {
        ensure_inventory_count(objects.len(), limits)?;
        ensure_strictly_sorted(
            &objects,
            AtpRefusal::NonCanonicalInventoryOrder,
            AtpRefusal::DuplicateInventoryIdentity,
        )?;
        Ok(Self::ExactObjects(objects))
    }

    /// Creates a canonical exact-segment inventory.
    pub fn exact_segments(
        segments: Vec<SegmentManifestId>,
        limits: TransferLimits,
    ) -> Result<Self, AtpRefusal> {
        ensure_inventory_count(segments.len(), limits)?;
        ensure_strictly_sorted(
            &segments,
            AtpRefusal::NonCanonicalInventoryOrder,
            AtpRefusal::DuplicateInventoryIdentity,
        )?;
        Ok(Self::ExactSegments(segments))
    }

    /// Classifies the summary form for a deterministic receipt.
    #[must_use]
    pub const fn kind(&self) -> InventoryKind {
        match self {
            Self::ExactObjects(_) => InventoryKind::ExactObjects,
            Self::ExactSegments(_) => InventoryKind::ExactSegments,
            Self::Probabilistic(_) => InventoryKind::Probabilistic,
        }
    }

    fn receipt(&self) -> InventoryReceipt {
        match self {
            Self::ExactObjects(objects) => InventoryReceipt::ExactObjects(objects.clone()),
            Self::ExactSegments(segments) => InventoryReceipt::ExactSegments(segments.clone()),
            Self::Probabilistic(summary) => InventoryReceipt::Probabilistic {
                bit_count: summary.bit_count(),
                bytes: summary.bytes().to_vec(),
            },
        }
    }
}

/// Summary form recorded in a plan receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryKind {
    /// Sorted exact object identities.
    ExactObjects,
    /// Sorted exact immutable segment identities.
    ExactSegments,
    /// Bounded false-positive-prone filter bytes.
    Probabilistic,
}

/// Canonical inventory input retained in a [`PlanReceipt`].
///
/// It is evidence of the exact selector input, not an assertion that a
/// probabilistic positive is a verified local object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryReceipt {
    /// Sorted exact object identities asserted by the receiver.
    ExactObjects(Vec<GitOid>),
    /// Sorted exact immutable segment identities asserted by the receiver.
    ExactSegments(Vec<SegmentManifestId>),
    /// Bounded filter parameters and bytes used only as a hint.
    Probabilistic {
        /// Number of filter bits.
        bit_count: u32,
        /// Canonical filter bytes.
        bytes: Vec<u8>,
    },
}

impl InventoryReceipt {
    /// Summary form whose exact input bytes or identities this receipt retains.
    #[must_use]
    pub const fn kind(&self) -> InventoryKind {
        match self {
            Self::ExactObjects(_) => InventoryKind::ExactObjects,
            Self::ExactSegments(_) => InventoryKind::ExactSegments,
            Self::Probabilistic { .. } => InventoryKind::Probabilistic,
        }
    }
}

/// Bounded Bloom-style receiver hint.
///
/// It intentionally exposes only a `may_contain` relation.  A positive bitset
/// answer must be rechecked against the exact final closure and therefore
/// cannot authorize omission from the completed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomHaveSummary {
    bit_count: u32,
    bytes: Vec<u8>,
}

impl BloomHaveSummary {
    /// Creates an empty summary with a byte-aligned number of bits.
    pub fn empty(bit_count: u32, limits: TransferLimits) -> Result<Self, AtpRefusal> {
        let byte_count = checked_summary_byte_count(bit_count, limits)?;
        Ok(Self {
            bit_count,
            bytes: vec![0; byte_count],
        })
    }

    /// Copies a received filter only after validating its wire bounds.
    pub fn from_wire(
        bit_count: u32,
        bytes: &[u8],
        limits: TransferLimits,
    ) -> Result<Self, AtpRefusal> {
        let byte_count = checked_summary_byte_count(bit_count, limits)?;
        if bytes.len() != byte_count {
            return Err(AtpRefusal::InvalidProbabilisticSummary);
        }
        Ok(Self {
            bit_count,
            bytes: bytes.to_vec(),
        })
    }

    /// Adds an exact object to a locally produced hint.
    ///
    /// This function exists for deterministic sender/receiver tests and for
    /// building an outbound hint.  A received summary must still be treated as
    /// untrusted efficiency data.
    pub fn insert(&mut self, identity: GitOid) -> Result<(), AtpRefusal> {
        for bit in bloom_bits(identity, self.bit_count) {
            let byte_index =
                usize::try_from(bit / 8).map_err(|_| AtpRefusal::InvalidProbabilisticSummary)?;
            let byte = self
                .bytes
                .get_mut(byte_index)
                .ok_or(AtpRefusal::InvalidProbabilisticSummary)?;
            *byte |= 1_u8 << (bit % 8);
        }
        Ok(())
    }

    /// Returns whether this hint may contain the identity.
    #[must_use]
    pub fn may_contain(&self, identity: GitOid) -> bool {
        bloom_bits(identity, self.bit_count).into_iter().all(|bit| {
            usize::try_from(bit / 8)
                .ok()
                .and_then(|byte_index| self.bytes.get(byte_index))
                .is_some_and(|byte| byte & (1_u8 << (bit % 8)) != 0)
        })
    }

    /// Encoded bit count.
    #[must_use]
    pub const fn bit_count(&self) -> u32 {
        self.bit_count
    }

    /// Canonical filter bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Why a full closure fallback was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullFallbackReason {
    /// Source or receiver lacks the only supported conservative profile.
    ConservativeProfileNotMutual,
    /// The receiver cannot perform the mandatory exact final closure check.
    ExactClosureVerificationUnavailable,
    /// Authenticated capabilities do not apply to the manifest repository.
    RepositoryScopeMismatch,
    /// A probabilistic summary exceeded its request bound.
    ProbabilisticSummaryTooLarge,
}

/// Deterministic plan class selected from one manifest and have summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPlanKind {
    /// Exact receiver knowledge covers the full required closure.
    AlreadyInSync,
    /// Complete object payloads are required for a subset of the closure.
    ObjectDelta,
    /// Several object placements share one content payload.
    UniqueContentDelta,
    /// ATP acceleration is unsuitable; transfer the full logical closure.
    FullClosureFallback(FullFallbackReason),
}

/// One unique payload and every logical object reconstructed from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPayload {
    payload_identity: Commitment,
    object_identities: Vec<GitOid>,
}

impl PlannedPayload {
    /// Content identity requested exactly once.
    #[must_use]
    pub const fn payload_identity(&self) -> Commitment {
        self.payload_identity
    }

    /// Logical placements reconstructed from the payload in canonical order.
    #[must_use]
    pub fn object_identities(&self) -> &[GitOid] {
        &self.object_identities
    }
}

/// Immutable receipt for a deterministic ATP-Git planning decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanReceipt {
    source_peer: PeerIdentity,
    receiver_peer: PeerIdentity,
    repository: RepositoryId,
    profile: AtpGitProfile,
    inventory: InventoryReceipt,
    plan_kind: TransferPlanKind,
    requires_exact_closure_repair: bool,
    required_closure: Vec<GitOid>,
}

impl PlanReceipt {
    /// Source peer chosen for the plan.
    #[must_use]
    pub const fn source_peer(&self) -> PeerIdentity {
        self.source_peer
    }

    /// Receiver peer whose inventory was used.
    #[must_use]
    pub const fn receiver_peer(&self) -> PeerIdentity {
        self.receiver_peer
    }

    /// Manifest repository scope.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// Selected ATP-Git profile.
    #[must_use]
    pub const fn profile(&self) -> AtpGitProfile {
        self.profile
    }

    /// Summary form whose semantics were used.
    #[must_use]
    pub const fn inventory_kind(&self) -> InventoryKind {
        self.inventory.kind()
    }

    /// Exact inventory input retained for plan replay and evidence review.
    #[must_use]
    pub const fn inventory(&self) -> &InventoryReceipt {
        &self.inventory
    }

    /// Selected plan class and, for fallback, its typed reason.
    #[must_use]
    pub const fn plan_kind(&self) -> TransferPlanKind {
        self.plan_kind
    }

    /// Whether final closure validation may emit an exact repair request.
    #[must_use]
    pub const fn requires_exact_closure_repair(&self) -> bool {
        self.requires_exact_closure_repair
    }

    /// Exact required closure bound into the receipt.
    #[must_use]
    pub fn required_closure(&self) -> &[GitOid] {
        &self.required_closure
    }
}

/// Executable deterministic object-transfer plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    payloads: Vec<PlannedPayload>,
    receipt: PlanReceipt,
}

impl TransferPlan {
    /// Unique payload requests in canonical content-identity order.
    #[must_use]
    pub fn payloads(&self) -> &[PlannedPayload] {
        &self.payloads
    }

    /// Immutable selection receipt.
    #[must_use]
    pub const fn receipt(&self) -> &PlanReceipt {
        &self.receipt
    }
}

/// Selects the conservative ATP-Git plan.
#[derive(Debug, Clone, Copy)]
pub struct PlanSelector {
    limits: TransferLimits,
}

impl PlanSelector {
    /// Builds a selector using explicit request bounds.
    #[must_use]
    pub const fn new(limits: TransferLimits) -> Self {
        Self { limits }
    }

    /// Selects a deterministic plan and records every input that influences it.
    #[must_use]
    pub fn select(
        &self,
        manifest: &TransferManifest,
        source: &AuthenticatedPeerCapabilities,
        receiver: &AuthenticatedPeerCapabilities,
        have: &HaveSummary,
    ) -> TransferPlan {
        let profile = AtpGitProfile::ConservativeInterimV1;
        let fallback = self.fallback_reason(manifest, source, receiver, have, profile);
        let (selected, requires_exact_closure_repair) = if fallback.is_some() {
            (manifest.objects.iter().collect::<Vec<_>>(), false)
        } else {
            select_delta(manifest.objects(), have)
        };
        let payloads = group_payloads(&selected);
        let plan_kind = fallback.map_or_else(
            || {
                if selected.is_empty() && !requires_exact_closure_repair {
                    TransferPlanKind::AlreadyInSync
                } else if payloads
                    .iter()
                    .any(|payload| payload.object_identities.len() > 1)
                {
                    TransferPlanKind::UniqueContentDelta
                } else {
                    TransferPlanKind::ObjectDelta
                }
            },
            TransferPlanKind::FullClosureFallback,
        );
        TransferPlan {
            payloads,
            receipt: PlanReceipt {
                source_peer: source.record().peer(),
                receiver_peer: receiver.record().peer(),
                repository: manifest.repository(),
                profile,
                inventory: have.receipt(),
                plan_kind,
                requires_exact_closure_repair,
                required_closure: manifest
                    .objects
                    .iter()
                    .map(TransferObjectEntry::identity)
                    .collect(),
            },
        }
    }

    fn fallback_reason(
        &self,
        manifest: &TransferManifest,
        source: &AuthenticatedPeerCapabilities,
        receiver: &AuthenticatedPeerCapabilities,
        have: &HaveSummary,
        profile: AtpGitProfile,
    ) -> Option<FullFallbackReason> {
        if source.record().repository() != manifest.repository()
            || receiver.record().repository() != manifest.repository()
        {
            return Some(FullFallbackReason::RepositoryScopeMismatch);
        }
        if !source.record().supports(profile) || !receiver.record().supports(profile) {
            return Some(FullFallbackReason::ConservativeProfileNotMutual);
        }
        if !receiver.record().supports_exact_closure_verification() {
            return Some(FullFallbackReason::ExactClosureVerificationUnavailable);
        }
        match have {
            HaveSummary::Probabilistic(summary)
                if summary.bytes().len() > self.limits.max_probabilistic_summary_bytes() =>
            {
                Some(FullFallbackReason::ProbabilisticSummaryTooLarge)
            }
            _ => None,
        }
    }
}

/// One payload supplied to the deterministic reconstruction pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPayload {
    identity: Commitment,
    bytes: Vec<u8>,
}

impl TransferPayload {
    /// Binds payload bytes to their content-only identity.
    pub fn new(bytes: Vec<u8>) -> Result<Self, AtpRefusal> {
        let identity = content_identity(&bytes)?;
        Ok(Self { identity, bytes })
    }

    /// Content identity carried by this payload.
    #[must_use]
    pub const fn identity(&self) -> Commitment {
        self.identity
    }

    /// Canonical logical payload bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Receiver lookup used only for exact final closure validation.
///
/// An implementation returns an object only after its own immutable-storage
/// verification.  A have-summary is never accepted as a substitute for this
/// check.
pub trait VerifiedObjectLookup {
    /// Returns a verified local object, or `None` when the object is absent.
    fn read_verified(&self, identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal>;
}

/// Sink whose contract exposes staging but no canonical visibility operation.
///
/// Authority publication remains outside ATP-Git.  The caller may promote
/// staged objects only through its repository authority protocol after this
/// pipeline has returned a complete verified closure.
pub trait QuarantineSink {
    /// Stages one fully verified object after the entire closure has verified.
    fn stage_verified(&mut self, object: VerifiedObject) -> Result<(), AtpRefusal>;
}

/// Exact repair request produced after a probabilistic or stale inventory hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactRepairRequest {
    missing: Vec<GitOid>,
}

impl ExactRepairRequest {
    /// Missing exact object identities in canonical order.
    #[must_use]
    pub fn missing(&self) -> &[GitOid] {
        &self.missing
    }
}

/// Receipt emitted after every object in the manifest closure is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructionReceipt {
    profile: AtpGitProfile,
    staged: Vec<GitOid>,
    reused_verified: Vec<GitOid>,
    closure: Vec<GitOid>,
}

impl ReconstructionReceipt {
    /// Conservative profile used to reconstruct the closure.
    #[must_use]
    pub const fn profile(&self) -> AtpGitProfile {
        self.profile
    }

    /// Newly reconstructed objects staged into quarantine in canonical order.
    #[must_use]
    pub fn staged(&self) -> &[GitOid] {
        &self.staged
    }

    /// Already-present objects independently revalidated in canonical order.
    #[must_use]
    pub fn reused_verified(&self) -> &[GitOid] {
        &self.reused_verified
    }

    /// Complete exact closure verified before the first staging call.
    #[must_use]
    pub fn closure(&self) -> &[GitOid] {
        &self.closure
    }
}

/// Outcome of one closure reconstruction attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructionOutcome {
    /// All required objects verified and newly reconstructed objects staged.
    Complete(ReconstructionReceipt),
    /// Exact closure validation found omissions; caller must request these identities.
    Repair(ExactRepairRequest),
}

/// Whole-object conservative reconstruction pipeline.
#[derive(Debug, Clone)]
pub struct ReconstructionPipeline {
    namespace: Vec<u8>,
    segment_limits: SegmentLimits,
    limits: TransferLimits,
}

impl ReconstructionPipeline {
    /// Creates a pipeline with explicit namespace, envelope, and request bounds.
    pub fn new(
        namespace: Vec<u8>,
        segment_limits: SegmentLimits,
        limits: TransferLimits,
    ) -> Result<Self, AtpRefusal> {
        if namespace.is_empty() {
            return Err(AtpRefusal::EmptyNamespace);
        }
        if namespace.len() > segment_limits.max_namespace_bytes {
            return Err(AtpRefusal::NamespaceTooLarge);
        }
        Ok(Self {
            namespace,
            segment_limits,
            limits,
        })
    }

    /// Verifies an exact closure and stages only a complete reconstruction.
    ///
    /// Supplied payloads are independently checked before the pipeline uses
    /// them.  The method accumulates verified objects in a request-local
    /// `BTreeMap`, validates every manifest entry or exact local object, and
    /// only then invokes [`QuarantineSink::stage_verified`] in OID order.
    pub fn reconstruct<L: VerifiedObjectLookup, Q: QuarantineSink>(
        &self,
        manifest: &TransferManifest,
        plan: &TransferPlan,
        payloads: impl IntoIterator<Item = TransferPayload>,
        lookup: &L,
        quarantine: &mut Q,
    ) -> Result<ReconstructionOutcome, AtpRefusal> {
        if plan.receipt.repository() != manifest.repository()
            || plan.receipt.required_closure()
                != manifest
                    .objects()
                    .iter()
                    .map(TransferObjectEntry::identity)
                    .collect::<Vec<_>>()
        {
            return Err(AtpRefusal::PlanManifestMismatch);
        }
        let payloads = self.collect_payloads(manifest, payloads)?;
        let mut staged = BTreeMap::new();
        let mut reused_verified = Vec::new();
        let mut missing = Vec::new();
        let mut staged_bytes = 0_u64;

        for entry in manifest.objects() {
            if let Some(payload) = payloads.get(&entry.payload_identity()) {
                let object = self.verify_payload(entry, payload)?;
                staged_bytes = staged_bytes
                    .checked_add(entry.logical_size())
                    .ok_or(AtpRefusal::LengthOverflow)?;
                if staged_bytes > self.limits.max_total_reconstruction_bytes() {
                    return Err(AtpRefusal::ReconstructionBudgetExceeded {
                        offered: staged_bytes,
                        maximum: self.limits.max_total_reconstruction_bytes(),
                    });
                }
                staged.insert(entry.identity(), object);
            } else if let Some(existing) = lookup.read_verified(entry.identity())? {
                verify_existing(entry, &existing)?;
                reused_verified.push(entry.identity());
            } else {
                missing.push(entry.identity());
            }
        }
        if !missing.is_empty() {
            return Ok(ReconstructionOutcome::Repair(ExactRepairRequest {
                missing,
            }));
        }

        let mut staged_identities = Vec::with_capacity(staged.len());
        for (identity, object) in staged {
            quarantine.stage_verified(object)?;
            staged_identities.push(identity);
        }
        Ok(ReconstructionOutcome::Complete(ReconstructionReceipt {
            profile: plan.receipt.profile(),
            staged: staged_identities,
            reused_verified,
            closure: manifest
                .objects()
                .iter()
                .map(TransferObjectEntry::identity)
                .collect(),
        }))
    }

    fn collect_payloads(
        &self,
        manifest: &TransferManifest,
        payloads: impl IntoIterator<Item = TransferPayload>,
    ) -> Result<BTreeMap<Commitment, Vec<u8>>, AtpRefusal> {
        let expected = manifest
            .objects()
            .iter()
            .map(TransferObjectEntry::payload_identity)
            .collect::<BTreeSet<_>>();
        let mut by_identity = BTreeMap::new();
        let mut total = 0_u64;
        for payload in payloads {
            let offered =
                u64::try_from(payload.bytes.len()).map_err(|_| AtpRefusal::LengthOverflow)?;
            if offered > self.limits.max_payload_bytes() {
                return Err(AtpRefusal::PayloadTooLarge {
                    offered,
                    maximum: self.limits.max_payload_bytes(),
                });
            }
            total = total
                .checked_add(offered)
                .ok_or(AtpRefusal::LengthOverflow)?;
            if total > self.limits.max_total_reconstruction_bytes() {
                return Err(AtpRefusal::ReconstructionBudgetExceeded {
                    offered: total,
                    maximum: self.limits.max_total_reconstruction_bytes(),
                });
            }
            if content_identity(&payload.bytes)? != payload.identity {
                return Err(AtpRefusal::PayloadIdentityMismatch);
            }
            if !expected.contains(&payload.identity) {
                return Err(AtpRefusal::UnrequestedPayload);
            }
            if by_identity
                .insert(payload.identity, payload.bytes)
                .is_some()
            {
                return Err(AtpRefusal::DuplicatePayload);
            }
        }
        Ok(by_identity)
    }

    fn verify_payload(
        &self,
        entry: &TransferObjectEntry,
        payload: &[u8],
    ) -> Result<VerifiedObject, AtpRefusal> {
        let offered = u64::try_from(payload.len()).map_err(|_| AtpRefusal::LengthOverflow)?;
        if offered != entry.logical_size() {
            return Err(AtpRefusal::PayloadLengthMismatch {
                identity: entry.identity(),
            });
        }
        if content_identity(payload)? != entry.payload_identity() {
            return Err(AtpRefusal::PayloadIdentityMismatch);
        }
        if payload_commitment(entry.object_kind(), payload)? != entry.payload_commitment() {
            return Err(AtpRefusal::PayloadCommitmentMismatch {
                identity: entry.identity(),
            });
        }
        let envelope = ObjectEnvelope::new(
            self.namespace.clone(),
            entry.identity(),
            entry.object_kind(),
            entry.logical_size(),
            entry.payload_commitment(),
            b"atp-git/conservative-interim-v1".to_vec(),
            entry.payload_identity(),
            None,
            &self.segment_limits,
        )
        .map_err(AtpRefusal::Fabric)?;
        VerifiedObject::new(envelope, payload.to_vec()).map_err(AtpRefusal::Store)
    }
}

/// Typed refusal from conservative ATP-Git planning or reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpRefusal {
    /// A request bound must be positive.
    InvalidLimits,
    /// The quarantine namespace is empty.
    EmptyNamespace,
    /// The quarantine namespace exceeds its envelope bound.
    NamespaceTooLarge,
    /// Object count exceeds the request bound.
    TooManyObjects,
    /// Receiver inventory entries exceed the request bound.
    InventoryTooLarge {
        /// Offered inventory entry count.
        offered: u64,
        /// Configured maximum entry count.
        maximum: u64,
    },
    /// Arithmetic conversion or accumulation overflowed.
    LengthOverflow,
    /// Requested roots are not in canonical strict order.
    NonCanonicalRootOrder,
    /// Requested roots contain a duplicate identity.
    DuplicateRequestedRoot,
    /// Manifest objects are not in canonical strict identity order.
    NonCanonicalObjectOrder,
    /// Manifest objects contain a duplicate native identity.
    DuplicateObjectIdentity,
    /// A requested root was absent from the supplied closure.
    RequestedRootAbsent {
        /// Missing native object identity.
        identity: GitOid,
    },
    /// Internal object kinds do not have a native Git object identity.
    InternalObjectKindUnsupported,
    /// An object or root used a different native hash algorithm than the manifest.
    ObjectFormatMismatch {
        /// Observed object identity.
        identity: GitOid,
        /// Manifest's declared object format.
        expected: GitHashAlgorithm,
    },
    /// One unique-content identity appeared with incompatible declared lengths.
    PayloadIdentitySizeMismatch,
    /// An individual payload exceeds the request bound.
    PayloadTooLarge {
        /// Offered byte count.
        offered: u64,
        /// Configured maximum byte count.
        maximum: u64,
    },
    /// Exact inventory values are not strictly sorted.
    NonCanonicalInventoryOrder,
    /// Exact inventory includes a duplicate identity.
    DuplicateInventoryIdentity,
    /// A Bloom-style summary had no usable byte-aligned bitset.
    InvalidProbabilisticSummary,
    /// A Bloom-style summary exceeded its wire-byte bound before copying.
    ProbabilisticSummaryTooLarge {
        /// Offered summary bytes.
        offered: usize,
        /// Configured maximum summary bytes.
        maximum: usize,
    },
    /// The source record did not authenticate.
    PeerCapabilityRejected,
    /// A transfer payload did not correspond to an expected manifest content identity.
    UnrequestedPayload,
    /// More than one payload claimed one content identity.
    DuplicatePayload,
    /// A payload's bytes disagreed with its carried content identity.
    PayloadIdentityMismatch,
    /// Payload length disagreed with the manifest's object descriptor.
    PayloadLengthMismatch {
        /// Object whose payload length differed.
        identity: GitOid,
    },
    /// Strong payload commitment disagreed with the manifest.
    PayloadCommitmentMismatch {
        /// Object whose strong commitment differed.
        identity: GitOid,
    },
    /// Native Git identity disagreed with the supplied bytes.
    NativeObjectIdentityMismatch {
        /// Claimed native object identity.
        identity: GitOid,
    },
    /// The plan receipt was built for another manifest closure.
    PlanManifestMismatch,
    /// Request-local reconstruction buffering exceeded its hard bound.
    ReconstructionBudgetExceeded {
        /// Bytes that would be buffered.
        offered: u64,
        /// Configured maximum bytes.
        maximum: u64,
    },
    /// A verified local object did not match the requested manifest descriptor.
    ExistingObjectMismatch {
        /// Object identity whose local bytes were unsuitable.
        identity: GitOid,
    },
    /// Object-fabric envelope construction refused the candidate object.
    Fabric(FabricError),
    /// Object-fabric verification refused the candidate object.
    Store(StoreRefusal),
}

impl fmt::Display for AtpRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("ATP-Git request limits must be positive"),
            Self::EmptyNamespace => formatter.write_str("ATP-Git quarantine namespace is empty"),
            Self::NamespaceTooLarge => {
                formatter.write_str("ATP-Git quarantine namespace exceeds its bound")
            }
            Self::TooManyObjects => formatter.write_str("ATP-Git manifest has too many objects"),
            Self::InventoryTooLarge { offered, maximum } => write!(
                formatter,
                "ATP-Git inventory entries {offered} exceed bound {maximum}"
            ),
            Self::LengthOverflow => formatter.write_str("ATP-Git length arithmetic overflowed"),
            Self::NonCanonicalRootOrder => {
                formatter.write_str("ATP-Git requested roots are not canonically ordered")
            }
            Self::DuplicateRequestedRoot => {
                formatter.write_str("ATP-Git requested roots contain a duplicate")
            }
            Self::NonCanonicalObjectOrder => {
                formatter.write_str("ATP-Git manifest objects are not canonically ordered")
            }
            Self::DuplicateObjectIdentity => {
                formatter.write_str("ATP-Git manifest objects contain a duplicate identity")
            }
            Self::RequestedRootAbsent { identity } => {
                write!(formatter, "ATP-Git requested root is absent: {identity}")
            }
            Self::InternalObjectKindUnsupported => {
                formatter.write_str("ATP-Git cannot transfer an internal object as a Git object")
            }
            Self::ObjectFormatMismatch { identity, expected } => write!(
                formatter,
                "ATP-Git object {identity} does not use manifest format {expected}"
            ),
            Self::PayloadIdentitySizeMismatch => formatter
                .write_str("ATP-Git content identity has incompatible declared payload lengths"),
            Self::PayloadTooLarge { offered, maximum } => {
                write!(
                    formatter,
                    "ATP-Git payload {offered} exceeds bound {maximum}"
                )
            }
            Self::NonCanonicalInventoryOrder => {
                formatter.write_str("ATP-Git exact inventory is not canonically ordered")
            }
            Self::DuplicateInventoryIdentity => {
                formatter.write_str("ATP-Git exact inventory contains a duplicate identity")
            }
            Self::InvalidProbabilisticSummary => {
                formatter.write_str("ATP-Git probabilistic summary is not byte-aligned")
            }
            Self::ProbabilisticSummaryTooLarge { offered, maximum } => write!(
                formatter,
                "ATP-Git probabilistic summary bytes {offered} exceed bound {maximum}"
            ),
            Self::PeerCapabilityRejected => {
                formatter.write_str("ATP-Git peer capability record did not authenticate")
            }
            Self::UnrequestedPayload => {
                formatter.write_str("ATP-Git payload does not belong to this manifest")
            }
            Self::DuplicatePayload => {
                formatter.write_str("ATP-Git transfer contains duplicate payload identity")
            }
            Self::PayloadIdentityMismatch => {
                formatter.write_str("ATP-Git payload bytes disagree with content identity")
            }
            Self::PayloadLengthMismatch { identity } => {
                write!(formatter, "ATP-Git payload length disagrees for {identity}")
            }
            Self::PayloadCommitmentMismatch { identity } => {
                write!(
                    formatter,
                    "ATP-Git payload commitment disagrees for {identity}"
                )
            }
            Self::NativeObjectIdentityMismatch { identity } => {
                write!(
                    formatter,
                    "ATP-Git native object identity disagrees for {identity}"
                )
            }
            Self::PlanManifestMismatch => {
                formatter.write_str("ATP-Git plan receipt does not bind this manifest closure")
            }
            Self::ReconstructionBudgetExceeded { offered, maximum } => write!(
                formatter,
                "ATP-Git reconstruction bytes {offered} exceed bound {maximum}"
            ),
            Self::ExistingObjectMismatch { identity } => {
                write!(
                    formatter,
                    "ATP-Git local verified object disagrees for {identity}"
                )
            }
            Self::Fabric(error) => fmt::Display::fmt(error, formatter),
            Self::Store(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for AtpRefusal {}

fn select_delta<'a>(
    objects: &'a [TransferObjectEntry],
    have: &HaveSummary,
) -> (Vec<&'a TransferObjectEntry>, bool) {
    match have {
        HaveSummary::ExactObjects(known) => (
            objects
                .iter()
                .filter(|entry| known.binary_search(&entry.identity()).is_err())
                .collect(),
            false,
        ),
        HaveSummary::ExactSegments(known) => (
            objects
                .iter()
                .filter(|entry| {
                    entry
                        .segment()
                        .is_none_or(|segment| known.binary_search(&segment).is_err())
                })
                .collect(),
            false,
        ),
        HaveSummary::Probabilistic(summary) => (
            objects
                .iter()
                .filter(|entry| !summary.may_contain(entry.identity()))
                .collect(),
            true,
        ),
    }
}

fn group_payloads(entries: &[&TransferObjectEntry]) -> Vec<PlannedPayload> {
    entries
        .iter()
        .fold(
            BTreeMap::<Commitment, Vec<GitOid>>::new(),
            |mut groups, entry| {
                groups
                    .entry(entry.payload_identity())
                    .or_default()
                    .push(entry.identity());
                groups
            },
        )
        .into_iter()
        .map(|(payload_identity, object_identities)| PlannedPayload {
            payload_identity,
            object_identities,
        })
        .collect()
}

fn ensure_strictly_sorted<T: Ord + Copy>(
    values: &[T],
    ordering_error: AtpRefusal,
    duplicate_error: AtpRefusal,
) -> Result<(), AtpRefusal> {
    for pair in values.windows(2) {
        match pair[0].cmp(&pair[1]) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(duplicate_error),
            std::cmp::Ordering::Greater => return Err(ordering_error),
        }
    }
    Ok(())
}

fn ensure_inventory_count(count: usize, limits: TransferLimits) -> Result<(), AtpRefusal> {
    let offered = u64::try_from(count).map_err(|_| AtpRefusal::LengthOverflow)?;
    let maximum = u64::from(limits.max_objects());
    if offered > maximum {
        return Err(AtpRefusal::InventoryTooLarge { offered, maximum });
    }
    Ok(())
}

fn checked_summary_byte_count(bit_count: u32, limits: TransferLimits) -> Result<usize, AtpRefusal> {
    if bit_count == 0 || !bit_count.is_multiple_of(8) {
        return Err(AtpRefusal::InvalidProbabilisticSummary);
    }
    let byte_count = usize::try_from(bit_count / 8).map_err(|_| AtpRefusal::LengthOverflow)?;
    if byte_count > limits.max_probabilistic_summary_bytes() {
        return Err(AtpRefusal::ProbabilisticSummaryTooLarge {
            offered: byte_count,
            maximum: limits.max_probabilistic_summary_bytes(),
        });
    }
    Ok(byte_count)
}

fn bloom_bits(identity: GitOid, bit_count: u32) -> [u32; 3] {
    let mut first = 14_695_981_039_346_656_037_u64;
    let mut second = 1_099_511_628_211_u64;
    for byte in identity
        .algorithm()
        .code_point()
        .to_be_bytes()
        .into_iter()
        .chain(identity.as_bytes().iter().copied())
    {
        first ^= u64::from(byte);
        first = first.wrapping_mul(1_099_511_628_211);
        second ^= first.rotate_left(17) ^ u64::from(byte);
        second = second
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
    }
    [
        u32::try_from(first % u64::from(bit_count)).expect("modulo bit position fits u32"),
        u32::try_from(second % u64::from(bit_count)).expect("modulo bit position fits u32"),
        u32::try_from((first ^ second.rotate_left(29)) % u64::from(bit_count))
            .expect("modulo bit position fits u32"),
    ]
}

fn content_identity(payload: &[u8]) -> Result<Commitment, AtpRefusal> {
    CryptoDigest
        .digest(DigestDomain::LogicalObject, &[payload])
        .map_err(AtpRefusal::Fabric)
}

fn payload_commitment(object_kind: ObjectKind, payload: &[u8]) -> Result<Commitment, AtpRefusal> {
    CryptoDigest
        .payload_commitment(object_kind, payload)
        .map_err(AtpRefusal::Fabric)
}

const fn crypto_kind(object_kind: ObjectKind) -> Result<fgit_crypto::GitObjectKind, AtpRefusal> {
    match object_kind {
        ObjectKind::Commit => Ok(fgit_crypto::GitObjectKind::Commit),
        ObjectKind::Tree => Ok(fgit_crypto::GitObjectKind::Tree),
        ObjectKind::Blob => Ok(fgit_crypto::GitObjectKind::Blob),
        ObjectKind::Tag => Ok(fgit_crypto::GitObjectKind::Tag),
        ObjectKind::Internal => Err(AtpRefusal::InternalObjectKindUnsupported),
    }
}

fn verify_existing(entry: &TransferObjectEntry, object: &VerifiedObject) -> Result<(), AtpRefusal> {
    if object.identity() != entry.identity()
        || object.envelope().object_kind() != entry.object_kind()
        || object.envelope().declared_length() != entry.logical_size()
        || object.envelope().payload_commitment() != entry.payload_commitment()
        || content_identity(object.payload())? != entry.payload_identity()
    {
        return Err(AtpRefusal::ExistingObjectMismatch {
            identity: entry.identity(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fgit_types::RepositoryId;

    use super::*;

    fn limits() -> TransferLimits {
        TransferLimits::new(16, 1024, 4096, 64).expect("test limits are valid")
    }

    #[derive(Debug, Default)]
    struct AcceptingVerifier;

    impl PeerCapabilityVerifier for AcceptingVerifier {
        fn verify(&self, _offered: &PeerCapabilities) -> Result<(), AtpRefusal> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RejectingVerifier;

    impl PeerCapabilityVerifier for RejectingVerifier {
        fn verify(&self, _offered: &PeerCapabilities) -> Result<(), AtpRefusal> {
            Err(AtpRefusal::PeerCapabilityRejected)
        }
    }

    #[derive(Debug, Default)]
    struct TestLookup(BTreeMap<GitOid, VerifiedObject>);

    impl VerifiedObjectLookup for TestLookup {
        fn read_verified(&self, identity: GitOid) -> Result<Option<VerifiedObject>, AtpRefusal> {
            Ok(self.0.get(&identity).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct TestQuarantine(Vec<GitOid>);

    impl QuarantineSink for TestQuarantine {
        fn stage_verified(&mut self, object: VerifiedObject) -> Result<(), AtpRefusal> {
            self.0.push(object.identity());
            Ok(())
        }
    }

    fn repository() -> RepositoryId {
        RepositoryId::from_bytes([7; 16])
    }

    fn peer(byte: u8) -> PeerCapabilities {
        PeerCapabilities::new(
            PeerIdentity::from_bytes([byte; 32]),
            repository(),
            [AtpGitProfile::ConservativeInterimV1],
            true,
        )
    }

    fn entry(kind: ObjectKind, payload: &[u8]) -> TransferObjectEntry {
        let identity = git_object_id(
            GitHashAlgorithm::Sha1,
            crypto_kind(kind).expect("kind"),
            payload,
        );
        TransferObjectEntry::from_payload(identity, kind, payload, None).expect("valid entry")
    }

    fn manifest(mut entries: Vec<TransferObjectEntry>) -> TransferManifest {
        entries.sort_by_key(TransferObjectEntry::identity);
        let roots = entries
            .last()
            .map(|entry| vec![entry.identity()])
            .unwrap_or_default();
        TransferManifest::new(
            repository(),
            GitHashAlgorithm::Sha1,
            roots,
            entries,
            limits(),
        )
        .expect("canonical manifest")
    }

    fn authenticated(peer: PeerCapabilities) -> AuthenticatedPeerCapabilities {
        AuthenticatedPeerCapabilities::verify(peer, &AcceptingVerifier).expect("authenticated")
    }

    #[test]
    fn exact_complete_inventory_short_circuits_deterministically() {
        let first = entry(ObjectKind::Blob, b"first");
        let second = entry(ObjectKind::Blob, b"second");
        let manifest = manifest(vec![first.clone(), second.clone()]);
        let mut known = vec![first.identity(), second.identity()];
        known.sort();
        let inventory = HaveSummary::exact_objects(known, limits()).expect("canonical inventory");
        let selector = PlanSelector::new(limits());
        let first_plan = selector.select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &inventory,
        );
        let second_plan = selector.select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &inventory,
        );
        assert_eq!(first_plan, second_plan);
        assert_eq!(
            first_plan.receipt().plan_kind(),
            TransferPlanKind::AlreadyInSync
        );
        assert_eq!(
            first_plan.receipt().inventory(),
            &InventoryReceipt::ExactObjects(
                manifest
                    .objects()
                    .iter()
                    .map(TransferObjectEntry::identity)
                    .collect(),
            )
        );
        assert_eq!(first_plan.payloads(), []);
    }

    #[test]
    fn exact_inventory_is_revalidated_against_a_verified_local_object() {
        let object = entry(ObjectKind::Blob, b"already verified");
        let manifest = manifest(vec![object.clone()]);
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::exact_objects(vec![object.identity()], limits())
                .expect("exact inventory"),
        );
        assert_eq!(plan.receipt().plan_kind(), TransferPlanKind::AlreadyInSync);

        let pipeline = ReconstructionPipeline::new(
            b"tenant/repository".to_vec(),
            SegmentLimits::default(),
            limits(),
        )
        .expect("valid pipeline");
        let verified = pipeline
            .verify_payload(&object, b"already verified")
            .expect("fixture object verifies");
        let lookup = TestLookup(BTreeMap::from([(object.identity(), verified)]));
        let mut quarantine = TestQuarantine::default();
        assert_eq!(
            pipeline.reconstruct(&manifest, &plan, [], &lookup, &mut quarantine),
            Ok(ReconstructionOutcome::Complete(ReconstructionReceipt {
                profile: AtpGitProfile::ConservativeInterimV1,
                staged: Vec::new(),
                reused_verified: vec![object.identity()],
                closure: vec![object.identity()],
            }))
        );
        assert_eq!(quarantine.0.len(), 0);
    }

    #[test]
    fn exact_inventory_does_not_bypass_local_byte_verification() {
        let requested = entry(ObjectKind::Blob, b"requested bytes");
        let manifest = manifest(vec![requested.clone()]);
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::exact_objects(vec![requested.identity()], limits())
                .expect("exact inventory"),
        );
        let pipeline = ReconstructionPipeline::new(
            b"tenant/repository".to_vec(),
            SegmentLimits::default(),
            limits(),
        )
        .expect("valid pipeline");
        let wrong = entry(ObjectKind::Blob, b"different bytes");
        let wrong_verified = pipeline
            .verify_payload(&wrong, b"different bytes")
            .expect("fixture object verifies");
        let lookup = TestLookup(BTreeMap::from([(requested.identity(), wrong_verified)]));
        let mut quarantine = TestQuarantine::default();
        assert_eq!(
            pipeline.reconstruct(&manifest, &plan, [], &lookup, &mut quarantine),
            Err(AtpRefusal::ExistingObjectMismatch {
                identity: requested.identity(),
            })
        );
        assert_eq!(quarantine.0.len(), 0);
    }

    #[test]
    fn non_mutual_profile_selects_typed_full_closure_fallback() {
        let first = entry(ObjectKind::Blob, b"first");
        let second = entry(ObjectKind::Blob, b"second");
        let manifest = manifest(vec![first, second]);
        let source = AuthenticatedPeerCapabilities::verify(
            PeerCapabilities::new(
                PeerIdentity::from_bytes([1; 32]),
                repository(),
                std::iter::empty::<AtpGitProfile>(),
                true,
            ),
            &AcceptingVerifier,
        )
        .expect("record authenticates even though ATP is unavailable");
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &source,
            &authenticated(peer(2)),
            &HaveSummary::exact_objects(
                manifest
                    .objects()
                    .iter()
                    .map(TransferObjectEntry::identity)
                    .collect(),
                limits(),
            )
            .expect("exact inventory"),
        );
        assert_eq!(
            plan.receipt().plan_kind(),
            TransferPlanKind::FullClosureFallback(FullFallbackReason::ConservativeProfileNotMutual)
        );
        assert_eq!(plan.payloads().len(), manifest.objects().len());
    }

    #[test]
    fn probabilistic_false_positive_requests_exact_repair_without_staging_partial_closure() {
        let first = entry(ObjectKind::Blob, b"first");
        let second = entry(ObjectKind::Blob, b"second");
        let manifest = manifest(vec![first.clone(), second]);
        let mut filter = BloomHaveSummary::empty(64, limits()).expect("valid filter");
        filter
            .insert(first.identity())
            .expect("valid filter insert");
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::Probabilistic(filter),
        );
        assert!(plan.receipt().requires_exact_closure_repair());

        let pipeline = ReconstructionPipeline::new(
            b"tenant/repository".to_vec(),
            SegmentLimits::default(),
            limits(),
        )
        .expect("valid pipeline");
        let mut quarantine = TestQuarantine::default();
        let repair = pipeline
            .reconstruct(
                &manifest,
                &plan,
                [TransferPayload::new(b"second".to_vec()).expect("payload")],
                &TestLookup::default(),
                &mut quarantine,
            )
            .expect("repair is an outcome");
        assert_eq!(
            repair,
            ReconstructionOutcome::Repair(ExactRepairRequest {
                missing: vec![first.identity()],
            })
        );
        assert_eq!(quarantine.0.len(), 0);

        let complete = pipeline
            .reconstruct(
                &manifest,
                &plan,
                [
                    TransferPayload::new(b"second".to_vec()).expect("payload"),
                    TransferPayload::new(b"first".to_vec()).expect("payload"),
                ],
                &TestLookup::default(),
                &mut quarantine,
            )
            .expect("complete reconstruction");
        let closure = manifest
            .objects()
            .iter()
            .map(TransferObjectEntry::identity)
            .collect::<Vec<_>>();
        assert_eq!(
            complete,
            ReconstructionOutcome::Complete(ReconstructionReceipt {
                profile: AtpGitProfile::ConservativeInterimV1,
                staged: closure.clone(),
                reused_verified: Vec::new(),
                closure: closure.clone(),
            })
        );
        assert_eq!(quarantine.0, closure);
    }

    #[test]
    fn equal_content_across_logical_kinds_uses_one_payload_with_independent_object_verification() {
        let blob = entry(ObjectKind::Blob, b"same");
        let commit = entry(ObjectKind::Commit, b"same");
        let mut entries = vec![blob, commit];
        entries.sort_by_key(TransferObjectEntry::identity);
        let manifest = manifest(entries);
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::exact_objects(Vec::new(), limits()).expect("empty exact inventory"),
        );
        assert_eq!(
            plan.receipt().plan_kind(),
            TransferPlanKind::UniqueContentDelta
        );
        assert_eq!(plan.payloads().len(), 1);
        assert_eq!(plan.payloads()[0].object_identities().len(), 2);

        let pipeline = ReconstructionPipeline::new(
            b"tenant/repository".to_vec(),
            SegmentLimits::default(),
            limits(),
        )
        .expect("valid pipeline");
        let mut quarantine = TestQuarantine::default();
        let outcome = pipeline
            .reconstruct(
                &manifest,
                &plan,
                [TransferPayload::new(b"same".to_vec()).expect("payload")],
                &TestLookup::default(),
                &mut quarantine,
            )
            .expect("complete reconstruction");
        assert!(matches!(outcome, ReconstructionOutcome::Complete(_)));
        assert_eq!(quarantine.0.len(), 2);
    }

    #[test]
    fn incorrect_payload_is_refused_before_quarantine_staging() {
        let object = entry(ObjectKind::Blob, b"expected");
        let manifest = manifest(vec![object]);
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::exact_objects(Vec::new(), limits()).expect("empty exact inventory"),
        );
        let pipeline = ReconstructionPipeline::new(
            b"tenant/repository".to_vec(),
            SegmentLimits::default(),
            limits(),
        )
        .expect("valid pipeline");
        let mut quarantine = TestQuarantine::default();
        assert_eq!(
            pipeline.reconstruct(
                &manifest,
                &plan,
                [TransferPayload::new(b"corrupt".to_vec()).expect("payload")],
                &TestLookup::default(),
                &mut quarantine,
            ),
            Err(AtpRefusal::UnrequestedPayload)
        );
        assert_eq!(quarantine.0.len(), 0);
    }

    #[test]
    fn capability_record_cannot_select_a_plan_until_authenticated() {
        assert_eq!(
            AuthenticatedPeerCapabilities::verify(peer(9), &RejectingVerifier),
            Err(AtpRefusal::PeerCapabilityRejected)
        );
    }

    #[test]
    fn oversized_probabilistic_wire_summary_is_refused_before_copying() {
        let constrained = TransferLimits::new(4, 16, 32, 1).expect("valid constrained limits");
        assert_eq!(
            BloomHaveSummary::from_wire(16, &[0; 2], constrained),
            Err(AtpRefusal::ProbabilisticSummaryTooLarge {
                offered: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn exact_segment_inventory_omits_whole_verified_segment() {
        let segment =
            SegmentManifestId::from_internal_object_id(fgit_types::InternalObjectId::new(
                fgit_types::DigestAlgorithmId::try_new(2).expect("algorithm"),
                SegmentManifestId::DOMAIN_TAG,
                fgit_types::CANONICAL_CODEC_VERSION,
                fgit_types::DigestBytes::try_new(&[3; 32]).expect("digest"),
            ))
            .expect("segment identity");
        let mut object = entry(ObjectKind::Blob, b"segment payload");
        object.segment = Some(segment);
        let manifest = manifest(vec![object]);
        let plan = PlanSelector::new(limits()).select(
            &manifest,
            &authenticated(peer(1)),
            &authenticated(peer(2)),
            &HaveSummary::exact_segments(vec![segment], limits()).expect("exact segment inventory"),
        );
        assert_eq!(plan.receipt().plan_kind(), TransferPlanKind::AlreadyInSync);
    }

    #[test]
    fn manifest_refuses_a_closure_larger_than_the_request_budget() {
        let first = entry(ObjectKind::Blob, b"six!!!");
        let second = entry(ObjectKind::Blob, b"seven!!");
        let mut entries = vec![first, second];
        entries.sort_by_key(TransferObjectEntry::identity);
        let roots = vec![entries[0].identity()];
        let constrained = TransferLimits::new(4, 8, 12, 64).expect("valid constrained limits");
        assert_eq!(
            TransferManifest::new(
                repository(),
                GitHashAlgorithm::Sha1,
                roots,
                entries,
                constrained,
            ),
            Err(AtpRefusal::ReconstructionBudgetExceeded {
                offered: 13,
                maximum: 12,
            })
        );
    }
}
