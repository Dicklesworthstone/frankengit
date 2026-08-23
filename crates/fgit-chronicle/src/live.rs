//! Freeze and stage a repository capsule from an authenticated live head.
//!
//! A capsule is not a best-effort snapshot. This boundary authenticates the
//! observed authority head, derives the capsule from that one body, stages and
//! rereads the capsule bytes, then rereads the authority head before returning
//! a pointer candidate. A concurrent head change therefore leaves only an
//! immutable, unreachable capsule body; it can never publish a stale root.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, AuthorityStore, CasOutcome, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableRead, PutOutcome, authority_head_identity, body_key,
    initialize_repository,
};
use fgit_codec::attest::BodyIdentity;
use fgit_codec::{
    CodecRefusal, DecodeLimits, RepositoryAuthorityHeadBody, decode_body, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{Digest, RepositoryCapsuleId};

use crate::{
    BackupExportBundleBody, BackupProfile, CapsuleDefect, CapsulePointer, ChronicleRefusal,
    RepositoryCapsuleBody, RestoreClassification, RestoreOutcome, capsule_identity,
};

/// Inputs naming immutable closure material that the object-fabric owner has
/// already verified. This crate never infers a closure from directory listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleClosure {
    /// Validated object closure root.
    pub object_closure_root: Digest,
    /// Validated segment-manifest root.
    pub segment_manifest_root: Digest,
    /// Coverage the staged material satisfies.
    pub backup_profile: BackupProfile,
}

/// A capsule body staged from a head that remained current through staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenCapsule {
    capsule: RepositoryCapsuleBody,
    capsule_id: RepositoryCapsuleId,
    pointer: CapsulePointer,
}

/// The byte-carrying part of an attestation-only backup export.
///
/// The existing [`BackupExportBundleBody`] remains the durable vocabulary: it
/// identifies the repository, capsule, declared coverage, inventory root, and
/// durability-evidence root. This type deliberately has no canonical-body
/// implementation, signature, signer, or key-policy field. It carries the
/// two exact bytes a clean destination needs to verify the capsule/head
/// boundary before it publishes local authority. A signed portable archive
/// containing object, segment, suffix, and repair material belongs to the
/// separately scoped archive slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedBackupExport {
    bundle: BackupExportBundleBody,
    capsule_bytes: Vec<u8>,
    authority_head_bytes: Vec<u8>,
}

impl AttestedBackupExport {
    /// Assemble an export received from an untrusted transport.
    ///
    /// This constructor intentionally performs no validation. The restore
    /// boundary below derives every decision from these actual bytes before it
    /// stages an immutable body or initializes destination authority.
    #[must_use]
    pub const fn new(
        bundle: BackupExportBundleBody,
        capsule_bytes: Vec<u8>,
        authority_head_bytes: Vec<u8>,
    ) -> Self {
        Self {
            bundle,
            capsule_bytes,
            authority_head_bytes,
        }
    }

    /// The existing durable attestation body for this export.
    #[must_use]
    pub const fn bundle(&self) -> &BackupExportBundleBody {
        &self.bundle
    }

    /// Exact canonical repository-capsule bytes from the source authority.
    #[must_use]
    pub fn capsule_bytes(&self) -> &[u8] {
        &self.capsule_bytes
    }

    /// Exact canonical authority-head bytes checkpointed by the capsule.
    #[must_use]
    pub fn authority_head_bytes(&self) -> &[u8] {
        &self.authority_head_bytes
    }
}

/// The replay claim a restore execution may make.
///
/// The reduced attestation-only export has the exact capsule/head boundary but
/// does not carry object bodies, segment manifests, decision suffixes,
/// materializations, or verification-tool identity. Its result is therefore
/// intentionally the third grade from plan section 34.3, never a claim of an
/// exact or structural replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReplayCompleteness {
    /// Every deterministic input, schedule, and toolchain artifact is present.
    Replayable,
    /// Logical state and control shape reproduce, with named external classes
    /// absent.
    StructuralReplay,
    /// The authority boundary verifies when the named external artifacts are
    /// supplied.
    VerifiableIfArtifactsSupplied,
    /// The record supports inspection but not replay or full verification.
    AuditOnly,
}

impl ReplayCompleteness {
    /// Stable lowercase receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replayable => "replayable",
            Self::StructuralReplay => "structural_replay",
            Self::VerifiableIfArtifactsSupplied => "verifiable_if_artifacts_supplied",
            Self::AuditOnly => "audit_only",
        }
    }
}

/// A completed authority-boundary restore.
///
/// This is a runtime receipt, not a new signed archive/report format. The
/// existing `BackupExportBundleBody` is the durable attestation; this value
/// reports what the local restore execution actually did and its explicit
/// replay limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoredAuthorityBoundary {
    head: HeadReadReceipt,
    capsule_id: RepositoryCapsuleId,
    classification: RestoreClassification,
    replay_completeness: ReplayCompleteness,
}

impl RestoredAuthorityBoundary {
    /// The destination authority receipt after root-last capsule activation.
    #[must_use]
    pub const fn head(&self) -> &HeadReadReceipt {
        &self.head
    }

    /// The capsule activated at the destination authority head.
    #[must_use]
    pub const fn capsule_id(&self) -> RepositoryCapsuleId {
        self.capsule_id
    }

    /// The byte-derived classification that permitted this execution.
    #[must_use]
    pub const fn classification(&self) -> &RestoreClassification {
        &self.classification
    }

    /// The replay-completeness grade disclosed by this execution.
    #[must_use]
    pub const fn replay_completeness(&self) -> ReplayCompleteness {
        self.replay_completeness
    }

    /// External artifact classes still needed to complete the full restore
    /// protocol.
    #[must_use]
    pub const fn missing_artifact_classes(&self) -> &'static [&'static str] {
        &[
            "decision suffix",
            "object closure bodies",
            "segment manifests",
            "materializations and projections",
            "verification-tool identity",
        ]
    }

    /// Whether this operation published destination routing.
    ///
    /// Routing is deliberately absent: a caller can only publish it after the
    /// remaining named artifact classes have been supplied and verified.
    #[must_use]
    pub const fn routing_published(&self) -> bool {
        false
    }
}

/// Why an attestation-only export could not be formed from live authority.
#[derive(Debug)]
pub enum BackupExportRefusal {
    /// The source receipt was not issued by the source authority endpoint.
    SourceHeadUnauthenticated(AuthorityFailure),
    /// The source capsule body could not be encoded for exact-byte comparison.
    CapsuleEncoding(CodecRefusal),
    /// Deriving the immutable capsule slot failed.
    CapsuleKey(Box<fgit_authority::OutcomeFailure>),
    /// Reading the source immutable capsule slot failed or was ambiguous.
    CapsuleRead(AuthorityFailure),
    /// The immutable slot did not contain the frozen capsule.
    CapsuleNotStaged,
    /// The source immutable bytes disagreed with the frozen capsule bytes.
    CapsuleReadbackMismatch,
    /// The capsule/head bytes could not be inspected.
    Inspection(Box<CapsuleInspectionRefusal>),
    /// Byte-derived defects prevent export of this authority boundary.
    NotRestorable(RestoreOutcome),
}

impl fmt::Display for BackupExportRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceHeadUnauthenticated(error) => {
                write!(
                    formatter,
                    "source head receipt was not authenticated: {error}"
                )
            }
            Self::CapsuleEncoding(error) => {
                write!(formatter, "frozen capsule could not be encoded: {error}")
            }
            Self::CapsuleKey(error) => {
                write!(
                    formatter,
                    "frozen capsule immutable key was unavailable: {error}"
                )
            }
            Self::CapsuleRead(error) => {
                write!(formatter, "source capsule read did not complete: {error}")
            }
            Self::CapsuleNotStaged => formatter.write_str("frozen capsule was not staged"),
            Self::CapsuleReadbackMismatch => {
                formatter.write_str("source capsule bytes disagreed with the frozen capsule")
            }
            Self::Inspection(error) => {
                write!(formatter, "source capsule/head inspection refused: {error}")
            }
            Self::NotRestorable(outcome) => write!(
                formatter,
                "source capsule/head classification does not permit export: {}",
                outcome.as_str()
            ),
        }
    }
}

impl std::error::Error for BackupExportRefusal {}

/// Why an attestation-only export could not initialize a clean destination.
#[derive(Debug)]
pub enum RestoreExecutionRefusal {
    /// The bundle names a repository other than the decoded capsule.
    RepositoryMismatch,
    /// This reduced export has a stricter coverage claim than the bytes it
    /// transports. A fuller archive is a separate format and execution path.
    UnsupportedExportProfile(BackupProfile),
    /// The transported capsule/head bytes could not be inspected.
    Inspection(Box<CapsuleInspectionRefusal>),
    /// Byte-derived defects prohibit automatic restore.
    NotRestorable(RestoreOutcome),
    /// Staging the destination capsule failed or was ambiguous.
    CapsuleStage(AuthorityFailure),
    /// The destination capsule slot already holds different bytes.
    CapsuleSlotConflict,
    /// Destination capsule staging lacked an exact byte readback.
    CapsuleReadbackMismatch,
    /// Restoring the immutable capsule pointer refused.
    CapsulePointer(ChronicleRefusal),
    /// Destination authority initialization failed or was ambiguous.
    DestinationInitialize(Box<fgit_authority::OutcomeFailure>),
    /// The destination head namespace was not fresh for this exact restore.
    DestinationHeadConflict,
    /// Root-last activation of the destination checkpoint refused.
    Activation(Box<LiveCapsuleRefusal>),
}

impl fmt::Display for RestoreExecutionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryMismatch => {
                formatter.write_str("backup bundle repository disagrees with capsule bytes")
            }
            Self::UnsupportedExportProfile(profile) => write!(
                formatter,
                "attestation-only restore cannot claim {} coverage",
                profile.as_str()
            ),
            Self::Inspection(error) => {
                write!(formatter, "backup capsule/head inspection refused: {error}")
            }
            Self::NotRestorable(outcome) => write!(
                formatter,
                "backup capsule/head classification does not permit restore: {}",
                outcome.as_str()
            ),
            Self::CapsuleStage(error) => {
                write!(
                    formatter,
                    "destination capsule staging did not complete: {error}"
                )
            }
            Self::CapsuleSlotConflict => {
                formatter.write_str("destination capsule slot held different bytes")
            }
            Self::CapsuleReadbackMismatch => formatter
                .write_str("destination capsule staging was not proven by exact byte readback"),
            Self::CapsulePointer(error) => {
                write!(formatter, "destination capsule pointer refused: {error}")
            }
            Self::DestinationInitialize(error) => {
                write!(
                    formatter,
                    "destination authority initialization refused: {error}"
                )
            }
            Self::DestinationHeadConflict => {
                formatter.write_str("destination authority namespace is not fresh")
            }
            Self::Activation(error) => {
                write!(
                    formatter,
                    "destination checkpoint activation refused: {error}"
                )
            }
        }
    }
}

impl std::error::Error for RestoreExecutionRefusal {}

/// The result of root-last checkpoint activation.
///
/// The returned head receipt is the new authority position carrying the
/// checkpoint pointer. Routing is deliberately absent from this type: it is a
/// derived publication and cannot become visible until a later consumer has
/// completed its own verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedCapsule {
    pointer: CapsulePointer,
    head: HeadReadReceipt,
}

impl ActivatedCapsule {
    /// The activated anti-rollback checkpoint pointer.
    pub const fn pointer(&self) -> CapsulePointer {
        self.pointer
    }

    /// The new authority-head receipt that records the activated pointer.
    #[must_use]
    pub const fn head(&self) -> &HeadReadReceipt {
        &self.head
    }
}

impl FrozenCapsule {
    /// The immutable staged capsule body.
    #[must_use]
    pub const fn capsule(&self) -> &RepositoryCapsuleBody {
        &self.capsule
    }

    /// The canonical identity of the staged body.
    #[must_use]
    pub const fn capsule_id(&self) -> RepositoryCapsuleId {
        self.capsule_id
    }

    /// The root-last pointer candidate. A caller publishes it only after this
    /// function's exact-byte and current-head checks have completed.
    pub const fn pointer(&self) -> CapsulePointer {
        self.pointer
    }
}

/// Why live capsule freezing stopped before yielding a pointer candidate.
#[derive(Debug)]
pub enum LiveCapsuleRefusal {
    /// The supplied receipt was not issued by this authority endpoint.
    HeadUnauthenticated(AuthorityFailure),
    /// The receipt bytes are not a canonical authority-head body.
    HeadDecode(CodecRefusal),
    /// The decoded head does not agree with the receipt's generation.
    HeadGenerationMismatch,
    /// The authority-head identity could not be derived from canonical bytes.
    HeadIdentity(Box<fgit_authority::OutcomeFailure>),
    /// Capsule construction or pointer monotonicity refused.
    Capsule(ChronicleRefusal),
    /// The capsule could not be encoded canonically.
    CapsuleEncoding(CodecRefusal),
    /// The authority backend refused or left staging ambiguous.
    CapsuleStage(AuthorityFailure),
    /// The canonical capsule slot was already occupied by different bytes.
    CapsuleSlotConflict,
    /// Readback after staging did not prove the exact capsule bytes exist.
    CapsuleReadbackMismatch,
    /// The repository head disappeared while the capsule was staged.
    HeadDisappeared,
    /// The repository advanced while the capsule was staged.
    HeadMoved,
    /// The authenticated activation basis does not match the frozen capsule.
    ActivationBasisMismatch,
    /// The existing checkpoint pointer is not the frozen capsule's predecessor.
    CheckpointPredecessorMismatch,
    /// The authority-head generation cannot advance without overflowing.
    ActivationGenerationExhausted,
    /// Staging the successor authority head failed or was ambiguous.
    ActivationHeadStage(AuthorityFailure),
    /// The successor authority-head identity slot already held different bytes.
    ActivationHeadSlotConflict,
    /// The staged successor authority head did not read back byte-identically.
    ActivationHeadReadbackMismatch,
}

impl fmt::Display for LiveCapsuleRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadUnauthenticated(error) => write!(
                formatter,
                "authority head receipt was not authenticated: {error}"
            ),
            Self::HeadDecode(error) => {
                write!(formatter, "authority head bytes did not decode: {error}")
            }
            Self::HeadGenerationMismatch => formatter.write_str(
                "authority head body disagrees with its authenticated receipt generation",
            ),
            Self::HeadIdentity(error) => write!(
                formatter,
                "authority head identity was unavailable: {error}"
            ),
            Self::Capsule(error) => write!(formatter, "capsule construction refused: {error}"),
            Self::CapsuleEncoding(error) => write!(formatter, "capsule encoding refused: {error}"),
            Self::CapsuleStage(error) => {
                write!(formatter, "capsule staging did not complete: {error}")
            }
            Self::CapsuleSlotConflict => {
                formatter.write_str("canonical capsule slot held different bytes")
            }
            Self::CapsuleReadbackMismatch => {
                formatter.write_str("capsule staging was not proven by exact byte readback")
            }
            Self::HeadDisappeared => {
                formatter.write_str("authority head disappeared while the capsule was staged")
            }
            Self::HeadMoved => {
                formatter.write_str("authority head moved while the capsule was staged")
            }
            Self::ActivationBasisMismatch => formatter.write_str(
                "activation receipt does not name the exact authority head frozen by this capsule",
            ),
            Self::CheckpointPredecessorMismatch => formatter.write_str(
                "authority head's checkpoint pointer is not the frozen capsule predecessor",
            ),
            Self::ActivationGenerationExhausted => formatter
                .write_str("authority head generation is exhausted before checkpoint activation"),
            Self::ActivationHeadStage(error) => {
                write!(
                    formatter,
                    "successor authority-head staging did not complete: {error}"
                )
            }
            Self::ActivationHeadSlotConflict => {
                formatter.write_str("successor authority-head identity slot held different bytes")
            }
            Self::ActivationHeadReadbackMismatch => formatter.write_str(
                "successor authority-head staging was not proven by exact byte readback",
            ),
        }
    }
}

impl std::error::Error for LiveCapsuleRefusal {}

/// The result of inspecting capsule bytes at a declared immutable identity.
///
/// The decoder, identity check, and predecessor check are deliberately here
/// rather than in a fixture. A restore executor can therefore only hand the
/// classifier defects it actually derived from the bytes and pointer chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleInspection {
    capsule: RepositoryCapsuleBody,
    classification: RestoreClassification,
}

/// Why a capsule could not be inspected as restore input.
#[derive(Debug)]
pub enum CapsuleInspectionRefusal {
    /// The supplied bytes are not a canonical capsule body.
    Decode(CodecRefusal),
    /// The decoded body has no registered canonical identity.
    Identity(ChronicleRefusal),
    /// The supplied authority-head bytes are not a canonical authority head.
    HeadDecode(CodecRefusal),
    /// The decoded authority head has no canonical identity.
    HeadIdentity(Box<fgit_authority::OutcomeFailure>),
}

impl fmt::Display for CapsuleInspectionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(formatter, "capsule bytes did not decode: {error}"),
            Self::Identity(error) => write!(formatter, "capsule identity was unavailable: {error}"),
            Self::HeadDecode(error) => {
                write!(formatter, "authority-head bytes did not decode: {error}")
            }
            Self::HeadIdentity(error) => write!(
                formatter,
                "authority-head identity was unavailable: {error}"
            ),
        }
    }
}

impl std::error::Error for CapsuleInspectionRefusal {}

impl CapsuleInspection {
    /// The decoded capsule body.
    #[must_use]
    pub const fn capsule(&self) -> &RepositoryCapsuleBody {
        &self.capsule
    }

    /// Classification of the byte-derived defects.
    #[must_use]
    pub const fn classification(&self) -> &RestoreClassification {
        &self.classification
    }
}

/// Decode a capsule and derive the identity and pointer-chain defects that
/// restore can determine without asking a placement backend to enumerate.
pub fn inspect_capsule_bytes<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<CapsuleInspection, CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let (capsule, defects) =
        decoded_capsule_defects(identity, declared_id, bytes, expected_predecessor)?;
    Ok(CapsuleInspection::from_defects(capsule, defects))
}

/// Decode a capsule and its named authority head, deriving every mismatch
/// between the two from their actual canonical bytes.
///
/// A portable restore cannot trust a caller that says a capsule was taken at a
/// particular head. This function recomputes that head's identity and checks
/// each field the capsule copies from it before a destination can stage or
/// initialize anything. The caller supplies bytes rather than a store because
/// the source authority may no longer exist during a clean-machine restore.
pub fn inspect_capsule_against_authority_head_bytes<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    capsule_bytes: &[u8],
    authority_head_bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<CapsuleInspection, CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let (capsule, mut defects) =
        decoded_capsule_defects(identity, declared_id, capsule_bytes, expected_predecessor)?;
    let head: RepositoryAuthorityHeadBody =
        decode_body(authority_head_bytes, DecodeLimits::DEFAULT)
            .map_err(CapsuleInspectionRefusal::HeadDecode)?;
    let head_id = authority_head_identity(&head)
        .map_err(|error| CapsuleInspectionRefusal::HeadIdentity(Box::new(error)))?;
    collect_authority_head_defects(&capsule, head_id, &head, &mut defects);
    Ok(CapsuleInspection::from_defects(capsule, defects))
}

impl CapsuleInspection {
    fn from_defects(capsule: RepositoryCapsuleBody, defects: Vec<CapsuleDefect>) -> Self {
        let classification = RestoreClassification::classify(&capsule, &defects);
        Self {
            capsule,
            classification,
        }
    }
}

fn decoded_capsule_defects<I>(
    identity: &I,
    declared_id: RepositoryCapsuleId,
    bytes: &[u8],
    expected_predecessor: Option<RepositoryCapsuleId>,
) -> Result<(RepositoryCapsuleBody, Vec<CapsuleDefect>), CapsuleInspectionRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let capsule: RepositoryCapsuleBody =
        decode_body(bytes, DecodeLimits::DEFAULT).map_err(CapsuleInspectionRefusal::Decode)?;
    let recomputed =
        capsule_identity(identity, &capsule).map_err(CapsuleInspectionRefusal::Identity)?;
    let mut defects = Vec::with_capacity(15);
    if recomputed != declared_id {
        defects.push(CapsuleDefect::IdentityMismatch {
            declared: declared_id,
            recomputed,
        });
    }
    if capsule.predecessor_capsule_id != expected_predecessor {
        defects.push(CapsuleDefect::PredecessorStale {
            named: capsule.predecessor_capsule_id,
            expected: expected_predecessor,
        });
    }
    Ok((capsule, defects))
}

fn collect_authority_head_defects(
    capsule: &RepositoryCapsuleBody,
    head_id: fgit_types::RepositoryAuthorityHeadId,
    head: &RepositoryAuthorityHeadBody,
    defects: &mut Vec<CapsuleDefect>,
) {
    for (field, agrees) in [
        ("head_id", capsule.head_id == head_id),
        ("repository_id", capsule.repository_id == head.repository_id),
        (
            "head_generation",
            capsule.head_generation == head.generation,
        ),
        (
            "decision_tail_id",
            capsule.decision_tail_id == head.decision_tail_id,
        ),
        (
            "latest_decision_sequence",
            capsule.latest_decision_sequence == head.latest_decision_sequence,
        ),
        (
            "latest_committed_rcr_id",
            capsule.latest_committed_rcr_id == head.latest_committed_rcr_id,
        ),
        (
            "latest_repository_sequence",
            capsule.latest_repository_sequence == head.latest_repository_sequence,
        ),
        ("ref_root", capsule.ref_root == head.ref_root),
        (
            "forge_position_root",
            capsule.forge_position_root == head.forge_position_root,
        ),
        (
            "retention_root",
            capsule.retention_root == head.retention_root,
        ),
        (
            "configuration_root",
            capsule.configuration_root == head.configuration_root,
        ),
        ("policy_epoch", capsule.policy_epoch == head.policy_epoch),
        (
            "format_registry_epoch",
            capsule.format_registry_epoch == head.format_registry_epoch,
        ),
    ] {
        if !agrees {
            defects.push(CapsuleDefect::AuthorityHeadMismatch { field });
        }
    }
}

/// Export a frozen capsule with the existing attestation-only bundle body.
///
/// The source receipt is authenticated again and the source immutable capsule
/// slot is read byte-for-byte. The resulting export therefore never treats an
/// in-memory `FrozenCapsule` as proof that another machine can read the
/// capsule. Its declared export profile is intentionally
/// [`BackupProfile::DecisionHistoryOnly`]: this type carries only the
/// capsule/head boundary, not the object, segment, suffix, or repair bytes a
/// full-closure archive would require.
pub fn export_frozen_capsule<S, I>(
    store: &S,
    identity: &I,
    basis: &HeadReadReceipt,
    frozen: &FrozenCapsule,
    export_inventory_root: Digest,
    durability_evidence_root: Digest,
) -> Result<AttestedBackupExport, BackupExportRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    store
        .authenticate_head_receipt(basis)
        .map_err(BackupExportRefusal::SourceHeadUnauthenticated)?;
    let capsule_bytes =
        encode_body(frozen.capsule()).map_err(BackupExportRefusal::CapsuleEncoding)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, frozen.capsule())
        .map_err(|error| BackupExportRefusal::CapsuleKey(Box::new(error.into())))?;
    let staged = store
        .read_immutable(&key)
        .map_err(BackupExportRefusal::CapsuleRead)?;
    match staged {
        ImmutableRead::Absent => return Err(BackupExportRefusal::CapsuleNotStaged),
        ImmutableRead::Present(found) if found != capsule_bytes => {
            return Err(BackupExportRefusal::CapsuleReadbackMismatch);
        }
        ImmutableRead::Present(_) => {}
    }

    let source_head: RepositoryAuthorityHeadBody = decode_body(basis.body(), DecodeLimits::DEFAULT)
        .map_err(|error| {
            BackupExportRefusal::Inspection(Box::new(CapsuleInspectionRefusal::HeadDecode(error)))
        })?;
    let inspection = inspect_capsule_against_authority_head_bytes(
        identity,
        frozen.capsule_id(),
        &capsule_bytes,
        basis.body(),
        source_head.last_checkpoint_id,
    )
    .map_err(|error| BackupExportRefusal::Inspection(Box::new(error)))?;
    if inspection.classification().outcome() != RestoreOutcome::Restorable {
        return Err(BackupExportRefusal::NotRestorable(
            inspection.classification().outcome(),
        ));
    }

    let bundle = BackupExportBundleBody {
        repository_id: frozen.capsule().repository_id,
        capsule_id: frozen.capsule_id(),
        exported_profile: BackupProfile::DecisionHistoryOnly,
        export_inventory_root,
        durability_evidence_root,
    };
    Ok(AttestedBackupExport::new(
        bundle,
        capsule_bytes,
        basis.body().to_vec(),
    ))
}

/// Restore an attestation-only export into a fresh authority namespace.
///
/// All capsule/head checks occur before any destination write. Once the exact
/// bytes classify as restorable, the capsule is staged and read back, the
/// destination's fresh head is initialized from the verified source body, and
/// the checkpoint pointer is activated root-last. No routing API is called or
/// exposed here. The returned receipt explicitly says that the omitted
/// archive classes must be supplied before a full replay can be claimed.
pub fn restore_attested_backup<S, I>(
    destination: &S,
    destination_key: &HeadKey,
    identity: &I,
    backup: &AttestedBackupExport,
) -> Result<RestoredAuthorityBoundary, RestoreExecutionRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    if backup.bundle().exported_profile != BackupProfile::DecisionHistoryOnly {
        return Err(RestoreExecutionRefusal::UnsupportedExportProfile(
            backup.bundle().exported_profile,
        ));
    }
    let source_head: RepositoryAuthorityHeadBody =
        decode_body(backup.authority_head_bytes(), DecodeLimits::DEFAULT).map_err(|error| {
            RestoreExecutionRefusal::Inspection(Box::new(CapsuleInspectionRefusal::HeadDecode(
                error,
            )))
        })?;
    let inspection = inspect_capsule_against_authority_head_bytes(
        identity,
        backup.bundle().capsule_id,
        backup.capsule_bytes(),
        backup.authority_head_bytes(),
        source_head.last_checkpoint_id,
    )
    .map_err(|error| RestoreExecutionRefusal::Inspection(Box::new(error)))?;
    if inspection.capsule().repository_id != backup.bundle().repository_id {
        return Err(RestoreExecutionRefusal::RepositoryMismatch);
    }
    if inspection.classification().outcome() != RestoreOutcome::Restorable {
        return Err(RestoreExecutionRefusal::NotRestorable(
            inspection.classification().outcome(),
        ));
    }

    let capsule = inspection.capsule().clone();
    let capsule_key = body_key(IdentityDomain::RepositoryCapsule, &capsule)
        .map_err(|error| RestoreExecutionRefusal::DestinationInitialize(Box::new(error.into())))?;
    match destination
        .put_if_absent(&capsule_key, backup.capsule_bytes())
        .map_err(RestoreExecutionRefusal::CapsuleStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(RestoreExecutionRefusal::CapsuleSlotConflict),
    }
    if !matches!(destination.read_immutable(&capsule_key), Ok(ImmutableRead::Present(found)) if found == backup.capsule_bytes())
    {
        return Err(RestoreExecutionRefusal::CapsuleReadbackMismatch);
    }

    let basis = match initialize_repository(destination, destination_key, &source_head)
        .map_err(|error| RestoreExecutionRefusal::DestinationInitialize(Box::new(error)))?
    {
        HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => receipt,
        HeadInit::Conflict => return Err(RestoreExecutionRefusal::DestinationHeadConflict),
    };
    let pointer = CapsulePointer::restored_root(backup.bundle().capsule_id, &capsule);
    let frozen = FrozenCapsule {
        capsule,
        capsule_id: backup.bundle().capsule_id,
        pointer,
    };
    let activated = activate_frozen_capsule(destination, &basis, &frozen)
        .map_err(|error| RestoreExecutionRefusal::Activation(Box::new(error)))?;
    Ok(RestoredAuthorityBoundary {
        head: activated.head,
        capsule_id: frozen.capsule_id,
        classification: inspection.classification().clone(),
        replay_completeness: ReplayCompleteness::VerifiableIfArtifactsSupplied,
    })
}

/// Stage and activate a frozen capsule through the exact authority head it
/// checkpointed.
///
/// The successor authority head is an immutable body and is staged/read back
/// before its head-slot CAS. The CAS is therefore the final visibility point:
/// neither a capsule nor a successor head object becoming readable publishes a
/// checkpoint on its own. The function performs no routing publication.
pub fn activate_frozen_capsule<S>(
    store: &S,
    basis: &HeadReadReceipt,
    frozen: &FrozenCapsule,
) -> Result<ActivatedCapsule, LiveCapsuleRefusal>
where
    S: AuthorityStore + ?Sized,
{
    store
        .authenticate_head_receipt(basis)
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let mut head: RepositoryAuthorityHeadBody =
        decode_body(basis.body(), DecodeLimits::DEFAULT).map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != basis.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let mut basis_defects = Vec::with_capacity(13);
    collect_authority_head_defects(frozen.capsule(), head_id, &head, &mut basis_defects);
    if !basis_defects.is_empty() {
        return Err(LiveCapsuleRefusal::ActivationBasisMismatch);
    }
    if head.last_checkpoint_id != frozen.capsule().predecessor_capsule_id {
        return Err(LiveCapsuleRefusal::CheckpointPredecessorMismatch);
    }

    head.predecessor_head_id = Some(head_id);
    head.generation = head
        .generation
        .next()
        .map_err(|_| LiveCapsuleRefusal::ActivationGenerationExhausted)?;
    head.last_checkpoint_id = Some(frozen.capsule_id());
    let successor_bytes = encode_body(&head).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let successor_key = body_key(IdentityDomain::RepositoryAuthorityHead, &head)
        .map_err(|_| LiveCapsuleRefusal::ActivationBasisMismatch)?;
    match store
        .put_if_absent(&successor_key, &successor_bytes)
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::ActivationHeadSlotConflict),
    }
    if !matches!(store.read_immutable(&successor_key), Ok(ImmutableRead::Present(found)) if found == successor_bytes)
    {
        return Err(LiveCapsuleRefusal::ActivationHeadReadbackMismatch);
    }
    let CasOutcome::Committed(head) = store
        .compare_exchange_head(
            basis.key(),
            basis.token(),
            head.generation,
            &successor_bytes,
        )
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    else {
        return Err(LiveCapsuleRefusal::HeadMoved);
    };
    Ok(ActivatedCapsule {
        pointer: frozen.pointer(),
        head,
    })
}

/// Async production twin of [`activate_frozen_capsule`].
///
/// It carries the same stage/readback/CAS order as the deterministic surface;
/// only the waiting belongs to the runtime-owned authority context.
pub async fn activate_frozen_capsule_async<S>(
    store: &S,
    cx: &S::Context,
    basis: &HeadReadReceipt,
    frozen: &FrozenCapsule,
) -> Result<ActivatedCapsule, LiveCapsuleRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
{
    store
        .authenticate_head_receipt(cx, basis)
        .await
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let mut head: RepositoryAuthorityHeadBody =
        decode_body(basis.body(), DecodeLimits::DEFAULT).map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != basis.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let mut basis_defects = Vec::with_capacity(13);
    collect_authority_head_defects(frozen.capsule(), head_id, &head, &mut basis_defects);
    if !basis_defects.is_empty() {
        return Err(LiveCapsuleRefusal::ActivationBasisMismatch);
    }
    if head.last_checkpoint_id != frozen.capsule().predecessor_capsule_id {
        return Err(LiveCapsuleRefusal::CheckpointPredecessorMismatch);
    }

    head.predecessor_head_id = Some(head_id);
    head.generation = head
        .generation
        .next()
        .map_err(|_| LiveCapsuleRefusal::ActivationGenerationExhausted)?;
    head.last_checkpoint_id = Some(frozen.capsule_id());
    let successor_bytes = encode_body(&head).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let successor_key = body_key(IdentityDomain::RepositoryAuthorityHead, &head)
        .map_err(|_| LiveCapsuleRefusal::ActivationBasisMismatch)?;
    match store
        .put_if_absent(cx, &successor_key, &successor_bytes)
        .await
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::ActivationHeadSlotConflict),
    }
    if !matches!(store.read_immutable(cx, &successor_key).await, Ok(ImmutableRead::Present(found)) if found == successor_bytes)
    {
        return Err(LiveCapsuleRefusal::ActivationHeadReadbackMismatch);
    }
    let CasOutcome::Committed(head) = store
        .compare_exchange_head(
            cx,
            basis.key(),
            basis.token(),
            head.generation,
            &successor_bytes,
        )
        .await
        .map_err(LiveCapsuleRefusal::ActivationHeadStage)?
    else {
        return Err(LiveCapsuleRefusal::HeadMoved);
    };
    Ok(ActivatedCapsule {
        pointer: frozen.pointer(),
        head,
    })
}

/// Freeze the authenticated head, stage its capsule, and return a pointer
/// candidate only if that exact head remains current.
pub fn freeze_capsule<S, I>(
    store: &S,
    identity: &I,
    receipt: &HeadReadReceipt,
    current_pointer: Option<&CapsulePointer>,
    closure: CapsuleClosure,
) -> Result<FrozenCapsule, LiveCapsuleRefusal>
where
    S: AuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized,
{
    store
        .authenticate_head_receipt(receipt)
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let head: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)
        .map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != receipt.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let capsule = RepositoryCapsuleBody::at_head(
        head_id,
        &head,
        current_pointer.map(CapsulePointer::capsule_id),
        closure.object_closure_root,
        closure.segment_manifest_root,
        closure.backup_profile,
    );
    let capsule_id = capsule_identity(identity, &capsule).map_err(LiveCapsuleRefusal::Capsule)?;
    let bytes = encode_body(&capsule).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, &capsule)
        .map_err(|_| LiveCapsuleRefusal::Capsule(ChronicleRefusal::CapsuleIdentityUnavailable))?;
    match store
        .put_if_absent(&key, &bytes)
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::CapsuleSlotConflict),
    }
    if !matches!(store.read_immutable(&key), Ok(ImmutableRead::Present(found)) if found == bytes) {
        return Err(LiveCapsuleRefusal::CapsuleReadbackMismatch);
    }
    match store
        .read_head(receipt.key())
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        HeadRead::Present(current) if current == *receipt => {}
        HeadRead::Present(_) => return Err(LiveCapsuleRefusal::HeadMoved),
        HeadRead::Absent => return Err(LiveCapsuleRefusal::HeadDisappeared),
    }
    let pointer = current_pointer
        .map_or_else(
            || CapsulePointer::genesis(capsule_id, &capsule),
            |pointer| pointer.advance(capsule_id, &capsule),
        )
        .map_err(LiveCapsuleRefusal::Capsule)?;
    Ok(FrozenCapsule {
        capsule,
        capsule_id,
        pointer,
    })
}

/// Async production twin of [`freeze_capsule`].
///
/// It has the same identity, staging, readback, and current-head decisions as
/// the deterministic surface above; only waiting is delegated to the one
/// runtime-owned authority context.
pub async fn freeze_capsule_async<S, I>(
    store: &S,
    cx: &S::Context,
    identity: &I,
    receipt: &HeadReadReceipt,
    current_pointer: Option<&CapsulePointer>,
    closure: CapsuleClosure,
) -> Result<FrozenCapsule, LiveCapsuleRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    I: BodyIdentity + ?Sized + Sync,
{
    store
        .authenticate_head_receipt(cx, receipt)
        .await
        .map_err(LiveCapsuleRefusal::HeadUnauthenticated)?;
    let head: RepositoryAuthorityHeadBody = decode_body(receipt.body(), DecodeLimits::DEFAULT)
        .map_err(LiveCapsuleRefusal::HeadDecode)?;
    if head.generation != receipt.generation() {
        return Err(LiveCapsuleRefusal::HeadGenerationMismatch);
    }
    let head_id = authority_head_identity(&head)
        .map_err(|error| LiveCapsuleRefusal::HeadIdentity(Box::new(error)))?;
    let capsule = RepositoryCapsuleBody::at_head(
        head_id,
        &head,
        current_pointer.map(CapsulePointer::capsule_id),
        closure.object_closure_root,
        closure.segment_manifest_root,
        closure.backup_profile,
    );
    let capsule_id = capsule_identity(identity, &capsule).map_err(LiveCapsuleRefusal::Capsule)?;
    let bytes = encode_body(&capsule).map_err(LiveCapsuleRefusal::CapsuleEncoding)?;
    let key = body_key(IdentityDomain::RepositoryCapsule, &capsule)
        .map_err(|_| LiveCapsuleRefusal::Capsule(ChronicleRefusal::CapsuleIdentityUnavailable))?;
    match store
        .put_if_absent(cx, &key, &bytes)
        .await
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        PutOutcome::Created | PutOutcome::IdenticalRetry => {}
        PutOutcome::Conflict => return Err(LiveCapsuleRefusal::CapsuleSlotConflict),
    }
    if !matches!(store.read_immutable(cx, &key).await, Ok(ImmutableRead::Present(found)) if found == bytes)
    {
        return Err(LiveCapsuleRefusal::CapsuleReadbackMismatch);
    }
    match store
        .read_head(cx, receipt.key())
        .await
        .map_err(LiveCapsuleRefusal::CapsuleStage)?
    {
        HeadRead::Present(current) if current == *receipt => {}
        HeadRead::Present(_) => return Err(LiveCapsuleRefusal::HeadMoved),
        HeadRead::Absent => return Err(LiveCapsuleRefusal::HeadDisappeared),
    }
    let pointer = current_pointer
        .map_or_else(
            || CapsulePointer::genesis(capsule_id, &capsule),
            |pointer| pointer.advance(capsule_id, &capsule),
        )
        .map_err(LiveCapsuleRefusal::Capsule)?;
    Ok(FrozenCapsule {
        capsule,
        capsule_id,
        pointer,
    })
}
