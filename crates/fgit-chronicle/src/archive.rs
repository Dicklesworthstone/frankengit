//! Backup bundle and restore report bodies.
//!
//! These are the two durable records section 23 needs beside the capsule
//! itself. A backup bundle *attests to* a capsule — it says which capsule some
//! exported copy covers and under what profile — without being one. A restore
//! report is the audit trail for the one operation that may abandon an
//! acknowledged position.
//!
//! They carry distinct domain separation tags, `frankengit/backup-export-bundle/v1`
//! and `frankengit/restore-report/v1`, both registered in `fgit-crypto`. That
//! separation is doing real work rather than being tidy: if a bundle shared the
//! capsule's domain, a bundle's bytes could be presented where a capsule
//! pointer expects a target, and the pointer would accept an attestation as
//! the thing it attests to. Distinct domains make that unrepresentable instead
//! of something a check has to catch.
//!
//! # Identity
//!
//! Neither type carries a typed identity accessor yet. `fgit-types` has no
//! derived id for either domain, and minting one locally is exactly the
//! parallel-vocabulary mistake the type crate's owner asked everyone to avoid.
//! Identity still works today — `fgit_codec::body_id` takes the domain from
//! `B::DOMAIN`, so both bodies identify correctly and are domain-separated —
//! it just returns an `InternalObjectId` rather than a pinned wrapper. When the
//! ids land, the accessors become two thin functions and nothing here changes.

use core::fmt;

use fgit_authority::{AuthorityStore, HeadKey};
use fgit_codec::reader::Decoder;
use fgit_codec::writer::Encoder;
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody,
    canonical_body_bytes, decode_body, encode_body,
};
use fgit_crypto::{
    Capsule, DetachedSignature, DigestAlgorithm, DigestHasher, IdentityDomain, KeyEpoch,
    KeyLifecycle, KeyPurpose, SecretKey, Sha256Hasher, SignatureError, VerifyingKey,
};
use fgit_types::{
    Digest, DigestBytes, DomainTag, HeadGeneration, PrincipalId, RepositoryCapsuleId, RepositoryId,
    SchemaFamily,
};

use crate::capsule::BackupProfile;
use crate::recovery::{AuditedRestore, HaltReason};
use crate::refusal::ChronicleRefusal;
use crate::{
    AttestedBackupExport, CapsuleInspectionRefusal, ReplayCompleteness, RepositoryCapsuleBody,
    RestoreExecutionRefusal, RestoreOutcome, RestoredAuthorityBoundary, capsule_identity,
    inspect_capsule_against_authority_head_bytes, restore_attested_backup,
};

/// One exported copy of a repository, attesting to the capsule it covers.
///
/// The bundle does not restate the capsule's roots. Duplicating them would
/// create a second place for the same fact to be wrong, and the capsule is
/// already immutable and identified — naming it is strictly better than
/// copying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupExportBundleBody {
    /// Repository this bundle exports.
    pub repository_id: RepositoryId,
    /// The capsule whose position this bundle covers.
    pub capsule_id: RepositoryCapsuleId,
    /// How much of the repository the exported data covers.
    ///
    /// Kept here as well as in the capsule because an export may legitimately
    /// carry less than the capsule describes — a decision-history-only bundle
    /// of a full-closure capsule is a real thing, and a restore has to know.
    pub exported_profile: BackupProfile,
    /// Root over the exported byte inventory.
    pub export_inventory_root: Digest,
    /// Root over the durability evidence collected for the export.
    pub durability_evidence_root: Digest,
}

impl CanonicalBody for BackupExportBundleBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/backup-export-bundle/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("backup-export-bundle");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_internal_object_id(self.capsule_id.as_internal_object_id())?;
        out.write_raw_byte(self.exported_profile.discriminant());
        out.write_digest(&self.export_inventory_root)?;
        out.write_digest(&self.durability_evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let capsule_id =
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        let profile_byte = input.read_raw_byte("exported_profile")?;
        let exported_profile = BackupProfile::from_discriminant(profile_byte).map_err(|_| {
            CodecRefusal::from(fgit_types::TypeRefusal::CodePointUnknown {
                field: "exported_profile",
                observed: u32::from(profile_byte),
            })
        })?;
        let export_inventory_root = input.read_digest()?;
        let durability_evidence_root = input.read_digest()?;
        Ok(Self {
            repository_id,
            capsule_id,
            exported_profile,
            export_inventory_root,
            durability_evidence_root,
        })
    }
}

/// The durable record of one audited restore.
///
/// This is what makes "older-state recovery is an explicit audited restore"
/// auditable rather than merely stated. It names who authorized abandoning an
/// acknowledged position, what was abandoned, what was restored to, and both
/// generations — the one the restored content came from and the one the
/// authority now occupies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReportBody {
    /// Repository that was restored.
    pub repository_id: RepositoryId,
    /// Principal who authorized abandoning the acknowledged position.
    pub authorized_by: PrincipalId,
    /// The capsule that was abandoned, absent when no bytes were there at all.
    pub abandoned_capsule_id: Option<RepositoryCapsuleId>,
    /// The capsule whose content the repository was restored to.
    pub restored_capsule_id: RepositoryCapsuleId,
    /// Generation the restored content was originally taken at.
    pub restored_from_generation: HeadGeneration,
    /// Generation the authority occupies after the restore.
    ///
    /// Strictly greater than the abandoned position, because a restore moves
    /// the authority forward to a position carrying older content rather than
    /// rewinding it.
    pub new_generation: HeadGeneration,
    /// Why automated recovery halted and a human had to decide.
    pub halt_reason: HaltReason,
}

impl RestoreReportBody {
    /// Builds the durable record from an authorized restore.
    ///
    /// Taking the [`AuditedRestore`] rather than loose fields is the point: the
    /// report cannot describe a restore that was never authorized, and cannot
    /// disagree with the authorization about what was abandoned.
    #[must_use]
    pub const fn of(
        repository_id: RepositoryId,
        restore: &AuditedRestore,
        halt_reason: HaltReason,
    ) -> Self {
        Self {
            repository_id,
            authorized_by: restore.authorized_by(),
            abandoned_capsule_id: restore.abandoned(),
            restored_capsule_id: restore.restored_to(),
            restored_from_generation: restore.restored_from_generation(),
            new_generation: restore.new_generation(),
            halt_reason,
        }
    }

    /// Re-checks the invariant the authorization enforced.
    ///
    /// A report can arrive as data — replayed, or read back from a store — with
    /// no `AuditedRestore` behind it, so the property is checked here too.
    pub const fn verify(&self) -> Result<(), ChronicleRefusal> {
        if self.abandoned_generation_check() {
            Ok(())
        } else {
            Err(ChronicleRefusal::RestoreDoesNotAdvance {
                abandoned: self.restored_from_generation,
                proposed: self.new_generation,
            })
        }
    }

    const fn abandoned_generation_check(&self) -> bool {
        self.new_generation.get() > self.restored_from_generation.get()
    }
}

/// Wire discriminant for a halt reason.
const fn halt_discriminant(reason: HaltReason) -> u8 {
    match reason {
        HaltReason::AcknowledgedRootUnverified => 1,
        HaltReason::AcknowledgedRootAbsent => 2,
    }
}

/// Reads a halt discriminant, refusing one this build does not define.
const fn halt_from_discriminant(value: u8) -> Option<HaltReason> {
    match value {
        1 => Some(HaltReason::AcknowledgedRootUnverified),
        2 => Some(HaltReason::AcknowledgedRootAbsent),
        _ => None,
    }
}

impl CanonicalBody for RestoreReportBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/restore-report/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("restore-report");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.authorized_by.as_bytes());
        out.write_option(self.abandoned_capsule_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_internal_object_id(self.restored_capsule_id.as_internal_object_id())?;
        out.write_scalar(self.restored_from_generation.get());
        out.write_scalar(self.new_generation.get());
        out.write_raw_byte(halt_discriminant(self.halt_reason));
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let authorized_by = PrincipalId::from_bytes(input.read_opaque_id("authorized_by")?);
        let abandoned_capsule_id = input.read_option("abandoned_capsule_id", |input| {
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)
        })?;
        let restored_capsule_id =
            RepositoryCapsuleId::from_internal_object_id(input.read_internal_object_id()?)
                .map_err(CodecRefusal::from)?;
        let restored_from_generation =
            HeadGeneration::try_new(input.read_scalar::<u64>("restored_from_generation")?)?;
        let new_generation = HeadGeneration::try_new(input.read_scalar::<u64>("new_generation")?)?;
        let halt_byte = input.read_raw_byte("halt_reason")?;
        let halt_reason = halt_from_discriminant(halt_byte).ok_or_else(|| {
            CodecRefusal::from(fgit_types::TypeRefusal::CodePointUnknown {
                field: "halt_reason",
                observed: u32::from(halt_byte),
            })
        })?;
        Ok(Self {
            repository_id,
            authorized_by,
            abandoned_capsule_id,
            restored_capsule_id,
            restored_from_generation,
            new_generation,
            halt_reason,
        })
    }
}

/// Maximum distinct artifact classes a portable capsule archive can carry.
///
/// The archive vocabulary is intentionally closed. A newer writer must use a
/// new format version rather than smuggling an unbounded, unclassified blob
/// into a restore lane that cannot say how it was verified.
pub const MAX_PORTABLE_ARCHIVE_ARTIFACTS: usize = 8;
/// Largest byte payload for one portable archive artifact.
pub const MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Largest opaque verification-tool identity carried by one archive.
pub const MAX_VERIFICATION_TOOL_IDENTITY_BYTES: usize = 4 * 1024;

const PORTABLE_ARCHIVE_MAGIC: &[u8; 8] = b"FGCPARC\0";
const PORTABLE_ARCHIVE_VERSION: u16 = 1;
const INVENTORY_DOMAIN: &[u8] = b"frankengit/signed-capsule-archive-inventory/v1\0";

/// A byte class that a portable archive can carry beside a signed capsule.
///
/// The set is a restore vocabulary, not an authority vocabulary. It says
/// which exact byte class was transferred; it never decides what repository
/// state is current. That remains the authenticated authority-head chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PortableArchiveArtifactKind {
    /// Decision records after the capsule's checkpoint boundary.
    DecisionSuffix,
    /// Object closure bytes named by the capsule's object-closure root.
    ObjectClosure,
    /// Segment manifests that describe the included object closure.
    SegmentManifest,
    /// Repair symbols for the declared repair profile.
    RepairSymbols,
    /// Derived materializations required for a structural replay.
    Materializations,
}

impl PortableArchiveArtifactKind {
    const fn discriminant(self) -> u8 {
        match self {
            Self::DecisionSuffix => 1,
            Self::ObjectClosure => 2,
            Self::SegmentManifest => 3,
            Self::RepairSymbols => 4,
            Self::Materializations => 5,
        }
    }

    const fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::DecisionSuffix),
            2 => Some(Self::ObjectClosure),
            3 => Some(Self::SegmentManifest),
            4 => Some(Self::RepairSymbols),
            5 => Some(Self::Materializations),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::DecisionSuffix => "decision suffix",
            Self::ObjectClosure => "object closure",
            Self::SegmentManifest => "segment manifest",
            Self::RepairSymbols => "repair symbols",
            Self::Materializations => "materializations",
        }
    }
}

/// One actual artifact byte string included in a portable archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableArchiveArtifact {
    kind: PortableArchiveArtifactKind,
    bytes: Vec<u8>,
}

impl PortableArchiveArtifact {
    /// Adopts one bounded, non-empty artifact byte string.
    pub fn new(
        kind: PortableArchiveArtifactKind,
        bytes: Vec<u8>,
    ) -> Result<Self, PortableArchiveRefusal> {
        if bytes.is_empty() || bytes.len() > MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES {
            return Err(PortableArchiveRefusal::ArtifactLength {
                kind,
                observed: bytes.len(),
            });
        }
        Ok(Self { kind, bytes })
    }

    /// The class this byte string fulfils.
    #[must_use]
    pub const fn kind(&self) -> PortableArchiveArtifactKind {
        self.kind
    }

    /// The exact transferred bytes for this class.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Key-policy evidence carried by an archive.
///
/// This value is deliberately not a trust anchor. It records which policy the
/// exporter says applied, but [`TrustedCapsuleArchivePolicy`] must be supplied
/// independently by the verifier. Comparing the two makes a policy swap a
/// typed refusal rather than a self-attestation accepted as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapsuleArchiveSignerPolicy {
    policy_commitment: [u8; 32],
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    key_commitment: [u8; 32],
    verifying_key: VerifyingKey,
    lifecycle: KeyLifecycle,
}

impl CapsuleArchiveSignerPolicy {
    /// Produces the active policy evidence for a capsule-signing key.
    #[must_use]
    pub fn active_issuer(policy_commitment: [u8; 32], signer: &SecretKey<Capsule>) -> Self {
        Self {
            policy_commitment,
            purpose: KeyPurpose::Capsule,
            epoch: signer.id().epoch(),
            key_commitment: *signer.id().commitment(),
            verifying_key: signer.verifying_key(),
            lifecycle: KeyLifecycle::Active,
        }
    }

    /// The opaque commitment of the independently managed signer policy.
    #[must_use]
    pub const fn policy_commitment(&self) -> &[u8; 32] {
        &self.policy_commitment
    }

    /// The signing purpose the evidence declares.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The declared rotation epoch.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The declared commitment of the signing key material.
    #[must_use]
    pub const fn key_commitment(&self) -> &[u8; 32] {
        &self.key_commitment
    }

    /// The declared verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// The lifecycle the exporter says applied to this key epoch.
    #[must_use]
    pub const fn lifecycle(&self) -> KeyLifecycle {
        self.lifecycle
    }
}

/// An out-of-band trust decision for an archive signer policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedCapsuleArchivePolicy(CapsuleArchiveSignerPolicy);

impl TrustedCapsuleArchivePolicy {
    /// Adopts a policy obtained independently of the archive being verified.
    ///
    /// A revoked or erased epoch cannot become trusted merely because an
    /// archive repeats its old public key and signature.
    pub fn from_out_of_band(
        policy: CapsuleArchiveSignerPolicy,
    ) -> Result<Self, PortableArchiveRefusal> {
        if policy.purpose != KeyPurpose::Capsule {
            return Err(PortableArchiveRefusal::PolicyPurpose(policy.purpose));
        }
        if !policy.lifecycle.may_verify() {
            return Err(PortableArchiveRefusal::PolicyCannotVerify(policy.lifecycle));
        }
        Ok(Self(policy))
    }

    const fn policy(&self) -> &CapsuleArchiveSignerPolicy {
        &self.0
    }
}

/// Verification result for a signed portable capsule archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableArchiveVerification {
    capsule_id: RepositoryCapsuleId,
    replay_completeness: ReplayCompleteness,
}

impl PortableArchiveVerification {
    /// The capsule whose exact bytes and signer policy were verified.
    #[must_use]
    pub const fn capsule_id(&self) -> RepositoryCapsuleId {
        self.capsule_id
    }

    /// The strongest replay claim justified by the carried artifact classes.
    #[must_use]
    pub const fn replay_completeness(&self) -> ReplayCompleteness {
        self.replay_completeness
    }
}

/// Receipt from restoring a verified archive's authority boundary.
///
/// The existing root-last restore owns authority publication. This receipt
/// carries the verified immutable artifact bytes for the next replay stage;
/// it does not claim that an object-fabric or materializer has already applied
/// them, nor does it publish routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoredPortableCapsuleArchive {
    authority_boundary: RestoredAuthorityBoundary,
    artifacts: Vec<PortableArchiveArtifact>,
    verification_tool_identity: Vec<u8>,
    replay_completeness: ReplayCompleteness,
}

impl RestoredPortableCapsuleArchive {
    /// The root-last authority restore receipt.
    #[must_use]
    pub const fn authority_boundary(&self) -> &RestoredAuthorityBoundary {
        &self.authority_boundary
    }

    /// Actual replay inputs, retained in canonical artifact-class order.
    #[must_use]
    pub const fn artifacts(&self) -> &[PortableArchiveArtifact] {
        self.artifacts.as_slice()
    }

    /// The exact verification-tool identity that accompanied those inputs.
    #[must_use]
    pub fn verification_tool_identity(&self) -> &[u8] {
        &self.verification_tool_identity
    }

    /// The archive's explicitly bounded replay claim.
    #[must_use]
    pub const fn replay_completeness(&self) -> ReplayCompleteness {
        self.replay_completeness
    }
}

/// A signed, deterministic portable archive around an existing capsule.
///
/// The capsule signature preserves the native capsule identity. A second
/// signature covers the existing backup-export bundle, whose inventory root
/// commits to every transported byte. This uses registered S5/backup domains
/// rather than creating a parallel archive authority vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPortableCapsuleArchive {
    bundle: BackupExportBundleBody,
    capsule_bytes: Vec<u8>,
    authority_head_bytes: Vec<u8>,
    artifacts: Vec<PortableArchiveArtifact>,
    verification_tool_identity: Vec<u8>,
    signer_policy: CapsuleArchiveSignerPolicy,
    capsule_signature: DetachedSignature,
    inventory_signature: DetachedSignature,
    replay_completeness: ReplayCompleteness,
}

impl SignedPortableCapsuleArchive {
    /// Builds and signs a portable archive from exact, canonical source bodies.
    ///
    /// The bundle intentionally declares the existing decision-history
    /// attestation profile. The additional bytes are committed by its inventory
    /// root and are made available after the authority boundary restores; they
    /// do not change the pre-existing S5 restore vocabulary.
    pub fn sign(
        capsule: &RepositoryCapsuleBody,
        authority_head: &RepositoryAuthorityHeadBody,
        mut artifacts: Vec<PortableArchiveArtifact>,
        verification_tool_identity: Vec<u8>,
        durability_evidence_root: Digest,
        signer_policy: CapsuleArchiveSignerPolicy,
        signer: &SecretKey<Capsule>,
    ) -> Result<Self, PortableArchiveRefusal> {
        if signer_policy
            != CapsuleArchiveSignerPolicy::active_issuer(signer_policy.policy_commitment, signer)
        {
            return Err(PortableArchiveRefusal::IssuerPolicyMismatch);
        }
        if verification_tool_identity.is_empty()
            || verification_tool_identity.len() > MAX_VERIFICATION_TOOL_IDENTITY_BYTES
        {
            return Err(PortableArchiveRefusal::VerificationToolIdentityLength(
                verification_tool_identity.len(),
            ));
        }
        artifacts.sort_by_key(PortableArchiveArtifact::kind);
        validate_artifacts(capsule.backup_profile, &artifacts)?;

        let capsule_bytes = encode_body(capsule).map_err(PortableArchiveRefusal::CapsuleEncode)?;
        let authority_head_bytes =
            encode_body(authority_head).map_err(PortableArchiveRefusal::AuthorityHeadEncode)?;
        if capsule_bytes.len() > MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES
            || authority_head_bytes.len() > MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES
        {
            return Err(PortableArchiveRefusal::FieldTooLarge);
        }
        let capsule_id = capsule_identity(&CryptoBodyIdentity, capsule)
            .map_err(PortableArchiveRefusal::CapsuleIdentity)?;
        if capsule.repository_id != authority_head.repository_id {
            return Err(PortableArchiveRefusal::RepositoryMismatch);
        }
        let inspection = inspect_capsule_against_authority_head_bytes(
            &CryptoBodyIdentity,
            capsule_id,
            &capsule_bytes,
            &authority_head_bytes,
            authority_head.last_checkpoint_id,
        )
        .map_err(|error| PortableArchiveRefusal::Inspection(Box::new(error)))?;
        if inspection.classification().outcome() != RestoreOutcome::Restorable {
            return Err(PortableArchiveRefusal::NotRestorable(
                inspection.classification().outcome(),
            ));
        }
        let inventory_root = inventory_root(
            &capsule_bytes,
            &authority_head_bytes,
            &verification_tool_identity,
            &artifacts,
        );
        let bundle = BackupExportBundleBody {
            repository_id: capsule.repository_id,
            capsule_id,
            exported_profile: BackupProfile::DecisionHistoryOnly,
            export_inventory_root: inventory_root,
            durability_evidence_root,
        };
        let capsule_payload =
            canonical_body_bytes(capsule).map_err(PortableArchiveRefusal::CapsuleEncode)?;
        let bundle_payload =
            canonical_body_bytes(&bundle).map_err(PortableArchiveRefusal::BundleEncode)?;
        Ok(Self {
            bundle,
            capsule_bytes,
            authority_head_bytes,
            artifacts,
            verification_tool_identity,
            signer_policy,
            capsule_signature: signer.sign(
                IdentityDomain::RepositoryCapsule,
                RepositoryCapsuleBody::schema_id(),
                &capsule_payload,
            ),
            inventory_signature: signer.sign(
                IdentityDomain::BackupExportBundle,
                BackupExportBundleBody::schema_id(),
                &bundle_payload,
            ),
            replay_completeness: completeness_for(capsule.backup_profile),
        })
    }

    /// Canonical portable wire bytes. Repeated calls return byte-identical data.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PortableArchiveRefusal> {
        let bundle_bytes =
            encode_body(&self.bundle).map_err(PortableArchiveRefusal::BundleEncode)?;
        let mut output = Vec::with_capacity(
            PORTABLE_ARCHIVE_MAGIC.len()
                + bundle_bytes.len()
                + self.capsule_bytes.len()
                + self.authority_head_bytes.len()
                + self.verification_tool_identity.len()
                + self
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.bytes.len())
                    .sum::<usize>()
                + 256,
        );
        output.extend_from_slice(PORTABLE_ARCHIVE_MAGIC);
        write_u16(&mut output, PORTABLE_ARCHIVE_VERSION);
        write_bytes(&mut output, &bundle_bytes)?;
        write_bytes(&mut output, &self.capsule_bytes)?;
        write_bytes(&mut output, &self.authority_head_bytes)?;
        write_bytes(&mut output, &self.verification_tool_identity)?;
        write_u8(&mut output, replay_discriminant(self.replay_completeness));
        write_policy(&mut output, self.signer_policy);
        write_signature(&mut output, self.capsule_signature);
        write_signature(&mut output, self.inventory_signature);
        write_u8(
            &mut output,
            u8::try_from(self.artifacts.len())
                .map_err(|_| PortableArchiveRefusal::TooManyArtifacts)?,
        );
        for artifact in &self.artifacts {
            write_u8(&mut output, artifact.kind.discriminant());
            write_bytes(&mut output, &artifact.bytes)?;
        }
        Ok(output)
    }

    /// Decodes an untrusted portable archive with bounds checked before each allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PortableArchiveRefusal> {
        let mut input = ArchiveReader::new(bytes);
        if input.take(PORTABLE_ARCHIVE_MAGIC.len())? != PORTABLE_ARCHIVE_MAGIC {
            return Err(PortableArchiveRefusal::WrongMagic);
        }
        if input.read_u16()? != PORTABLE_ARCHIVE_VERSION {
            return Err(PortableArchiveRefusal::UnsupportedVersion);
        }
        let bundle_bytes = input.read_bytes(MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES)?;
        let bundle: BackupExportBundleBody = decode_body(&bundle_bytes, DecodeLimits::DEFAULT)
            .map_err(PortableArchiveRefusal::BundleDecode)?;
        let capsule_bytes = input.read_bytes(MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES)?;
        let authority_head_bytes = input.read_bytes(MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES)?;
        let verification_tool_identity = input.read_bytes(MAX_VERIFICATION_TOOL_IDENTITY_BYTES)?;
        if verification_tool_identity.is_empty() {
            return Err(PortableArchiveRefusal::VerificationToolIdentityLength(0));
        }
        let replay_completeness = replay_from_discriminant(input.read_u8()?)
            .ok_or(PortableArchiveRefusal::UnknownReplayCompleteness)?;
        let signer_policy = read_policy(&mut input)?;
        let capsule_signature = read_signature(&mut input)?;
        let inventory_signature = read_signature(&mut input)?;
        let count = usize::from(input.read_u8()?);
        if count > MAX_PORTABLE_ARCHIVE_ARTIFACTS {
            return Err(PortableArchiveRefusal::TooManyArtifacts);
        }
        let mut artifacts = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = PortableArchiveArtifactKind::from_discriminant(input.read_u8()?)
                .ok_or(PortableArchiveRefusal::UnknownArtifactKind)?;
            artifacts.push(PortableArchiveArtifact::new(
                kind,
                input.read_bytes(MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES)?,
            )?);
        }
        if !input.is_empty() {
            return Err(PortableArchiveRefusal::TrailingBytes);
        }
        let capsule: RepositoryCapsuleBody = decode_body(&capsule_bytes, DecodeLimits::DEFAULT)
            .map_err(PortableArchiveRefusal::CapsuleDecode)?;
        validate_artifacts(capsule.backup_profile, &artifacts)?;
        if replay_completeness != completeness_for(capsule.backup_profile) {
            return Err(PortableArchiveRefusal::ReplayCompletenessMismatch);
        }
        Ok(Self {
            bundle,
            capsule_bytes,
            authority_head_bytes,
            artifacts,
            verification_tool_identity,
            signer_policy,
            capsule_signature,
            inventory_signature,
            replay_completeness,
        })
    }

    /// Verifies exact bytes, canonical capsule/head agreement, inventory, and
    /// both signatures against an independently trusted policy.
    pub fn verify(
        &self,
        trusted: &TrustedCapsuleArchivePolicy,
    ) -> Result<PortableArchiveVerification, PortableArchiveRefusal> {
        if self.signer_policy != *trusted.policy() {
            return Err(PortableArchiveRefusal::PolicyNotTrusted);
        }
        verify_signature_policy(self.capsule_signature, self.signer_policy)?;
        verify_signature_policy(self.inventory_signature, self.signer_policy)?;
        let capsule: RepositoryCapsuleBody =
            decode_body(&self.capsule_bytes, DecodeLimits::DEFAULT)
                .map_err(PortableArchiveRefusal::CapsuleDecode)?;
        let head: RepositoryAuthorityHeadBody =
            decode_body(&self.authority_head_bytes, DecodeLimits::DEFAULT)
                .map_err(PortableArchiveRefusal::AuthorityHeadDecode)?;
        let capsule_id = capsule_identity(&CryptoBodyIdentity, &capsule)
            .map_err(PortableArchiveRefusal::CapsuleIdentity)?;
        if self.bundle.repository_id != capsule.repository_id
            || head.repository_id != capsule.repository_id
        {
            return Err(PortableArchiveRefusal::RepositoryMismatch);
        }
        if self.bundle.capsule_id != capsule_id {
            return Err(PortableArchiveRefusal::BundleCapsuleMismatch);
        }
        if self.bundle.exported_profile != BackupProfile::DecisionHistoryOnly {
            return Err(PortableArchiveRefusal::BundleProfileMismatch);
        }
        validate_artifacts(capsule.backup_profile, &self.artifacts)?;
        if self.replay_completeness != completeness_for(capsule.backup_profile) {
            return Err(PortableArchiveRefusal::ReplayCompletenessMismatch);
        }
        if self.bundle.export_inventory_root
            != inventory_root(
                &self.capsule_bytes,
                &self.authority_head_bytes,
                &self.verification_tool_identity,
                &self.artifacts,
            )
        {
            return Err(PortableArchiveRefusal::InventoryMismatch);
        }
        let inspection = inspect_capsule_against_authority_head_bytes(
            &CryptoBodyIdentity,
            capsule_id,
            &self.capsule_bytes,
            &self.authority_head_bytes,
            head.last_checkpoint_id,
        )
        .map_err(|error| PortableArchiveRefusal::Inspection(Box::new(error)))?;
        if inspection.classification().outcome() != RestoreOutcome::Restorable {
            return Err(PortableArchiveRefusal::NotRestorable(
                inspection.classification().outcome(),
            ));
        }
        let capsule_payload =
            canonical_body_bytes(&capsule).map_err(PortableArchiveRefusal::CapsuleEncode)?;
        self.capsule_signature
            .verify_with(
                &trusted.policy().verifying_key,
                IdentityDomain::RepositoryCapsule,
                RepositoryCapsuleBody::schema_id(),
                &capsule_payload,
            )
            .map_err(PortableArchiveRefusal::Signature)?;
        let bundle_payload =
            canonical_body_bytes(&self.bundle).map_err(PortableArchiveRefusal::BundleEncode)?;
        self.inventory_signature
            .verify_with(
                &trusted.policy().verifying_key,
                IdentityDomain::BackupExportBundle,
                BackupExportBundleBody::schema_id(),
                &bundle_payload,
            )
            .map_err(PortableArchiveRefusal::Signature)?;
        Ok(PortableArchiveVerification {
            capsule_id,
            replay_completeness: self.replay_completeness,
        })
    }

    /// Restores the verified archive's authority boundary root-last and
    /// returns the authenticated replay inputs without publishing routing.
    pub fn restore<S>(
        &self,
        destination: &S,
        destination_key: &HeadKey,
        trusted: &TrustedCapsuleArchivePolicy,
    ) -> Result<RestoredPortableCapsuleArchive, PortableArchiveRefusal>
    where
        S: AuthorityStore + ?Sized,
    {
        let verification = self.verify(trusted)?;
        let authority_boundary = restore_attested_backup(
            destination,
            destination_key,
            &CryptoBodyIdentity,
            &AttestedBackupExport::new(
                self.bundle.clone(),
                self.capsule_bytes.clone(),
                self.authority_head_bytes.clone(),
            ),
        )
        .map_err(PortableArchiveRefusal::Restore)?;
        Ok(RestoredPortableCapsuleArchive {
            authority_boundary,
            artifacts: self.artifacts.clone(),
            verification_tool_identity: self.verification_tool_identity.clone(),
            replay_completeness: verification.replay_completeness,
        })
    }
}

/// Refusal from constructing, decoding, verifying, or restoring an archive.
#[derive(Debug)]
pub enum PortableArchiveRefusal {
    /// Artifact bytes were empty or exceeded the pre-allocation bound.
    ArtifactLength {
        kind: PortableArchiveArtifactKind,
        observed: usize,
    },
    /// The archive carried too many artifact classes.
    TooManyArtifacts,
    /// Artifact classes must be strictly increasing and unique.
    ArtifactOrder,
    /// The declared capsule profile requires this absent byte class.
    MissingArtifact(PortableArchiveArtifactKind),
    /// Verification-tool identity was missing or exceeded its bound.
    VerificationToolIdentityLength(usize),
    /// The policy was not an active capsule-signing policy for the supplied key.
    IssuerPolicyMismatch,
    /// A purported trust policy named a non-capsule purpose.
    PolicyPurpose(KeyPurpose),
    /// A revoked or erased policy cannot verify existing archive signatures.
    PolicyCannotVerify(KeyLifecycle),
    /// Archive policy evidence disagreed with the caller's independent policy.
    PolicyNotTrusted,
    /// A signature's declared key material disagreed with its carried policy.
    SignaturePolicyMismatch,
    /// Encoding the capsule failed.
    CapsuleEncode(CodecRefusal),
    /// Decoding the capsule failed.
    CapsuleDecode(CodecRefusal),
    /// Identifying the canonical capsule failed.
    CapsuleIdentity(ChronicleRefusal),
    /// Encoding the source authority head failed.
    AuthorityHeadEncode(CodecRefusal),
    /// Decoding the source authority head failed.
    AuthorityHeadDecode(CodecRefusal),
    /// Encoding the existing backup bundle failed.
    BundleEncode(CodecRefusal),
    /// Decoding the existing backup bundle failed.
    BundleDecode(CodecRefusal),
    /// Capsule, bundle, and head did not name one repository.
    RepositoryMismatch,
    /// The bundle did not name the canonical capsule bytes it carried.
    BundleCapsuleMismatch,
    /// The bundle did not retain the attestation-only authority vocabulary.
    BundleProfileMismatch,
    /// Actual transferred bytes disagreed with the signed inventory root.
    InventoryMismatch,
    /// Capsule and authority head bytes did not pass the existing inspection.
    Inspection(Box<CapsuleInspectionRefusal>),
    /// Inspection classified the capsule/head boundary as non-restorable.
    NotRestorable(RestoreOutcome),
    /// Signature verification refused the envelope.
    Signature(SignatureError),
    /// Archive magic was not recognised.
    WrongMagic,
    /// Archive format version was not supported.
    UnsupportedVersion,
    /// Archive ended before a declared bounded field completed.
    Truncated,
    /// Archive included bytes after its complete final artifact.
    TrailingBytes,
    /// An artifact discriminant was not part of the closed vocabulary.
    UnknownArtifactKind,
    /// Archive replay claim was not part of the closed vocabulary.
    UnknownReplayCompleteness,
    /// Archive replay claim did not match its declared capsule profile.
    ReplayCompletenessMismatch,
    /// Archive carried an unknown key-purpose code point.
    UnknownKeyPurpose,
    /// Archive carried a zero key epoch.
    InvalidKeyEpoch,
    /// Archive carried an unknown key lifecycle discriminant.
    UnknownKeyLifecycle,
    /// An encoded field cannot fit in the portable wire length slot.
    FieldTooLarge,
    /// The existing authority-boundary restore refused.
    Restore(RestoreExecutionRefusal),
}

impl fmt::Display for PortableArchiveRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactLength { kind, observed } => write!(
                formatter,
                "{} artifact has invalid byte length {observed}",
                kind.label()
            ),
            Self::TooManyArtifacts => {
                formatter.write_str("portable archive has too many artifacts")
            }
            Self::ArtifactOrder => {
                formatter.write_str("portable archive artifact classes are not canonical")
            }
            Self::MissingArtifact(kind) => {
                write!(formatter, "portable archive lacks {} bytes", kind.label())
            }
            Self::VerificationToolIdentityLength(observed) => write!(
                formatter,
                "portable archive verification-tool identity has invalid length {observed}"
            ),
            Self::IssuerPolicyMismatch => {
                formatter.write_str("archive issuer key disagrees with active policy evidence")
            }
            Self::PolicyPurpose(purpose) => write!(
                formatter,
                "archive policy has non-capsule purpose {purpose}"
            ),
            Self::PolicyCannotVerify(lifecycle) => write!(
                formatter,
                "archive policy lifecycle {lifecycle} cannot verify"
            ),
            Self::PolicyNotTrusted => formatter
                .write_str("archive policy evidence is not the independently trusted policy"),
            Self::SignaturePolicyMismatch => {
                formatter.write_str("archive signature disagrees with signer policy evidence")
            }
            Self::CapsuleEncode(error) => write!(formatter, "could not encode capsule: {error}"),
            Self::CapsuleDecode(error) => write!(formatter, "could not decode capsule: {error}"),
            Self::CapsuleIdentity(error) => {
                write!(formatter, "could not identify capsule: {error}")
            }
            Self::AuthorityHeadEncode(error) => {
                write!(formatter, "could not encode authority head: {error}")
            }
            Self::AuthorityHeadDecode(error) => {
                write!(formatter, "could not decode authority head: {error}")
            }
            Self::BundleEncode(error) => {
                write!(formatter, "could not encode backup bundle: {error}")
            }
            Self::BundleDecode(error) => {
                write!(formatter, "could not decode backup bundle: {error}")
            }
            Self::RepositoryMismatch => formatter
                .write_str("archive capsule, bundle, and authority head disagree on repository"),
            Self::BundleCapsuleMismatch => {
                formatter.write_str("archive bundle does not name its carried capsule")
            }
            Self::BundleProfileMismatch => formatter
                .write_str("archive bundle did not retain the existing attestation profile"),
            Self::InventoryMismatch => {
                formatter.write_str("archive bytes disagree with signed inventory root")
            }
            Self::Inspection(error) => {
                write!(formatter, "archive capsule inspection refused: {error}")
            }
            Self::NotRestorable(outcome) => write!(
                formatter,
                "archive capsule is not restorable: {}",
                outcome.as_str()
            ),
            Self::Signature(error) => {
                write!(formatter, "archive signature verification refused: {error}")
            }
            Self::WrongMagic => formatter.write_str("portable archive magic is not recognised"),
            Self::UnsupportedVersion => {
                formatter.write_str("portable archive version is not supported")
            }
            Self::Truncated => formatter.write_str("portable archive is truncated"),
            Self::TrailingBytes => formatter.write_str("portable archive contains trailing bytes"),
            Self::UnknownArtifactKind => {
                formatter.write_str("portable archive has an unknown artifact class")
            }
            Self::UnknownReplayCompleteness => {
                formatter.write_str("portable archive has an unknown replay claim")
            }
            Self::ReplayCompletenessMismatch => {
                formatter.write_str("portable archive replay claim does not match its contents")
            }
            Self::UnknownKeyPurpose => {
                formatter.write_str("portable archive has an unknown key purpose")
            }
            Self::InvalidKeyEpoch => {
                formatter.write_str("portable archive has a reserved key epoch")
            }
            Self::UnknownKeyLifecycle => {
                formatter.write_str("portable archive has an unknown key lifecycle")
            }
            Self::FieldTooLarge => {
                formatter.write_str("portable archive field exceeds wire length capacity")
            }
            Self::Restore(error) => write!(
                formatter,
                "portable archive authority restore refused: {error}"
            ),
        }
    }
}

impl std::error::Error for PortableArchiveRefusal {}

fn validate_artifacts(
    profile: BackupProfile,
    artifacts: &[PortableArchiveArtifact],
) -> Result<(), PortableArchiveRefusal> {
    if artifacts.len() > MAX_PORTABLE_ARCHIVE_ARTIFACTS {
        return Err(PortableArchiveRefusal::TooManyArtifacts);
    }
    let mut previous = None;
    for artifact in artifacts {
        if artifact.bytes.is_empty() || artifact.bytes.len() > MAX_PORTABLE_ARCHIVE_ARTIFACT_BYTES {
            return Err(PortableArchiveRefusal::ArtifactLength {
                kind: artifact.kind,
                observed: artifact.bytes.len(),
            });
        }
        if previous.is_some_and(|prior| prior >= artifact.kind) {
            return Err(PortableArchiveRefusal::ArtifactOrder);
        }
        previous = Some(artifact.kind);
    }
    for required in required_artifacts(profile) {
        if !artifacts.iter().any(|artifact| artifact.kind == *required) {
            return Err(PortableArchiveRefusal::MissingArtifact(*required));
        }
    }
    Ok(())
}

const fn required_artifacts(profile: BackupProfile) -> &'static [PortableArchiveArtifactKind] {
    match profile {
        BackupProfile::DecisionHistoryOnly => &[PortableArchiveArtifactKind::DecisionSuffix],
        BackupProfile::FullClosure => &[
            PortableArchiveArtifactKind::DecisionSuffix,
            PortableArchiveArtifactKind::ObjectClosure,
            PortableArchiveArtifactKind::SegmentManifest,
        ],
        BackupProfile::FullClosureWithRepair => &[
            PortableArchiveArtifactKind::DecisionSuffix,
            PortableArchiveArtifactKind::ObjectClosure,
            PortableArchiveArtifactKind::SegmentManifest,
            PortableArchiveArtifactKind::RepairSymbols,
        ],
    }
}

const fn completeness_for(profile: BackupProfile) -> ReplayCompleteness {
    match profile {
        BackupProfile::DecisionHistoryOnly => ReplayCompleteness::VerifiableIfArtifactsSupplied,
        BackupProfile::FullClosure | BackupProfile::FullClosureWithRepair => {
            ReplayCompleteness::StructuralReplay
        }
    }
}

const fn replay_discriminant(value: ReplayCompleteness) -> u8 {
    match value {
        ReplayCompleteness::Replayable => 1,
        ReplayCompleteness::StructuralReplay => 2,
        ReplayCompleteness::VerifiableIfArtifactsSupplied => 3,
        ReplayCompleteness::AuditOnly => 4,
    }
}

const fn replay_from_discriminant(value: u8) -> Option<ReplayCompleteness> {
    match value {
        1 => Some(ReplayCompleteness::Replayable),
        2 => Some(ReplayCompleteness::StructuralReplay),
        3 => Some(ReplayCompleteness::VerifiableIfArtifactsSupplied),
        4 => Some(ReplayCompleteness::AuditOnly),
        _ => None,
    }
}

fn inventory_root(
    capsule_bytes: &[u8],
    authority_head_bytes: &[u8],
    verification_tool_identity: &[u8],
    artifacts: &[PortableArchiveArtifact],
) -> Digest {
    let mut hasher = Sha256Hasher::new();
    hasher.update(INVENTORY_DOMAIN);
    hash_field(&mut hasher, capsule_bytes);
    hash_field(&mut hasher, authority_head_bytes);
    hash_field(&mut hasher, verification_tool_identity);
    hasher.update(
        &u64::try_from(artifacts.len())
            .expect("artifact count fits u64")
            .to_be_bytes(),
    );
    for artifact in artifacts {
        hasher.update(&[artifact.kind.discriminant()]);
        hash_field(&mut hasher, &artifact.bytes);
    }
    let bytes = hasher.finish();
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&bytes).expect("SHA-256 output is a valid digest body"),
    )
}

fn hash_field(hasher: &mut Sha256Hasher, bytes: &[u8]) {
    hasher.update(
        &u64::try_from(bytes.len())
            .expect("slice length fits u64")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

fn verify_signature_policy(
    signature: DetachedSignature,
    policy: CapsuleArchiveSignerPolicy,
) -> Result<(), PortableArchiveRefusal> {
    if signature.purpose() != policy.purpose
        || signature.epoch() != policy.epoch
        || signature.key_commitment() != &policy.key_commitment
        || signature.declared_verifying_key() != policy.verifying_key
    {
        return Err(PortableArchiveRefusal::SignaturePolicyMismatch);
    }
    Ok(())
}

fn write_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PortableArchiveRefusal> {
    write_u32(
        output,
        u32::try_from(bytes.len()).map_err(|_| PortableArchiveRefusal::FieldTooLarge)?,
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_policy(output: &mut Vec<u8>, policy: CapsuleArchiveSignerPolicy) {
    output.extend_from_slice(&policy.policy_commitment);
    write_u16(output, policy.purpose.code_point());
    write_u32(output, policy.epoch.get());
    output.extend_from_slice(&policy.key_commitment);
    output.extend_from_slice(policy.verifying_key.as_bytes());
    write_u8(output, lifecycle_discriminant(policy.lifecycle));
}

fn read_policy(
    input: &mut ArchiveReader<'_>,
) -> Result<CapsuleArchiveSignerPolicy, PortableArchiveRefusal> {
    let policy_commitment = input.read_array()?;
    let purpose = KeyPurpose::from_code_point(input.read_u16()?)
        .ok_or(PortableArchiveRefusal::UnknownKeyPurpose)?;
    let epoch = KeyEpoch::new(input.read_u32()?).ok_or(PortableArchiveRefusal::InvalidKeyEpoch)?;
    let key_commitment = input.read_array()?;
    let verifying_key = VerifyingKey::from_bytes(input.read_array()?);
    let lifecycle = lifecycle_from_discriminant(input.read_u8()?)
        .ok_or(PortableArchiveRefusal::UnknownKeyLifecycle)?;
    Ok(CapsuleArchiveSignerPolicy {
        policy_commitment,
        purpose,
        epoch,
        key_commitment,
        verifying_key,
        lifecycle,
    })
}

const fn lifecycle_discriminant(value: KeyLifecycle) -> u8 {
    match value {
        KeyLifecycle::Active => 1,
        KeyLifecycle::Retired => 2,
        KeyLifecycle::Revoked => 3,
        KeyLifecycle::Erased => 4,
    }
}

const fn lifecycle_from_discriminant(value: u8) -> Option<KeyLifecycle> {
    match value {
        1 => Some(KeyLifecycle::Active),
        2 => Some(KeyLifecycle::Retired),
        3 => Some(KeyLifecycle::Revoked),
        4 => Some(KeyLifecycle::Erased),
        _ => None,
    }
}

fn write_signature(output: &mut Vec<u8>, signature: DetachedSignature) {
    write_u16(output, signature.scheme());
    write_u16(output, signature.purpose().code_point());
    write_u32(output, signature.epoch().get());
    output.extend_from_slice(signature.key_commitment());
    output.extend_from_slice(signature.declared_verifying_key().as_bytes());
    output.extend_from_slice(signature.signature());
}

fn read_signature(
    input: &mut ArchiveReader<'_>,
) -> Result<DetachedSignature, PortableArchiveRefusal> {
    let scheme = input.read_u16()?;
    let purpose = KeyPurpose::from_code_point(input.read_u16()?)
        .ok_or(PortableArchiveRefusal::UnknownKeyPurpose)?;
    let epoch = KeyEpoch::new(input.read_u32()?).ok_or(PortableArchiveRefusal::InvalidKeyEpoch)?;
    let key_commitment = input.read_array()?;
    let verifying_key = input.read_array()?;
    let signature = input.read_array()?;
    Ok(DetachedSignature::from_parts(
        scheme,
        purpose,
        epoch,
        key_commitment,
        verifying_key,
        signature,
    ))
}

struct ArchiveReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ArchiveReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    const fn take(&mut self, length: usize) -> Result<&'a [u8], PortableArchiveRefusal> {
        if length > self.remaining.len() {
            return Err(PortableArchiveRefusal::Truncated);
        }
        let (taken, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(taken)
    }

    fn read_u8(&mut self) -> Result<u8, PortableArchiveRefusal> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PortableArchiveRefusal> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| PortableArchiveRefusal::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, PortableArchiveRefusal> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| PortableArchiveRefusal::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PortableArchiveRefusal> {
        self.take(N)?
            .try_into()
            .map_err(|_| PortableArchiveRefusal::Truncated)
    }

    fn read_bytes(&mut self, limit: usize) -> Result<Vec<u8>, PortableArchiveRefusal> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| PortableArchiveRefusal::FieldTooLarge)?;
        if length > limit {
            return Err(PortableArchiveRefusal::FieldTooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }
}
