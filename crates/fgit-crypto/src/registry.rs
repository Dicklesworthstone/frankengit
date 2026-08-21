//! The versioned cryptographic registry: closed algorithm and identity-domain
//! enumerations.
//!
//! `fgit-types` deliberately owns no algorithm: it carries a
//! [`DigestAlgorithmId`] code point and states that "mapping a code point to a
//! concrete construction, declaring the output length of that construction,
//! and the migration policy between constructions all belong to the digest
//! registry in `fgit-crypto`". This module is that registry.
//!
//! Both registries are exhaustive Rust enumerations with stable numeric
//! identifiers, so adding a row is a source change that also moves the
//! checked-in golden corpus — which is the review point FG-002c's independent
//! verifier needs.
//!
//! Two separations are encoded in the types rather than in prose:
//!
//! * SHA-1 is `GitIdentityOnly`. Nothing can name it as the algorithm of an
//!   internal domain, because [`IdentityDomain::algorithm`] returns
//!   [`InternalDigestAlgorithm`], whose v1 value set is `{ SHA-256 }`, and the
//!   only bridge from [`DigestAlgorithm`] is
//!   [`DigestAlgorithm::internal_identity_algorithm`], which answers `None`
//!   for SHA-1.
//! * Every internal domain carries its own tag, and the tag is committed into
//!   the digest preimage, so a digest computed for one body class does not
//!   verify under another.
//!
//! Domain tags are not invented here where `fgit-types` already pins one. Its
//! derived identities (`TxId`, `TransactionSealId`, and the rest) each fix a
//! tag, and `domain_registry_covers_every_derived_identity_domain` asserts
//! that every one of them appears below. The additional rows cover durable
//! object classes from `registries/durable_objects.tsv` that have no derived
//! identity shell yet.

use core::fmt;

use fgit_types::hash::DigestAlgorithmId;
use fgit_types::label::DomainTag;
use fgit_types::native::GitHashAlgorithm as GitObjectFormat;

/// Lifecycle of a registry row.
///
/// v1 has no retired rows. The variant exists so that retiring a construction
/// is a data change with an explicit meaning, rather than a deletion that
/// silently renumbers the registry and re-points old code points.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RowStatus {
    /// The row may be used to produce and to verify identities.
    Active,
    /// The row may verify existing identities but must not produce new ones.
    Retired,
}

impl RowStatus {
    /// Stable lowercase token used in the exported golden corpus.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

/// How a registered digest construction is allowed to be used.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AlgorithmUsage {
    /// Native Git object identity only. Never an internal body identity.
    GitIdentityOnly,
    /// Native Git object identity and internal body identity.
    GitAndInternalIdentity,
}

impl AlgorithmUsage {
    /// Stable lowercase token used in the exported golden corpus.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::GitIdentityOnly => "git_identity_only",
            Self::GitAndInternalIdentity => "git_and_internal_identity",
        }
    }
}

/// Every digest construction this registry recognises.
///
/// The code points match `GitHashAlgorithm::code_point` in `fgit-types`, so an
/// identity that names SHA-1 as a digest construction and a repository that
/// declares the SHA-1 object format agree on the number 1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    /// FIPS 180-4 SHA-1. Native Git identity for SHA-1 repositories, and
    /// never an internal identity.
    Sha1,
    /// FIPS 180-4 SHA-256. Native Git identity for SHA-256 repositories and
    /// the sole v1 internal-identity construction.
    Sha256,
}

/// Digest-algorithm code points reserved for non-cryptographic corpus and
/// harness use, and never allocated by this registry.
///
/// `fgit-codec`'s golden corpus needs an algorithm slot for a fully specified
/// non-cryptographic function that carries no collision-resistance claim, so
/// that identity plumbing can be exercised without implying a security
/// property. Keeping that slot out of the registry's own range is what stops
/// a corpus identity from ever being mistaken for a real one.
pub const CORPUS_RESERVED_CODE_POINTS: core::ops::RangeInclusive<u16> = 0xfff0..=0xffff;

// A registered construction must never land in the corpus-reserved range.
const _: () = {
    let mut index = 0;
    while index < ALGORITHM_REGISTRY.len() {
        assert!(ALGORITHM_REGISTRY[index].code_point < 0xfff0);
        index += 1;
    }
};

impl DigestAlgorithm {
    /// Every registered construction, in code-point order.
    pub const ALL: &'static [Self] = &[Self::Sha1, Self::Sha256];

    /// Stable registry code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }

    /// The code point as the `fgit-types` shell carries it.
    #[must_use]
    pub fn id(self) -> DigestAlgorithmId {
        DigestAlgorithmId::try_new(self.code_point())
            .expect("every registry code point is non-zero")
    }

    /// Recover a construction from a code point carried by a shell.
    #[must_use]
    pub fn from_id(id: DigestAlgorithmId) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|algorithm| algorithm.code_point() == id.code_point())
    }

    /// Stable lowercase construction name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Output width in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Output width in lowercase hexadecimal characters.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        self.digest_len() * 2
    }

    /// Usage class for this construction.
    #[must_use]
    pub const fn usage(self) -> AlgorithmUsage {
        match self {
            Self::Sha1 => AlgorithmUsage::GitIdentityOnly,
            Self::Sha256 => AlgorithmUsage::GitAndInternalIdentity,
        }
    }

    /// The internal-identity construction this names, when it is permitted for
    /// internal identity at all.
    ///
    /// This is the typed refusal that keeps SHA-1 out of internal identities:
    /// `DigestAlgorithm::Sha1.internal_identity_algorithm()` is `None`, and
    /// there is no other route from a construction to an internal digest.
    #[must_use]
    pub const fn internal_identity_algorithm(self) -> Option<InternalDigestAlgorithm> {
        match self {
            Self::Sha1 => None,
            Self::Sha256 => Some(InternalDigestAlgorithm::Sha256),
        }
    }

    /// The declared repository object format that uses this construction.
    #[must_use]
    pub const fn git_object_format(self) -> GitObjectFormat {
        match self {
            Self::Sha1 => GitObjectFormat::Sha1,
            Self::Sha256 => GitObjectFormat::Sha256,
        }
    }

    /// The construction a declared repository object format uses.
    #[must_use]
    pub const fn from_git_object_format(format: GitObjectFormat) -> Self {
        match format {
            GitObjectFormat::Sha1 => Self::Sha1,
            GitObjectFormat::Sha256 => Self::Sha256,
        }
    }

    /// Resolve a construction from its stable name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|algorithm| algorithm.name() == name)
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The constructions permitted for internal body identity.
///
/// v1 admits exactly one. The enumeration is not a placeholder: it is the
/// mechanism that makes "SHA-1 is never an internal identity" a statement the
/// compiler enforces rather than a comment, and it is the extension point a
/// future construction migration uses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InternalDigestAlgorithm {
    /// FIPS 180-4 SHA-256.
    Sha256,
}

impl InternalDigestAlgorithm {
    /// Every internal-identity construction, in code-point order.
    pub const ALL: &'static [Self] = &[Self::Sha256];

    /// The corresponding entry in the general algorithm registry.
    #[must_use]
    pub const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::Sha256 => DigestAlgorithm::Sha256,
        }
    }

    /// Output width in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        self.digest_algorithm().digest_len()
    }

    /// The code point as the `fgit-types` shell carries it.
    #[must_use]
    pub fn id(self) -> DigestAlgorithmId {
        self.digest_algorithm().id()
    }
}

impl fmt::Display for InternalDigestAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.digest_algorithm().name())
    }
}

/// One exported row of the algorithm registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AlgorithmRow {
    /// Stable code point.
    pub code_point: u16,
    /// The construction this row describes.
    pub algorithm: DigestAlgorithm,
    /// Stable lowercase name.
    pub name: &'static str,
    /// Output width in bytes.
    pub digest_len: usize,
    /// Usage class.
    pub usage: AlgorithmUsage,
    /// Row lifecycle.
    pub status: RowStatus,
}

/// One exported row of the identity-domain registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DomainRow {
    /// Stable numeric identifier.
    pub registry_id: u16,
    /// The domain this row describes.
    pub domain: IdentityDomain,
    /// Canonical domain tag committed into the digest preimage.
    pub tag: &'static str,
    /// The same tag as the bounded label `fgit-types` validates.
    pub domain_tag: DomainTag,
    /// Construction used for identities in this domain.
    pub algorithm: InternalDigestAlgorithm,
    /// The `registries/durable_objects.tsv` row this domain serves, when the
    /// domain names a durable object class.
    pub durable_object_row: Option<&'static str>,
    /// The `fgit-types` derived identity that pins this tag, when one exists.
    pub derived_identity: Option<&'static str>,
    /// Row lifecycle.
    pub status: RowStatus,
}

/// Every identity-bearing internal body class.
///
/// Variants 1 to 14 carry the tags `fgit-types` pins on its derived
/// identities; the remainder cover durable object classes from
/// `registries/durable_objects.tsv` and plan section 11.3 that have no derived
/// identity shell yet.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentityDomain {
    /// One sealed logical mutation (`TxId`).
    RefTransaction,
    /// One transaction seal body (`TransactionSealId`).
    TransactionSeal,
    /// One prepared transaction capsule (`PreparedTxnCapsuleId`).
    PreparedTransactionCapsule,
    /// One Repository Commit Record (`RepositoryCommitId`).
    RepositoryCommitRecord,
    /// One repository decision batch body (`RepositoryDecisionBatchId`).
    RepositoryDecisionBatch,
    /// One repository authority head body (`RepositoryAuthorityHeadId`).
    RepositoryAuthorityHead,
    /// One immutable refusal record (`RefusalRecordId`).
    RefusalRecord,
    /// One repository checkpoint capsule (`RepositoryCapsuleId`).
    RepositoryCapsule,
    /// One immutable principal and capability snapshot (`PrincipalSnapshotId`).
    PrincipalSnapshot,
    /// One internal object envelope (`ObjectEnvelopeId`).
    ObjectEnvelope,
    /// One object-fabric segment manifest (`SegmentManifestId`).
    SegmentManifest,
    /// One canonical forge event body (`ForgeEventId`).
    ForgeEvent,
    /// One immutable evidence record (`EvidenceRecordId`).
    EvidenceRecord,
    /// One immutable search, graph, policy, or workspace generation
    /// (`GenerationId`).
    Generation,
    /// Strong internal commitment over one native Git object's framed bytes.
    GitPayloadCommitment,
    /// One repository segment body.
    RepositorySegment,
    /// One object-fabric microsegment body.
    GitObjectMicrosegment,
    /// One forge checkpoint body.
    ForgeCheckpoint,
    /// One policy, key, and format checkpoint body.
    PolicyCheckpoint,
    /// One immutable claim record.
    ClaimRecord,
    /// One `TreeFS` workspace snapshot body.
    TreefsSnapshot,
    /// One backup export bundle body.
    BackupExportBundle,
    /// One release asset body.
    ReleaseAsset,
    /// One ATP transfer manifest body.
    AtpTransferManifest,
    /// One continuous-integration artifact body.
    CiArtifact,
    /// One leaf of a segment or microsegment Merkle structure.
    ///
    /// Leaves and interior nodes are separate domains on purpose: a Merkle
    /// tree whose leaf and node hashing share a domain lets an interior node's
    /// preimage be presented as a leaf, which is the classic second-preimage
    /// construction against unseparated Merkle trees.
    MerkleLeaf,
    /// One interior node of a segment or microsegment Merkle structure.
    MerkleNode,
    /// One immutable admission receipt over a transaction seal identity.
    ///
    /// `NORMATIVE_PROTOCOL_CONTRACTS.md` section 5.2: admission capability,
    /// policy epoch, issuer, and first-seen time are "separate immutable
    /// admission receipts over the seal ID; they are not fields a retry must
    /// regenerate". They are therefore their own body class, and folding them
    /// into the seal body or reusing the evidence-record tag would either make
    /// a retry regenerate them or make a receipt forgeable as an evidence
    /// record.
    AdmissionReceipt,
    /// One source-span anchor into a parsed document.
    ///
    /// Plan section 28.4: an anchor binds source object, byte and codepoint
    /// spans, parse-profile identity, diff basis, and semantic context. Its
    /// canonical body is the injective anchor preimage; the digest of that
    /// body is the anchor's stable identity across re-parses.
    DocumentAnchor,
    /// One signed envelope body.
    ///
    /// The envelope carries a body together with detached attestations. Its
    /// own identity is a body identity in its own right, distinct from the
    /// identity of the body it wraps — adding or removing an attestation must
    /// change the envelope's identity and must not change the wrapped body's.
    SignedEnvelope,
}

/// The identity-domain registry, in registry-identifier order.
///
/// The enumeration is declared in this order, so a variant's discriminant is
/// its row index; `domain_rows_match_the_enumeration` asserts it.
pub const DOMAIN_REGISTRY: &[DomainRow] = &[
    pinned_row(
        1,
        IdentityDomain::RefTransaction,
        "frankengit/ref-txn/v2",
        None,
        "TxId",
    ),
    pinned_row(
        2,
        IdentityDomain::TransactionSeal,
        "frankengit/txn-seal/v1",
        Some("DUR-010"),
        "TransactionSealId",
    ),
    pinned_row(
        3,
        IdentityDomain::PreparedTransactionCapsule,
        "frankengit/prepared-capsule/v1",
        Some("DUR-011"),
        "PreparedTxnCapsuleId",
    ),
    pinned_row(
        4,
        IdentityDomain::RepositoryCommitRecord,
        "frankengit/rcr/v1",
        Some("DUR-003"),
        "RepositoryCommitId",
    ),
    pinned_row(
        5,
        IdentityDomain::RepositoryDecisionBatch,
        "frankengit/decision-batch/v1",
        Some("DUR-003"),
        "RepositoryDecisionBatchId",
    ),
    pinned_row(
        6,
        IdentityDomain::RepositoryAuthorityHead,
        "frankengit/authority-head/v1",
        Some("DUR-009"),
        "RepositoryAuthorityHeadId",
    ),
    pinned_row(
        7,
        IdentityDomain::RefusalRecord,
        "frankengit/refusal-record/v1",
        Some("DUR-003"),
        "RefusalRecordId",
    ),
    pinned_row(
        8,
        IdentityDomain::RepositoryCapsule,
        "frankengit/repository-capsule/v1",
        Some("DUR-004"),
        "RepositoryCapsuleId",
    ),
    pinned_row(
        9,
        IdentityDomain::PrincipalSnapshot,
        "frankengit/principal-snapshot/v1",
        None,
        "PrincipalSnapshotId",
    ),
    pinned_row(
        10,
        IdentityDomain::ObjectEnvelope,
        "frankengit/object-envelope/v1",
        Some("DUR-001"),
        "ObjectEnvelopeId",
    ),
    pinned_row(
        11,
        IdentityDomain::SegmentManifest,
        "frankengit/segment-manifest/v1",
        Some("DUR-002"),
        "SegmentManifestId",
    ),
    pinned_row(
        12,
        IdentityDomain::ForgeEvent,
        "frankengit/forge-event/v1",
        Some("DUR-012"),
        "ForgeEventId",
    ),
    pinned_row(
        13,
        IdentityDomain::EvidenceRecord,
        "frankengit/evidence-record/v1",
        None,
        "EvidenceRecordId",
    ),
    pinned_row(
        14,
        IdentityDomain::Generation,
        "frankengit/generation/v1",
        Some("DUR-005"),
        "GenerationId",
    ),
    owned_row(
        15,
        IdentityDomain::GitPayloadCommitment,
        "frankengit/git-payload-commitment/v1",
        Some("DUR-001"),
    ),
    owned_row(
        16,
        IdentityDomain::RepositorySegment,
        "frankengit/repository-segment/v1",
        Some("DUR-002"),
    ),
    owned_row(
        17,
        IdentityDomain::GitObjectMicrosegment,
        "frankengit/git-object-microsegment/v1",
        Some("DUR-016"),
    ),
    owned_row(
        18,
        IdentityDomain::ForgeCheckpoint,
        "frankengit/forge-checkpoint/v1",
        Some("DUR-012"),
    ),
    owned_row(
        19,
        IdentityDomain::PolicyCheckpoint,
        "frankengit/policy-checkpoint/v1",
        Some("DUR-014"),
    ),
    owned_row(
        20,
        IdentityDomain::ClaimRecord,
        "frankengit/claim-record/v1",
        None,
    ),
    owned_row(
        21,
        IdentityDomain::TreefsSnapshot,
        "frankengit/treefs-snapshot/v1",
        Some("DUR-015"),
    ),
    owned_row(
        22,
        IdentityDomain::BackupExportBundle,
        "frankengit/backup-export-bundle/v1",
        Some("DUR-013"),
    ),
    owned_row(
        23,
        IdentityDomain::ReleaseAsset,
        "frankengit/release-asset/v1",
        Some("DUR-017"),
    ),
    owned_row(
        24,
        IdentityDomain::AtpTransferManifest,
        "frankengit/atp-transfer-manifest/v1",
        Some("DUR-008"),
    ),
    owned_row(
        25,
        IdentityDomain::CiArtifact,
        "frankengit/ci-artifact/v1",
        Some("DUR-007"),
    ),
    owned_row(
        26,
        IdentityDomain::MerkleLeaf,
        "frankengit/merkle-leaf/v1",
        None,
    ),
    owned_row(
        27,
        IdentityDomain::MerkleNode,
        "frankengit/merkle-node/v1",
        None,
    ),
    owned_row(
        28,
        IdentityDomain::AdmissionReceipt,
        "frankengit/admission-receipt/v1",
        None,
    ),
    owned_row(
        29,
        IdentityDomain::DocumentAnchor,
        "frankengit/doc-anchor/v1",
        None,
    ),
    owned_row(
        30,
        IdentityDomain::SignedEnvelope,
        "frankengit/signed-envelope/v1",
        None,
    ),
];

const fn pinned_row(
    registry_id: u16,
    domain: IdentityDomain,
    tag: &'static str,
    durable_object_row: Option<&'static str>,
    derived_identity: &'static str,
) -> DomainRow {
    DomainRow {
        registry_id,
        domain,
        tag,
        domain_tag: DomainTag::from_static(tag),
        algorithm: InternalDigestAlgorithm::Sha256,
        durable_object_row,
        derived_identity: Some(derived_identity),
        status: RowStatus::Active,
    }
}

const fn owned_row(
    registry_id: u16,
    domain: IdentityDomain,
    tag: &'static str,
    durable_object_row: Option<&'static str>,
) -> DomainRow {
    DomainRow {
        registry_id,
        domain,
        tag,
        domain_tag: DomainTag::from_static(tag),
        algorithm: InternalDigestAlgorithm::Sha256,
        durable_object_row,
        derived_identity: None,
        status: RowStatus::Active,
    }
}

/// The algorithm registry, in code-point order.
pub const ALGORITHM_REGISTRY: &[AlgorithmRow] = &[
    AlgorithmRow {
        code_point: 1,
        algorithm: DigestAlgorithm::Sha1,
        name: "sha1",
        digest_len: 20,
        usage: AlgorithmUsage::GitIdentityOnly,
        status: RowStatus::Active,
    },
    AlgorithmRow {
        code_point: 2,
        algorithm: DigestAlgorithm::Sha256,
        name: "sha256",
        digest_len: 32,
        usage: AlgorithmUsage::GitAndInternalIdentity,
        status: RowStatus::Active,
    },
];

// A variant without a row would make `IdentityDomain::row` index past the end
// of the registry and panic at runtime. These assertions turn that into a
// compile error instead, and pin the discriminant-is-the-row-index invariant
// that `row` depends on.
const _: () = assert!(DOMAIN_REGISTRY.len() == IdentityDomain::ALL.len());
const _: () = {
    let mut index = 0;
    while index < DOMAIN_REGISTRY.len() {
        assert!(DOMAIN_REGISTRY[index].domain.index() == index);
        assert!(DOMAIN_REGISTRY[index].registry_id as usize == index + 1);
        index += 1;
    }
};
const _: () = assert!(ALGORITHM_REGISTRY.len() == DigestAlgorithm::ALL.len());
const _: () = {
    let mut index = 0;
    while index < ALGORITHM_REGISTRY.len() {
        assert!(ALGORITHM_REGISTRY[index].code_point as usize == index + 1);
        index += 1;
    }
};

impl IdentityDomain {
    /// Every identity domain, in registry order.
    pub const ALL: &'static [Self] = &[
        Self::RefTransaction,
        Self::TransactionSeal,
        Self::PreparedTransactionCapsule,
        Self::RepositoryCommitRecord,
        Self::RepositoryDecisionBatch,
        Self::RepositoryAuthorityHead,
        Self::RefusalRecord,
        Self::RepositoryCapsule,
        Self::PrincipalSnapshot,
        Self::ObjectEnvelope,
        Self::SegmentManifest,
        Self::ForgeEvent,
        Self::EvidenceRecord,
        Self::Generation,
        Self::GitPayloadCommitment,
        Self::RepositorySegment,
        Self::GitObjectMicrosegment,
        Self::ForgeCheckpoint,
        Self::PolicyCheckpoint,
        Self::ClaimRecord,
        Self::TreefsSnapshot,
        Self::BackupExportBundle,
        Self::ReleaseAsset,
        Self::AtpTransferManifest,
        Self::CiArtifact,
        Self::MerkleLeaf,
        Self::MerkleNode,
        Self::AdmissionReceipt,
        Self::DocumentAnchor,
        Self::SignedEnvelope,
    ];

    /// Position of this domain in [`DOMAIN_REGISTRY`].
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The registry row describing this domain.
    #[must_use]
    pub const fn row(self) -> &'static DomainRow {
        &DOMAIN_REGISTRY[self.index()]
    }

    /// Stable numeric registry identifier.
    #[must_use]
    pub const fn registry_id(self) -> u16 {
        self.row().registry_id
    }

    /// Canonical domain tag committed into the digest preimage.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        self.row().tag
    }

    /// The domain tag as the bounded label `fgit-types` validates.
    #[must_use]
    pub const fn domain_tag(self) -> DomainTag {
        self.row().domain_tag
    }

    /// Construction used for identities in this domain.
    #[must_use]
    pub const fn algorithm(self) -> InternalDigestAlgorithm {
        self.row().algorithm
    }

    /// The `registries/durable_objects.tsv` row this domain serves.
    #[must_use]
    pub const fn durable_object_row(self) -> Option<&'static str> {
        self.row().durable_object_row
    }

    /// The `fgit-types` derived identity that pins this tag, when one exists.
    #[must_use]
    pub const fn derived_identity(self) -> Option<&'static str> {
        self.row().derived_identity
    }

    /// Row lifecycle.
    #[must_use]
    pub const fn status(self) -> RowStatus {
        self.row().status
    }

    /// Resolve a domain from its canonical tag.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        DOMAIN_REGISTRY
            .iter()
            .find(|row| row.tag == tag)
            .map(|row| row.domain)
    }
}

impl fmt::Display for IdentityDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}
