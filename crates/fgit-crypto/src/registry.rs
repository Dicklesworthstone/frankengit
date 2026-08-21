//! The versioned cryptographic registry: closed algorithm and identity-domain
//! enumerations.
//!
//! Plan section 11.3 requires internal immutable identities to come from "a
//! versioned cryptographic registry", and the bead that owns this crate
//! requires those rows to live in code as closed enumerations rather than as
//! strings assembled at a call site. Both registries are therefore exhaustive
//! Rust enums with stable numeric identifiers; adding a row is a source change
//! that moves the checked-in golden corpus, which is exactly the review point
//! an independent verifier needs.
//!
//! Two separation rules are encoded in the types rather than in prose:
//!
//! * SHA-1 is `GitIdentityOnly`. There is no way to name it as the algorithm
//!   of an internal domain, because [`IdentityDomain::algorithm`] returns
//!   [`InternalDigestAlgorithm`], whose v1 value set is `{ SHA-256 }`.
//! * Every internal domain carries its own tag, and the tag is committed into
//!   the digest preimage, so a digest computed for one domain does not verify
//!   under another.

use core::fmt;

use fgit_types::DomainTag;

/// Lifecycle of a registry row.
///
/// v1 has no retired rows; the variant exists so that retiring one is a data
/// change with an explicit meaning rather than a deletion that silently
/// renumbers the registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RowStatus {
    /// The row may be used to produce and verify identities.
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

/// How a registered digest algorithm is allowed to be used.
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

/// Every digest algorithm `FrankenGit` recognises.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    /// FIPS 180-4 SHA-1. Native Git identity for SHA-1 repositories.
    Sha1,
    /// FIPS 180-4 SHA-256. Native Git identity for SHA-256 repositories and
    /// the sole v1 internal-identity algorithm.
    Sha256,
}

impl DigestAlgorithm {
    /// Every registered algorithm, in registry order.
    pub const ALL: &'static [Self] = &[Self::Sha1, Self::Sha256];

    /// Stable numeric registry identifier.
    #[must_use]
    pub const fn registry_id(self) -> u16 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }

    /// Stable lowercase algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Digest width in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Digest width in lowercase hexadecimal characters.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        self.digest_len() * 2
    }

    /// Usage class for this algorithm.
    #[must_use]
    pub const fn usage(self) -> AlgorithmUsage {
        match self {
            Self::Sha1 => AlgorithmUsage::GitIdentityOnly,
            Self::Sha256 => AlgorithmUsage::GitAndInternalIdentity,
        }
    }

    /// The internal-identity algorithm this algorithm names, when it is
    /// permitted for internal identity at all.
    ///
    /// This is the typed refusal that keeps SHA-1 out of internal identities:
    /// `DigestAlgorithm::Sha1.internal_identity_algorithm()` is `None`, and
    /// there is no other route from a [`DigestAlgorithm`] to an internal
    /// digest.
    #[must_use]
    pub const fn internal_identity_algorithm(self) -> Option<InternalDigestAlgorithm> {
        match self {
            Self::Sha1 => None,
            Self::Sha256 => Some(InternalDigestAlgorithm::Sha256),
        }
    }

    /// Resolve an algorithm from its stable name.
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

/// The algorithms permitted for internal body identity.
///
/// v1 admits exactly one. The enumeration is not a placeholder: it is the
/// mechanism that makes "SHA-1 is never an internal identity" a statement the
/// compiler enforces instead of a comment, and it is the extension point a
/// future algorithm migration uses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InternalDigestAlgorithm {
    /// FIPS 180-4 SHA-256.
    Sha256,
}

impl InternalDigestAlgorithm {
    /// Every internal-identity algorithm, in registry order.
    pub const ALL: &'static [Self] = &[Self::Sha256];

    /// The corresponding entry in the general algorithm registry.
    #[must_use]
    pub const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::Sha256 => DigestAlgorithm::Sha256,
        }
    }

    /// Digest width in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        self.digest_algorithm().digest_len()
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
    /// Stable numeric identifier.
    pub registry_id: u16,
    /// The algorithm this row describes.
    pub algorithm: DigestAlgorithm,
    /// Stable lowercase name.
    pub name: &'static str,
    /// Digest width in bytes.
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
    /// Algorithm used for identities in this domain.
    pub algorithm: InternalDigestAlgorithm,
    /// The `registries/durable_objects.tsv` row this domain serves, when the
    /// domain names a durable object class.
    pub durable_object_row: Option<&'static str>,
    /// Row lifecycle.
    pub status: RowStatus,
}

/// Every identity-bearing internal body class.
///
/// The variants are drawn from plan section 11.3 and cross-referenced against
/// `registries/durable_objects.tsv`; the `ref-txn` domain additionally carries
/// the transaction-identity derivation fixed in NORMATIVE_PROTOCOL_CONTRACTS
/// section 3.3.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IdentityDomain {
    /// Strong internal commitment over one native Git object's framed bytes.
    GitPayloadCommitment,
    /// Internal envelope binding a native Git object to its stored form.
    GitObjectEnvelope,
    /// Repository segment body.
    RepositorySegment,
    /// Segment manifest body.
    SegmentManifest,
    /// Object-fabric microsegment body.
    GitObjectMicrosegment,
    /// Transaction seal body.
    TransactionSeal,
    /// Logical mutation identity for one sealed ref transaction.
    RefTransaction,
    /// Prepared transaction capsule body.
    PreparedTransactionCapsule,
    /// One terminal repository decision body.
    RepositoryDecision,
    /// Repository Commit Record body.
    RepositoryCommitRecord,
    /// Repository decision batch body.
    RepositoryDecisionBatch,
    /// Repository authority head body.
    RepositoryAuthorityHead,
    /// Forge event segment body.
    ForgeEventSegment,
    /// Forge checkpoint body.
    ForgeCheckpoint,
    /// Policy, key, and format checkpoint body.
    PolicyCheckpoint,
    /// Evidence record body.
    EvidenceRecord,
    /// Claim record body.
    ClaimRecord,
    /// Graph generation body.
    GraphGeneration,
    /// Search generation body.
    SearchGeneration,
    /// Document generation body.
    DocumentGeneration,
    /// `TreeFS` workspace snapshot body.
    TreefsSnapshot,
    /// Repository capsule body.
    RepositoryCapsule,
    /// Backup export bundle body.
    BackupExportBundle,
    /// Release asset body.
    ReleaseAsset,
    /// ATP transfer manifest body.
    AtpTransferManifest,
    /// Continuous-integration artifact body.
    CiArtifact,
}

/// The registry rows, in registry-identifier order.
///
/// This is the single source of truth: [`IdentityDomain`] accessors read it,
/// and the golden-corpus export serialises it.
pub const DOMAIN_REGISTRY: &[DomainRow] = &[
    domain_row(1, IdentityDomain::GitPayloadCommitment, "frankengit/git-payload-commitment/v1", Some("DUR-001")),
    domain_row(2, IdentityDomain::GitObjectEnvelope, "frankengit/git-object-envelope/v1", Some("DUR-001")),
    domain_row(3, IdentityDomain::RepositorySegment, "frankengit/repository-segment/v1", Some("DUR-002")),
    domain_row(4, IdentityDomain::SegmentManifest, "frankengit/segment-manifest/v1", Some("DUR-002")),
    domain_row(5, IdentityDomain::GitObjectMicrosegment, "frankengit/git-object-microsegment/v1", Some("DUR-016")),
    domain_row(6, IdentityDomain::TransactionSeal, "frankengit/transaction-seal/v1", Some("DUR-010")),
    domain_row(7, IdentityDomain::RefTransaction, "frankengit/ref-txn/v2", None),
    domain_row(8, IdentityDomain::PreparedTransactionCapsule, "frankengit/prepared-transaction-capsule/v1", Some("DUR-011")),
    domain_row(9, IdentityDomain::RepositoryDecision, "frankengit/repository-decision/v1", Some("DUR-003")),
    domain_row(10, IdentityDomain::RepositoryCommitRecord, "frankengit/repository-commit-record/v1", Some("DUR-003")),
    domain_row(11, IdentityDomain::RepositoryDecisionBatch, "frankengit/repository-decision-batch/v1", Some("DUR-003")),
    domain_row(12, IdentityDomain::RepositoryAuthorityHead, "frankengit/repository-authority-head/v1", Some("DUR-009")),
    domain_row(13, IdentityDomain::ForgeEventSegment, "frankengit/forge-event-segment/v1", Some("DUR-012")),
    domain_row(14, IdentityDomain::ForgeCheckpoint, "frankengit/forge-checkpoint/v1", Some("DUR-012")),
    domain_row(15, IdentityDomain::PolicyCheckpoint, "frankengit/policy-checkpoint/v1", Some("DUR-014")),
    domain_row(16, IdentityDomain::EvidenceRecord, "frankengit/evidence-record/v1", None),
    domain_row(17, IdentityDomain::ClaimRecord, "frankengit/claim-record/v1", None),
    domain_row(18, IdentityDomain::GraphGeneration, "frankengit/graph-generation/v1", Some("DUR-006")),
    domain_row(19, IdentityDomain::SearchGeneration, "frankengit/search-generation/v1", Some("DUR-005")),
    domain_row(20, IdentityDomain::DocumentGeneration, "frankengit/document-generation/v1", None),
    domain_row(21, IdentityDomain::TreefsSnapshot, "frankengit/treefs-snapshot/v1", Some("DUR-015")),
    domain_row(22, IdentityDomain::RepositoryCapsule, "frankengit/repository-capsule/v1", Some("DUR-004")),
    domain_row(23, IdentityDomain::BackupExportBundle, "frankengit/backup-export-bundle/v1", Some("DUR-013")),
    domain_row(24, IdentityDomain::ReleaseAsset, "frankengit/release-asset/v1", Some("DUR-017")),
    domain_row(25, IdentityDomain::AtpTransferManifest, "frankengit/atp-transfer-manifest/v1", Some("DUR-008")),
    domain_row(26, IdentityDomain::CiArtifact, "frankengit/ci-artifact/v1", Some("DUR-007")),
];

const fn domain_row(
    registry_id: u16,
    domain: IdentityDomain,
    tag: &'static str,
    durable_object_row: Option<&'static str>,
) -> DomainRow {
    DomainRow {
        registry_id,
        domain,
        tag,
        algorithm: InternalDigestAlgorithm::Sha256,
        durable_object_row,
        status: RowStatus::Active,
    }
}

/// The exported algorithm registry.
pub const ALGORITHM_REGISTRY: &[AlgorithmRow] = &[
    AlgorithmRow {
        registry_id: 1,
        algorithm: DigestAlgorithm::Sha1,
        name: "sha1",
        digest_len: 20,
        usage: AlgorithmUsage::GitIdentityOnly,
        status: RowStatus::Active,
    },
    AlgorithmRow {
        registry_id: 2,
        algorithm: DigestAlgorithm::Sha256,
        name: "sha256",
        digest_len: 32,
        usage: AlgorithmUsage::GitAndInternalIdentity,
        status: RowStatus::Active,
    },
];

impl IdentityDomain {
    /// Every identity domain, in registry order.
    pub const ALL: &'static [Self] = &[
        Self::GitPayloadCommitment,
        Self::GitObjectEnvelope,
        Self::RepositorySegment,
        Self::SegmentManifest,
        Self::GitObjectMicrosegment,
        Self::TransactionSeal,
        Self::RefTransaction,
        Self::PreparedTransactionCapsule,
        Self::RepositoryDecision,
        Self::RepositoryCommitRecord,
        Self::RepositoryDecisionBatch,
        Self::RepositoryAuthorityHead,
        Self::ForgeEventSegment,
        Self::ForgeCheckpoint,
        Self::PolicyCheckpoint,
        Self::EvidenceRecord,
        Self::ClaimRecord,
        Self::GraphGeneration,
        Self::SearchGeneration,
        Self::DocumentGeneration,
        Self::TreefsSnapshot,
        Self::RepositoryCapsule,
        Self::BackupExportBundle,
        Self::ReleaseAsset,
        Self::AtpTransferManifest,
        Self::CiArtifact,
    ];

    /// Position of this domain in [`DOMAIN_REGISTRY`].
    ///
    /// The enumeration is declared in registry order, so the discriminant is
    /// the row index; `domain_rows_match_the_enumeration` asserts it.
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

    /// Algorithm used for identities in this domain.
    #[must_use]
    pub const fn algorithm(self) -> InternalDigestAlgorithm {
        self.row().algorithm
    }

    /// The `registries/durable_objects.tsv` row this domain serves.
    #[must_use]
    pub const fn durable_object_row(self) -> Option<&'static str> {
        self.row().durable_object_row
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

    /// The domain tag as the bounded scalar `fgit-types` validates.
    ///
    /// Every registered tag satisfies the canonical-token rules, which the
    /// registry tests assert for all rows.
    #[must_use]
    pub fn domain_tag(self) -> DomainTag {
        DomainTag::new(self.tag()).expect("every registered domain tag is a canonical token")
    }
}

impl fmt::Display for IdentityDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}
