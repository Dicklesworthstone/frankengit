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
//
// WHY THIS BLOCK IS NON-VACUOUS, AND IT IS NOT THE CONSTRUCT. A `while` loop
// over a const array asserts nothing about an EMPTY array: the body never runs
// and the guard compiles while proving nothing. Measured, not reasoned --
// YellowOak (cc_2) compiled this shape against an empty registry and it passed
// clean, against one violating row and it failed E0080. So the pattern is
// silently vacuous if transplanted to a registry that can be empty.
//
// What saves THIS one is a sibling three hundred lines down:
//     registry.rs  const _: () = assert!(ALGORITHM_REGISTRY.len() == DigestAlgorithm::ALL.len());
// pinning the array to a two-variant enum, so the array cannot be empty and the
// loop cannot be. The guarantee is real; it comes from the neighbour rather than
// from the construct, and anyone copying this pattern must copy that too.
//
// Given the length is pinned, the block then cannot fail to fire -- it is
// evaluated every build, so a violating row makes the crate not compile and
// "the crate built" is the presence case. That is why it has no `compile_fail`
// twin, unlike the guards in `keys.rs`, `body_identity.rs` and `native.rs`: a
// doctest cannot add a row to a const registry, so any in-tree version would
// assert against a COPY of this block and drift from it.
//
// Its boundary was characterised out-of-tree by YellowOak (cc_2) on 2026-08-22,
// by compiling this block verbatim against synthetic registries: `0xfff1`
// refused, `0xfff0` refused, `0xffef` compiles, and the real `{1, 2}` compiles.
// The two boundary cases are the ones that matter, because `< 0xfff0` here and
// the inclusive `0xfff0..=` above must agree at exactly one value; they do, so
// the range's own first slot cannot be allocated to a construction.
//
// The runtime twin over the REAL registry is
// `tests/identity_boundaries.rs::registered_code_points_stay_out_of_the_corpus_reserved_range`,
// which iterates `ALGORITHM_REGISTRY` against `CORPUS_RESERVED_CODE_POINTS`
// itself rather than a literal, so it also catches the range being moved.
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
    /// One key-lifecycle receipt body.
    ///
    /// Rotation, revocation and cryptographic erasure each produce an
    /// immutable record. Plan section 19.4 makes erasure a deletion state with
    /// its own evidence, which means the record is a body with an identity
    /// rather than a log line.
    KeyLifecycleReceipt,
    /// One restore report body.
    ///
    /// `NORMATIVE_PROTOCOL_CONTRACTS.md` section 23: *"Older-state recovery is an
    /// explicit audited restore that advances a new authority generation."*
    /// An audited action that advances a generation needs a record, and a
    /// record with an identity is a body. The specification does not name the
    /// body itself; this row exists on the strength of the audit requirement,
    /// with FG-010a as the consumer building it.
    RestoreReport,
    /// One authority-history body.
    ///
    /// `fgit-authority` already writes this tag at `src/history.rs` as its
    /// `CanonicalBody::DOMAIN`, so the tag was live in the `frankengit/`
    /// namespace before it was registered and [`crate::resolve_domain`] would
    /// have refused it. Registered here rather than asking that crate to
    /// invent a different string, because the tag it chose is the right one:
    /// authority history is authority-local semantics, not a
    /// protocol-normative body, which is why it is an `owned_row` with no
    /// `fgit-types` derived identity pinning it.
    AuthorityHistory,
    /// One canonical immutable admission ref-state body.
    AdmissionRefState,
    /// One canonical immutable admission permitted-object closure body.
    AdmissionObjectClosure,
    /// One canonical immutable admission ref delta body.
    AdmissionRefDelta,
    /// One ATP trust-scoped transfer cache key.
    ///
    /// A cache key is an identity like any other: FG-075 keys entries by
    /// content identity PLUS trust scope, and `ATP_GIT_PROFILE.md` section 9 is
    /// explicit that content equality does not authorise cross-tenant reuse. A
    /// key derived outside this registry could collide with, or be mistaken
    /// for, an identity that carries different disclosure rules -- so the cache
    /// gets its own domain rather than borrowing `AtpTransferManifest`, which
    /// means something else.
    AtpTrustCacheKey,
    /// One immutable admission policy-decision evidence body.
    AdmissionPolicyDecision,
    /// One immutable admission invariant-evidence body.
    AdmissionInvariantEvidence,
    /// One immutable batch of forge effects from an admitted decision.
    ForgeEventBatch,
    /// One immutable batch of outbox effects from an admitted decision.
    OutboxEffectBatch,
    /// One immutable retention delta from an admitted decision.
    RetentionDelta,
    /// One immutable evidence body supporting a terminal admission refusal.
    AdmissionRefusalEvidence,
    /// One canonical repository-configuration body.
    ///
    /// Selected by an authority head's existing `configuration_root`, so a
    /// repository states how its authenticated roots are laid out without the
    /// head body growing a field — and migration becomes an ordinary head
    /// transition rather than a rewrite of published bytes.
    ///
    /// Its own domain rather than a reused one: a configuration body decides
    /// how other commitments are READ, so letting it be forgeable as some
    /// other body class would let an attacker change the interpretation of
    /// every root at once.
    RepositoryConfiguration,
    /// One immutable repository-creation attempt body.
    ///
    /// The body binds the first successful creation writer's minted
    /// incarnation to the fixed request facts.  Retrying the caller-supplied
    /// idempotency key reuses that body rather than minting a new incarnation.
    RepositoryCreationAttempt,
    /// One retained leaf-set checkpoint for the cumulative outcome index.
    OutcomeIndexCheckpoint,
    /// One versioned hidden-ref policy body, named by a configuration's
    /// `policy_root`.
    ///
    /// Separate from the configuration bodies that point at it so that policy
    /// content evolves in its own versioned body and the carriers never
    /// re-version for a policy change. Shared by both carrier families: the
    /// major-1 configuration and the incarnation-aware one name the same policy
    /// body, so a repository's hide rules mean one thing regardless of which
    /// carrier its head selects.
    HiddenRefPolicy,
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
    owned_row(
        31,
        IdentityDomain::KeyLifecycleReceipt,
        "frankengit/key-lifecycle-receipt/v1",
        None,
    ),
    owned_row(
        32,
        IdentityDomain::RestoreReport,
        "frankengit/restore-report/v1",
        Some("DUR-004"),
    ),
    owned_row(
        33,
        IdentityDomain::AuthorityHistory,
        "frankengit/authority-history/v1",
        None,
    ),
    owned_row(
        34,
        IdentityDomain::AdmissionRefState,
        "frankengit/ref-state/v1",
        None,
    ),
    owned_row(
        35,
        IdentityDomain::AdmissionObjectClosure,
        "frankengit/admission-object-closure/v1",
        None,
    ),
    owned_row(
        36,
        IdentityDomain::AdmissionRefDelta,
        "frankengit/admission-ref-delta/v1",
        None,
    ),
    owned_row(
        37,
        IdentityDomain::AtpTrustCacheKey,
        "frankengit/atp-trust-cache-key/v1",
        None,
    ),
    owned_row(
        38,
        IdentityDomain::AdmissionPolicyDecision,
        "frankengit/admission-policy-decision/v1",
        None,
    ),
    owned_row(
        39,
        IdentityDomain::AdmissionInvariantEvidence,
        "frankengit/admission-invariant-evidence/v1",
        None,
    ),
    owned_row(
        40,
        IdentityDomain::ForgeEventBatch,
        "frankengit/forge-event-batch/v1",
        None,
    ),
    owned_row(
        41,
        IdentityDomain::OutboxEffectBatch,
        "frankengit/outbox-effect-batch/v1",
        None,
    ),
    owned_row(
        42,
        IdentityDomain::RetentionDelta,
        "frankengit/retention-delta/v1",
        None,
    ),
    owned_row(
        43,
        IdentityDomain::AdmissionRefusalEvidence,
        "frankengit/admission-refusal-evidence/v1",
        None,
    ),
    owned_row(
        44,
        IdentityDomain::RepositoryConfiguration,
        "frankengit/repository-configuration/v1",
        None,
    ),
    owned_row(
        45,
        IdentityDomain::RepositoryCreationAttempt,
        "frankengit/repository-creation-attempt/v1",
        None,
    ),
    owned_row(
        46,
        IdentityDomain::OutcomeIndexCheckpoint,
        "frankengit/outcome-index-checkpoint/v1",
        Some("DUR-018"),
    ),
    owned_row(
        47,
        IdentityDomain::HiddenRefPolicy,
        "frankengit/hidden-ref-policy/v1",
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

/// A `frankengit/` domain-separation tag that is deliberately *not* an
/// identity domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NonIdentityTag {
    /// The literal tag string.
    pub tag: &'static str,
    /// The crate that writes it.
    pub owner: &'static str,
    /// Why it is not an identity domain.
    pub reason: &'static str,
}

/// Tags allocated in the `frankengit/` namespace that compute no identity.
///
/// # Why this list exists rather than more [`DOMAIN_REGISTRY`] rows
///
/// Every row in [`DOMAIN_REGISTRY`] carries an [`InternalDigestAlgorithm`] and
/// is reachable from [`crate::internal_object_id`]. A tag that is only a
/// domain-separation prefix inside an encoding — never hashed, no body schema,
/// no derived identity — cannot honestly take such a row: it would have to
/// become an [`IdentityDomain`] variant, which would make it *constructible*
/// into an identity computation that has no meaning for it. Registering it
/// would put a claim in the table that the code does not honour.
///
/// But the `frankengit/` namespace is shared whether or not a tag is hashed.
/// Two crates independently choosing one string for different purposes is the
/// same class of bug as a fixture squatting a production code point, and this
/// project has now hit that class twice. So the allocation is recorded, and
/// the collision is made a build failure, without lying about what the tag is.
///
/// The rule this encodes: **the identity registry covers derived-identity
/// domains only; this list covers the rest of the namespace.**
pub const RESERVED_NON_IDENTITY_TAGS: &[NonIdentityTag] = &[
    NonIdentityTag {
        tag: "frankengit/model-trace/v1",
        owner: "fgit-reference",
        reason: "domain-separation prefix on the model trace encoding; fgit-reference computes no digests",
    },
    NonIdentityTag {
        tag: "frankengit/model-roots/v1",
        owner: "fgit-reference",
        reason: "domain-separation prefix on the model roots encoding; fgit-reference computes no digests",
    },
];

/// Byte equality for two `&str` in a `const` context.
const fn tags_equal(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

// The guard that makes the list above worth having. A tag cannot be both an
// identity domain and a non-identity separation constant, and discovering that
// at runtime would mean two different bodies had already been written under
// one string.
const _: () = {
    let mut reserved = 0;
    while reserved < RESERVED_NON_IDENTITY_TAGS.len() {
        let mut row = 0;
        while row < DOMAIN_REGISTRY.len() {
            assert!(
                !tags_equal(
                    DOMAIN_REGISTRY[row].tag,
                    RESERVED_NON_IDENTITY_TAGS[reserved].tag
                ),
                "a frankengit/ tag is registered as both an identity domain and a non-identity separation constant"
            );
            row += 1;
        }
        reserved += 1;
    }
};

// Two entries in the non-identity list must not collide with each other
// either; the list is an allocation record, and a duplicate would mean two
// owners believe they hold the same string.
const _: () = {
    let mut outer = 0;
    while outer < RESERVED_NON_IDENTITY_TAGS.len() {
        let mut inner = outer + 1;
        while inner < RESERVED_NON_IDENTITY_TAGS.len() {
            assert!(
                !tags_equal(
                    RESERVED_NON_IDENTITY_TAGS[outer].tag,
                    RESERVED_NON_IDENTITY_TAGS[inner].tag
                ),
                "two owners are recorded as holding the same frankengit/ tag"
            );
            inner += 1;
        }
        outer += 1;
    }
};

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

// `IdentityDomain::ALL` and `DOMAIN_REGISTRY` must grow together. The
// completeness guard beside `ALL` makes adding an enum variant a compiler-held
// decision; these assertions then pin the matching row and stable identifier.
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
        Self::KeyLifecycleReceipt,
        Self::RestoreReport,
        Self::AuthorityHistory,
        Self::AdmissionRefState,
        Self::AdmissionObjectClosure,
        Self::AdmissionRefDelta,
        Self::AtpTrustCacheKey,
        Self::AdmissionPolicyDecision,
        Self::AdmissionInvariantEvidence,
        Self::ForgeEventBatch,
        Self::OutboxEffectBatch,
        Self::RetentionDelta,
        Self::AdmissionRefusalEvidence,
        Self::RepositoryConfiguration,
        Self::RepositoryCreationAttempt,
        Self::OutcomeIndexCheckpoint,
        Self::HiddenRefPolicy,
    ];

    /// Compile-time completeness guard for [`IdentityDomain::ALL`].
    ///
    /// `ALL` is written by hand, and the registry closure and domain-sweep
    /// tests intentionally iterate it. A variant omitted from the array would
    /// otherwise shrink each “every domain” check silently; worse, its
    /// discriminant would select past [`DOMAIN_REGISTRY`] at runtime. This is
    /// the same hand-maintained-enumeration defect class guarded in
    /// `fgit-types` by `frankengit-13ng`.
    ///
    /// This match has no wildcard, so a new variant fails to compile here,
    /// beside the array that must be updated. Once it is listed, the
    /// `DOMAIN_REGISTRY.len() == IdentityDomain::ALL.len()` assertion below
    /// requires a corresponding registry row before compilation can proceed.
    ///
    /// The guard cannot make an author add the variant to `ALL`; it makes the
    /// omission explicit. Remove it only if `ALL` becomes mechanically derived
    /// from the enum, at which point this hand-maintained drift boundary no
    /// longer exists.
    const fn _every_identity_domain_is_listed(value: Self) {
        match value {
            Self::RefTransaction
            | Self::TransactionSeal
            | Self::PreparedTransactionCapsule
            | Self::RepositoryCommitRecord
            | Self::RepositoryDecisionBatch
            | Self::RepositoryAuthorityHead
            | Self::RefusalRecord
            | Self::RepositoryCapsule
            | Self::PrincipalSnapshot
            | Self::ObjectEnvelope
            | Self::SegmentManifest
            | Self::ForgeEvent
            | Self::EvidenceRecord
            | Self::Generation
            | Self::GitPayloadCommitment
            | Self::RepositorySegment
            | Self::GitObjectMicrosegment
            | Self::ForgeCheckpoint
            | Self::PolicyCheckpoint
            | Self::ClaimRecord
            | Self::TreefsSnapshot
            | Self::BackupExportBundle
            | Self::ReleaseAsset
            | Self::AtpTransferManifest
            | Self::CiArtifact
            | Self::MerkleLeaf
            | Self::MerkleNode
            | Self::AdmissionReceipt
            | Self::DocumentAnchor
            | Self::SignedEnvelope
            | Self::KeyLifecycleReceipt
            | Self::RestoreReport
            | Self::AuthorityHistory
            | Self::AdmissionRefState
            | Self::AdmissionObjectClosure
            | Self::AdmissionRefDelta
            | Self::AtpTrustCacheKey
            | Self::AdmissionPolicyDecision
            | Self::AdmissionInvariantEvidence
            | Self::ForgeEventBatch
            | Self::OutboxEffectBatch
            | Self::RetentionDelta
            | Self::AdmissionRefusalEvidence
            | Self::RepositoryConfiguration
            | Self::RepositoryCreationAttempt
            | Self::OutcomeIndexCheckpoint
            | Self::HiddenRefPolicy => (),
        }
    }

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
