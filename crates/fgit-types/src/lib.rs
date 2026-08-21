#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod hash;
pub mod identity;
pub mod label;
pub mod native;
pub mod numeric;
pub mod refs;
pub mod vocabulary;

pub use error::TypeRefusal;
pub use hash::{Digest, DigestAlgorithmId, DigestBytes, MAX_DIGEST_LEN, MIN_DIGEST_LEN};
pub use identity::{
    DERIVED_ID_DOMAINS, EvidenceRecordId, ForgeEventId, GenerationId, InternalObjectId,
    MAX_OPAQUE_STORE_TOKEN_LEN, OPAQUE_ID_LEN, ObjectEnvelopeId, OpaqueStoreToken,
    PreparationProfileId, PreparedTxnCapsuleId, PrincipalId, PrincipalSnapshotId, RefusalRecordId,
    RepositoryAuthorityHeadId, RepositoryCapsuleId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, RepositoryIncarnationId, RequestId, SegmentManifestId, TenantId,
    TransactionSealId, TxId,
};
pub use label::{AsciiSlug, DomainTag, MAX_LABEL_LEN, SchemaFamily, SchemaId};
pub use native::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};
pub use numeric::{
    ByteCount, CanonicalScalar, CodecVersion, DecisionSequence, HeadGeneration, PolicyEpoch,
    RegistryEpoch, RepositorySequence, ScalarWidth,
};
pub use refs::{MAX_REF_NAME_LEN, RefName};
pub use vocabulary::{
    DecisionOutcome, MismatchPolicy, PublicationEpoch, RefusalCode, RequestRejectionCode,
};

/// The canonical codec version this crate's identities are stamped with.
///
/// Bumping the major component is a compatibility break: a decoder that meets
/// an unknown major refuses rather than guessing.
pub const CANONICAL_CODEC_VERSION: CodecVersion = CodecVersion::new(1, 0);
