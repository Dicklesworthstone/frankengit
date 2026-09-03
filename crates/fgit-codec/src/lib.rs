#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod attest;
pub mod bounds;
pub mod bridge;
pub mod canonical_state;
pub mod error;
pub mod harness;
pub mod outbox_identity;
pub mod reader;
pub mod repository_configuration;
pub mod schema;
pub mod wire;
pub mod writer;

pub use attest::{
    BodyIdentity, DetachedSignature, SignatureSchemeId, SignedEnvelopeBody, body_id,
    body_id_of_frame, body_id_of_frame_as,
};
pub use bounds::DecodeLimits;
pub use bridge::CryptoBodyIdentity;
pub use canonical_state::{
    CanonicalForgePositionState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    ForgePositionStateEntry, MAX_FORGE_POSITION_STATE_ENTRIES, MAX_OUTBOX_STATE_ENTRIES,
};
pub use error::CodecRefusal;
pub use outbox_identity::{OutboxDeliveryIdentityInput, derive_outbox_delivery_key};
pub use reader::Decoder;
pub use repository_configuration::RepositoryIncarnationConfigurationBodyV2_2;
pub use schema::{
    CreationAttemptBody, HiddenRefPolicyBody, MAX_REFUSAL_DETAIL_LEN, RefusalRecordBody,
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryConfigurationBody,
    RepositoryDecision, RepositoryDecisionBatchBody, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, TransactionSealBody,
};
pub use wire::{
    CODEC_MAJOR, CODEC_MINOR, CODEC_VERSION, CanonicalBody, DecodedBody, FRAME_MAGIC, FrameHeader,
    canonical_body_bytes, decode_body, decode_body_preserving, encode_body, encode_preserved,
    peek_frame_domain, read_frame_header, split_frame,
};
pub use writer::Encoder;
