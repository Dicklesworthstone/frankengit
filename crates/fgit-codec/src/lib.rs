#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod attest;
pub mod bounds;
pub mod bridge;
pub mod error;
pub mod harness;
pub mod reader;
pub mod schema;
pub mod wire;
pub mod writer;

pub use attest::{
    BodyIdentity, DetachedSignature, SignatureSchemeId, SignedEnvelopeBody, body_id,
    body_id_of_frame,
};
pub use bounds::DecodeLimits;
pub use bridge::CryptoBodyIdentity;
pub use error::CodecRefusal;
pub use reader::Decoder;
pub use schema::{
    MAX_REFUSAL_DETAIL_LEN, RefusalRecordBody, RepositoryAuthorityHeadBody, RepositoryCommitRecord,
    RepositoryDecision, RepositoryDecisionBatchBody, TransactionSealBody,
};
pub use wire::{
    CODEC_MAJOR, CODEC_MINOR, CODEC_VERSION, CanonicalBody, DecodedBody, FRAME_MAGIC, FrameHeader,
    canonical_body_bytes, decode_body, decode_body_preserving, encode_body, encode_preserved,
    peek_frame_domain, read_frame_header, split_frame,
};
pub use writer::Encoder;
