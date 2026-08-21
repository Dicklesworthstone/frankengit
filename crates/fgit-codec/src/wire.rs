//! Body framing: the outer envelope that makes a canonical body
//! self-describing and domain-separated.
//!
//! A frame is:
//!
//! ```text
//! magic          4 bytes, "FGC1"
//! codec_major    u16 big-endian
//! codec_minor    u16 big-endian
//! domain         u32 length + label bytes
//! schema_family  u32 length + label bytes
//! schema_major   u16 big-endian
//! schema_minor   u16 big-endian
//! payload        u32 length + payload bytes
//! ```
//!
//! The whole frame is the body's canonical bytes, and the internal identity of
//! a body is the digest of the frame. Because the domain separation tag and
//! the schema identifier sit inside the digested bytes at fixed, explicitly
//! length-delimited positions, this satisfies the domain-separated identity
//! rule of `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.2, and it binds
//! strictly more than that rule requires: the codec version and every length
//! are committed too. Binding more cannot weaken domain separation, and it
//! means a codec change can never silently reinterpret old bytes.
//!
//! # Version rules
//!
//! * An unknown **codec major** is refused. A future major may reorder or
//!   reinterpret fields, so a decoder that guessed would be confidently wrong.
//! * An unknown **schema major** is refused, for the same reason at body level.
//! * A **higher minor** is additive: it may append fields to a payload. A
//!   decoder reads the fields its own minor declares and keeps the unparsed
//!   suffix verbatim in [`DecodedBody`], so re-encoding reproduces the
//!   original bytes exactly and the body's identity is preserved by a process
//!   that does not understand all of it.
//! * At a minor this build implements, there is no suffix. Trailing bytes
//!   there are refused: a canonical body has exactly one byte string.

use fgit_types::numeric::CodecVersion;
use fgit_types::{DomainTag, SchemaFamily, SchemaId};

use crate::bounds::DecodeLimits;
use crate::error::CodecRefusal;
use crate::reader::Decoder;
use crate::writer::Encoder;

/// The four bytes every canonical frame starts with.
pub const FRAME_MAGIC: [u8; 4] = *b"FGC1";

/// Codec major version this build implements.
pub const CODEC_MAJOR: u16 = 1;

/// Codec minor version this build implements.
pub const CODEC_MINOR: u16 = 0;

/// Codec version this build implements.
pub const CODEC_VERSION: CodecVersion = CodecVersion::new(CODEC_MAJOR, CODEC_MINOR);

/// A body that has one canonical byte encoding.
///
/// Implementors declare their domain separation tag and schema identifier as
/// associated constants, so a body's domain is a property of its type and
/// cannot be supplied at a call site.
pub trait CanonicalBody: Sized {
    /// Domain separation tag for this body.
    const DOMAIN: DomainTag;
    /// Schema family for this body.
    const SCHEMA_FAMILY: SchemaFamily;
    /// Schema major version this build implements.
    const SCHEMA_MAJOR: u16;
    /// Schema minor version this build implements.
    const SCHEMA_MINOR: u16;

    /// Writes the payload, without the frame.
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal>;

    /// Reads the payload, without the frame.
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal>;

    /// The schema identifier this build implements.
    #[must_use]
    fn schema_id() -> SchemaId {
        SchemaId::new(Self::SCHEMA_FAMILY, Self::SCHEMA_MAJOR, Self::SCHEMA_MINOR)
    }
}

/// A body decoded together with everything needed to reproduce its exact
/// bytes, including fields a future minor added that this build does not
/// understand.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecodedBody<B> {
    /// The parsed body.
    pub body: B,
    /// Codec minor version the frame declared.
    pub codec_minor: u16,
    /// Schema minor version the frame declared.
    pub schema_minor: u16,
    /// Payload bytes after the fields this build understands. Empty at a
    /// minor this build implements.
    pub unknown_suffix: Vec<u8>,
}

impl<B> DecodedBody<B> {
    /// True when the frame carried fields this build does not understand.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        !self.unknown_suffix.is_empty()
    }
}

/// Encodes a body into its canonical frame.
pub fn encode_body<B: CanonicalBody>(body: &B) -> Result<Vec<u8>, CodecRefusal> {
    let mut payload = Encoder::new();
    body.write_payload(&mut payload)?;
    let payload = payload.into_bytes();
    write_frame(
        CODEC_MINOR,
        B::DOMAIN,
        B::SCHEMA_FAMILY,
        B::SCHEMA_MAJOR,
        B::SCHEMA_MINOR,
        &payload,
    )
}

/// Re-encodes a preserved body, reproducing the original bytes exactly,
/// including any fields this build did not understand.
pub fn encode_preserved<B: CanonicalBody>(
    decoded: &DecodedBody<B>,
) -> Result<Vec<u8>, CodecRefusal> {
    let mut payload = Encoder::new();
    decoded.body.write_payload(&mut payload)?;
    let mut payload = payload.into_bytes();
    payload.extend_from_slice(&decoded.unknown_suffix);
    write_frame(
        decoded.codec_minor,
        B::DOMAIN,
        B::SCHEMA_FAMILY,
        B::SCHEMA_MAJOR,
        decoded.schema_minor,
        &payload,
    )
}

fn write_frame(
    codec_minor: u16,
    domain: DomainTag,
    family: SchemaFamily,
    schema_major: u16,
    schema_minor: u16,
    payload: &[u8],
) -> Result<Vec<u8>, CodecRefusal> {
    let mut frame = Encoder::with_capacity(payload.len() + 64);
    frame.write_raw(&FRAME_MAGIC);
    frame.write_scalar(CODEC_MAJOR);
    frame.write_scalar(codec_minor);
    frame.write_domain_tag(domain)?;
    frame.write_schema_id(SchemaId::new(family, schema_major, schema_minor))?;
    frame.write_bytes("payload", payload)?;
    Ok(frame.into_bytes())
}

/// The header a frame declares, before any payload is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrameHeader {
    /// Codec minor version the frame declares.
    pub codec_minor: u16,
    /// Domain separation tag the frame declares.
    pub domain: DomainTag,
    /// Schema identifier the frame declares.
    pub schema: SchemaId,
}

/// Reads a frame's header without decoding its payload.
///
/// Refuses an unrecognized magic or an unsupported codec major, so a caller
/// that only needs the domain still cannot be handed bytes from a format it
/// does not implement.
pub fn read_frame_header(
    frame: &[u8],
    limits: DecodeLimits,
) -> Result<(FrameHeader, Decoder<'_>), CodecRefusal> {
    let mut decoder = Decoder::new(frame, limits);
    let magic = decoder.take("magic", FRAME_MAGIC.len())?;
    if magic != FRAME_MAGIC {
        let mut observed = [0_u8; 4];
        observed.copy_from_slice(magic);
        return Err(CodecRefusal::MagicUnrecognized { observed });
    }
    let codec_major = decoder.read_scalar::<u16>("codec_major")?;
    if codec_major != CODEC_MAJOR {
        return Err(CodecRefusal::CodecMajorUnsupported {
            observed: codec_major,
            supported: CODEC_MAJOR,
        });
    }
    let codec_minor = decoder.read_scalar::<u16>("codec_minor")?;
    let domain = decoder.read_domain_tag()?;
    let schema = decoder.read_schema_id()?;
    Ok((
        FrameHeader {
            codec_minor,
            domain,
            schema,
        },
        decoder,
    ))
}

/// Reads only the domain separation tag a frame declares.
pub fn peek_frame_domain(frame: &[u8], limits: DecodeLimits) -> Result<DomainTag, CodecRefusal> {
    read_frame_header(frame, limits).map(|(header, _)| header.domain)
}

/// Decodes a body strictly: the frame must declare exactly the versions this
/// build implements, and the payload must contain no unknown suffix.
pub fn decode_body<B: CanonicalBody>(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<B, CodecRefusal> {
    let decoded = decode_body_preserving::<B>(bytes, limits)?;
    if decoded.has_unknown_fields() {
        return Err(CodecRefusal::TrailingBytes {
            offset: u64::try_from(bytes.len() - decoded.unknown_suffix.len()).unwrap_or(u64::MAX),
            remaining: u64::try_from(decoded.unknown_suffix.len()).unwrap_or(u64::MAX),
        });
    }
    Ok(decoded.body)
}

/// Decodes a body, tolerating and preserving fields added by a higher minor.
pub fn decode_body_preserving<B: CanonicalBody>(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<DecodedBody<B>, CodecRefusal> {
    let frame_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if frame_len > limits.max_frame_len {
        return Err(CodecRefusal::LengthBoundExceeded {
            field: "frame",
            observed: frame_len,
            limit: limits.max_frame_len,
        });
    }
    let (header, mut frame) = read_frame_header(bytes, limits)?;
    let FrameHeader {
        codec_minor,
        domain,
        schema,
    } = header;
    if domain != B::DOMAIN {
        return Err(CodecRefusal::DomainUnexpected {
            expected: B::DOMAIN,
            observed: domain,
        });
    }
    if schema.family() != B::SCHEMA_FAMILY {
        return Err(CodecRefusal::SchemaFamilyUnexpected {
            expected: B::SCHEMA_FAMILY,
            observed: schema.family(),
        });
    }
    if schema.major() != B::SCHEMA_MAJOR {
        return Err(CodecRefusal::SchemaMajorUnsupported {
            domain,
            observed: schema.major(),
            supported: B::SCHEMA_MAJOR,
        });
    }

    let payload = frame.read_bytes("payload")?;
    frame.finish()?;

    let mut payload_reader = Decoder::new(payload, limits);
    let body = B::read_payload(&mut payload_reader)?;
    let consumed = usize::try_from(payload_reader.offset()).unwrap_or(payload.len());
    let suffix = payload.get(consumed..).unwrap_or_default();

    if !suffix.is_empty() && schema.minor() <= B::SCHEMA_MINOR {
        // At a minor this build implements, every byte is accounted for. A
        // suffix here is a second byte string for one value, not a new field.
        return Err(CodecRefusal::TrailingBytes {
            offset: payload_reader.offset(),
            remaining: u64::try_from(suffix.len()).unwrap_or(u64::MAX),
        });
    }

    Ok(DecodedBody {
        body,
        codec_minor,
        schema_minor: schema.minor(),
        unknown_suffix: suffix.to_vec(),
    })
}
