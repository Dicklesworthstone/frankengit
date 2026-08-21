// Bounded decoding and typed refusals.
//
// Every forbidden case here is paired with a near-identical permitted case, so
// the suite shows the codec still does its job rather than only that it says
// no.

mod support;

use fgit_codec::attest::{DetachedSignature, SignatureSchemeId, SignedEnvelopeBody};
use fgit_codec::schema::TransactionSealBody;
use fgit_codec::wire::{CODEC_MAJOR, FRAME_MAGIC, read_frame_header};
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body, encode_body,
    peek_frame_domain,
};
use fgit_types::identity::InternalObjectId;
use fgit_types::{DomainTag, RefusalCode, SchemaFamily, SchemaId, TypeRefusal};

fn seal_bytes() -> Vec<u8> {
    encode_body(&support::transaction_seal()).expect("the fixture encodes")
}

fn raw_frame(
    domain: DomainTag,
    family: SchemaFamily,
    schema_major: u16,
    schema_minor: u16,
    codec_major: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Encoder::new();
    frame.write_raw(&FRAME_MAGIC);
    frame.write_scalar(codec_major);
    frame.write_scalar(0_u16);
    frame.write_domain_tag(domain).expect("label fits");
    frame
        .write_schema_id(SchemaId::new(family, schema_major, schema_minor))
        .expect("label fits");
    frame.write_bytes("payload", payload).expect("payload fits");
    frame.into_bytes()
}

fn seal_payload() -> Vec<u8> {
    let mut payload = Encoder::new();
    support::transaction_seal()
        .write_payload(&mut payload)
        .expect("encodes");
    payload.into_bytes()
}

#[test]
fn an_unknown_codec_major_is_refused_and_the_known_one_is_not() {
    let future = raw_frame(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR,
        TransactionSealBody::SCHEMA_MINOR,
        CODEC_MAJOR + 1,
        &seal_payload(),
    );
    let refusal = decode_body::<TransactionSealBody>(&future, DecodeLimits::DEFAULT)
        .expect_err("a future codec major may reinterpret fields, so it must not be guessed");
    assert_eq!(
        refusal,
        CodecRefusal::CodecMajorUnsupported {
            observed: CODEC_MAJOR + 1,
            supported: CODEC_MAJOR,
        }
    );
    assert_eq!(refusal.refusal_code(), RefusalCode::SchemaUnsupported);

    // Permitted counterpart: identical bytes at the known major.
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn an_unknown_schema_major_is_refused_and_the_known_one_is_not() {
    let future = raw_frame(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR + 1,
        TransactionSealBody::SCHEMA_MINOR,
        CODEC_MAJOR,
        &seal_payload(),
    );
    let refusal = decode_body::<TransactionSealBody>(&future, DecodeLimits::DEFAULT)
        .expect_err("a future schema major must not be guessed either");
    assert!(matches!(
        refusal,
        CodecRefusal::SchemaMajorUnsupported {
            observed: 2,
            supported: 1,
            ..
        }
    ));

    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn one_schemas_bytes_cannot_be_decoded_as_another() {
    let refusal = decode_body::<SignedEnvelopeBody>(&seal_bytes(), DecodeLimits::DEFAULT)
        .expect_err("domain separation must stop a cross-schema read");
    assert!(matches!(refusal, CodecRefusal::DomainUnexpected { .. }));
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn a_frame_over_the_size_bound_is_refused_before_it_is_parsed() {
    let bytes = seal_bytes();
    let refusal = decode_body::<TransactionSealBody>(&bytes, DecodeLimits::MINIMAL)
        .expect_err("a frame larger than the bound must be refused up front");
    assert!(matches!(
        refusal,
        CodecRefusal::LengthBoundExceeded { field: "frame", .. }
    ));
    assert_eq!(refusal.refusal_code(), RefusalCode::CanonicalBoundExceeded);

    // Permitted counterpart: the same bytes under bounds that admit them.
    assert!(decode_body::<TransactionSealBody>(&bytes, DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn a_declared_length_larger_than_the_input_is_refused_without_allocating() {
    let mut encoder = Encoder::new();
    encoder.write_scalar(0xffff_fff0_u32); // claims four gigabytes
    encoder.write_raw(b"only a few bytes actually follow");
    let hostile = encoder.into_bytes();

    let mut decoder = Decoder::new(&hostile, DecodeLimits::DEFAULT);
    let refusal = decoder
        .read_bytes("hostile")
        .expect_err("a declared length beyond the bound must be refused");
    assert!(matches!(
        refusal,
        CodecRefusal::LengthBoundExceeded {
            field: "hostile",
            observed: 0xffff_fff0,
            ..
        }
    ));

    // Just under the byte-string bound but longer than the input: still
    // refused, now for truncation rather than for the bound.
    let mut encoder = Encoder::new();
    encoder.write_scalar(4096_u32);
    encoder.write_raw(b"short");
    let truncated = encoder.into_bytes();
    let mut decoder = Decoder::new(&truncated, DecodeLimits::DEFAULT);
    assert!(matches!(
        decoder.read_bytes("hostile"),
        Err(CodecRefusal::InputTruncated { .. })
    ));

    // Permitted counterpart: a length the input actually backs.
    let mut encoder = Encoder::new();
    encoder.write_bytes("ok", b"short").expect("encodes");
    let honest = encoder.into_bytes();
    let mut decoder = Decoder::new(&honest, DecodeLimits::DEFAULT);
    assert_eq!(decoder.read_bytes("ok").expect("decodes"), b"short");
}

#[test]
fn a_declared_element_count_larger_than_the_input_is_refused() {
    let mut encoder = Encoder::new();
    encoder.write_scalar(1_000_000_u32);
    let hostile = encoder.into_bytes();
    let mut decoder = Decoder::new(&hostile, DecodeLimits::DEFAULT);
    let refusal = decoder
        .read_sequence("hostile", |input| input.read_scalar::<u64>("element"))
        .expect_err("a count with no bytes behind it must be refused before reserving");
    assert!(matches!(
        refusal,
        CodecRefusal::CountBoundExceeded {
            field: "hostile",
            ..
        }
    ));

    // Permitted counterpart: a count the input backs.
    let mut encoder = Encoder::new();
    encoder
        .write_sequence("ok", &[1_u64, 2, 3], |out, value| {
            out.write_scalar(*value);
            Ok(())
        })
        .expect("encodes");
    let honest = encoder.into_bytes();
    let mut decoder = Decoder::new(&honest, DecodeLimits::DEFAULT);
    assert_eq!(
        decoder
            .read_sequence("ok", |input| input.read_scalar::<u64>("element"))
            .expect("decodes"),
        vec![1_u64, 2, 3]
    );
}

#[test]
fn nesting_past_the_depth_bound_is_refused() {
    // Three nested sequences under a bound of two.
    let mut encoder = Encoder::new();
    encoder.write_scalar(1_u32);
    encoder.write_scalar(1_u32);
    encoder.write_scalar(1_u32);
    encoder.write_scalar(7_u64);
    let deep = encoder.into_bytes();

    let mut decoder = Decoder::new(&deep, DecodeLimits::MINIMAL);
    let refusal = decoder
        .read_sequence("outer", |input| {
            input.read_sequence("middle", |input| {
                input.read_sequence("inner", |input| input.read_scalar::<u64>("leaf"))
            })
        })
        .expect_err("nesting past the bound must be refused");
    assert!(matches!(
        refusal,
        CodecRefusal::DepthBoundExceeded { limit: 2, .. }
    ));

    // Permitted counterpart: two levels, which the same bound admits.
    let mut encoder = Encoder::new();
    encoder.write_scalar(1_u32);
    encoder.write_scalar(1_u32);
    encoder.write_scalar(7_u64);
    let shallow = encoder.into_bytes();
    let mut decoder = Decoder::new(&shallow, DecodeLimits::MINIMAL);
    assert_eq!(
        decoder
            .read_sequence("outer", |input| {
                input.read_sequence("inner", |input| input.read_scalar::<u64>("leaf"))
            })
            .expect("two levels are inside the bound"),
        vec![vec![7_u64]]
    );
}

#[test]
fn a_boolean_or_option_byte_outside_its_two_values_is_refused() {
    for byte in [0x02_u8, 0xff] {
        let input = [byte];
        let mut decoder = Decoder::new(&input, DecodeLimits::DEFAULT);
        assert!(matches!(
            decoder.read_bool("flag"),
            Err(CodecRefusal::BooleanByteInvalid { .. })
        ));

        let mut decoder = Decoder::new(&input, DecodeLimits::DEFAULT);
        let refusal = decoder
            .read_option("maybe", |input| input.read_scalar::<u64>("value"))
            .expect_err("only 0x00 and 0x01 are tags");
        assert!(matches!(refusal, CodecRefusal::OptionTagInvalid { .. }));
    }

    // Permitted counterparts.
    for (byte, expected) in [(0x00_u8, false), (0x01_u8, true)] {
        let input = [byte];
        let mut decoder = Decoder::new(&input, DecodeLimits::DEFAULT);
        assert_eq!(decoder.read_bool("flag").expect("valid"), expected);
    }
}

#[test]
fn text_that_is_not_utf8_is_refused_and_text_that_is_is_not() {
    let mut encoder = Encoder::new();
    encoder.write_bytes("text", &[0xff, 0xfe]).expect("encodes");
    let invalid = encoder.into_bytes();
    let mut decoder = Decoder::new(&invalid, DecodeLimits::DEFAULT);
    let refusal = decoder
        .read_text("text")
        .expect_err("a text field must not carry arbitrary bytes");
    assert!(matches!(
        refusal,
        CodecRefusal::TextNotUtf8 { field: "text", .. }
    ));

    let mut encoder = Encoder::new();
    encoder
        .write_text("text", "hello \u{2014} world")
        .expect("encodes");
    let valid = encoder.into_bytes();
    let mut decoder = Decoder::new(&valid, DecodeLimits::DEFAULT);
    assert_eq!(
        decoder.read_text("text").expect("valid"),
        "hello \u{2014} world"
    );
}

#[test]
fn a_derived_identity_from_the_wrong_domain_is_refused_on_the_way_in() {
    // Hand-build a seal payload whose tx_id carries the commit-record domain.
    let mut payload = Encoder::new();
    let wrong = InternalObjectId::new(
        support::algorithm(),
        fgit_types::identity::RepositoryCommitId::DOMAIN_TAG,
        fgit_types::CANONICAL_CODEC_VERSION,
        *support::digest_of(0x01).bytes(),
    );
    payload.write_internal_object_id(&wrong).expect("encodes");
    payload.write_opaque_id(support::tenant_id().as_bytes());
    payload.write_opaque_id(support::repository_id().as_bytes());
    payload.write_opaque_id(support::principal_id().as_bytes());
    payload
        .write_digest(&support::digest_of(0x44))
        .expect("encodes");
    payload
        .write_digest(&support::digest_of(0x55))
        .expect("encodes");
    payload
        .write_schema_id(SchemaId::new(SchemaFamily::from_static("ref-txn"), 2, 0))
        .expect("encodes");

    let frame = raw_frame(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR,
        TransactionSealBody::SCHEMA_MINOR,
        CODEC_MAJOR,
        &payload.into_bytes(),
    );
    let refusal = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect_err("a commit-record digest must not become a transaction identity");
    assert_eq!(
        refusal,
        CodecRefusal::Type(TypeRefusal::DomainMismatch {
            field: "TxId",
            expected: "frankengit/ref-txn/v2",
        })
    );

    // Permitted counterpart: the same body with the right domain.
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn a_signature_bound_to_another_schemas_body_cannot_be_attached() {
    let mut envelope = SignedEnvelopeBody::seal(&support::transaction_seal()).expect("seals");
    let foreign = DetachedSignature {
        scheme: SignatureSchemeId::try_new(1).expect("nonzero"),
        key_id: b"key-a".to_vec(),
        body_id: InternalObjectId::new(
            support::algorithm(),
            fgit_types::identity::RepositoryCommitId::DOMAIN_TAG,
            fgit_types::CANONICAL_CODEC_VERSION,
            *support::digest_of(0x01).bytes(),
        ),
        signature: vec![0xa0; 64],
    };
    let refusal = envelope
        .attach(foreign.clone(), DecodeLimits::DEFAULT)
        .expect_err("a signature over a different schema must not graft on");
    assert!(matches!(refusal, CodecRefusal::DomainUnexpected { .. }));

    // Permitted counterpart: the same signature bound to the carried body's
    // own domain.
    let native = DetachedSignature {
        body_id: InternalObjectId::new(
            support::algorithm(),
            TransactionSealBody::DOMAIN,
            fgit_types::CANONICAL_CODEC_VERSION,
            *support::digest_of(0x01).bytes(),
        ),
        ..foreign
    };
    envelope
        .attach(native, DecodeLimits::DEFAULT)
        .expect("a signature in the carried body's domain attaches");
    assert_eq!(envelope.signatures().len(), 1);
    let bytes = encode_body(&envelope).expect("encodes");
    assert_eq!(
        decode_body::<SignedEnvelopeBody>(&bytes, DecodeLimits::DEFAULT).expect("decodes"),
        envelope
    );
}

#[test]
fn a_reserved_zero_signature_scheme_is_refused() {
    let refusal = SignatureSchemeId::try_new(0).expect_err("zero is reserved");
    assert!(matches!(refusal, CodecRefusal::VariantUnknown { .. }));
    assert!(SignatureSchemeId::try_new(1).is_ok());
}

#[test]
fn the_header_can_be_read_without_decoding_the_payload() {
    let bytes = seal_bytes();
    let (header, _rest) = read_frame_header(&bytes, DecodeLimits::DEFAULT).expect("header parses");
    assert_eq!(header.domain, TransactionSealBody::DOMAIN);
    assert_eq!(header.schema.major(), TransactionSealBody::SCHEMA_MAJOR);
    assert_eq!(header.codec_minor, fgit_codec::CODEC_MINOR);
    assert_eq!(
        peek_frame_domain(&bytes, DecodeLimits::DEFAULT).expect("domain parses"),
        TransactionSealBody::DOMAIN
    );

    let refusal = peek_frame_domain(b"not a frame at all", DecodeLimits::DEFAULT)
        .expect_err("garbage has no header");
    assert!(matches!(refusal, CodecRefusal::MagicUnrecognized { .. }));
}

#[test]
fn every_codec_refusal_reports_a_live_protocol_code_and_prints() {
    let samples = [
        CodecRefusal::MagicUnrecognized { observed: [0; 4] },
        CodecRefusal::CodecMajorUnsupported {
            observed: 2,
            supported: 1,
        },
        CodecRefusal::SchemaMajorUnsupported {
            domain: TransactionSealBody::DOMAIN,
            observed: 2,
            supported: 1,
        },
        CodecRefusal::SchemaFamilyUnexpected {
            expected: TransactionSealBody::SCHEMA_FAMILY,
            observed: SchemaFamily::from_static("rcr"),
        },
        CodecRefusal::DomainUnexpected {
            expected: TransactionSealBody::DOMAIN,
            observed: SignedEnvelopeBody::DOMAIN,
        },
        CodecRefusal::InputTruncated {
            field: "f",
            needed: 4,
            available: 1,
            offset: 0,
        },
        CodecRefusal::TrailingBytes {
            offset: 4,
            remaining: 1,
        },
        CodecRefusal::LengthBoundExceeded {
            field: "f",
            observed: 9,
            limit: 4,
        },
        CodecRefusal::CountBoundExceeded {
            field: "f",
            observed: 9,
            limit: 4,
        },
        CodecRefusal::DepthBoundExceeded {
            limit: 2,
            offset: 0,
        },
        CodecRefusal::BooleanByteInvalid {
            observed: 2,
            offset: 0,
        },
        CodecRefusal::OptionTagInvalid {
            observed: 2,
            offset: 0,
        },
        CodecRefusal::TextNotUtf8 {
            field: "f",
            offset: 0,
        },
        CodecRefusal::CollectionUnordered {
            field: "f",
            index: 1,
            offset: 0,
        },
        CodecRefusal::CollectionDuplicate {
            field: "f",
            index: 1,
            offset: 0,
        },
        CodecRefusal::VariantUnknown {
            field: "f",
            observed: 9,
            offset: 0,
        },
        CodecRefusal::ValueUnrepresentable {
            field: "f",
            observed: 9,
            limit: 4,
        },
        CodecRefusal::Type(TypeRefusal::DomainMismatch {
            field: "TxId",
            expected: "frankengit/ref-txn/v2",
        }),
    ];
    let mut kinds = std::collections::BTreeSet::new();
    for sample in &samples {
        assert!(!sample.to_string().is_empty(), "a refusal must print");
        assert!(RefusalCode::ALL.contains(&sample.refusal_code()));
        assert!(
            kinds.insert(sample.kind()),
            "two variants share the kind {:?}",
            sample.kind()
        );
    }
    assert_eq!(kinds.len(), samples.len());
}
