// Bounded decoding and typed refusals.
//
// Every forbidden case here is paired with a near-identical permitted case, so
// the suite shows the codec still does its job rather than only that it says
// no.

use fgit_codec::harness as support;

use fgit_codec::attest::{DetachedSignature, SignatureSchemeId, SignedEnvelopeBody};
use fgit_codec::schema::TransactionSealBody;
use fgit_codec::wire::{CODEC_MAJOR, FRAME_MAGIC, read_frame_header};
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body, encode_body,
    peek_frame_domain,
};
use fgit_crypto::{CORPUS_RESERVED_CODE_POINTS, DigestAlgorithm};
use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{InternalObjectId, TxId};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DomainTag, RefusalCode, SchemaFamily, SchemaId, TypeRefusal,
};

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
fn a_frame_at_its_exact_limit_decodes_and_one_byte_over_is_refused() {
    let bytes = seal_bytes();
    let frame_bytes = u64::try_from(bytes.len()).expect("fixture frame length fits in u64");
    assert!(
        frame_bytes > 0,
        "an empty fixture cannot exercise the frame bound"
    );
    let exact = DecodeLimits {
        frame_bytes,
        ..DecodeLimits::DEFAULT
    };
    assert!(
        decode_body::<TransactionSealBody>(&bytes, exact).is_ok(),
        "a complete canonical frame exactly at frame_bytes must decode"
    );

    let one_byte_over = DecodeLimits {
        frame_bytes: frame_bytes - 1,
        ..exact
    };
    assert_eq!(
        decode_body::<TransactionSealBody>(&bytes, one_byte_over),
        Err(CodecRefusal::LengthBoundExceeded {
            field: "frame",
            observed: frame_bytes,
            limit: frame_bytes - 1,
        }),
        "lowering the wall by one byte must reject the same frame"
    );
}

#[test]
fn a_byte_string_at_its_exact_limit_decodes_and_one_byte_over_is_refused() {
    let exact_len = usize::try_from(DecodeLimits::MINIMAL.byte_string_bytes)
        .expect("minimal byte-string bound fits in usize");
    let exact_bytes = vec![0x5a; exact_len];
    let mut encoder = Encoder::new();
    encoder
        .write_bytes("boundary", &exact_bytes)
        .expect("the canonical encoder accepts the exact fixture");
    let exact_frame = encoder.into_bytes();
    let mut decoder = Decoder::new(&exact_frame, DecodeLimits::MINIMAL);
    assert_eq!(
        decoder
            .read_bytes("boundary")
            .expect("a byte string exactly at byte_string_bytes must decode"),
        exact_bytes
    );
    decoder.finish().expect("the exact frame is fully consumed");

    let one_byte_over = vec![0x5a; exact_len + 1];
    let mut encoder = Encoder::new();
    encoder
        .write_bytes("boundary", &one_byte_over)
        .expect("the encoder admits the adversarial wire fixture");
    let hostile = encoder.into_bytes();
    let mut decoder = Decoder::new(&hostile, DecodeLimits::MINIMAL);
    assert_eq!(
        decoder.read_bytes("boundary"),
        Err(CodecRefusal::LengthBoundExceeded {
            field: "boundary",
            observed: u64::try_from(exact_len + 1).expect("fixture length fits in u64"),
            limit: DecodeLimits::MINIMAL.byte_string_bytes,
        }),
        "one byte past byte_string_bytes must keep its typed refusal"
    );
}

#[test]
fn an_element_count_at_its_exact_limit_decodes_and_one_over_is_refused() {
    let exact_count = usize::try_from(DecodeLimits::MINIMAL.elements)
        .expect("minimal element bound fits in usize");
    let exact_values = vec![7_u8; exact_count];
    let mut encoder = Encoder::new();
    encoder
        .write_sequence("boundary", &exact_values, |out, value| {
            out.write_scalar(*value);
            Ok(())
        })
        .expect("the canonical encoder accepts the exact fixture");
    let exact_frame = encoder.into_bytes();
    let mut decoder = Decoder::new(&exact_frame, DecodeLimits::MINIMAL);
    assert_eq!(
        decoder
            .read_sequence("boundary", |input| input.read_scalar::<u8>("element"))
            .expect("a collection exactly at elements must decode"),
        exact_values
    );
    decoder.finish().expect("the exact frame is fully consumed");

    let one_over_values = vec![7_u8; exact_count + 1];
    let mut encoder = Encoder::new();
    encoder
        .write_sequence("boundary", &one_over_values, |out, value| {
            out.write_scalar(*value);
            Ok(())
        })
        .expect("the encoder admits the adversarial wire fixture");
    let hostile = encoder.into_bytes();
    let mut decoder = Decoder::new(&hostile, DecodeLimits::MINIMAL);
    assert_eq!(
        decoder.read_sequence("boundary", |input| input.read_scalar::<u8>("element")),
        Err(CodecRefusal::CountBoundExceeded {
            field: "boundary",
            observed: u64::try_from(exact_count + 1).expect("fixture count fits in u64"),
            limit: DecodeLimits::MINIMAL.elements,
        }),
        "one element past elements must keep its typed refusal"
    );
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
        scheme: SignatureSchemeId::try_new(support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT)
            .expect("nonzero"),
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
        CodecRefusal::schema_major_unsupported(TransactionSealBody::DOMAIN, 2, 1),
        CodecRefusal::schema_family_unexpected(
            TransactionSealBody::SCHEMA_FAMILY,
            SchemaFamily::from_static("rcr"),
        ),
        CodecRefusal::domain_unexpected(TransactionSealBody::DOMAIN, SignedEnvelopeBody::DOMAIN),
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

// ------------------------------------------------ digest width at the boundary
//
// `DigestBytes` enforces a generic 16..=64 shell bound, which is algorithm-blind.
// Until `read_digest` consulted the registry, a frame could declare SHA-256 and
// carry a 20-byte body: the stronger algorithm's name over 96 fewer bits of
// collision resistance. `TypeRefusal::DigestLengthMismatch` existed and was
// asserted on in a sample array, but nothing on any decode path could fire it.
//
// Every case below reaches the check through `decode_body` on an encoded frame.
// None constructs the refusal by hand.

/// A digest body whose width contradicts its own algorithm tag.
fn seal_with_digest(digest: Digest) -> Vec<u8> {
    let mut body = support::transaction_seal();
    body.idempotency_key_digest = digest;
    // The encoder does not validate width -- this is precisely the frame a
    // hostile peer can put on the wire, built the only way it can be built.
    encode_body(&body).expect("a malformed digest still encodes")
}

fn body_of(fill: u8, length: usize) -> DigestBytes {
    DigestBytes::try_new(&vec![fill; length]).expect("length is inside the shell bound")
}

#[test]
fn a_digest_body_of_the_wrong_width_for_its_algorithm_is_refused_on_the_way_in() {
    let sha256 = DigestAlgorithm::Sha256;
    let frame = seal_with_digest(Digest::new(sha256.id(), body_of(0x77, 20)));

    let refusal = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect_err("a 20-byte body must not pass as SHA-256");
    assert_eq!(
        refusal,
        CodecRefusal::Type(TypeRefusal::DigestLengthMismatch {
            algorithm: sha256.id(),
            expected: 32,
            observed: 20,
        })
    );

    // Permitted twin: the same algorithm at the width it declares.
    let honest = seal_with_digest(Digest::new(sha256.id(), body_of(0x77, 32)));
    assert!(decode_body::<TransactionSealBody>(&honest, DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn the_width_check_discriminates_on_the_algorithm_and_not_on_the_number_twenty() {
    // The body that is wrong for SHA-256 is exactly right for SHA-1. Without
    // this case the refusal above is consistent with a check that simply
    // dislikes short bodies, which would be a different and weaker guard.
    let sha1 = DigestAlgorithm::Sha1;
    assert_eq!(sha1.digest_len(), 20);
    let frame = seal_with_digest(Digest::new(sha1.id(), body_of(0x77, 20)));
    assert!(decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT).is_ok());

    // And the width that is right for SHA-256 is wrong for SHA-1, so the check
    // is symmetric rather than a one-directional floor.
    let swapped = seal_with_digest(Digest::new(sha1.id(), body_of(0x77, 32)));
    let refusal = decode_body::<TransactionSealBody>(&swapped, DecodeLimits::DEFAULT)
        .expect_err("32 bytes is not a SHA-1 output");
    assert_eq!(
        refusal,
        CodecRefusal::Type(TypeRefusal::DigestLengthMismatch {
            algorithm: sha1.id(),
            expected: 20,
            observed: 32,
        })
    );
}

#[test]
fn a_code_point_naming_no_construction_carries_no_width_claim() {
    // The corpus algorithm sits in `CORPUS_RESERVED_CODE_POINTS`, a range
    // `fgit-crypto` asserts at compile time that no registered construction
    // occupies. It resolves to no construction, so it declares no width and
    // there is nothing to match -- which is what lets the golden corpus round
    // trip through the production reader rather than being refused by it.
    assert!(
        DigestAlgorithm::from_id(support::algorithm()).is_none(),
        "the corpus slot must never resolve to a real construction"
    );
    let wide = seal_with_digest(Digest::new(support::algorithm(), body_of(0x77, 64)));
    assert!(decode_body::<TransactionSealBody>(&wide, DecodeLimits::DEFAULT).is_ok());
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn the_same_width_check_guards_the_internal_object_id_door() {
    // `read_internal_object_id` reads an algorithm and a digest body through a
    // different function, so guarding only `read_digest` would close the hole
    // under one name and leave it open under another.
    let sha256 = DigestAlgorithm::Sha256;
    let mut body = support::transaction_seal();
    body.tx_id = TxId::from_internal_object_id(InternalObjectId::new(
        sha256.id(),
        TxId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        body_of(0x77, 20),
    ))
    .expect("own domain");
    let frame = encode_body(&body).expect("a malformed identity still encodes");

    let refusal = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect_err("a truncated identity digest must not decode");
    assert_eq!(
        refusal,
        CodecRefusal::Type(TypeRefusal::DigestLengthMismatch {
            algorithm: sha256.id(),
            expected: 32,
            observed: 20,
        })
    );

    // Permitted twin: the corpus identity through the same door, unchanged.
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn the_corpus_slots_sit_inside_the_range_crypto_reserves() {
    // Ties the literal floor in `harness.rs` back to the range `fgit-crypto`
    // actually publishes, so the two cannot drift apart silently.
    assert_eq!(*CORPUS_RESERVED_CODE_POINTS.start(), 0xfff0);
    assert!(CORPUS_RESERVED_CODE_POINTS.contains(&support::CORPUS_ALGORITHM_CODE_POINT));
    assert!(CORPUS_RESERVED_CODE_POINTS.contains(&support::FIXTURE_SIGNATURE_SCHEME_CODE_POINT));

    // Presence case: the same predicate must REJECT the production slots.
    // Without this the assertions above pass for a range that contains
    // everything, which is the shape a vacuous guard takes.
    assert!(!CORPUS_RESERVED_CODE_POINTS.contains(&DigestAlgorithm::Sha1.code_point()));
    assert!(!CORPUS_RESERVED_CODE_POINTS.contains(&DigestAlgorithm::Sha256.code_point()));
}

// ------------------------------------- unregistered algorithm code points
//
// `DigestAlgorithmId::try_new` refuses only code point 0, correctly: `fgit-types`
// is L0 and cannot see the registry. So until this check, the decoder accepted a
// digest under any non-zero u16, including points the registry never allocated.
// ADR-0002 already settled the doctrine for the *domain* vocabulary -- "an
// unregistered domain is now a typed refusal" -- and `fgit-types` already
// refuses an unknown *Git* hash algorithm. The internal digest vocabulary was
// the one that missed it.

#[test]
fn a_digest_under_an_unregistered_algorithm_code_point_is_refused() {
    // 3 names no construction and sits outside the corpus-reserved range, so
    // nothing can attach a width or a collision-resistance property to it.
    let unregistered = DigestAlgorithmId::try_new(3).expect("nonzero");
    let frame = seal_with_digest(Digest::new(unregistered, body_of(0x77, 32)));
    let refusal = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect_err("an unallocated code point must not decode");
    assert_eq!(
        refusal,
        CodecRefusal::DigestAlgorithmUnregistered { code_point: 3 }
    );

    // Permitted twin 1: a REGISTERED point at its own width still decodes.
    let registered = seal_with_digest(Digest::new(DigestAlgorithm::Sha256.id(), body_of(0x77, 32)));
    assert!(decode_body::<TransactionSealBody>(&registered, DecodeLimits::DEFAULT).is_ok());

    // Permitted twin 2: a corpus-reserved point is DELIBERATELY unresolvable
    // and must stay accepted, or the golden corpus stops decoding.
    let reserved = seal_with_digest(Digest::new(support::algorithm(), body_of(0x77, 32)));
    assert!(decode_body::<TransactionSealBody>(&reserved, DecodeLimits::DEFAULT).is_ok());
}

#[test]
fn the_unregistered_refusal_stops_exactly_at_the_reserved_boundary() {
    // Arms 2 and 3 meet at one value. `CORPUS_RESERVED_CODE_POINTS` starts
    // INCLUSIVELY at 0xfff0, so 0xfff0 is accepted and 0xffef is refused. A
    // refusal-only test cannot tell a correct boundary from an off-by-one, and
    // an off-by-one here would refuse the range's own first slot -- the slot
    // every migrated fixture in the workspace is entitled to use.
    let below = DigestAlgorithmId::try_new(0xffef).expect("nonzero");
    let refusal = decode_body::<TransactionSealBody>(
        &seal_with_digest(Digest::new(below, body_of(0x77, 32))),
        DecodeLimits::DEFAULT,
    )
    .expect_err("0xffef is one below the reserved range");
    assert_eq!(
        refusal,
        CodecRefusal::DigestAlgorithmUnregistered { code_point: 0xffef }
    );

    let first_reserved = DigestAlgorithmId::try_new(0xfff0).expect("nonzero");
    assert!(
        decode_body::<TransactionSealBody>(
            &seal_with_digest(Digest::new(first_reserved, body_of(0x77, 32))),
            DecodeLimits::DEFAULT,
        )
        .is_ok(),
        "0xfff0 is the first reserved point and must be accepted"
    );
}

#[test]
fn the_unregistered_refusal_guards_the_internal_object_id_door_too() {
    // Same second door as the width check: a different function reads an
    // algorithm and a digest body, so a guard on `read_digest` alone would
    // close this under one name and leave it open under another.
    let unregistered = DigestAlgorithmId::try_new(3).expect("nonzero");
    let mut body = support::transaction_seal();
    body.tx_id = TxId::from_internal_object_id(InternalObjectId::new(
        unregistered,
        TxId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        body_of(0x77, 32),
    ))
    .expect("own domain");
    let frame = encode_body(&body).expect("a malformed identity still encodes");

    let refusal = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect_err("an unallocated code point must not decode as an identity");
    assert_eq!(
        refusal,
        CodecRefusal::DigestAlgorithmUnregistered { code_point: 3 }
    );

    // Permitted twin: the corpus identity through the same door, unchanged.
    assert!(decode_body::<TransactionSealBody>(&seal_bytes(), DecodeLimits::DEFAULT).is_ok());
}
