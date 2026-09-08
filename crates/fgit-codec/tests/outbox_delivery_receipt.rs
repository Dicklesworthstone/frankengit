#![forbid(unsafe_code)]
//! Codec and identity evidence only; these tests do not claim live delivery.

use fgit_codec::{
    CanonicalBody, CanonicalOutboxDeliveryReceipt, CanonicalOutboxEffectState, CodecRefusal,
    DecodeLimits, Decoder, Encoder, MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES,
    OutboxDeliveryDisposition, decode_body, encode_body,
};
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes, RepositoryId, TypeRefusal};

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256"),
        DigestBytes::try_new(&[byte; 32]).expect("SHA-256 width"),
    )
}

fn receipt(
    disposition: OutboxDeliveryDisposition,
    evidence: Vec<u8>,
) -> Result<CanonicalOutboxDeliveryReceipt, CodecRefusal> {
    CanonicalOutboxDeliveryReceipt::try_new(
        RepositoryId::from_bytes([1; 16]),
        AsciiSlug::from_static("delivery"),
        AsciiSlug::from_static("forge-events"),
        digest(2),
        digest(3),
        disposition,
        evidence,
    )
}

#[test]
fn every_disposition_round_trips_its_exact_observation_and_binding() {
    for disposition in [
        OutboxDeliveryDisposition::Acknowledged,
        OutboxDeliveryDisposition::TerminallyRefused,
        OutboxDeliveryDisposition::Indeterminate,
    ] {
        for evidence in [
            vec![0, 255, 1],
            vec![7; MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES],
        ] {
            let original = receipt(disposition, evidence.clone()).expect("bounded receipt");
            assert_eq!(original.repository_id(), RepositoryId::from_bytes([1; 16]));
            assert_eq!(original.delivery_key(), AsciiSlug::from_static("delivery"));
            assert_eq!(
                original.destination(),
                AsciiSlug::from_static("forge-events")
            );
            assert_eq!(original.payload_root(), digest(2));
            assert_eq!(original.predecessor_effect_state_root(), digest(3));
            assert_eq!(original.disposition(), disposition);
            assert_eq!(original.evidence(), evidence);
            let frame = encode_body(&original).expect("canonical encoding");
            let decoded =
                decode_body::<CanonicalOutboxDeliveryReceipt>(&frame, DecodeLimits::DEFAULT)
                    .expect("strict decoding");
            assert_eq!(decoded, original);
            assert_eq!(encode_body(&decoded).expect("re-encode"), frame);
            assert_eq!(
                decoded.root().expect("root"),
                original.root().expect("root")
            );
        }
    }
    let unknown = receipt(OutboxDeliveryDisposition::Indeterminate, Vec::new())
        .expect("unknown delivery may lack an observation");
    let frame = encode_body(&unknown).expect("encode");
    assert_eq!(
        decode_body::<CanonicalOutboxDeliveryReceipt>(&frame, DecodeLimits::DEFAULT)
            .expect("empty indeterminate observation"),
        unknown,
    );
}

#[test]
fn every_semantic_input_changes_the_receipt_identity() {
    let original = receipt(OutboxDeliveryDisposition::Acknowledged, vec![1]).expect("receipt");
    let root = original.root().expect("root");
    let variants = [
        (
            RepositoryId::from_bytes([9; 16]),
            original.delivery_key(),
            original.destination(),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            original.disposition(),
            vec![1],
        ),
        (
            original.repository_id(),
            AsciiSlug::from_static("other-delivery"),
            original.destination(),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            original.disposition(),
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            AsciiSlug::from_static("other-destination"),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            original.disposition(),
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            original.destination(),
            digest(9),
            original.predecessor_effect_state_root(),
            original.disposition(),
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            original.destination(),
            original.payload_root(),
            digest(9),
            original.disposition(),
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            original.destination(),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            OutboxDeliveryDisposition::TerminallyRefused,
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            original.destination(),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            OutboxDeliveryDisposition::Indeterminate,
            vec![1],
        ),
        (
            original.repository_id(),
            original.delivery_key(),
            original.destination(),
            original.payload_root(),
            original.predecessor_effect_state_root(),
            original.disposition(),
            vec![2],
        ),
    ];
    for (repository, key, destination, payload, predecessor, disposition, evidence) in variants {
        let changed = CanonicalOutboxDeliveryReceipt::try_new(
            repository,
            key,
            destination,
            payload,
            predecessor,
            disposition,
            evidence,
        )
        .expect("valid neighboring receipt");
        assert_ne!(changed.root().expect("changed root"), root);
    }
    assert_eq!(
        receipt(OutboxDeliveryDisposition::Acknowledged, vec![1]).expect("retry"),
        original
    );
    assert!(matches!(
        decode_body::<CanonicalOutboxEffectState>(
            &encode_body(&original).expect("frame"),
            DecodeLimits::DEFAULT,
        ),
        Err(CodecRefusal::SchemaFamilyUnexpected { .. })
    ));
}

#[test]
fn construction_refuses_absent_terminal_evidence_and_oversized_observations() {
    for disposition in [
        OutboxDeliveryDisposition::Acknowledged,
        OutboxDeliveryDisposition::TerminallyRefused,
    ] {
        assert!(matches!(
            receipt(disposition, Vec::new()),
            Err(CodecRefusal::Type(TypeRefusal::LengthOutOfRange {
                field: "outbox_delivery_receipt_evidence",
                observed: 0,
                minimum: 1,
                maximum: 4096,
            }))
        ));
        assert!(receipt(disposition, vec![1]).is_ok());
    }
    for disposition in [
        OutboxDeliveryDisposition::Acknowledged,
        OutboxDeliveryDisposition::TerminallyRefused,
        OutboxDeliveryDisposition::Indeterminate,
    ] {
        assert!(matches!(
            receipt(
                disposition,
                vec![1; MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES + 1]
            ),
            Err(CodecRefusal::LengthBoundExceeded {
                field: "outbox_delivery_receipt_evidence",
                observed: 4097,
                limit: 4096,
            })
        ));
        assert!(
            receipt(
                disposition,
                vec![1; MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES]
            )
            .is_ok()
        );
    }
}

/// Explicit schema-v1 wire constructor, including malformed values that the
/// product constructor deliberately cannot represent.
fn wire_payload(
    key: &[u8],
    destination: &[u8],
    tag: u16,
    declared_len: u32,
    evidence: &[u8],
) -> Vec<u8> {
    let mut out = Encoder::new();
    out.write_opaque_id(&[1; 16]);
    out.write_bytes("delivery_key", key).expect("test bytes");
    out.write_bytes("destination", destination)
        .expect("test bytes");
    out.write_digest(&digest(2)).expect("digest");
    out.write_digest(&digest(3)).expect("digest");
    out.write_scalar(tag);
    out.write_scalar(declared_len);
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(evidence);
    bytes
}

fn decode_payload(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<CanonicalOutboxDeliveryReceipt, CodecRefusal> {
    let mut input = Decoder::new(bytes, limits);
    let body = CanonicalOutboxDeliveryReceipt::read_payload(&mut input)?;
    input.finish()?;
    Ok(body)
}

#[test]
fn schema_v1_wire_order_and_closed_disposition_tags_match_the_product_codec() {
    for (tag, disposition) in [
        (0, OutboxDeliveryDisposition::Acknowledged),
        (1, OutboxDeliveryDisposition::TerminallyRefused),
        (2, OutboxDeliveryDisposition::Indeterminate),
    ] {
        let bytes = wire_payload(b"delivery", b"forge-events", tag, 2, &[0, 255]);
        let body = receipt(disposition, vec![0, 255]).expect("receipt");
        let mut encoded = Encoder::new();
        body.write_payload(&mut encoded).expect("payload");
        assert_eq!(encoded.into_bytes(), bytes);
        assert_eq!(
            decode_payload(&bytes, DecodeLimits::DEFAULT).expect("wire reads"),
            body
        );
    }
    for tag in [3, u16::MAX] {
        assert!(matches!(
            decode_payload(
                &wire_payload(b"delivery", b"forge-events", tag, 1, &[1]),
                DecodeLimits::DEFAULT
            ),
            Err(CodecRefusal::VariantUnknown {
                field: "outbox_delivery_disposition",
                ..
            })
        ));
    }
}

#[test]
fn malformed_wire_evidence_is_bounded_before_copying_or_waiting_for_payload() {
    for tag in [0, 1] {
        assert!(matches!(
            decode_payload(
                &wire_payload(b"delivery", b"forge-events", tag, 0, &[]),
                DecodeLimits::DEFAULT
            ),
            Err(CodecRefusal::Type(TypeRefusal::LengthOutOfRange {
                observed: 0,
                ..
            }))
        ));
        assert!(
            decode_payload(
                &wire_payload(b"delivery", b"forge-events", tag, 1, &[1]),
                DecodeLimits::DEFAULT
            )
            .is_ok()
        );
    }
    for declared in [4097, u32::MAX] {
        assert!(matches!(
            decode_payload(
                &wire_payload(b"delivery", b"forge-events", 2, declared, &[]),
                DecodeLimits::DEFAULT
            ),
            Err(CodecRefusal::LengthBoundExceeded {
                field: "outbox_delivery_receipt_evidence",
                limit: 4096,
                ..
            })
        ));
    }
    let limits = DecodeLimits {
        byte_string_bytes: 64,
        ..DecodeLimits::DEFAULT
    };
    assert!(matches!(
        decode_payload(
            &wire_payload(b"delivery", b"forge-events", 2, 65, &[]),
            limits
        ),
        Err(CodecRefusal::LengthBoundExceeded {
            field: "outbox_delivery_receipt_evidence",
            observed: 65,
            limit: 64
        })
    ));
    assert!(
        decode_payload(
            &wire_payload(b"delivery", b"forge-events", 2, 64, &[1; 64]),
            limits
        )
        .is_ok()
    );
    assert!(matches!(
        decode_payload(
            &wire_payload(b"delivery", b"forge-events", 0, 2, &[1]),
            DecodeLimits::DEFAULT
        ),
        Err(CodecRefusal::InputTruncated {
            field: "outbox_delivery_receipt_evidence",
            ..
        })
    ));
    assert!(matches!(
        decode_payload(
            &wire_payload(b"delivery", b"forge-events", 0, 1, &[1, 2]),
            DecodeLimits::DEFAULT
        ),
        Err(CodecRefusal::TrailingBytes { remaining: 1, .. })
    ));
}

#[test]
fn malformed_keys_destinations_and_truncated_frames_fail_closed() {
    for (key, destination) in [
        (b"".as_slice(), b"forge-events".as_slice()),
        (b"UPPER", b"forge-events"),
        (b"delivery", b""),
        (b"delivery", b"space here"),
    ] {
        assert!(
            decode_payload(
                &wire_payload(key, destination, 0, 1, &[1]),
                DecodeLimits::DEFAULT
            )
            .is_err()
        );
        assert!(
            decode_payload(
                &wire_payload(b"delivery", b"forge-events", 0, 1, &[1]),
                DecodeLimits::DEFAULT
            )
            .is_ok()
        );
    }
    let body = receipt(OutboxDeliveryDisposition::Acknowledged, vec![1]).expect("receipt");
    let frame = encode_body(&body).expect("frame");
    for end in 0..frame.len() {
        assert!(
            decode_body::<CanonicalOutboxDeliveryReceipt>(&frame[..end], DecodeLimits::DEFAULT)
                .is_err()
        );
    }
}
