use super::*;
use crate::NativeChecksumVerifier;

fn native_pack(format: ObjectFormat) -> Vec<u8> {
    let body = b"custody\n";
    let length = u16::try_from(body.len()).unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.push(0x30 | u8::try_from(body.len()).unwrap());
    pack.extend_from_slice(&[0x78, 0x01, 0x01]);
    pack.extend_from_slice(&length.to_le_bytes());
    pack.extend_from_slice(&(!length).to_le_bytes());
    pack.extend_from_slice(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
    match format {
        ObjectFormat::Sha1 => pack.extend_from_slice(&fgit_crypto::sha1_digest(&pack)),
        ObjectFormat::Sha256 => pack.extend_from_slice(&fgit_crypto::sha256_digest(&pack)),
    }
    pack
}

fn same_parsed_objects(actual: &QuarantinedPack, expected: &QuarantinedPack) {
    assert_eq!(actual.header, expected.header);
    assert_eq!(actual.format, expected.format);
    assert_eq!(actual.trailer, expected.trailer);
    assert_eq!(actual.entries(), expected.entries());
}

#[test]
fn owned_reader_retains_original_allocation_and_clones_only_custody() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_pack(format);
        let expected = bytes.clone();
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
        let parsed = read_verified_pack_owned(
            bytes,
            format,
            &PackLimits::default(),
            &mut || true,
            &NativeChecksumVerifier,
            capacity,
        )
        .unwrap();
        let retained = parsed.retained_bytes().unwrap().clone();
        assert_eq!(retained.bytes(), expected);
        assert_eq!(retained.bytes().as_ptr(), pointer);
        assert_eq!(retained.retained_capacity(), capacity);
        assert_eq!(retained.format(), format);
        assert_eq!(retained.checksum(), parsed.trailer);
        assert_eq!(retained.object_count(), 1);
        assert_eq!(parsed.entries()[0].inflated, b"custody\n");
        let duplicate = retained.clone();
        assert_eq!(duplicate.bytes().as_ptr(), pointer);
        drop(parsed);
        drop(retained);
        assert_eq!(duplicate.bytes(), expected);
    }
}

#[test]
fn original_retained_metadata_cannot_be_rewritten_with_public_quarantine_fields() {
    let format = ObjectFormat::Sha1;
    let mut parsed = read_verified_pack_owned(
        native_pack(format),
        format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
        4096,
    )
    .unwrap();
    let checksum = parsed.trailer;
    parsed.header.object_count = 0;
    parsed.format = ObjectFormat::Sha256;
    parsed.trailer = object_id_from_bytes(ObjectFormat::Sha1, &[0; 20]).unwrap();
    let retained = parsed.retained_bytes().unwrap();
    assert_eq!(retained.object_count(), 1);
    assert_eq!(retained.format(), format);
    assert_eq!(retained.checksum(), checksum);
}

#[test]
fn disabled_and_over_capacity_retention_preserve_the_ordinary_parse() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_pack(format);
        let limits = PackLimits::default();
        let expected = read_verified_pack(
            &bytes,
            format,
            &limits,
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        assert!(expected.retained_bytes().is_none());
        assert!(
            parse_quarantined_pack(&bytes, format, &limits, &mut || true)
                .unwrap()
                .retained_bytes()
                .is_none()
        );
        for cap in [0, bytes.len() - 1] {
            let actual = read_verified_pack_owned(
                bytes.clone(),
                format,
                &limits,
                &mut || true,
                &NativeChecksumVerifier,
                cap,
            )
            .unwrap();
            assert!(actual.retained_bytes().is_none());
            same_parsed_objects(&actual, &expected);
        }
        let mut overallocated = Vec::with_capacity(bytes.len() + 512);
        overallocated.extend_from_slice(&bytes);
        assert!(overallocated.capacity() > bytes.len());
        let actual = read_verified_pack_owned(
            overallocated,
            format,
            &limits,
            &mut || true,
            &NativeChecksumVerifier,
            bytes.len(),
        )
        .unwrap();
        assert!(actual.retained_bytes().is_none());
        same_parsed_objects(&actual, &expected);
    }
}

#[test]
fn corrupt_pack_and_resource_refusals_cannot_yield_retained_custody() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_pack(format);
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        for cap in [0, 4096] {
            assert_eq!(
                read_verified_pack_owned(
                    corrupt.clone(),
                    format,
                    &PackLimits::default(),
                    &mut || true,
                    &NativeChecksumVerifier,
                    cap,
                ),
                Err(PackError::TrailerChecksumMismatch)
            );
            for limits in [
                PackLimits {
                    max_input_bytes: bytes.len() - 1,
                    ..PackLimits::default()
                },
                PackLimits {
                    max_object_bytes: 1,
                    ..PackLimits::default()
                },
            ] {
                let ordinary = read_verified_pack(
                    &bytes,
                    format,
                    &limits,
                    &mut || true,
                    &NativeChecksumVerifier,
                );
                assert!(ordinary.is_err());
                assert_eq!(
                    read_verified_pack_owned(
                        bytes.clone(),
                        format,
                        &limits,
                        &mut || true,
                        &NativeChecksumVerifier,
                        cap,
                    ),
                    ordinary
                );
            }
        }
    }
}

#[test]
fn retention_preserves_all_parser_cancellation_checkpoints() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_pack(format);
        let limits = PackLimits::default();
        let mut ordinary_count = 0;
        let ordinary = read_verified_pack(
            &bytes,
            format,
            &limits,
            &mut || {
                ordinary_count += 1;
                true
            },
            &NativeChecksumVerifier,
        )
        .unwrap();
        assert!(ordinary_count > 2);
        for cap in [0, 4096] {
            let mut observed_count = 0;
            let observed = read_verified_pack_owned(
                bytes.clone(),
                format,
                &limits,
                &mut || {
                    observed_count += 1;
                    true
                },
                &NativeChecksumVerifier,
                cap,
            )
            .unwrap();
            same_parsed_objects(&observed, &ordinary);
            assert_eq!(observed_count, ordinary_count);
            for stop_at in 1..=ordinary_count {
                let mut ordinary_seen = 0;
                let expected = read_verified_pack(
                    &bytes,
                    format,
                    &limits,
                    &mut || {
                        ordinary_seen += 1;
                        ordinary_seen < stop_at
                    },
                    &NativeChecksumVerifier,
                );
                assert!(expected.is_err());
                let mut observed_seen = 0;
                let actual = read_verified_pack_owned(
                    bytes.clone(),
                    format,
                    &limits,
                    &mut || {
                        observed_seen += 1;
                        observed_seen < stop_at
                    },
                    &NativeChecksumVerifier,
                    cap,
                );
                assert_eq!(actual, expected);
                assert_eq!(observed_seen, ordinary_seen);
            }
        }
    }
}
