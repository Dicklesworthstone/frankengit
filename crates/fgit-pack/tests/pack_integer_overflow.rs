#![forbid(unsafe_code)]
//! Pack integer commitments must not alias smaller values after a shift.
//! These fixtures have valid native trailers and valid compressed payloads:
//! their only defect is a size or OFS distance greater than u64::MAX.

mod fixtures;

use std::convert::Infallible;
use std::io::{BufReader, Cursor};

use fgit_pack::{
    EntryKind, NativeChecksumVerifier, ObjectFormat, PackBoundaryScanner, PackError, PackLimits,
    ParsedDeltaBase, ScanStatus, StreamPackError, StreamPackEvent, apply_delta,
    decode_entry_header, decode_ofs_delta_base, read_streamed_pack, read_streamed_pack_chunks,
    read_verified_pack,
};

fn checksummed_pack(format: ObjectFormat, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = fixtures::pack_with_entries(entries);
    bytes.truncate(bytes.len() - fixtures::SHA1_TRAILER.len());
    match format {
        ObjectFormat::Sha1 => bytes.extend_from_slice(&fgit_crypto::sha1_digest(&bytes)),
        ObjectFormat::Sha256 => bytes.extend_from_slice(&fgit_crypto::sha256_digest(&bytes)),
    }
    bytes
}

/// Encode a mathematical distance wider than the production u64 domain.
fn ofs_distance(mut distance: u128) -> Vec<u8> {
    assert_ne!(distance, 0);
    let mut bytes = vec![u8::try_from(distance & 0x7f).unwrap()];
    loop {
        distance >>= 7;
        if distance == 0 {
            break;
        }
        distance -= 1;
        bytes.push(u8::try_from(distance & 0x7f).unwrap() | 0x80);
    }
    bytes.reverse();
    bytes
}

fn oversized_entry(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 16);
    let valid = fixtures::entry(3, payload);
    // The eight intervening groups are zero. 0x10 at shift 60 contributes
    // exactly 2^64, which used to disappear and leave only the low nibble.
    let mut entry = vec![valid[0] | 0x80];
    entry.extend_from_slice(&[0x80; 8]);
    entry.push(0x10);
    entry.extend_from_slice(&valid[1..]);
    entry
}

fn delta_entries(oversized: bool) -> Vec<Vec<u8>> {
    let base = fixtures::entry(3, b"base");
    let distance = u128::try_from(base.len()).unwrap();
    let distance = if oversized {
        (1_u128 << 64) + distance
    } else {
        distance
    };
    let program = [4, 8, 0x90, 4, 4, b'p', b'l', b'u', b's'];
    let encoded = fixtures::entry(6, &program);
    let mut delta = vec![encoded[0]];
    delta.extend_from_slice(&ofs_distance(distance));
    delta.extend_from_slice(&encoded[1..]);
    vec![base, delta]
}

fn scan(bytes: &[u8], format: ObjectFormat, chunk: usize) -> Result<u64, PackError> {
    let mut scanner = PackBoundaryScanner::new(format, PackLimits::default());
    for part in bytes.chunks(chunk) {
        if let ScanStatus::Finished { pack_len } = scanner.push(part, &mut || true)? {
            return Ok(pack_len);
        }
    }
    panic!("complete test pack must finish or refuse");
}

fn assert_readers_refuse(
    bytes: &[u8],
    format: ObjectFormat,
    expected: &PackError,
    preceding_entries: usize,
) {
    let limits = PackLimits::default();
    assert_eq!(
        &read_verified_pack(
            bytes,
            format,
            &limits,
            &mut || true,
            &NativeChecksumVerifier,
        )
        .expect_err("overflowing commitment cannot authenticate a pack"),
        expected,
    );
    for chunk in [1, 2, 7, 11, bytes.len()] {
        let mut reader = BufReader::with_capacity(chunk, Cursor::new(bytes));
        let mut entries = 0;
        let error = read_streamed_pack(&mut reader, format, &limits, &mut || true, |_| {
            entries += 1;
            Ok::<_, Infallible>(())
        })
        .expect_err("streamed entry intake must refuse the same integer");
        match error {
            StreamPackError::Pack(actual) => assert_eq!(&actual, expected),
            other => panic!("unexpected stream error: {other:?}"),
        }
        assert_eq!(entries, preceding_entries);

        let mut reader = BufReader::with_capacity(chunk, Cursor::new(bytes));
        let mut begins = 0;
        let mut ends = 0;
        let error = read_streamed_pack_chunks(
            &mut reader,
            format,
            &limits,
            limits.max_object_bytes,
            &mut || true,
            |event| {
                match event {
                    StreamPackEvent::Begin(_) => begins += 1,
                    StreamPackEvent::Data(_) => {}
                    StreamPackEvent::End(_) => ends += 1,
                }
                Ok::<_, Infallible>(())
            },
        )
        .expect_err("chunked intake cannot begin an overflowing entry");
        match error {
            StreamPackError::Pack(actual) => assert_eq!(&actual, expected),
            other => panic!("unexpected chunked stream error: {other:?}"),
        }
        assert_eq!(begins, preceding_entries);
        assert_eq!(ends, preceding_entries);
        assert_eq!(&scan(bytes, format, chunk).unwrap_err(), expected);
    }
}

fn assert_readers_accept(bytes: &[u8], format: ObjectFormat) {
    let limits = PackLimits::default();
    let expected = read_verified_pack(
        bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .expect("valid twin must authenticate");
    for chunk in [1, 2, 7, 11, bytes.len()] {
        let mut reader = BufReader::with_capacity(chunk, Cursor::new(bytes));
        let mut entries = Vec::new();
        let receipt = read_streamed_pack(&mut reader, format, &limits, &mut || true, |entry| {
            entries.push(entry.entry);
            Ok::<_, Infallible>(())
        })
        .expect("valid twin must stream");
        assert_eq!(entries.as_slice(), expected.entries());
        assert_eq!(receipt.trailer(), expected.trailer);
        assert_eq!(receipt.pack_bytes(), u64::try_from(bytes.len()).unwrap());

        let mut reader = BufReader::with_capacity(chunk, Cursor::new(bytes));
        let mut index = 0;
        let mut open = false;
        let mut body = Vec::new();
        let chunked_receipt = read_streamed_pack_chunks(
            &mut reader,
            format,
            &limits,
            limits.max_object_bytes,
            &mut || true,
            |event| {
                let entry = &expected.entries()[index];
                match event {
                    StreamPackEvent::Begin(start) => {
                        assert!(!open);
                        assert_eq!(start.offset, entry.offset);
                        assert_eq!(start.header, entry.header);
                        assert_eq!(start.delta_base, entry.delta_base);
                        body.clear();
                        open = true;
                    }
                    StreamPackEvent::Data(bytes) => {
                        assert!(open);
                        body.extend_from_slice(bytes);
                    }
                    StreamPackEvent::End(end) => {
                        assert!(open);
                        assert_eq!(body, entry.inflated);
                        assert!(end.end_offset > entry.offset);
                        index += 1;
                        open = false;
                    }
                }
                Ok::<_, Infallible>(())
            },
        )
        .expect("valid twin must complete chunked entry intake");
        assert!(!open);
        assert_eq!(index, expected.entries().len());
        assert_eq!(chunked_receipt, receipt);
        assert_eq!(
            scan(bytes, format, chunk).expect("valid twin must have a pack boundary"),
            u64::try_from(bytes.len()).unwrap(),
        );
    }
}

#[test]
fn overflowing_object_sizes_refuse_before_any_entry_is_offered() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for payload in [b"".as_slice(), b"base".as_slice()] {
            let malformed = checksummed_pack(format, &[oversized_entry(payload)]);
            assert_readers_refuse(
                &malformed,
                format,
                &PackError::InvalidVarint {
                    context: "pack entry size",
                },
                0,
            );
            let permitted = checksummed_pack(format, &[fixtures::entry(3, payload)]);
            assert_readers_accept(&permitted, format);
        }
    }
}

#[test]
fn overflowing_ofs_distances_cannot_alias_a_valid_earlier_entry() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let malformed = checksummed_pack(format, &delta_entries(true));
        assert_readers_refuse(&malformed, format, &PackError::InvalidOfsDelta, 1);
        let permitted = checksummed_pack(format, &delta_entries(false));
        assert_readers_accept(&permitted, format);

        let pack = read_verified_pack(
            &permitted,
            format,
            &PackLimits::default(),
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(
            pack.entries()[1].delta_base,
            Some(ParsedDeltaBase::Ofs {
                base_offset: 12,
                consumed: 1,
            }),
        );
        assert_eq!(
            apply_delta(
                &pack.entries()[0].inflated,
                &pack.entries()[1].inflated,
                &PackLimits::default(),
                &mut || true,
            )
            .unwrap(),
            b"baseplus",
        );
    }
}

#[test]
fn the_final_size_group_preserves_every_representable_bit() {
    let limits = PackLimits {
        max_object_bytes: usize::MAX,
        ..PackLimits::default()
    };
    for high in 0_u8..=0x7f {
        let mut encoded = vec![0xb5];
        encoded.extend_from_slice(&[0x80; 8]);
        encoded.push(high);
        let decoded = decode_entry_header(&encoded, &limits, &mut || true);
        if high > 0x0f {
            assert_eq!(
                decoded,
                Err(PackError::InvalidVarint {
                    context: "pack entry size",
                }),
            );
        } else {
            let value = (u64::from(high) << 60) + 5;
            match usize::try_from(value) {
                Ok(value) => {
                    let (header, consumed) = decoded.expect("all represented bits must survive");
                    assert_eq!(header.kind, EntryKind::Blob);
                    assert_eq!(header.declared_size, value);
                    assert_eq!(consumed, encoded.len());
                }
                Err(_) => assert_eq!(
                    decoded,
                    Err(PackError::ObjectSizeLimit {
                        actual: usize::MAX,
                        limit: usize::MAX,
                    }),
                ),
            }
        }
    }
}

#[test]
fn ofs_scaling_accepts_its_last_in_range_base_and_rejects_wraparound() {
    let maximum = u64::MAX;
    let encoded = ofs_distance(u128::from(maximum - 12));
    assert_eq!(
        decode_ofs_delta_base(maximum, &encoded, &mut || true),
        Ok((12, encoded.len())),
    );
    for low in [1_u64, 12, 16, 127] {
        let oversized = ofs_distance((1_u128 << 64) + u128::from(low));
        assert_eq!(
            decode_ofs_delta_base(256, &oversized, &mut || true),
            Err(PackError::InvalidOfsDelta),
        );
        let valid = ofs_distance(u128::from(low));
        assert_eq!(
            decode_ofs_delta_base(256, &valid, &mut || true),
            Ok((256 - low, valid.len())),
        );
    }
}

#[test]
fn cancellation_is_observed_before_continuation_arithmetic() {
    let mut header = vec![0xb4];
    header.extend_from_slice(&[0x80; 8]);
    header.push(0x10);
    let distance = ofs_distance((1_u128 << 64) + 16);
    for allowed in [0, 1, 5] {
        let mut calls = 0;
        assert_eq!(
            decode_entry_header(&header, &PackLimits::default(), &mut || {
                calls += 1;
                calls <= allowed
            }),
            Err(PackError::DeadlineExceeded),
        );
        let mut calls = 0;
        assert_eq!(
            decode_ofs_delta_base(256, &distance, &mut || {
                calls += 1;
                calls <= allowed
            }),
            Err(PackError::DeadlineExceeded),
        );
    }
}
