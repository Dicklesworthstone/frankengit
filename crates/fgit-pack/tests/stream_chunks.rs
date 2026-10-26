#![forbid(unsafe_code)]
//! A large base blob is drained without an entry-sized allocation; all framing
//! evidence remains tentative through native trailer and exact EOF checks.
use fgit_deflate::{DeflateLimits, DeflateProfile, deflate_zlib};
use fgit_pack::{
    EntryKind, NativeChecksumVerifier, ObjectFormat, PackError, PackLimits,
    STREAM_PACK_CHUNK_BYTES, StreamPackError, StreamPackEvent, read_streamed_pack,
    read_streamed_pack_chunks, read_verified_pack,
};
use std::cell::Cell;
use std::convert::Infallible;
use std::io::{BufReader, Cursor};

fn header(kind: u8, mut size: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = kind << 4 | (size & 15) as u8;
    size >>= 4;
    while size != 0 {
        bytes.push(byte | 128);
        byte = (size & 127) as u8;
        size >>= 7;
    }
    bytes.push(byte);
    bytes
}
fn member(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut entry = header(kind, body.len());
    if kind == 6 {
        entry.push(1);
    }
    if kind == 7 {
        entry.extend([0x11; 20]);
    }
    entry.extend(deflate_zlib(body, DeflateLimits::GIT_OBJECT, DeflateProfile::DYNAMIC).unwrap());
    entry
}
fn pack(format: ObjectFormat, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend((entries.len() as u32).to_be_bytes());
    for entry in entries {
        bytes.extend(entry);
    }
    match format {
        ObjectFormat::Sha1 => bytes.extend(fgit_crypto::sha1_digest(&bytes)),
        ObjectFormat::Sha256 => bytes.extend(fgit_crypto::sha256_digest(&bytes)),
    }
    bytes
}

#[test]
fn chunked_reader_preserves_whole_entry_bytes_boundaries_crc_and_native_receipt() {
    let bodies = [
        b"first base".to_vec(),
        vec![b'a'; 96 * 1024],
        Vec::new(),
        b"last base".to_vec(),
    ];
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = pack(
            format,
            &bodies.iter().map(|b| member(3, b)).collect::<Vec<_>>(),
        );
        let limits = PackLimits {
            max_object_bytes: 128,
            ..PackLimits::default()
        };
        let wide = PackLimits {
            max_object_bytes: 128 * 1024,
            ..limits.clone()
        };
        let expected =
            read_verified_pack(&bytes, format, &wide, &mut || true, &NativeChecksumVerifier)
                .unwrap();
        for input_chunk in [1, 17, 32 * 1024] {
            let mut reader = BufReader::with_capacity(input_chunk, Cursor::new(&bytes));
            let (mut starts, mut ends, mut seen) = (Vec::new(), Vec::new(), Vec::<Vec<u8>>::new());
            let receipt = read_streamed_pack_chunks(
                &mut reader,
                format,
                &limits,
                128 * 1024,
                &mut || true,
                |event| {
                    match event {
                        StreamPackEvent::Begin(start) => {
                            starts.push(start);
                            seen.push(Vec::new());
                        }
                        StreamPackEvent::Data(chunk) => {
                            assert!(chunk.len() <= STREAM_PACK_CHUNK_BYTES);
                            assert!(!chunk.is_empty());
                            seen.last_mut().unwrap().extend(chunk);
                        }
                        StreamPackEvent::End(end) => ends.push(end),
                    }
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap();
            assert_eq!(seen, bodies);
            assert_eq!(receipt.trailer(), expected.trailer);
            assert_eq!(receipt.pack_sha256(), fgit_crypto::sha256_digest(&bytes));
            let mut old_entries = Vec::new();
            let old = read_streamed_pack(
                &mut Cursor::new(&bytes),
                format,
                &wide,
                &mut || true,
                |entry| {
                    old_entries.push(entry);
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap();
            assert_eq!(receipt, old);
            for (i, entry) in old_entries.iter().enumerate() {
                assert_eq!(starts[i].header, entry.entry.header);
                assert_eq!(starts[i].offset, entry.entry.offset);
                assert_eq!(ends[i].end_offset, entry.end_offset);
                assert_eq!(ends[i].crc32, entry.crc32);
            }
        }
    }
}

#[test]
fn blob_allowance_does_not_widen_metadata_or_delta_programs() {
    let body = vec![b'x'; 4096];
    let limits = PackLimits {
        max_object_bytes: 1024,
        ..PackLimits::default()
    };
    for kind in [1, 2, 3, 4, 6, 7] {
        let bytes = pack(ObjectFormat::Sha1, &[member(kind, &body)]);
        let events = Cell::new(0);
        let result = read_streamed_pack_chunks(
            &mut Cursor::new(bytes),
            ObjectFormat::Sha1,
            &limits,
            body.len(),
            &mut || true,
            |_| {
                events.set(events.get() + 1);
                Ok::<_, Infallible>(())
            },
        );
        if kind == 3 {
            assert!(result.is_ok());
            assert!(events.get() > 0);
        } else {
            assert!(matches!(
                result,
                Err(StreamPackError::Pack(PackError::ObjectSizeLimit {
                    actual: 4096,
                    limit: 1024
                }))
            ));
            assert_eq!(events.get(), 0);
        }
    }
}

#[test]
fn entry_end_cannot_authenticate_corrupt_pack_or_nonempty_suffix() {
    let bytes = pack(ObjectFormat::Sha1, &[member(3, &vec![b'x'; 100_000])]);
    let mut bad_trailer = bytes.clone();
    *bad_trailer.last_mut().unwrap() ^= 1;
    let mut suffix = bytes.clone();
    suffix.push(0);
    for (input, trailer) in [(bad_trailer, true), (suffix, false)] {
        let (mut chunks, mut ends) = (0, 0);
        let result = read_streamed_pack_chunks(
            &mut Cursor::new(input),
            ObjectFormat::Sha1,
            &PackLimits::default(),
            200_000,
            &mut || true,
            |event| {
                if matches!(event, StreamPackEvent::Data(_)) {
                    chunks += 1;
                }
                if matches!(event, StreamPackEvent::End(_)) {
                    ends += 1;
                }
                Ok::<_, Infallible>(())
            },
        );
        assert!(chunks > 1);
        assert_eq!(ends, 1);
        assert!(matches!(
            (result, trailer),
            (
                Err(StreamPackError::Pack(PackError::TrailerChecksumMismatch)),
                true
            ) | (
                Err(StreamPackError::Pack(PackError::TrailingPackData)),
                false
            )
        ));
    }
    assert!(
        read_streamed_pack_chunks(
            &mut Cursor::new(bytes),
            ObjectFormat::Sha1,
            &PackLimits::default(),
            200_000,
            &mut || true,
            |_| Ok::<_, Infallible>(())
        )
        .is_ok()
    );
}

#[test]
fn corrupt_zlib_and_short_length_do_not_end_the_entry() {
    let body = vec![b'z'; 64 * 1024];
    let mut corrupt = member(3, &body);
    *corrupt.last_mut().unwrap() ^= 1;
    let mut short = header(3, body.len() + 1);
    short.extend(deflate_zlib(&body, DeflateLimits::GIT_OBJECT, DeflateProfile::DYNAMIC).unwrap());
    for entry in [corrupt, short] {
        let bytes = pack(ObjectFormat::Sha1, &[entry]);
        let mut ends = 0;
        let result = read_streamed_pack_chunks(
            &mut Cursor::new(bytes),
            ObjectFormat::Sha1,
            &PackLimits::default(),
            200_000,
            &mut || true,
            |event| {
                if matches!(event, StreamPackEvent::End(_)) {
                    ends += 1;
                }
                Ok::<_, Infallible>(())
            },
        );
        assert!(result.is_err());
        assert_eq!(ends, 0);
    }
}

#[test]
fn aggregate_blob_work_sink_and_cancellation_bounds_are_independent() {
    let body = vec![b'v'; 100_000];
    let bytes = pack(ObjectFormat::Sha1, &[member(3, &body)]);
    let limits = PackLimits::default();
    for profile in [
        PackLimits {
            max_total_expanded_bytes: body.len() - 1,
            ..limits.clone()
        },
        PackLimits {
            max_input_bytes: bytes.len() - 1,
            ..limits.clone()
        },
        PackLimits {
            max_inflate_work: 10,
            ..limits.clone()
        },
    ] {
        assert!(
            read_streamed_pack_chunks(
                &mut Cursor::new(&bytes),
                ObjectFormat::Sha1,
                &profile,
                body.len(),
                &mut || true,
                |_| Ok::<_, Infallible>(())
            )
            .is_err()
        );
    }
    assert!(matches!(
        read_streamed_pack_chunks(
            &mut Cursor::new(&bytes),
            ObjectFormat::Sha1,
            &limits,
            body.len() - 1,
            &mut || true,
            |_| Ok::<_, Infallible>(())
        ),
        Err(StreamPackError::Pack(PackError::ObjectSizeLimit { .. }))
    ));
    let mut data_calls = 0;
    let result = read_streamed_pack_chunks(
        &mut Cursor::new(&bytes),
        ObjectFormat::Sha1,
        &limits,
        body.len(),
        &mut || true,
        |event| {
            if matches!(event, StreamPackEvent::Data(_)) {
                data_calls += 1;
                return Err("sink-full");
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(StreamPackError::Sink("sink-full"))));
    assert_eq!(data_calls, 1);
    let cancelled = Cell::new(false);
    let result = read_streamed_pack_chunks(
        &mut Cursor::new(&bytes),
        ObjectFormat::Sha1,
        &limits,
        body.len(),
        &mut || !cancelled.get(),
        |event| {
            if matches!(event, StreamPackEvent::Data(_)) {
                cancelled.set(true);
            }
            Ok::<_, Infallible>(())
        },
    );
    assert!(result.is_err());
    let mut begin = 0;
    assert!(
        read_streamed_pack_chunks(
            &mut Cursor::new(&bytes),
            ObjectFormat::Sha1,
            &limits,
            body.len(),
            &mut || true,
            |event| {
                if let StreamPackEvent::Begin(start) = event {
                    assert_eq!(start.header.kind, EntryKind::Blob);
                    begin += 1;
                }
                Ok::<_, Infallible>(())
            }
        )
        .is_ok()
    );
    assert_eq!(begin, 1);
}
