use super::*;
use fgit_crypto::{GitObjectHasher, IdentityDomain, NativeObjectIdentity, Sha1, Sha256};
use std::cell::Cell;
use std::io::Cursor;

fn commitment(kind: GitObjectKind, payload: &[u8]) -> [u8; 32] {
    git_payload_commitment(kind, payload, CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}

#[test]
fn stream_visitors_preserve_every_record_kind_and_the_original_wire_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut rows = GitObjectKind::ALL
            .iter()
            .copied()
            .map(|kind| {
                let payload = format!("{}\0arbitrary record bytes\n", kind.label()).into_bytes();
                (git_object_id(format, kind, &payload), kind, payload)
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|row| row.0);
        let mut old = Encoder::new(identity(format), &authority(), rows.len()).unwrap();
        let mut actual = Vec::new();
        let mut streamed = StreamEncoder::new(
            &mut actual,
            identity(format),
            &authority(),
            rows.len(),
            Default::default(),
            &mut || Ok(()),
        )
        .unwrap();
        for (id, kind, body) in &rows {
            let proof = commitment(*kind, body);
            old.object(*id, *kind, body, &proof).unwrap();
            let mut input = Fragmented {
                input: body.as_slice(),
                interrupted: false,
                largest: 0,
            };
            streamed
                .object_stream(
                    *id,
                    *kind,
                    body.len() as u64,
                    &proof,
                    &mut input,
                    &mut || Ok(()),
                )
                .unwrap();
            assert!(input.largest <= CHUNK_BYTES);
        }
        let seal = streamed.finish(&mut || Ok(())).unwrap();
        assert_eq!(actual, old.finish().unwrap());
        let mut decoder =
            StreamDecoder::new(actual.as_slice(), Default::default(), &mut || Ok(())).unwrap();
        for (id, kind, body) in &rows {
            assert!(
                decoder
                    .visit_record(&mut || Ok(()), |header, input| {
                        assert_eq!(
                            (header.oid, header.kind, header.length),
                            (*id, *kind, body.len() as u64)
                        );
                        assert_eq!(header.commitment, commitment(*kind, body));
                        let mut restored = Vec::new();
                        input
                            .read_to_end(&mut restored)
                            .map_err(|error| error.to_string())?;
                        assert_eq!(&restored, body);
                        assert_eq!(input.read(&mut [0; 1]).unwrap(), 0);
                        Ok(())
                    })
                    .unwrap()
            );
        }
        assert!(
            !decoder
                .visit_record(&mut || Ok(()), |_, _| panic!("no further record"))
                .unwrap()
        );
        assert_eq!(decoder.payload.capacity(), 0);
        assert_eq!(decoder.finish(seal.digest, &mut || Ok(())).unwrap().1, seal);
    }
}

struct PrefixSink {
    prefix: Vec<u8>,
    keep: usize,
    written: u64,
    largest: usize,
}
impl Write for PrefixSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        let keep = bytes.len().min(self.keep - self.prefix.len());
        self.prefix.extend_from_slice(&bytes[..keep]);
        self.written += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn repeated_identity(format: GitHashAlgorithm, length: u64, byte: u8) -> (GitOid, [u8; 32]) {
    let mut sha1 = GitObjectHasher::<Sha1>::new(GitObjectKind::Blob, length);
    let mut sha256 = GitObjectHasher::<Sha256>::new(GitObjectKind::Blob, length);
    let git_header = format!("blob {length}\0");
    let mut strong = Sha256Hasher::new();
    strong.update(&fgit_crypto::internal_id_preimage_header(
        IdentityDomain::GitPayloadCommitment,
        fgit_crypto::GIT_PAYLOAD_SCHEMA,
        length + git_header.len() as u64,
    ));
    strong.update(git_header.as_bytes());
    let buffer = vec![byte; CHUNK_BYTES];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        match format {
            GitHashAlgorithm::Sha1 => sha1.update(&buffer[..count]).unwrap(),
            GitHashAlgorithm::Sha256 => sha256.update(&buffer[..count]).unwrap(),
        }
        strong.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let oid = match format {
        GitHashAlgorithm::Sha1 => sha1.finish().unwrap().erase(),
        GitHashAlgorithm::Sha256 => sha256.finish().unwrap().erase(),
    };
    (oid, strong.finish())
}

#[test]
fn blobs_larger_than_32_mib_roundtrip_with_bounded_generated_sources_and_visitors() {
    const LENGTH: u64 = 33 * 1024 * 1024 + 19;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (oid, proof) = repeated_identity(format, LENGTH, 173);
        let authority = authority();
        let header_size = 65 + authority.len() + 8 + format.digest_len() + 1 + 8 + 32;
        let mut sink = PrefixSink {
            prefix: Vec::new(),
            keep: header_size,
            written: 0,
            largest: 0,
        };
        let limits = TransferLimits {
            max_blob_bytes: LENGTH,
            ..Default::default()
        };
        let mut encoder = StreamEncoder::new(
            &mut sink,
            identity(format),
            &authority,
            1,
            limits,
            &mut || Ok(()),
        )
        .unwrap();
        encoder
            .object_stream(
                oid,
                GitObjectKind::Blob,
                LENGTH,
                &proof,
                &mut io::repeat(173).take(LENGTH),
                &mut || Ok(()),
            )
            .unwrap();
        let seal = encoder.finish(&mut || Ok(())).unwrap();
        assert_eq!(sink.written, header_size as u64 + LENGTH);
        assert_eq!(sink.prefix.len(), header_size);
        assert!(sink.largest <= CHUNK_BYTES);
        let input = Cursor::new(&sink.prefix).chain(io::repeat(173).take(LENGTH));
        let mut decoder = StreamDecoder::new(input, limits, &mut || Ok(())).unwrap();
        let mut total = 0;
        assert!(
            decoder
                .visit_record(&mut || Ok(()), |header, input| {
                    assert_eq!(header.oid, oid);
                    assert_eq!(header.length, LENGTH);
                    let mut chunk = vec![0; 2 * CHUNK_BYTES];
                    loop {
                        let count = input.read(&mut chunk).map_err(|error| error.to_string())?;
                        if count == 0 {
                            break;
                        }
                        assert!(count <= CHUNK_BYTES);
                        assert!(chunk[..count].iter().all(|byte| *byte == 173));
                        total += count as u64;
                    }
                    Ok(())
                })
                .unwrap()
        );
        assert_eq!(total, LENGTH);
        assert_eq!(
            decoder.payload.capacity(),
            0,
            "streaming never touches the retained payload buffer"
        );
        assert_eq!(decoder.finish(seal.digest, &mut || Ok(())).unwrap().1, seal);
        // The near-identical default profile refuses before any payload read.
        let mut default =
            StreamDecoder::new(sink.prefix.as_slice(), Default::default(), &mut || Ok(())).unwrap();
        assert!(
            default
                .visit_record(&mut || Ok(()), |_, _| panic!(
                    "default bound must precede visitor"
                ))
                .is_err()
        );
        // Merely raising the blob allowance cannot widen the buffered method.
        let mut buffered =
            StreamDecoder::new(sink.prefix.as_slice(), limits, &mut || Ok(())).unwrap();
        assert!(
            buffered
                .record(&mut || Ok(()))
                .unwrap_err()
                .contains("buffered object-byte limit")
        );
        assert_eq!(buffered.payload.capacity(), 0);
    }
}

#[test]
fn streaming_limits_precede_payload_reads_and_do_not_widen_metadata_or_archive_bounds() {
    let format = GitHashAlgorithm::Sha1;
    let bytes = sample(format);
    let start = 65 + authority().len() + 8;
    let mut metadata = bytes.clone();
    metadata[start + format.digest_len()] = kind_byte(GitObjectKind::Tree);
    metadata[start + format.digest_len() + 1..start + format.digest_len() + 9]
        .copy_from_slice(&((MAX_OBJECT_BYTES + 1) as u64).to_be_bytes());
    let limits = TransferLimits {
        max_blob_bytes: 1 << 40,
        ..Default::default()
    };
    let mut decoder = StreamDecoder::new(metadata.as_slice(), limits, &mut || Ok(())).unwrap();
    assert!(
        decoder
            .visit_record(&mut || Ok(()), |_, _| panic!(
                "metadata bound before visitor"
            ))
            .is_err()
    );
    let payload = b"binary\0payload\xff\n";
    let id = git_object_id(format, GitObjectKind::Blob, payload);
    for denied in [
        TransferLimits {
            max_blob_bytes: payload.len() as u64 - 1,
            ..Default::default()
        },
        TransferLimits {
            max_archive_bytes: bytes.len() as u64 - 1,
            ..Default::default()
        },
    ] {
        let mut encoder = StreamEncoder::new(
            io::sink(),
            identity(format),
            &authority(),
            1,
            denied,
            &mut || Ok(()),
        )
        .unwrap();
        let mut unread = Cursor::new(payload);
        assert!(
            encoder
                .object_stream(
                    id,
                    GitObjectKind::Blob,
                    payload.len() as u64,
                    &proof(payload),
                    &mut unread,
                    &mut || Ok(())
                )
                .is_err()
        );
        assert_eq!(unread.position(), 0);
        assert!(encoder.finish(&mut || Ok(())).is_err());
        let mut decoder = StreamDecoder::new(bytes.as_slice(), denied, &mut || Ok(())).unwrap();
        assert!(
            decoder
                .visit_record(&mut || Ok(()), |_, _| panic!("limit before visitor"))
                .is_err()
        );
    }
    for max_blob_bytes in [0, (1 << 40) + 1] {
        assert!(
            TransferLimits {
                max_blob_bytes,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(limits.validate().is_ok());
}

#[test]
fn incomplete_or_failed_visitors_and_swallowed_verification_errors_poison_the_pass() {
    let valid = sample(GitHashAlgorithm::Sha1);
    for scenario in 0..4 {
        let mut bytes = valid.clone();
        if scenario == 3 {
            // Keep native bytes intact, but invalidate the original strong commitment.
            bytes[65 + authority().len() + 8 + 20 + 1 + 8] ^= 1;
        }
        let mut decoder =
            StreamDecoder::new(bytes.as_slice(), Default::default(), &mut || Ok(())).unwrap();
        assert!(
            decoder
                .visit_record(&mut || Ok(()), |_, input| {
                    match scenario {
                        0 => Ok(()),
                        1 => {
                            input.read_exact(&mut [0; 1]).unwrap();
                            Ok(())
                        }
                        2 => {
                            io::copy(input, &mut io::sink()).unwrap();
                            Err("consumer refused".into())
                        }
                        _ => {
                            assert!(io::copy(input, &mut io::sink()).is_err());
                            Ok(())
                        }
                    }
                })
                .is_err(),
            "scenario {scenario}"
        );
        assert!(decoder.visit_record(&mut || Ok(()), |_, _| Ok(())).is_err());
        assert!(decoder.finish(hash(&bytes), &mut || Ok(())).is_err());
    }
    let mut decoder =
        StreamDecoder::new(valid.as_slice(), Default::default(), &mut || Ok(())).unwrap();
    assert!(
        decoder
            .visit_record(&mut || Ok(()), |_, input| {
                io::copy(input, &mut io::sink()).map_err(|error| error.to_string())?;
                Ok(())
            })
            .unwrap()
    );
    assert!(decoder.finish(hash(&valid), &mut || Ok(())).is_ok());
}

struct LateFailure<'a> {
    bytes: &'a [u8],
}

#[test]
fn empty_and_tiny_sources_preserve_exact_length_and_eof_with_small_chunks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for body in [b"".as_slice(), b"12345678".as_slice()] {
            let id = git_object_id(format, GitObjectKind::Blob, body);
            for scenario in 0..3 {
                let mut encoder = StreamEncoder::new(
                    io::sink(),
                    identity(format),
                    &authority(),
                    1,
                    Default::default(),
                    &mut || Ok(()),
                )
                .unwrap();
                let supplied = if scenario == 1 {
                    [body, b"x"].concat()
                } else {
                    body.to_vec()
                };
                let mut input = Fragmented {
                    input: supplied.as_slice(),
                    interrupted: false,
                    largest: 0,
                };
                let result = if scenario == 2 {
                    encoder.object_stream(
                        id,
                        GitObjectKind::Blob,
                        body.len() as u64,
                        &proof(body),
                        &mut LateFailure { bytes: body },
                        &mut || Ok(()),
                    )
                } else {
                    encoder.object_stream(
                        id,
                        GitObjectKind::Blob,
                        body.len() as u64,
                        &proof(body),
                        &mut input,
                        &mut || Ok(()),
                    )
                };
                if scenario == 0 {
                    assert!(result.is_ok());
                    assert_eq!(input.largest, body.len().max(1));
                    assert!(encoder.finish(&mut || Ok(())).is_ok());
                } else {
                    assert!(result.is_err());
                    assert!(encoder.finish(&mut || Ok(())).is_err());
                }
            }
        }
    }
}
impl Read for LateFailure<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.bytes.is_empty() {
            Err(io::Error::other("late source commitment failure"))
        } else {
            self.bytes.read(output)
        }
    }
}

#[test]
fn streamed_encoder_rejects_wrong_hash_short_extra_and_late_failed_sources() {
    let format = GitHashAlgorithm::Sha256;
    let body = b"authentic object bytes";
    let id = git_object_id(format, GitObjectKind::Blob, body);
    for scenario in 0..5 {
        let mut encoder = StreamEncoder::new(
            io::sink(),
            identity(format),
            &authority(),
            1,
            Default::default(),
            &mut || Ok(()),
        )
        .unwrap();
        let mut expected = proof(body);
        let mut supplied = body.to_vec();
        match scenario {
            0 => {
                supplied.pop();
            }
            1 => supplied.push(0),
            2 => supplied[0] ^= 1,
            3 => expected[0] ^= 1,
            _ => (),
        }
        let result = if scenario == 4 {
            encoder.object_stream(
                id,
                GitObjectKind::Blob,
                body.len() as u64,
                &expected,
                &mut LateFailure { bytes: body },
                &mut || Ok(()),
            )
        } else {
            encoder.object_stream(
                id,
                GitObjectKind::Blob,
                body.len() as u64,
                &expected,
                &mut supplied.as_slice(),
                &mut || Ok(()),
            )
        };
        assert!(result.is_err(), "scenario {scenario}");
        assert!(encoder.finish(&mut || Ok(())).is_err());
    }
    let mut encoder = StreamEncoder::new(
        io::sink(),
        identity(format),
        &authority(),
        1,
        Default::default(),
        &mut || Ok(()),
    )
    .unwrap();
    encoder
        .object_stream(
            id,
            GitObjectKind::Blob,
            body.len() as u64,
            &proof(body),
            &mut body.as_slice(),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(encoder.finish(&mut || Ok(())).is_ok());
}

#[test]
fn cancellation_after_last_payload_read_and_after_source_eof_cannot_complete() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    let cancelled = Cell::new(false);
    let mut live_check = || {
        if cancelled.get() {
            Err("cancelled".into())
        } else {
            Ok(())
        }
    };
    let mut decoder =
        StreamDecoder::new(bytes.as_slice(), Default::default(), &mut live_check).unwrap();
    assert!(
        decoder
            .visit_record(&mut live_check, |header, input| {
                let mut payload = vec![0; header.length as usize];
                input.read_exact(&mut payload).unwrap();
                cancelled.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(decoder.finish(hash(&bytes), &mut || Ok(())).is_err());
    struct CancelAtEof<'a> {
        input: &'a [u8],
        cancelled: &'a Cell<bool>,
    }
    impl Read for CancelAtEof<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(out)?;
            if count == 0 {
                self.cancelled.set(true);
            }
            Ok(count)
        }
    }
    cancelled.set(false);
    let body = b"bytes";
    let id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, body);
    let mut encoder = StreamEncoder::new(
        io::sink(),
        identity(GitHashAlgorithm::Sha1),
        &authority(),
        1,
        Default::default(),
        &mut live_check,
    )
    .unwrap();
    let mut input = CancelAtEof {
        input: body,
        cancelled: &cancelled,
    };
    assert!(
        encoder
            .object_stream(
                id,
                GitObjectKind::Blob,
                body.len() as u64,
                &proof(body),
                &mut input,
                &mut live_check
            )
            .is_err()
    );
    assert!(encoder.finish(&mut || Ok(())).is_err());
}

#[test]
fn empty_blob_reader_eof_is_verified_without_consuming_the_following_record() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut rows = [b"".as_slice(), b"next".as_slice()]
            .map(|body| (git_object_id(format, GitObjectKind::Blob, body), body));
        rows.sort_by_key(|row| row.0);
        let mut bytes = Vec::new();
        let mut encoder = StreamEncoder::new(
            &mut bytes,
            identity(format),
            &authority(),
            2,
            Default::default(),
            &mut || Ok(()),
        )
        .unwrap();
        for (oid, body) in rows {
            encoder
                .object_stream(
                    oid,
                    GitObjectKind::Blob,
                    body.len() as u64,
                    &proof(body),
                    &mut &*body,
                    &mut || Ok(()),
                )
                .unwrap();
        }
        let seal = encoder.finish(&mut || Ok(())).unwrap();
        let mut decoder =
            StreamDecoder::new(bytes.as_slice(), Default::default(), &mut || Ok(())).unwrap();
        for (oid, body) in rows {
            assert!(
                decoder
                    .visit_record(&mut || Ok(()), |header, input| {
                        assert_eq!(header.oid, oid);
                        let mut restored = Vec::new();
                        input.read_to_end(&mut restored).unwrap();
                        assert_eq!(restored, body);
                        Ok(())
                    })
                    .unwrap()
            );
        }
        assert_eq!(decoder.finish(seal.digest, &mut || Ok(())).unwrap().1, seal);
    }
}
