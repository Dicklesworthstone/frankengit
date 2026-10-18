#![forbid(unsafe_code)]

mod fixtures;

use std::convert::Infallible;
use std::io::{self, BufRead, BufReader, Cursor, Read};

use fgit_pack::full_bundle::{
    FullBundleError, FullBundleHeader, FullBundleInput, FullBundleLimits, StreamBundleHeaderError,
};
use fgit_pack::{
    IdxEntry, NativeChecksumVerifier, ObjectFormat, ObjectId, PackError, PackLimits,
    StreamPackEntry, StreamPackError, StreamPackIndexEntry, build_pack_index_v2,
    build_streamed_pack_index_v2, read_streamed_pack, read_verified_pack, validate_idx_entry_crc,
};

fn decode_hex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn native_bundle(format: ObjectFormat) -> Vec<u8> {
    decode_hex(match format {
        ObjectFormat::Sha1 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
        )),
        ObjectFormat::Sha256 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"
        )),
    })
}

fn sign_pack(mut bytes: Vec<u8>, format: ObjectFormat) -> Vec<u8> {
    bytes.truncate(bytes.len() - fixtures::SHA1_TRAILER.len());
    match format {
        ObjectFormat::Sha1 => bytes.extend_from_slice(&fgit_crypto::sha1_digest(&bytes)),
        ObjectFormat::Sha256 => bytes.extend_from_slice(&fgit_crypto::sha256_digest(&bytes)),
    }
    bytes
}

fn consume<R: BufRead>(
    reader: &mut R,
    format: ObjectFormat,
    limits: &PackLimits,
) -> Result<fgit_pack::StreamPackReceipt, StreamPackError<Infallible>> {
    read_streamed_pack(reader, format, limits, &mut || true, |_| Ok(()))
}

#[test]
fn streamed_native_fixtures_match_whole_reader_at_every_small_chunk_boundary() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_bundle(format);
        let old = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let expected = read_verified_pack(
            old.pack_bytes(),
            format,
            &PackLimits::default(),
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        // Independent Git fixtures contain a REF_DELTA that precedes its
        // base. Framing must not assume resolution order.
        assert!(expected.entries().iter().any(|entry| matches!(
            entry.delta_base,
            Some(fgit_pack::ParsedDeltaBase::Ref { .. })
        )));
        for chunk in 1..=67 {
            let mut reader = BufReader::with_capacity(chunk, Cursor::new(&bytes));
            let header =
                FullBundleHeader::read(&mut reader, Default::default(), &mut || true).unwrap();
            assert_eq!(header.raw_bytes(), &bytes[..old.header_bytes()]);
            assert_eq!(header.references(), old.references());
            assert_eq!(header.head(), old.head());
            assert_eq!(header.format(), old.format());
            let mut entries = Vec::new();
            let receipt = read_streamed_pack(
                &mut reader,
                format,
                &PackLimits::default(),
                &mut || true,
                |entry| {
                    entries.push(entry);
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap();
            assert_eq!(receipt.header(), expected.header);
            assert_eq!(receipt.trailer(), expected.trailer);
            assert_eq!(receipt.pack_bytes(), old.pack_bytes().len() as u64);
            assert_eq!(
                receipt.pack_sha256(),
                fgit_crypto::sha256_digest(old.pack_bytes())
            );
            assert_eq!(entries.len(), expected.entries().len());
            for (i, (actual, expected)) in entries.iter().zip(expected.entries()).enumerate() {
                assert_eq!(&actual.entry, expected, "chunk {chunk}, entry {i}");
                let end = entries.get(i + 1).map_or(
                    old.pack_bytes().len() as u64 - format.digest_len() as u64,
                    |entry| entry.entry.offset,
                );
                assert_eq!(actual.end_offset, end);
                let row = IdxEntry {
                    oid: receipt.trailer(),
                    crc32: actual.crc32,
                    pack_offset: actual.entry.offset,
                };
                validate_idx_entry_crc(
                    &row,
                    &old.pack_bytes()[actual.entry.offset as usize..end as usize],
                    &PackLimits::default(),
                    &mut || true,
                )
                .unwrap();
            }
            assert!(reader.fill_buf().unwrap().is_empty());
        }
    }
}

#[test]
fn ofs_delta_framing_uses_the_same_base_and_instruction_decoders() {
    let base = fixtures::entry(3, b"base");
    let program = [4, 8, 0x90, 4, 4, b'p', b'l', b'u', b's'];
    let mut delta = fixtures::entry(6, &program);
    // The tiny program uses a one-byte type/size header and the predecessor
    // entry is short enough for a one-byte native OFS distance.
    delta.insert(1, u8::try_from(base.len()).unwrap());
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = sign_pack(
            fixtures::pack_with_entries(&[base.clone(), delta.clone()]),
            format,
        );
        let limits = PackLimits::default();
        let expected = read_verified_pack(
            &bytes,
            format,
            &limits,
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(
            expected.entries()[1].delta_base,
            Some(fgit_pack::ParsedDeltaBase::Ofs {
                base_offset: 12,
                consumed: 1
            })
        );
        let second_offset = expected.entries()[1].offset;
        let objects = expected.clone().into_scalar_objects(|_| None).unwrap();
        let resolver =
            fgit_pack::ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
        assert_eq!(
            resolver
                .resolve_offset_typed(second_offset, &mut || true)
                .unwrap(),
            (fgit_git_object::ObjectType::Blob, b"baseplus".to_vec())
        );
        for chunk in 1..=bytes.len() {
            let mut reader = BufReader::with_capacity(chunk, Cursor::new(&bytes));
            let mut entries = Vec::new();
            let receipt = read_streamed_pack(&mut reader, format, &limits, &mut || true, |entry| {
                entries.push(entry);
                Ok::<_, Infallible>(())
            })
            .unwrap();
            assert_eq!(entries[0].entry, expected.entries()[0]);
            assert_eq!(entries[1].entry, expected.entries()[1]);
            let rows: Vec<_> = entries
                .iter()
                .zip([b"base".as_slice(), b"baseplus".as_slice()])
                .map(|(entry, body)| StreamPackIndexEntry {
                    oid: fgit_crypto::git_object_id(
                        format,
                        fgit_git_object::ObjectType::Blob,
                        body,
                    ),
                    pack_offset: entry.entry.offset,
                    end_offset: entry.end_offset,
                    crc32: entry.crc32,
                })
                .collect();
            let locations: Vec<_> = rows.iter().map(|row| (row.oid, row.pack_offset)).collect();
            assert_eq!(
                build_streamed_pack_index_v2(&receipt, &rows, &limits, &mut || true).unwrap(),
                build_pack_index_v2(&bytes, format, &locations, &limits, &mut || true).unwrap()
            );
        }
    }
}

#[test]
fn compressed_members_cross_large_input_chunks_without_retaining_the_pack() {
    for profile in [
        fgit_deflate::DeflateProfile::FAST_STORED,
        fgit_deflate::DeflateProfile::FIXED,
        fgit_deflate::DeflateProfile::DYNAMIC,
    ] {
        let body: Vec<u8> = (0..130_000)
            .map(|i| ((i * 193 + i / 257) & 255) as u8)
            .collect();
        let member =
            fgit_deflate::deflate_zlib(&body, fgit_deflate::DeflateLimits::GIT_OBJECT, profile)
                .unwrap();
        let entry = fixtures::declared_entry(3, body.len(), &member);
        let bytes = sign_pack(fixtures::pack_with_entries(&[entry]), ObjectFormat::Sha256);
        for chunk in [1, 1021, 32_768, 65_536, bytes.len()] {
            let mut reader = BufReader::with_capacity(chunk, Cursor::new(&bytes));
            let mut observed = None;
            let receipt = read_streamed_pack(
                &mut reader,
                ObjectFormat::Sha256,
                &PackLimits::default(),
                &mut || true,
                |entry| {
                    observed = Some(entry.entry.inflated);
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap();
            assert_eq!(observed.as_deref(), Some(body.as_slice()));
            assert_eq!(receipt.pack_sha256(), fgit_crypto::sha256_digest(&bytes));
        }
    }
}

#[test]
fn callbacks_remain_tentative_until_native_trailer_and_exact_eof() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let pack = sign_pack(
            fixtures::pack_with_entries(&[fixtures::entry(3, b"one"), fixtures::entry(3, b"two")]),
            format,
        );
        for mutation in 0..3 {
            let mut changed = pack.clone();
            match mutation {
                0 => *changed.last_mut().unwrap() ^= 1,
                1 => {
                    changed.pop();
                }
                _ => changed.push(0),
            }
            let mut observed = 0;
            let error = read_streamed_pack(
                &mut changed.as_slice(),
                format,
                &PackLimits::default(),
                &mut || true,
                |_| {
                    observed += 1;
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap_err();
            assert_eq!(observed, 2);
            assert!(matches!(
                error,
                StreamPackError::Pack(
                    PackError::TrailerChecksumMismatch
                        | PackError::TrailingPackData
                        | PackError::Truncated { .. }
                )
            ));
        }
        assert!(consume(&mut pack.as_slice(), format, &PackLimits::default()).is_ok());
    }
}

#[test]
fn empty_packs_and_all_truncated_prefixes_have_exact_results() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let empty = sign_pack(fixtures::pack_with_entries(&[]), format);
        let receipt = consume(&mut empty.as_slice(), format, &PackLimits::default()).unwrap();
        assert_eq!(receipt.header().object_count, 0);
        assert_eq!(receipt.pack_bytes(), (12 + format.digest_len()) as u64);
        let pack = sign_pack(
            fixtures::pack_with_entries(&[fixtures::entry(3, b"body")]),
            format,
        );
        for cut in 0..pack.len() {
            assert!(
                consume(&mut &pack[..cut], format, &PackLimits::default()).is_err(),
                "cut {cut}"
            );
        }
        let index =
            build_streamed_pack_index_v2(&receipt, &[], &PackLimits::default(), &mut || true)
                .unwrap();
        assert_eq!(
            index,
            build_pack_index_v2(&empty, format, &[], &PackLimits::default(), &mut || true).unwrap()
        );
    }
}

#[test]
fn streaming_limits_refuse_before_callback_and_have_exact_permitted_twins() {
    let pack = sign_pack(
        fixtures::pack_with_entries(&[
            fixtures::entry(3, b"12345678"),
            fixtures::entry(3, b"abcdef"),
        ]),
        ObjectFormat::Sha1,
    );
    let mut limits = PackLimits {
        max_input_bytes: pack.len(),
        max_entries: 2,
        max_object_bytes: 8,
        max_total_expanded_bytes: 14,
        ..Default::default()
    };
    assert!(consume(&mut pack.as_slice(), ObjectFormat::Sha1, &limits).is_ok());
    for field in 0..5 {
        let saved = limits.clone();
        match field {
            0 => limits.max_input_bytes -= 1,
            1 => limits.max_entries -= 1,
            2 => limits.max_object_bytes -= 1,
            3 => limits.max_total_expanded_bytes -= 1,
            _ => limits.max_inflate_work = 1,
        }
        assert!(
            consume(&mut pack.as_slice(), ObjectFormat::Sha1, &limits).is_err(),
            "limit {field}"
        );
        limits = saved;
    }
    let bad = sign_pack(
        fixtures::pack_with_entries(&[fixtures::declared_entry(
            3,
            9,
            &fixtures::entry(3, b"eight888")[1..],
        )]),
        ObjectFormat::Sha1,
    );
    assert!(matches!(
        consume(
            &mut bad.as_slice(),
            ObjectFormat::Sha1,
            &PackLimits::default()
        ),
        Err(StreamPackError::Pack(
            PackError::InflatedEntrySizeMismatch { .. }
        ))
    ));
}

#[test]
fn every_cooperative_stop_refuses_a_completed_stream_receipt() {
    let pack = sign_pack(
        fixtures::pack_with_entries(&[fixtures::entry(3, b"first"), fixtures::entry(3, b"second")]),
        ObjectFormat::Sha1,
    );
    let mut checkpoints = 0;
    read_streamed_pack(
        &mut pack.as_slice(),
        ObjectFormat::Sha1,
        &PackLimits::default(),
        &mut || {
            checkpoints += 1;
            true
        },
        |_| Ok::<_, Infallible>(()),
    )
    .unwrap();
    for stop in 1..=checkpoints {
        let mut calls = 0;
        assert!(
            read_streamed_pack(
                &mut pack.as_slice(),
                ObjectFormat::Sha1,
                &PackLimits::default(),
                &mut || {
                    calls += 1;
                    calls != stop
                },
                |_| Ok::<_, Infallible>(())
            )
            .is_err(),
            "stop {stop}"
        );
    }
}

#[test]
fn sink_and_source_errors_keep_their_original_details() {
    let pack = sign_pack(
        fixtures::pack_with_entries(&[fixtures::entry(3, b"first"), fixtures::entry(3, b"second")]),
        ObjectFormat::Sha1,
    );
    let mut callbacks = 0;
    let error = read_streamed_pack(
        &mut pack.as_slice(),
        ObjectFormat::Sha1,
        &PackLimits::default(),
        &mut || true,
        |_| {
            callbacks += 1;
            Err("scratch full")
        },
    )
    .unwrap_err();
    assert!(matches!(error, StreamPackError::Sink("scratch full")));
    assert_eq!(callbacks, 1);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "input revoked",
            ))
        }
    }
    assert!(
        matches!(consume(&mut BufReader::new(Broken), ObjectFormat::Sha1, &PackLimits::default()), Err(StreamPackError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied && error.to_string() == "input revoked")
    );
    assert!(
        matches!(FullBundleHeader::read(&mut BufReader::new(Broken), Default::default(), &mut || true), Err(StreamBundleHeaderError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn streamed_header_shares_raw_name_capability_and_prerequisite_rules() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_bundle(format);
        let old = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let mut exact = FullBundleLimits {
            max_header_bytes: old.header_bytes(),
            ..Default::default()
        };
        assert!(FullBundleHeader::read(&mut bytes.as_slice(), exact, &mut || true).is_ok());
        exact.max_header_bytes -= 1;
        assert!(matches!(
            FullBundleHeader::read(&mut bytes.as_slice(), exact, &mut || true),
            Err(StreamBundleHeaderError::Bundle(FullBundleError::Limit(
                "header bytes"
            )))
        ));
        let id = old.references()[0].target();
        let prefix = if format == ObjectFormat::Sha1 {
            "# v2 git bundle\n"
        } else {
            "# v3 git bundle\n@object-format=sha256\n"
        };
        let header = format!("{prefix}-{id} prerequisite comment\n{id} refs/heads/main\n\n");
        let mut cursor = [header.as_bytes(), old.pack_bytes()].concat();
        let stream = FullBundleHeader::read_incremental(
            &mut cursor.as_slice(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
        let whole =
            FullBundleInput::parse_incremental(&cursor, Default::default(), &mut || true).unwrap();
        assert_eq!(stream.prerequisites(), whole.prerequisites());
        assert!(
            FullBundleHeader::read(&mut cursor.as_slice(), Default::default(), &mut || true)
                .is_err()
        );
        cursor[0] = b'!';
        assert!(
            FullBundleHeader::read_incremental(
                &mut cursor.as_slice(),
                Default::default(),
                &mut || true
            )
            .is_err()
        );
    }
    for bytes in [b"not a bundle".as_slice(), b"# v2 git bundle", b""] {
        assert!(matches!(
            FullBundleHeader::read(&mut bytes.as_ref(), Default::default(), &mut || true),
            Err(StreamBundleHeaderError::Bundle(FullBundleError::Invalid(
                "header line without delimiter"
            )))
        ));
    }
}

fn rows_for_fixture(
    format: ObjectFormat,
    entries: &[StreamPackEntry],
) -> Vec<StreamPackIndexEntry> {
    let names = match format {
        ObjectFormat::Sha1 => [
            "ec20141f0267805d3db1349c4701ed1f84f3ee61",
            "4a58007052a65fbc2fc3f910f2855f45a4058e74",
            "af05a70f13bc2fba5597c7aa79022b367d4ef140",
            "8e66527465821b289d8ad275784255bc8825617a",
            "fdf36c252d4e297cc62a161ba48176f6dcafa08a",
        ],
        ObjectFormat::Sha256 => [
            "7f159d843933f44185df4dcaab90c6eda9595d849d31ac3122fa3857fab799c6",
            "9f8bf964b2f278e643f6ee93dd5980698a5f515048b2a27134a294e5e3376180",
            "4672839c4a5ff4dc4778627c88122511b4d8da2f781beb99202c9e6dd2978321",
            "c2a1cfc79b851e01921198e44377712b8ce0593cafe564873b9de729af20ec78",
            "91cf791e6e424d4f8449c7f57012ce46de9c7053ed326b0c34744d522c9da04d",
        ],
    };
    entries
        .iter()
        .zip(names)
        .map(|(entry, name)| StreamPackIndexEntry {
            oid: ObjectId::from_hex(format, name).unwrap(),
            pack_offset: entry.entry.offset,
            end_offset: entry.end_offset,
            crc32: entry.crc32,
        })
        .collect()
}

#[test]
fn streamed_indexes_match_independent_git_goldens_and_bind_exact_framing_rows() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bytes = native_bundle(format);
        let input = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        let mut entries = Vec::new();
        let receipt = read_streamed_pack(
            &mut input.pack_bytes(),
            format,
            &PackLimits::default(),
            &mut || true,
            |entry| {
                entries.push(entry);
                Ok::<_, Infallible>(())
            },
        )
        .unwrap();
        let rows = rows_for_fixture(format, &entries);
        let index =
            build_streamed_pack_index_v2(&receipt, &rows, &PackLimits::default(), &mut || true)
                .unwrap();
        let locations: Vec<_> = rows.iter().map(|row| (row.oid, row.pack_offset)).collect();
        assert_eq!(
            index,
            build_pack_index_v2(
                input.pack_bytes(),
                format,
                &locations,
                &PackLimits::default(),
                &mut || true
            )
            .unwrap()
        );
        let golden = if format == ObjectFormat::Sha1 {
            "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7"
        } else {
            "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579"
        };
        assert_eq!(
            fgit_crypto::lowercase_hex(&fgit_crypto::sha256_digest(&index)),
            golden
        );
        let mut reversed = rows.clone();
        reversed.reverse();
        assert_eq!(
            build_streamed_pack_index_v2(&receipt, &reversed, &PackLimits::default(), &mut || true)
                .unwrap(),
            index
        );
        for mutation in 0..5 {
            let mut changed = rows.clone();
            match mutation {
                0 => changed[1].oid = changed[0].oid,
                1 => changed[1].crc32 ^= 1,
                2 => {
                    changed[0].end_offset += 1;
                    changed[1].pack_offset += 1;
                }
                3 => {
                    changed.pop();
                }
                _ => changed[0].pack_offset = u64::MAX,
            }
            assert!(
                build_streamed_pack_index_v2(
                    &receipt,
                    &changed,
                    &PackLimits::default(),
                    &mut || true
                )
                .is_err(),
                "mutation {mutation}"
            );
        }
    }
}

#[test]
fn delta_application_shares_one_operation_budget_and_never_resets_on_refusal() {
    let mut limits = PackLimits {
        max_total_expanded_bytes: 16,
        ..Default::default()
    };
    let base = b"base";
    let program = [4, 4, 0x90, 4];
    let mut budget = fgit_pack::ResolutionBudget::new();
    budget.charge_expanded(base.len(), &limits).unwrap();
    let first =
        fgit_pack::apply_delta_with_budget(base, &program, &limits, &mut budget, &mut || true)
            .unwrap();
    assert_eq!(
        first,
        fgit_pack::apply_delta(base, &program, &limits, &mut || true).unwrap()
    );
    assert!(matches!(
        fgit_pack::apply_delta_with_budget(base, &program, &limits, &mut budget, &mut || true),
        Err(PackError::TotalExpandedLimit { .. })
    ));
    assert!(budget.charge_expanded(1, &limits).is_err());
    limits.max_delta_work = 5;
    let mut work = fgit_pack::ResolutionBudget::new();
    work.charge_work(5, &limits).unwrap();
    assert!(matches!(
        work.charge_work(1, &limits),
        Err(PackError::DeltaWorkLimit { .. })
    ));
}

#[test]
fn charged_base_delta_counts_only_unique_expansion_without_changing_standalone_accounting() {
    let base = b"base";
    let program = [4, 8, 0x90, 4, 0x90, 4];
    let mut limits = PackLimits {
        max_total_expanded_bytes: 12,
        ..Default::default()
    };
    let mut budget = fgit_pack::ResolutionBudget::new();
    budget.charge_expanded(base.len(), &limits).unwrap();
    assert_eq!(
        fgit_pack::apply_delta_to_charged_base_with_budget(
            base,
            &program,
            &limits,
            &mut budget,
            &mut || true
        )
        .unwrap(),
        b"basebase"
    );
    assert!(matches!(
        budget.charge_expanded(1, &limits),
        Err(PackError::TotalExpandedLimit {
            actual: 13,
            limit: 12
        })
    ));
    let mut standalone = fgit_pack::ResolutionBudget::new();
    standalone.charge_expanded(base.len(), &limits).unwrap();
    assert!(matches!(
        fgit_pack::apply_delta_with_budget(base, &program, &limits, &mut standalone, &mut || true),
        Err(PackError::TotalExpandedLimit {
            actual: 16,
            limit: 12
        })
    ));
    limits.max_total_expanded_bytes = 11;
    let mut below = fgit_pack::ResolutionBudget::new();
    below.charge_expanded(base.len(), &limits).unwrap();
    assert!(matches!(
        fgit_pack::apply_delta_to_charged_base_with_budget(
            base,
            &program,
            &limits,
            &mut below,
            &mut || true
        ),
        Err(PackError::TotalExpandedLimit {
            actual: 12,
            limit: 11
        })
    ));
}

#[test]
fn charged_shared_base_retains_unique_payload_and_repeated_read_work_boundaries() {
    let base = b"base";
    let mut limits = PackLimits {
        max_total_expanded_bytes: 31,
        max_delta_work: 39,
        ..Default::default()
    };
    let resolve = |limits: &PackLimits| -> Result<Vec<Vec<u8>>, PackError> {
        let mut budget = fgit_pack::ResolutionBudget::new();
        budget.charge_expanded(base.len(), limits)?;
        let mut results = Vec::new();
        for suffix in b"ABC" {
            let program = [4, 9, 0x90, 4, 0x90, 4, 1, *suffix];
            results.push(fgit_pack::apply_delta_to_charged_base_with_budget(
                base,
                &program,
                limits,
                &mut budget,
                &mut || true,
            )?);
        }
        Ok(results)
    };
    assert_eq!(
        resolve(&limits).unwrap(),
        [
            b"basebaseA".to_vec(),
            b"basebaseB".to_vec(),
            b"basebaseC".to_vec()
        ]
    );
    // Four unique base bytes plus three nine-byte results; every reuse still
    // consumes four read bytes plus nine copied/inserted instruction bytes.
    limits.max_total_expanded_bytes = 30;
    assert!(matches!(
        resolve(&limits),
        Err(PackError::TotalExpandedLimit {
            actual: 31,
            limit: 30
        })
    ));
    limits.max_total_expanded_bytes = 31;
    limits.max_delta_work = 38;
    assert!(matches!(
        resolve(&limits),
        Err(PackError::DeltaWorkLimit {
            attempted: 39,
            limit: 38
        })
    ));
}
