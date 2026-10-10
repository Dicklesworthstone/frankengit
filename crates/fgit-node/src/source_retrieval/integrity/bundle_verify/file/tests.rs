//! Actual generic I/O core, compared with the existing native slice verifier.
//! Stored-zlib fixtures below are independently encoded; Git-produced fixture
//! indexes additionally pin interoperability across both native hash formats.
use super::super::{ObjectKind, prepare_git_bundle_recovery, verify_git_bundle};
use super::*;
use fgit_crypto::{git_object_id, lowercase_hex, sha1_digest, sha256_digest};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

fn decode(hex: &str) -> Vec<u8> {
    hex.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(format: GitHashAlgorithm) -> Vec<u8> {
    decode(match format {
        GitHashAlgorithm::Sha1 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"
        )),
        GitHashAlgorithm::Sha256 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"
        )),
    })
}
fn verify(input: &[u8]) -> Result<FileBundleVerification, BundleVerifyError> {
    verify_git_bundle_reader(
        &mut Cursor::new(input),
        &mut Cursor::new(Vec::new()),
        &BundleVerifyLimits::default(),
        None,
        &mut || true,
    )
}
fn zlib(body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(body.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(length.to_le_bytes());
    bytes.extend((!length).to_le_bytes());
    bytes.extend(body);
    let (mut a, mut b) = (1_u32, 0_u32);
    for &byte in body {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes.extend(((b << 16) | a).to_be_bytes());
    bytes
}
fn record(kind: u8, body: &[u8], base: &[u8]) -> Vec<u8> {
    let mut size = body.len();
    let mut byte = kind << 4 | (size & 15) as u8;
    size >>= 4;
    let mut out = Vec::new();
    while size != 0 {
        out.push(byte | 128);
        byte = (size & 127) as u8;
        size >>= 7;
    }
    out.push(byte);
    out.extend(base);
    out.extend(zlib(body));
    out
}
fn bundle(format: GitHashAlgorithm, records: &[Vec<u8>], target: GitOid) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend((records.len() as u32).to_be_bytes());
    for row in records {
        pack.extend(row);
    }
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend(checksum);
    let mut out = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    out.extend(format!("{} refs/tags/result\n\n", lowercase_hex(target.as_bytes())).as_bytes());
    out.extend(pack);
    out
}
fn delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    assert!(base.len() < 128 && result.len() < 128);
    [
        vec![base.len() as u8, result.len() as u8, result.len() as u8],
        result.to_vec(),
    ]
    .concat()
}
fn ofs(mut distance: u64) -> Vec<u8> {
    let mut out = vec![(distance & 127) as u8];
    loop {
        distance >>= 7;
        if distance == 0 {
            break;
        }
        distance -= 1;
        out.push(128 | (distance & 127) as u8);
    }
    out.reverse();
    out
}
fn assert_same(actual: &VerifiedGitBundle, expected: &VerifiedGitBundle) {
    assert_eq!(actual.format(), expected.format());
    assert_eq!(actual.bytes(), expected.bytes());
    assert_eq!(actual.sha256(), expected.sha256());
    assert_eq!(actual.pack_bytes(), expected.pack_bytes());
    assert_eq!(actual.pack_checksum(), expected.pack_checksum());
    assert_eq!(actual.advertised_head(), expected.advertised_head());
    assert_eq!(actual.references(), expected.references());
    assert_eq!(actual.graph(), expected.graph());
    assert_eq!(actual.delta_objects(), expected.delta_objects());
    // Resolution passes describe the selected algorithm's actual work, not
    // content identity. The file path resolves each learned base only once.
}

#[test]
fn original_git_fixtures_match_slice_graph_index_and_recovery_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = fixture(format);
        let limits = BundleVerifyLimits::default();
        let head = RefName::try_new(b"refs/heads/main").unwrap();
        let expected =
            prepare_git_bundle_recovery(&input, &limits, None, &head, &mut || true).unwrap();
        let mut scratch = Cursor::new(Vec::new());
        let actual = prepare_git_bundle_recovery_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &head,
            &mut || true,
        )
        .unwrap();
        assert_same(actual.verified(), expected.verified());
        assert_eq!(actual.index(), expected.index());
        assert_eq!(actual.packed_refs(), expected.packed_refs());
        assert_eq!(actual.config(), expected.config());
        assert_eq!(actual.head(), expected.head());
        assert_eq!(actual.pack_offset() as usize, expected.pack_offset());
        assert_eq!(actual.pack_len() as usize, expected.pack().len());
        assert_eq!(actual.pack_sha256(), &sha256_digest(expected.pack()));
        assert_eq!(actual.scratch_bytes(), scratch.get_ref().len() as u64);
        assert!(actual.scratch_bytes() > 0);
    }
}

#[test]
fn offset_and_forward_ref_deltas_have_identical_content_and_index() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = b"base";
        let result = b"second\0\xff";
        let base_id = git_object_id(format, ObjectKind::Blob, base);
        let result_id = git_object_id(format, ObjectKind::Blob, result);
        let direct = record(3, base, &[]);
        for records in [
            vec![
                direct.clone(),
                record(6, &delta(base, result), &ofs(direct.len() as u64)),
            ],
            vec![
                record(7, &delta(base, result), base_id.as_bytes()),
                direct.clone(),
            ],
        ] {
            let input = bundle(format, &records, result_id);
            let actual = verify(&input).unwrap();
            let expected =
                verify_git_bundle(&input, &BundleVerifyLimits::default(), &mut || true).unwrap();
            assert_same(actual.verified(), &expected);
            assert_eq!(actual.verified().delta_objects(), 1);
        }
    }
}

#[test]
fn file_resolution_matches_unique_expansion_boundaries_of_the_native_slice_verifier() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = b"base";
        let result = b"basebase";
        // A six-byte copy program keeps the framing budget (base + program =
        // ten) below the independently checked unique expansion (4 + 8 = 12).
        let program = [4, 8, 0x90, 4, 0x90, 4];
        let direct = record(3, base, &[]);
        let input = bundle(
            format,
            &[
                direct.clone(),
                record(6, &program, &ofs(direct.len() as u64)),
            ],
            git_object_id(format, ObjectKind::Blob, result),
        );
        let mut limits = BundleVerifyLimits::default();
        limits.pack.max_total_expanded_bytes = 12;
        let expected = verify_git_bundle(&input, &limits, &mut || true).unwrap();
        let actual = verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        )
        .unwrap();
        assert_same(actual.verified(), &expected);
        assert_eq!(actual.verified().graph().payload_bytes, 12);
        limits.pack.max_total_expanded_bytes = 11;
        for refusal in [
            verify_git_bundle(&input, &limits, &mut || true).unwrap_err(),
            verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                &limits,
                None,
                &mut || true,
            )
            .unwrap_err(),
        ] {
            assert!(matches!(
                refusal,
                BundleVerifyError::Pack(fgit_pack::PackError::TotalExpandedLimit {
                    actual: 12,
                    limit: 11
                })
            ));
        }
    }
}

#[test]
fn file_shared_base_fanout_counts_unique_objects_and_still_bounds_reuse_work() {
    let format = GitHashAlgorithm::Sha256;
    let base = b"base";
    let mut records = vec![record(3, base, &[])];
    let mut next_offset = records[0].len() as u64;
    for suffix in b"ABC" {
        let program = [4, 9, 0x90, 4, 0x90, 4, 1, *suffix];
        let child = record(6, &program, &ofs(next_offset));
        next_offset += child.len() as u64;
        records.push(child);
    }
    let input = bundle(
        format,
        &records,
        git_object_id(format, ObjectKind::Blob, b"basebaseC"),
    );
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_total_expanded_bytes = 31;
    let expected = verify_git_bundle(&input, &limits, &mut || true).unwrap();
    // Four accepted entries and four discovery visits use eight work units;
    // each child charges four reused base bytes and nine instruction bytes.
    limits.pack.max_delta_work = 8 + 3 * (4 + 9);
    let actual = verify_git_bundle_reader(
        &mut Cursor::new(&input),
        &mut Cursor::new(Vec::new()),
        &limits,
        None,
        &mut || true,
    )
    .unwrap();
    assert_same(actual.verified(), &expected);
    limits.pack.max_delta_work -= 1;
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        ),
        Err(BundleVerifyError::Pack(
            fgit_pack::PackError::DeltaWorkLimit {
                attempted: 47,
                limit: 46
            }
        ))
    ));
    limits.pack.max_delta_work = BundleVerifyLimits::default().pack.max_delta_work;
    limits.pack.max_total_expanded_bytes = 30;
    for refusal in [
        verify_git_bundle(&input, &limits, &mut || true).unwrap_err(),
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        )
        .unwrap_err(),
    ] {
        assert!(matches!(
            refusal,
            BundleVerifyError::Pack(fgit_pack::PackError::TotalExpandedLimit {
                actual: 31,
                limit: 30
            })
        ));
    }
}

#[test]
fn delta_program_size_is_separate_from_the_reconstructed_object_graph_limit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = b"base";
        let result = b"baseplus";
        let program = delta(base, result);
        assert!(program.len() > result.len());
        let direct = record(3, base, &[]);
        let input = bundle(
            format,
            &[
                direct.clone(),
                record(6, &program, &ofs(direct.len() as u64)),
            ],
            git_object_id(format, ObjectKind::Blob, result),
        );
        let mut limits = BundleVerifyLimits::default();
        limits.graph.max_object_bytes = result.len();
        limits.pack.max_object_bytes = program.len();
        let expected = verify_git_bundle(&input, &limits, &mut || true).unwrap();
        let actual = verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        )
        .unwrap();
        assert_same(actual.verified(), &expected);
        for dimension in 0..3 {
            let mut below = limits.clone();
            match dimension {
                0 => below.graph.max_object_bytes = result.len() - 1,
                1 => below.graph.max_object_bytes = base.len() - 1,
                _ => below.pack.max_object_bytes = program.len() - 1,
            }
            assert!(verify_git_bundle(&input, &below, &mut || true).is_err());
            assert!(
                verify_git_bundle_reader(
                    &mut Cursor::new(&input),
                    &mut Cursor::new(Vec::new()),
                    &below,
                    None,
                    &mut || true,
                )
                .is_err(),
                "independent limit {dimension}"
            );
        }
    }
}

#[test]
fn reverse_ref_delta_chain_discovers_only_native_verified_local_bases() {
    let format = GitHashAlgorithm::Sha256;
    let bodies: Vec<_> = (0..8).map(|i| vec![b'a' + i]).collect();
    let ids: Vec<_> = bodies
        .iter()
        .map(|body| git_object_id(format, ObjectKind::Blob, body))
        .collect();
    let mut records = Vec::new();
    for at in (1..bodies.len()).rev() {
        records.push(record(
            7,
            &delta(&bodies[at - 1], &bodies[at]),
            ids[at - 1].as_bytes(),
        ));
    }
    records.push(record(3, &bodies[0], &[]));
    let input = bundle(format, &records, *ids.last().unwrap());
    assert_same(
        verify(&input).unwrap().verified(),
        &verify_git_bundle(&input, &BundleVerifyLimits::default(), &mut || true).unwrap(),
    );
    records.pop();
    assert!(matches!(
        verify(&bundle(format, &records, *ids.last().unwrap())),
        Err(BundleVerifyError::ResolutionIncomplete)
    ));
}

#[test]
fn wrong_anchor_is_rejected_before_any_scratch_payload_is_written() {
    let input = fixture(GitHashAlgorithm::Sha1);
    let bad = BundleExpectations::new(Some([0x51; 32]), None, &[], false).unwrap();
    let mut scratch = Cursor::new(Vec::new());
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &BundleVerifyLimits::default(),
            Some(&bad),
            &mut || true
        ),
        Err(BundleVerifyError::Expectation(
            BundleExpectationError::ArtifactMismatch
        ))
    ));
    assert!(scratch.get_ref().is_empty());
    let good = BundleExpectations::new(Some(sha256_digest(&input)), None, &[], false).unwrap();
    assert!(
        verify_git_bundle_reader(
            &mut Cursor::new(input),
            &mut scratch,
            &BundleVerifyLimits::default(),
            Some(&good),
            &mut || true
        )
        .is_ok()
    );
}

#[test]
fn every_truncation_corrupt_trailer_and_duplicate_native_object_refuses() {
    let input = fixture(GitHashAlgorithm::Sha1);
    for end in 0..input.len() {
        assert!(verify(&input[..end]).is_err(), "prefix {end}");
    }
    let mut corrupt = input;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(verify(&corrupt).is_err());
    let format = GitHashAlgorithm::Sha256;
    let body = b"duplicate";
    let records = [record(3, body, &[]), record(3, body, &[])];
    assert!(matches!(
        verify(&bundle(
            format,
            &records,
            git_object_id(format, ObjectKind::Blob, body)
        )),
        Err(BundleVerifyError::DuplicateObject(_))
    ));
}

#[test]
fn matching_anchor_does_not_authorize_an_invalid_graph_or_external_delta_base() {
    let format = GitHashAlgorithm::Sha1;
    let malformed = b"not a commit";
    let input = bundle(
        format,
        &[record(1, malformed, &[])],
        git_object_id(format, ObjectKind::Commit, malformed),
    );
    let expected = BundleExpectations::new(Some(sha256_digest(&input)), None, &[], false).unwrap();
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
            &BundleVerifyLimits::default(),
            Some(&expected),
            &mut || true
        ),
        Err(BundleVerifyError::Graph(_))
    ));
    let base = b"missing";
    let result = b"result";
    let input = bundle(
        format,
        &[record(
            7,
            &delta(base, result),
            git_object_id(format, ObjectKind::Blob, base).as_bytes(),
        )],
        git_object_id(format, ObjectKind::Blob, result),
    );
    assert!(matches!(
        verify(&input),
        Err(BundleVerifyError::ResolutionIncomplete)
    ));
}

#[test]
fn independent_input_object_inventory_payload_delta_and_index_limits_are_enforced() {
    let input = fixture(GitHashAlgorithm::Sha256);
    for dimension in 0..9 {
        let mut limits = BundleVerifyLimits::default();
        match dimension {
            0 => limits.envelope.max_bundle_bytes = input.len() - 1,
            1 => limits.pack.max_input_bytes = 10,
            2 => limits.graph.max_objects = 4,
            3 => limits.graph.max_object_bytes = 2,
            4 => limits.graph.max_payload_bytes = 2,
            5 => limits.pack.max_total_expanded_bytes = 2,
            6 => limits.pack.max_delta_depth = 0,
            7 => limits.pack.max_delta_fanout = 0,
            8 => limits.pack.max_index_entries = 4,
            _ => unreachable!(),
        }
        assert!(
            verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                &limits,
                None,
                &mut || true
            )
            .is_err(),
            "limit {dimension}"
        );
    }
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_delta_work = 0;
    assert!(
        verify_git_bundle_reader(
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true
        )
        .is_err()
    );
}

#[test]
fn cumulative_payload_larger_than_object_memory_bound_uses_scratch() {
    let format = GitHashAlgorithm::Sha256;
    let bodies: Vec<_> = (0..80_u8).map(|i| vec![i; 2048]).collect();
    let records: Vec<_> = bodies.iter().map(|body| record(3, body, &[])).collect();
    let input = bundle(
        format,
        &records,
        git_object_id(format, ObjectKind::Blob, &bodies[0]),
    );
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_object_bytes = 2048;
    limits.graph.max_object_bytes = 2048;
    let actual = verify_git_bundle_reader(
        &mut Cursor::new(&input),
        &mut Cursor::new(Vec::new()),
        &limits,
        None,
        &mut || true,
    )
    .unwrap();
    assert_eq!(actual.verified().graph().objects, 80);
    assert_eq!(actual.verified().graph().payload_bytes, 80 * 2048);
    assert_eq!(actual.scratch_bytes(), 80 * 2048);
    assert!(actual.verified().bytes() > 80 * limits.graph.max_object_bytes);
}

#[test]
fn cancellation_latches_across_preflight_sink_resolution_graph_and_index() {
    let input = fixture(GitHashAlgorithm::Sha1);
    let mut total = 0_usize;
    verify_git_bundle_reader(
        &mut Cursor::new(&input),
        &mut Cursor::new(Vec::new()),
        &BundleVerifyLimits::default(),
        None,
        &mut || {
            total += 1;
            true
        },
    )
    .unwrap();
    for stop in [1, total / 4, total / 2, total * 3 / 4, total] {
        let mut calls = 0;
        assert!(
            verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                &BundleVerifyLimits::default(),
                None,
                &mut || {
                    calls += 1;
                    calls != stop
                }
            )
            .is_err()
        );
        assert_eq!(calls, stop);
    }
}

struct CorruptScratch(Cursor<Vec<u8>>);
impl Read for CorruptScratch {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(out)?;
        if count != 0 {
            out[0] ^= 1;
        }
        Ok(count)
    }
}
impl Write for CorruptScratch {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for CorruptScratch {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

#[test]
fn occupied_or_corrupted_scratch_never_becomes_verification_evidence() {
    let input = fixture(GitHashAlgorithm::Sha1);
    let mut occupied = Cursor::new(b"existing".to_vec());
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut occupied,
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        ),
        Err(BundleVerifyError::ScratchNotEmpty)
    ));
    assert_eq!(occupied.get_ref(), b"existing");
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(input),
            &mut CorruptScratch(Cursor::new(Vec::new())),
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
}

struct MovingSource {
    input: Cursor<Vec<u8>>,
    replacement: Vec<u8>,
    starts: usize,
}
impl Read for MovingSource {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.input.read(out)
    }
}
impl Seek for MovingSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if pos == SeekFrom::Start(0) {
            self.starts += 1;
            if self.starts == 3 {
                self.input = Cursor::new(self.replacement.clone());
            }
        }
        self.input.seek(pos)
    }
}

#[test]
fn same_length_valid_pack_replacement_after_preflight_is_refused() {
    let format = GitHashAlgorithm::Sha256;
    let fixed = b"advertised";
    let target = git_object_id(format, ObjectKind::Blob, fixed);
    let first = bundle(
        format,
        &[record(3, fixed, &[]), record(3, b"first", &[])],
        target,
    );
    let second = bundle(
        format,
        &[record(3, fixed, &[]), record(3, b"other", &[])],
        target,
    );
    assert_eq!(first.len(), second.len());
    assert!(verify(&first).is_ok());
    assert!(verify(&second).is_ok());
    let mut source = MovingSource {
        input: Cursor::new(first),
        replacement: second,
        starts: 0,
    };
    assert!(matches!(
        verify_git_bundle_reader(
            &mut source,
            &mut Cursor::new(Vec::new()),
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        ),
        Err(BundleVerifyError::SourceChanged)
    ));
}
