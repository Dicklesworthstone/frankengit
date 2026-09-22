use super::super::{Encoder, decode};
use super::*;
use fgit_authority::{HeadGeneration, StoreInstanceId};
use fgit_authority_fsqlite::{
    ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION, export_bundle, mint_token,
};

fn live() -> Result<(), String> {
    Ok(())
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256Hasher::new();
    hash.update(bytes);
    hash.finish()
}
fn identity(format: GitHashAlgorithm) -> Identity {
    Identity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
    }
}
fn authority() -> Vec<u8> {
    let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST)
        .to_opaque_bytes()
        .to_vec();
    export_bundle(&ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![],
        head: Some(ExportedHead {
            key: b"head".to_vec(),
            token: token.clone(),
            generation: HeadGeneration::FIRST.get(),
            body: b"head body".to_vec(),
        }),
        issuance: vec![ExportedIssuance {
            token,
            sequence: 1,
            head_key: b"head".to_vec(),
            generation: 1,
            body: b"head body".to_vec(),
        }],
    })
    .unwrap()
}
fn proof(body: &[u8]) -> [u8; 32] {
    git_payload_commitment(GitObjectKind::Blob, body, CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}
fn sample(format: GitHashAlgorithm) -> Vec<u8> {
    let body = b"binary\0payload\xff\n";
    let mut encoder = Encoder::new(identity(format), &authority(), 1).unwrap();
    encoder
        .object(
            git_object_id(format, GitObjectKind::Blob, body),
            GitObjectKind::Blob,
            body,
            &proof(body),
        )
        .unwrap();
    encoder.finish().unwrap()
}
fn scan(input: impl Read, expected: [u8; 32], limits: TransferLimits) -> Result<Seal, String> {
    let mut decoder = StreamDecoder::new(input, limits, &mut live)?;
    while decoder.record(&mut live)?.is_some() {}
    decoder.finish(expected, &mut live).map(|(_, seal)| seal)
}

#[test]
fn streaming_is_byte_identical_to_the_original_transport_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let old = sample(format);
        let parsed = decode(&old, live).unwrap();
        let mut output = Vec::new();
        let mut encoder = StreamEncoder::new(
            &mut output,
            parsed.identity,
            &authority(),
            parsed.records.len(),
            Default::default(),
            &mut live,
        )
        .unwrap();
        for row in &parsed.records {
            encoder
                .object(
                    row.oid,
                    row.kind,
                    row.payload,
                    &proof(row.payload),
                    &mut live,
                )
                .unwrap();
        }
        let seal = encoder.finish(&mut live).unwrap();
        assert_eq!(old, output);
        assert_eq!(
            seal,
            Seal {
                digest: hash(&old),
                bytes: old.len() as u64
            }
        );
        assert_eq!(
            scan(old.as_slice(), seal.digest, Default::default()).unwrap(),
            seal
        );
    }
}

#[test]
fn every_truncation_trailing_bytes_and_wrong_pin_refuse() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    for end in 0..bytes.len() {
        assert!(
            scan(&bytes[..end], hash(&bytes), Default::default()).is_err(),
            "truncation {end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(
        scan(extra.as_slice(), hash(&extra), Default::default())
            .unwrap_err()
            .contains("trailing")
    );
    assert!(
        scan(bytes.as_slice(), [0; 32], Default::default())
            .unwrap_err()
            .contains("checksum")
    );
    assert!(scan(bytes.as_slice(), hash(&bytes), Default::default()).is_ok());
}

#[test]
fn exact_byte_budget_is_inclusive_and_payload_allocation_is_preflighted() {
    let bytes = sample(GitHashAlgorithm::Sha256);
    let limits = TransferLimits {
        max_archive_bytes: bytes.len() as u64,
    };
    assert!(scan(bytes.as_slice(), hash(&bytes), limits).is_ok());
    assert!(
        scan(
            bytes.as_slice(),
            hash(&bytes),
            TransferLimits {
                max_archive_bytes: limits.max_archive_bytes - 1
            }
        )
        .is_err()
    );
    let mut huge_authority = bytes.clone();
    huge_authority[57..65].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(
        scan(
            huge_authority.as_slice(),
            hash(&huge_authority),
            Default::default()
        )
        .is_err()
    );
    let record_at = 65 + authority().len() + 8;
    let length_at = record_at + 32 + 1;
    let mut oversized = bytes;
    oversized[length_at..length_at + 8]
        .copy_from_slice(&((MAX_OBJECT_BYTES + 1) as u64).to_be_bytes());
    let mut decoder =
        StreamDecoder::new(oversized.as_slice(), Default::default(), &mut live).unwrap();
    assert!(decoder.record(&mut live).is_err());
    assert_eq!(
        decoder.payload.capacity(),
        0,
        "declared size refused before object allocation"
    );
    assert!(decoder.finish(hash(&oversized), &mut live).is_err());
}

#[test]
fn native_identity_and_original_commitment_are_independent_of_the_file_pin() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    let at = 65 + authority().len() + 8;
    let mut bad_payload = bytes.clone();
    *bad_payload.last_mut().unwrap() ^= 1;
    assert!(
        scan(
            bad_payload.as_slice(),
            hash(&bad_payload),
            Default::default()
        )
        .unwrap_err()
        .contains("identity mismatch")
    );
    let mut bad_proof = bytes;
    bad_proof[at + 20 + 1 + 8] ^= 1;
    assert!(
        scan(bad_proof.as_slice(), hash(&bad_proof), Default::default())
            .unwrap_err()
            .contains("commitment mismatch")
    );
}

struct Fragmented<R> {
    input: R,
    interrupted: bool,
    largest: usize,
}
impl<R: Read> Read for Fragmented<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(out.len());
        self.interrupted = !self.interrupted;
        if self.interrupted {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = out.len().min(7);
        self.input.read(&mut out[..count])
    }
}
#[test]
fn fragmented_reads_and_interrupted_syscalls_preserve_exact_bytes() {
    let bytes = sample(GitHashAlgorithm::Sha1);
    let mut fragmented = Fragmented {
        input: bytes.as_slice(),
        interrupted: false,
        largest: 0,
    };
    assert_eq!(
        scan(&mut fragmented, hash(&bytes), Default::default())
            .unwrap()
            .bytes,
        bytes.len() as u64
    );
    assert!(fragmented.largest <= CHUNK_BYTES);
}

struct ShortWriter {
    bytes: Vec<u8>,
    fail_at: usize,
    flush_fails: bool,
}
impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let amount = bytes
            .len()
            .min(7)
            .min(self.fail_at.saturating_sub(self.bytes.len()));
        if amount == 0 {
            return Ok(0);
        }
        self.bytes.extend_from_slice(&bytes[..amount]);
        Ok(amount)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fails {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn partial_writes_flush_failure_and_abandoned_records_cannot_finish() {
    let format = GitHashAlgorithm::Sha1;
    let body = b"binary\0payload\xff\n";
    let oid = git_object_id(format, GitObjectKind::Blob, body);
    for flush_fails in [false, true] {
        let mut sink = ShortWriter {
            bytes: vec![],
            fail_at: usize::MAX,
            flush_fails,
        };
        let mut encoder = StreamEncoder::new(
            &mut sink,
            identity(format),
            &authority(),
            1,
            Default::default(),
            &mut live,
        )
        .unwrap();
        encoder
            .object(oid, GitObjectKind::Blob, body, &proof(body), &mut live)
            .unwrap();
        assert_eq!(encoder.finish(&mut live).is_err(), flush_fails);
        assert_eq!(sink.bytes, sample(format));
    }
    let mut sink = ShortWriter {
        bytes: vec![],
        fail_at: sample(format).len() - 1,
        flush_fails: false,
    };
    let mut encoder = StreamEncoder::new(
        &mut sink,
        identity(format),
        &authority(),
        1,
        Default::default(),
        &mut live,
    )
    .unwrap();
    assert!(
        encoder
            .object(oid, GitObjectKind::Blob, body, &proof(body), &mut live)
            .is_err()
    );
    assert!(
        encoder
            .object(oid, GitObjectKind::Blob, body, &proof(body), &mut live)
            .is_err()
    );
    assert!(encoder.finish(&mut live).is_err());
    let input = sample(format);
    let decoder = StreamDecoder::new(input.as_slice(), Default::default(), &mut live).unwrap();
    assert!(
        decoder.finish(hash(&input), &mut live).is_err(),
        "unconsumed records cannot yield a verified pass"
    );
}

#[test]
fn cancellation_is_checked_during_payload_io_and_poisons_the_decoder() {
    let format = GitHashAlgorithm::Sha1;
    let body = vec![23; 3 * CHUNK_BYTES];
    let mut encoder = Encoder::new(identity(format), &authority(), 1).unwrap();
    encoder
        .object(
            git_object_id(format, GitObjectKind::Blob, &body),
            GitObjectKind::Blob,
            &body,
            &proof(&body),
        )
        .unwrap();
    let bytes = encoder.finish().unwrap();
    let mut steps = 0;
    let mut decoder = StreamDecoder::new(bytes.as_slice(), Default::default(), &mut live).unwrap();
    assert!(
        decoder
            .record(&mut || {
                steps += 1;
                if steps == 11 {
                    Err("stop".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert!(decoder.input.bytes < bytes.len() as u64);
    assert!(decoder.finish(hash(&bytes), &mut live).is_err());
}

struct InterruptForever;
impl Read for InterruptForever {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Interrupted.into())
    }
}
#[test]
fn repeated_interruption_cannot_bypass_cooperative_termination() {
    let mut checks = 0;
    let result = StreamDecoder::new(InterruptForever, Default::default(), &mut || {
        checks += 1;
        if checks > 8 {
            Err("deadline".into())
        } else {
            Ok(())
        }
    });
    assert_eq!(result.err().unwrap(), "deadline");
    assert_eq!(checks, 9);
}
