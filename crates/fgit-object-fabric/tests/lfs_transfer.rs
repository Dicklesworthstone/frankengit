#![forbid(unsafe_code)]

use fgit_crypto::sha256_digest;
use fgit_object_fabric::artifact::storage::lfs::transfer::{
    Encoder, Seal, SourceIdentity, TransferError as Error, TransferLimits, verify,
};
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid, MAX_OBJECT_BYTES};
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};
use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

const HEADER: usize = 125;
const RECORD: usize = 40;
const CHUNK: usize = 64 * 1024;
type Records = Vec<(LfsObject, Vec<u8>)>;

fn source(format: GitHashAlgorithm) -> SourceIdentity {
    SourceIdentity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
        head_generation: 7,
        head_token: [4; 16],
        head_sha256: [5; 32],
    }
}
fn object(bytes: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(bytes),
        size: bytes.len() as u64,
    }
}
fn records(payloads: Vec<Vec<u8>>) -> Records {
    let mut records: Records = payloads
        .into_iter()
        .map(|bytes| (object(&bytes), bytes))
        .collect();
    records.sort_by_key(|(object, _)| object.oid);
    records
}
fn encode(format: GitHashAlgorithm, records: &Records) -> (Vec<u8>, Seal) {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(
        &mut bytes,
        source(format),
        records.len(),
        records.iter().map(|(object, _)| object.size).sum(),
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    for (object, payload) in records {
        encoder
            .object(*object, &mut payload.as_slice(), &mut || true)
            .unwrap();
    }
    let seal = encoder.finish(&mut || true).unwrap();
    (bytes, seal)
}

// Independent framing for deliberately malformed fixtures. In particular this
// does not use the encoder that refuses duplicate/order/length defects.
fn raw_archive(source: SourceIdentity, records: &Records, declared_payload: u64) -> Vec<u8> {
    let mut bytes = b"FGLF\0\0\0\x01".to_vec();
    bytes.extend_from_slice(source.tenant.as_bytes());
    bytes.extend_from_slice(source.repository.as_bytes());
    bytes.extend_from_slice(source.incarnation.as_bytes());
    bytes.push(match source.format {
        GitHashAlgorithm::Sha1 => 1,
        GitHashAlgorithm::Sha256 => 2,
    });
    bytes.extend_from_slice(&source.head_generation.to_be_bytes());
    bytes.extend_from_slice(&source.head_token);
    bytes.extend_from_slice(&source.head_sha256);
    bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&declared_payload.to_be_bytes());
    assert_eq!(bytes.len(), HEADER);
    for (object, payload) in records {
        let digest = object.oid.to_string();
        for pair in digest.as_bytes().as_chunks::<2>().0 {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        bytes.extend_from_slice(&object.size.to_be_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes
}
fn verify_bytes(bytes: &[u8]) -> Result<(), Error> {
    verify(
        &mut Cursor::new(bytes),
        sha256_digest(bytes),
        TransferLimits::default(),
        &mut || true,
    )
    .map(|_| ())
}

#[test]
fn deterministic_archive_preserves_exact_source_labels_and_binary_offsets() {
    let records = records(vec![
        Vec::new(),
        b"binary\0\xff\nasset".to_vec(),
        (0..CHUNK * 2 + 17).map(|i| (i % 251) as u8).collect(),
    ]);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (bytes, seal) = encode(format, &records);
        assert_eq!(encode(format, &records), (bytes.clone(), seal));
        assert_eq!(seal.digest, sha256_digest(&bytes));
        assert_eq!(seal.bytes, bytes.len() as u64);
        let payload: u64 = records.iter().map(|(object, _)| object.size).sum();
        assert_eq!(seal.payload_bytes, payload);
        assert_eq!(bytes, raw_archive(source(format), &records, payload));
        let mut input = Cursor::new(bytes);
        input.set_position(29); // Validation must rewind, not trust cursor state.
        let verified = verify(
            &mut input,
            seal.digest,
            TransferLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(verified.source(), &source(format));
        assert_eq!(verified.seal(), seal);
        assert_eq!(verified.records().len(), records.len());
        let mut offset = HEADER as u64;
        for (record, (object, expected)) in verified.records().iter().zip(&records) {
            offset += RECORD as u64;
            assert_eq!(record.object(), *object);
            assert_eq!(record.payload_offset(), offset);
            input
                .seek(SeekFrom::Start(record.payload_offset()))
                .unwrap();
            let mut payload = Vec::new();
            (&mut input)
                .take(object.size)
                .read_to_end(&mut payload)
                .unwrap();
            assert_eq!(&payload, expected);
            offset += object.size;
        }
        assert_eq!(offset, seal.bytes);
    }
}

#[test]
fn empty_inventory_is_distinct_from_one_empty_object() {
    let (empty, empty_seal) = encode(GitHashAlgorithm::Sha256, &Vec::new());
    let (one, one_seal) = encode(GitHashAlgorithm::Sha256, &records(vec![Vec::new()]));
    assert_eq!(empty.len(), HEADER);
    assert_eq!(one.len(), HEADER + RECORD);
    assert_eq!(empty_seal.payload_bytes, 0);
    assert_eq!(one_seal.payload_bytes, 0);
    assert_ne!(empty_seal.digest, one_seal.digest);
    verify_bytes(&empty).unwrap();
    verify_bytes(&one).unwrap();
}

#[test]
fn trusted_whole_archive_digest_and_each_payload_are_both_required() {
    let (bytes, seal) = encode(GitHashAlgorithm::Sha256, &records(vec![b"asset".to_vec()]));
    let mut wrong = seal.digest;
    wrong[0] ^= 1;
    assert_eq!(
        verify(
            &mut Cursor::new(&bytes),
            wrong,
            TransferLimits::default(),
            &mut || true,
        )
        .unwrap_err(),
        Error::DigestMismatch
    );
    let mut corrupt_payload = bytes.clone();
    corrupt_payload[HEADER + RECORD] ^= 1;
    // Even trusting this changed transport checksum cannot bless bad custody.
    assert_eq!(verify_bytes(&corrupt_payload), Err(Error::PayloadMismatch));
    // Every source label is covered by the independently pinned transport hash.
    for index in [8, 24, 40, 56, 64, 65, 81] {
        let mut changed = bytes.clone();
        changed[index] ^= if index == 56 { 3 } else { 1 };
        assert_eq!(
            verify(
                &mut Cursor::new(changed),
                seal.digest,
                TransferLimits::default(),
                &mut || true,
            )
            .unwrap_err(),
            Error::DigestMismatch
        );
    }
}

#[test]
fn structural_refusals_hold_even_with_the_matching_transport_digest() {
    let sorted = records(vec![b"first".to_vec(), b"second".to_vec()]);
    let total = sorted.iter().map(|(object, _)| object.size).sum();
    let (bytes, _) = encode(GitHashAlgorithm::Sha256, &sorted);
    let mut reversed = sorted.clone();
    reversed.reverse();
    assert_eq!(
        verify_bytes(&raw_archive(
            source(GitHashAlgorithm::Sha256),
            &reversed,
            total
        )),
        Err(Error::ObjectOrder)
    );
    let mut duplicate = vec![sorted[0].clone(), sorted[0].clone()];
    duplicate[1].0.size += 1; // OID uniqueness must not be tuple uniqueness.
    duplicate[1].1.push(0);
    let total = duplicate.iter().map(|(object, _)| object.size).sum();
    assert_eq!(
        verify_bytes(&raw_archive(
            source(GitHashAlgorithm::Sha256),
            &duplicate,
            total
        )),
        Err(Error::ObjectOrder)
    );
    for index in [0, 7, 56] {
        let mut bad = bytes.clone();
        bad[index] = 0xff;
        assert!(matches!(verify_bytes(&bad), Err(Error::InvalidEncoding(_))));
    }
    let mut zero_generation = bytes.clone();
    zero_generation[57..65].fill(0);
    assert_eq!(
        verify_bytes(&zero_generation),
        Err(Error::InvalidEncoding("zero source head generation"))
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(verify_bytes(&trailing), Err(Error::TrailingBytes));
    for length in 0..bytes.len() {
        assert!(verify_bytes(&bytes[..length]).is_err(), "prefix {length}");
    }
}

#[test]
fn limits_are_checked_before_allocating_inventory_or_reading_payloads() {
    let records = records(vec![b"ab".to_vec()]);
    let (bytes, seal) = encode(GitHashAlgorithm::Sha1, &records);
    for (limits, expected) in [
        (
            TransferLimits {
                max_object_bytes: 1,
                ..TransferLimits::default()
            },
            Error::ObjectLimit,
        ),
        (
            TransferLimits {
                max_payload_bytes: 1,
                ..TransferLimits::default()
            },
            Error::PayloadLimit,
        ),
        (
            TransferLimits {
                max_archive_bytes: seal.bytes - 1,
                ..TransferLimits::default()
            },
            Error::ArchiveLimit,
        ),
        (
            TransferLimits {
                max_archive_bytes: 1,
                ..TransferLimits::default()
            },
            Error::ArchiveLimit,
        ),
    ] {
        assert_eq!(
            verify(&mut Cursor::new(&bytes), seal.digest, limits, &mut || true).unwrap_err(),
            expected
        );
    }
    let mut excessive_count = bytes.clone();
    excessive_count[113..117].copy_from_slice(&1_000_001_u32.to_be_bytes());
    assert_eq!(verify_bytes(&excessive_count), Err(Error::ObjectCountLimit));
    let mut overflow = bytes.clone();
    overflow[117..125].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(verify_bytes(&overflow), Err(Error::PayloadLimit));
    let mut excessive_object = bytes.clone();
    excessive_object[HEADER + 32..HEADER + 40]
        .copy_from_slice(&(MAX_OBJECT_BYTES + 1).to_be_bytes());
    assert_eq!(verify_bytes(&excessive_object), Err(Error::ObjectLimit));
    let mut aggregate = bytes;
    aggregate[117..125].copy_from_slice(&3_u64.to_be_bytes());
    assert_eq!(
        verify_bytes(&aggregate),
        Err(Error::InvalidEncoding("aggregate LFS payload length"))
    );
}

#[test]
fn failed_or_incomplete_encoder_cannot_return_a_seal() {
    for (mut supplied, expected) in [
        (b"as".as_slice(), Error::Truncated),
        (b"asset!".as_slice(), Error::TrailingBytes),
        (b"wrong".as_slice(), Error::PayloadMismatch),
    ] {
        let mut output = Vec::new();
        let mut encoder = Encoder::new(
            &mut output,
            source(GitHashAlgorithm::Sha256),
            1,
            5,
            TransferLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            encoder.object(object(b"asset"), &mut supplied, &mut || true),
            Err(expected)
        );
        assert_eq!(
            encoder.object(object(b"asset"), &mut b"asset".as_slice(), &mut || true),
            Err(Error::Incomplete)
        );
        assert_eq!(encoder.finish(&mut || true), Err(Error::Incomplete));
    }
    let encoder = Encoder::new(
        Vec::new(),
        source(GitHashAlgorithm::Sha1),
        1,
        1,
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    assert_eq!(encoder.finish(&mut || true), Err(Error::Incomplete));
}

struct ShortIo {
    bytes: Cursor<Vec<u8>>,
    calls: usize,
    interrupted_flush: bool,
}
impl Read for ShortIo {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert!(out.len() <= CHUNK);
        self.calls += 1;
        if self.calls % 3 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = out.len().min(97);
        self.bytes.read(&mut out[..length])
    }
}
impl Seek for ShortIo {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(at)
    }
}
impl Write for ShortIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() <= CHUNK);
        self.calls += 1;
        if self.calls % 3 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.bytes.write(&bytes[..bytes.len().min(83)])
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.interrupted_flush {
            self.interrupted_flush = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

#[test]
fn interrupted_and_short_io_preserve_the_exact_transport_commitment() {
    let payload = vec![0xa5; CHUNK + 17];
    let records = records(vec![payload.clone()]);
    let (expected, expected_seal) = encode(GitHashAlgorithm::Sha256, &records);
    let mut output = ShortIo {
        bytes: Cursor::new(Vec::new()),
        calls: 0,
        interrupted_flush: false,
    };
    let mut input = ShortIo {
        bytes: Cursor::new(payload.clone()),
        calls: 0,
        interrupted_flush: false,
    };
    let mut encoder = Encoder::new(
        &mut output,
        source(GitHashAlgorithm::Sha256),
        1,
        payload.len() as u64,
        TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    encoder
        .object(object(&payload), &mut input, &mut || true)
        .unwrap();
    assert_eq!(encoder.finish(&mut || true).unwrap(), expected_seal);
    assert_eq!(output.bytes.get_ref(), &expected);
    assert!(output.interrupted_flush);
    assert_eq!(
        verify(
            &mut output,
            expected_seal.digest,
            TransferLimits::default(),
            &mut || true,
        )
        .unwrap()
        .seal(),
        expected_seal
    );
}

struct CancellingReader<'a> {
    bytes: Cursor<Vec<u8>>,
    live: &'a Cell<bool>,
    after: u64,
    interrupted: bool,
}
impl Read for CancellingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.interrupted {
            self.live.set(false);
            return Err(io::ErrorKind::Interrupted.into());
        }
        assert!(output.len() <= CHUNK);
        let count = self.bytes.read(output)?;
        if self.bytes.position() >= self.after {
            self.live.set(false);
        }
        Ok(count)
    }
}
impl Seek for CancellingReader<'_> {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(at)
    }
}

#[test]
fn cancellation_during_payload_or_interrupted_read_returns_no_inventory() {
    let (bytes, seal) = encode(GitHashAlgorithm::Sha256, &records(vec![vec![7; CHUNK * 2]]));
    for interrupted in [false, true] {
        let live = Cell::new(true);
        let mut input = CancellingReader {
            bytes: Cursor::new(bytes.clone()),
            live: &live,
            after: (HEADER + RECORD + CHUNK) as u64,
            interrupted,
        };
        assert_eq!(
            verify(
                &mut input,
                seal.digest,
                TransferLimits::default(),
                &mut || live.get()
            )
            .unwrap_err(),
            Error::Cancelled
        );
        assert!(input.bytes.position() <= (HEADER + RECORD + CHUNK) as u64);
    }
}

struct CancellingWriter<'a> {
    bytes: Vec<u8>,
    live: &'a Cell<bool>,
    cancel_on_flush: bool,
}
impl Write for CancellingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(17);
        self.bytes.extend_from_slice(&bytes[..count]);
        if !self.cancel_on_flush && self.bytes.len() > HEADER + RECORD {
            self.live.set(false);
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.cancel_on_flush {
            self.live.set(false);
        }
        Ok(())
    }
}

#[test]
fn cancellation_after_partial_write_or_flush_cannot_seal_output() {
    for cancel_on_flush in [false, true] {
        let live = Cell::new(true);
        let mut output = CancellingWriter {
            bytes: Vec::new(),
            live: &live,
            cancel_on_flush,
        };
        let mut encoder = Encoder::new(
            &mut output,
            source(GitHashAlgorithm::Sha256),
            1,
            5,
            TransferLimits::default(),
            &mut || live.get(),
        )
        .unwrap();
        let result = encoder.object(object(b"asset"), &mut b"asset".as_slice(), &mut || {
            live.get()
        });
        if cancel_on_flush {
            result.unwrap();
            assert_eq!(encoder.finish(&mut || live.get()), Err(Error::Cancelled));
        } else {
            assert_eq!(result, Err(Error::Cancelled));
            live.set(true);
            assert_eq!(encoder.finish(&mut || live.get()), Err(Error::Incomplete));
        }
    }
}
