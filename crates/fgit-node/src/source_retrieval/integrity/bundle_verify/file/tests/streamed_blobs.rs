//! A real scratch file and a compact independently encoded 33 MiB blob. The
//! fixture never constructs its complete blob payload in memory.
use super::*;
use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha256};
use fgit_pack::STREAM_PACK_CHUNK_BYTES;
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

const LARGE: usize = 33 * 1024 * 1024 + 17;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        for _ in 0..32 {
            let path = std::env::temp_dir().join(format!(
                "fgit-stream-blob-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("private fixture directory: {error}"),
            }
        }
        panic!("private fixture directory exhausted")
    }
    fn file(&self, name: &str) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.0.join(name))
            .unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn repeated_id(length: usize) -> GitOid {
    let mut hash = GitObjectHasher::<Sha256>::new(ObjectKind::Blob, length as u64);
    let bytes = [b'x'; 8192];
    let mut remaining = length;
    while remaining != 0 {
        let take = remaining.min(bytes.len());
        hash.update(&bytes[..take]).unwrap();
        remaining -= take;
    }
    hash.finish().unwrap().erase()
}

#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    current: u8,
    used: u8,
}
impl Bits {
    fn push(&mut self, value: u16, count: u8) {
        for bit in 0..count {
            self.current |= (((value >> bit) & 1) as u8) << self.used;
            self.used += 1;
            if self.used == 8 {
                self.bytes.push(self.current);
                self.current = 0;
                self.used = 0;
            }
        }
    }
    fn literal(&mut self, byte: u8) {
        let (code, count) = if byte <= 143 {
            (0x30_u16 + u16::from(byte), 8)
        } else {
            (0x190 + u16::from(byte - 144), 9)
        };
        self.push(code.reverse_bits() >> (16 - count), count);
    }
    fn finish(mut self) -> Vec<u8> {
        if self.used != 0 {
            self.bytes.push(self.current);
        }
        self.bytes
    }
}
fn repeated_entry(length: usize) -> Vec<u8> {
    assert!(length > 0);
    let mut header = Vec::new();
    let mut size = length;
    let mut byte = 3 << 4 | (size & 15) as u8;
    size >>= 4;
    while size != 0 {
        header.push(byte | 128);
        byte = (size & 127) as u8;
        size >>= 7;
    }
    header.push(byte);
    let mut bits = Bits::default();
    bits.push(3, 3); // one final fixed-Huffman block
    bits.literal(b'x');
    let mut remaining = length - 1;
    while remaining >= 258 {
        bits.push(0xc5_u16.reverse_bits() >> 8, 8); // fixed literal/length 285
        bits.push(0, 5); // distance 1, overlapping copy
        remaining -= 258;
    }
    for _ in 0..remaining {
        bits.literal(b'x');
    }
    bits.push(0, 7); // end-of-block 256
    header.extend([0x78, 0x01]);
    header.extend(bits.finish());
    let n = length as u128;
    let a = (1 + n * u128::from(b'x')) % 65521;
    let b = (n + u128::from(b'x') * n * (n + 1) / 2) % 65521;
    header.extend((((b as u32) << 16) | a as u32).to_be_bytes());
    header
}
fn blob_bundle(length: usize) -> Vec<u8> {
    let bytes = bundle(
        GitHashAlgorithm::Sha256,
        &[repeated_entry(length)],
        repeated_id(length),
    );
    assert!(bytes.len() < length / 8);
    bytes
}

struct BoundedScratch {
    file: File,
    read_bytes: usize,
    write_bytes: usize,
    corrupt_at: Option<usize>,
    cancel: Option<Rc<Cell<bool>>>,
    cancel_on_read: Option<Rc<Cell<bool>>>,
}
impl BoundedScratch {
    fn new(file: File) -> Self {
        Self {
            file,
            read_bytes: 0,
            write_bytes: 0,
            corrupt_at: None,
            cancel: None,
            cancel_on_read: None,
        }
    }
}
impl Read for BoundedScratch {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        assert!(
            output.len() <= CHUNK_BYTES,
            "object-sized scratch read request"
        );
        let count = self.file.read(output)?;
        if let Some(at) = self.corrupt_at
            && (self.read_bytes..self.read_bytes + count).contains(&at)
        {
            output[at - self.read_bytes] ^= 1;
            self.corrupt_at = None;
        }
        self.read_bytes += count;
        if let Some(cancel) = &self.cancel_on_read {
            cancel.set(true);
        }
        Ok(count)
    }
}
impl Write for BoundedScratch {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(
            bytes.len() <= STREAM_PACK_CHUNK_BYTES,
            "whole-entry scratch write"
        );
        let count = self.file.write(bytes)?;
        self.write_bytes += count;
        if let Some(cancel) = &self.cancel {
            cancel.set(true);
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for BoundedScratch {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
fn large_limits() -> BundleVerifyLimits {
    BundleVerifyLimits {
        max_streamed_blob_bytes: LARGE,
        ..BundleVerifyLimits::default()
    }
}

#[test]
fn native_large_blob_verifies_from_real_files_with_exact_chunk_and_payload_bounds() {
    let files = Files::new();
    let input = blob_bundle(LARGE);
    let mut source = files.file("source.bundle");
    source.write_all(&input).unwrap();
    let limits = large_limits();
    assert!(limits.pack.max_object_bytes < LARGE);
    assert!(limits.graph.max_object_bytes < LARGE);
    let mut scratch = BoundedScratch::new(files.file("scratch"));
    let actual =
        verify_git_bundle_reader(&mut source, &mut scratch, &limits, None, &mut || true).unwrap();
    assert_eq!(actual.verified().graph().objects, 1);
    assert_eq!(actual.verified().graph().payload_bytes, LARGE as u64);
    assert_eq!(actual.scratch_bytes(), LARGE as u64);
    assert_eq!(scratch.write_bytes, LARGE);
    assert_eq!(scratch.read_bytes, LARGE);
    assert_eq!(actual.verified().sha256(), &sha256_digest(&input));
    assert_eq!(actual.verified().delta_objects(), 0);
    // The same input still refuses under the unchanged default and byte-slice
    // profile. A large aggregate allowance alone grants no larger blob.
    for (index, mut denied) in [
        BundleVerifyLimits::default(),
        limits.clone(),
        limits.clone(),
    ]
    .into_iter()
    .enumerate()
    {
        if index == 1 {
            denied.max_streamed_blob_bytes = LARGE - 1;
        }
        if index == 2 {
            denied.pack.max_total_expanded_bytes = LARGE - 1;
        }
        let mut scratch = BoundedScratch::new(files.file(&format!("refused-{index}")));
        assert!(
            verify_git_bundle_reader(&mut source, &mut scratch, &denied, None, &mut || true)
                .is_err()
        );
        assert_eq!(scratch.write_bytes, 0);
    }
    assert!(verify_git_bundle(&input, &limits, &mut || true).is_err());
}

#[test]
fn streamed_blob_scratch_and_final_pack_corruption_or_cancellation_cannot_issue_a_report() {
    let files = Files::new();
    let input = blob_bundle(2 * 1024 * 1024 + 17);
    let length = 2 * 1024 * 1024 + 17;
    let mut source = files.file("source.bundle");
    source.write_all(&input).unwrap();
    let mut scratch = BoundedScratch::new(files.file("corrupt-scratch"));
    scratch.corrupt_at = Some(length - 3);
    assert!(matches!(
        verify_git_bundle_reader(
            &mut source,
            &mut scratch,
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert_eq!(scratch.read_bytes, length);
    let mut corrupt = input.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut scratch = BoundedScratch::new(files.file("bad-trailer"));
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(corrupt),
            &mut scratch,
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        ),
        Err(BundleVerifyError::Pack(
            fgit_pack::PackError::TrailerChecksumMismatch
        ))
    ));
    assert_eq!(scratch.write_bytes, length);
    assert_eq!(scratch.read_bytes, 0);
    let cancelled = Rc::new(Cell::new(false));
    let mut scratch = BoundedScratch::new(files.file("cancelled"));
    scratch.cancel = Some(Rc::clone(&cancelled));
    assert!(matches!(
        verify_git_bundle_reader(
            &mut source,
            &mut scratch,
            &BundleVerifyLimits::default(),
            None,
            &mut || !cancelled.get()
        ),
        Err(BundleVerifyError::Stopped)
    ));
    assert!(scratch.write_bytes <= STREAM_PACK_CHUNK_BYTES);
    assert_eq!(scratch.read_bytes, 0);
    let cancelled = Rc::new(Cell::new(false));
    let mut scratch = BoundedScratch::new(files.file("cancelled-read"));
    scratch.cancel_on_read = Some(Rc::clone(&cancelled));
    assert!(matches!(
        verify_git_bundle_reader(
            &mut source,
            &mut scratch,
            &BundleVerifyLimits::default(),
            None,
            &mut || !cancelled.get()
        ),
        Err(BundleVerifyError::Stopped)
    ));
    assert_eq!(scratch.write_bytes, length);
    assert!(scratch.read_bytes > 0 && scratch.read_bytes <= CHUNK_BYTES);
    let mut scratch = BoundedScratch::new(files.file("valid-twin"));
    assert!(
        verify_git_bundle_reader(
            &mut source,
            &mut scratch,
            &BundleVerifyLimits::default(),
            None,
            &mut || true
        )
        .is_ok()
    );
}

fn delta_varint(mut value: usize, bytes: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 127) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 128;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}
#[test]
fn streaming_blob_allowance_supports_large_delta_bases_without_expanding_memory_limits() {
    let files = Files::new();
    for (case, length) in [4096, 96 * 1024].into_iter().enumerate() {
        let base = repeated_id(length);
        let mut program = Vec::new();
        delta_varint(length, &mut program);
        delta_varint(1, &mut program);
        program.extend([1, b'y']);
        let result = git_object_id(GitHashAlgorithm::Sha256, ObjectKind::Blob, b"y");
        let input = bundle(
            GitHashAlgorithm::Sha256,
            &[repeated_entry(length), record(7, &program, base.as_bytes())],
            result,
        );
        let mut limits = BundleVerifyLimits::default();
        limits.pack.max_object_bytes = 8192;
        limits.graph.max_object_bytes = 8192;
        limits.max_streamed_blob_bytes = 128 * 1024;
        let mut scratch = BoundedScratch::new(files.file(&format!("delta-{case}")));
        let actual = verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &mut || true,
        );
        let actual = actual.unwrap();
        assert_eq!(actual.verified().graph().objects, 2);
        assert_eq!(actual.verified().delta_objects(), 1);
        assert_eq!(actual.verified().graph().payload_bytes, length as u64 + 1);
        assert_eq!(limits.pack.max_object_bytes, 8192);
        assert_eq!(limits.graph.max_object_bytes, 8192);
        assert_eq!(scratch.write_bytes, length + program.len() + 1);
        // The explicit blob allowance is still checked before payload writes.
        limits.max_streamed_blob_bytes = length - 1;
        let mut scratch = BoundedScratch::new(files.file(&format!("too-large-{case}")));
        assert!(
            verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut scratch,
                &limits,
                None,
                &mut || true,
            )
            .is_err()
        );
        assert_eq!(scratch.write_bytes, 0);
    }
}

mod deltas;
