#![forbid(unsafe_code)]
//! Real-file regression for streaming beyond the materializing bundle ceiling.
//!
//! The ordinary case is small. The ignored case generates 33 incompressible
//! 4 MiB blobs per native format, so both selected payload and encoded pack
//! exceed 128 MiB. No blob corpus or complete artifact is held in memory.
//! Source loads must follow actual file writes; the independent native reader
//! verifies and drops each recovered body before the next callback. This is a
//! custody/order regression, not an RSS measurement or node/CLI acceptance.
//!
//! Set `FGIT_STREAM_BUNDLE_ARTIFACT_DIR` to an existing directory to retain the
//! generated files and small `.expected.tsv` inventories for a separate,
//! pinned consumer oracle. Otherwise only the test's own uniquely created
//! temporary file is removed.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use fgit_crypto::{
    DigestHasher, GitHashAlgorithm, GitObjectHasher, NativeObjectIdentity, Sha1, Sha256,
    Sha256Hasher,
};
use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::FullBundleHeader;
use fgit_pack::full_bundle::stream::{
    StreamFullBundleLimits, StreamFullBundleReceipt, write_full_bundle_stream,
};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, EntryKind, ObjectFormat, ObjectId,
    PackWriteError, object_type_from_base_entry, read_streamed_pack,
};
use fgit_types::RefName;

const MIB: usize = 1024 * 1024;
const SCRATCH_BYTES: usize = 64 * 1024;
const OLD_BUNDLE_CEILING: usize = 128 * MIB;
static FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

/// SplitMix64-derived words are reproducible at any aligned offset. The source
/// and verifier can generate a fragment without retaining the preceding bytes.
fn fill_blob(index: usize, offset: usize, bytes: &mut [u8]) {
    assert_eq!(offset % 8, 0);
    let seed = 0x2545_f491_4f6c_dd1d_u64 ^ u64::try_from(index).unwrap();
    let first_word = u64::try_from(offset / 8).unwrap();
    for (word_index, chunk) in bytes.chunks_mut(8).enumerate() {
        let word_index = first_word + u64::try_from(word_index).unwrap();
        let mut word = seed.wrapping_add(
            word_index
                .wrapping_add(1)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15),
        );
        word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^= word >> 31;
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
}

fn blob_id<A: GitHashAlgorithm>(index: usize, bytes: usize) -> ObjectId {
    let mut hash = GitObjectHasher::<A>::new(ObjectType::Blob, u64::try_from(bytes).unwrap());
    let mut scratch = vec![0_u8; SCRATCH_BYTES];
    for offset in (0..bytes).step_by(SCRATCH_BYTES) {
        let length = (bytes - offset).min(scratch.len());
        fill_blob(index, offset, &mut scratch[..length]);
        hash.update(&scratch[..length]).unwrap();
    }
    hash.finish().unwrap().erase()
}

fn tree_body(blobs: &[ObjectId]) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, id) in blobs.iter().enumerate() {
        write!(&mut body, "100644 part-{index:03}\0").unwrap();
        body.extend_from_slice(id.as_bytes());
    }
    body
}

fn commit_body(tree: ObjectId) -> Vec<u8> {
    format!(
        "tree {tree}\nauthor Native <native@example.invalid> 1 +0000\ncommitter Native <native@example.invalid> 1 +0000\n\ngenerated streaming corpus\n"
    )
    .into_bytes()
}

#[derive(Clone, Copy)]
enum ObjectSpec {
    Blob(usize),
    Tree,
    Commit,
}
impl ObjectSpec {
    const fn kind(self) -> ObjectType {
        match self {
            Self::Blob(_) => ObjectType::Blob,
            Self::Tree => ObjectType::Tree,
            Self::Commit => ObjectType::Commit,
        }
    }
}

struct GeneratedSource<'a> {
    inventory: BTreeMap<ObjectId, ObjectSpec>,
    blob_ids: Vec<ObjectId>,
    blob_bytes: usize,
    tree: ObjectId,
    commit: ObjectId,
    total_bytes: usize,
    output_bytes: &'a Cell<usize>,
    previous_output: Cell<usize>,
    loaded: RefCell<Vec<ObjectId>>,
    largest_body: Cell<usize>,
}

impl<'a> GeneratedSource<'a> {
    fn new(
        format: ObjectFormat,
        count: usize,
        blob_bytes: usize,
        output_bytes: &'a Cell<usize>,
    ) -> Self {
        let blob_ids: Vec<_> = (0..count)
            .map(|index| match format {
                ObjectFormat::Sha1 => blob_id::<Sha1>(index, blob_bytes),
                ObjectFormat::Sha256 => blob_id::<Sha256>(index, blob_bytes),
            })
            .collect();
        let tree_bytes = tree_body(&blob_ids);
        let tree = fgit_crypto::git_object_id(format, ObjectType::Tree, &tree_bytes);
        let commit_bytes = commit_body(tree);
        let commit = fgit_crypto::git_object_id(format, ObjectType::Commit, &commit_bytes);
        let total_bytes = count * blob_bytes + tree_bytes.len() + commit_bytes.len();
        let mut inventory: BTreeMap<_, _> = blob_ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, ObjectSpec::Blob(index)))
            .collect();
        assert!(inventory.insert(tree, ObjectSpec::Tree).is_none());
        assert!(inventory.insert(commit, ObjectSpec::Commit).is_none());
        assert_eq!(inventory.len(), count + 2);
        Self {
            inventory,
            blob_ids,
            blob_bytes,
            tree,
            commit,
            total_bytes,
            output_bytes,
            previous_output: Cell::new(0),
            loaded: RefCell::new(Vec::new()),
            largest_body: Cell::new(0),
        }
    }

    fn verify_body(&self, spec: ObjectSpec, body: &[u8]) {
        match spec {
            ObjectSpec::Blob(index) => {
                assert_eq!(body.len(), self.blob_bytes);
                let mut expected = vec![0_u8; SCRATCH_BYTES];
                for (chunk_index, chunk) in body.chunks(SCRATCH_BYTES).enumerate() {
                    let offset = chunk_index * SCRATCH_BYTES;
                    fill_blob(index, offset, &mut expected[..chunk.len()]);
                    assert!(
                        chunk == &expected[..chunk.len()],
                        "blob {index} differs at offset {offset}"
                    );
                }
            }
            ObjectSpec::Tree => assert_eq!(body, tree_body(&self.blob_ids)),
            ObjectSpec::Commit => assert_eq!(body, commit_body(self.tree)),
        }
    }
}

impl CanonicalObjectSource for GeneratedSource<'_> {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert!(
            self.output_bytes.get() > self.previous_output.get(),
            "loading the next object before any preceding bytes reach the file"
        );
        self.previous_output.set(self.output_bytes.get());
        let spec = *self
            .inventory
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        let body = match spec {
            ObjectSpec::Blob(index) => {
                let mut body = vec![0; self.blob_bytes];
                fill_blob(index, 0, &mut body);
                body
            }
            ObjectSpec::Tree => tree_body(&self.blob_ids),
            ObjectSpec::Commit => commit_body(self.tree),
        };
        self.largest_body
            .set(self.largest_body.get().max(body.len()));
        self.loaded.borrow_mut().push(*id);
        // Native typed edges must come from the body, not supplied metadata.
        Ok(CanonicalPackObject::new(
            *id,
            spec.kind(),
            body,
            vec![],
            0,
            0,
        ))
    }
}

struct BundleFile {
    path: PathBuf,
    retain: bool,
}
impl BundleFile {
    fn create(format: ObjectFormat) -> (Self, File) {
        let retained_directory = std::env::var_os("FGIT_STREAM_BUNDLE_ARTIFACT_DIR");
        let retain = retained_directory.is_some();
        let directory = retained_directory.map_or_else(std::env::temp_dir, PathBuf::from);
        for _ in 0..32 {
            let sequence = FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                "fgit-native-stream-{format:?}-{}-{sequence}.bundle",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return (Self { path, retain }, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create {}: {error}", path.display()),
            }
        }
        panic!("cannot allocate a unique streaming test file");
    }
}
impl Drop for BundleFile {
    fn drop(&mut self) {
        if !self.retain {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct FileSink<'a> {
    file: File,
    written: &'a Cell<usize>,
}
impl Write for FileSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let accepted = self.file.write(bytes)?;
        self.written.set(self.written.get() + accepted);
        Ok(accepted)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct HashingRead<R> {
    reader: R,
    hash: Sha256Hasher,
    bytes: usize,
}
impl<R: Read> Read for HashingRead<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = self.reader.read(buffer)?;
        self.hash.update(&buffer[..length]);
        self.bytes += length;
        Ok(length)
    }
}

fn write_expected_inventory(
    artifact: &BundleFile,
    source: &GeneratedSource<'_>,
    receipt: &StreamFullBundleReceipt,
) {
    if !artifact.retain {
        return;
    }
    let path = artifact.path.with_extension("expected.tsv");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let format = match receipt.format() {
        ObjectFormat::Sha1 => "sha1",
        ObjectFormat::Sha256 => "sha256",
    };
    writeln!(&mut file, "format\t{format}").unwrap();
    writeln!(&mut file, "ref\trefs/heads/main\t{}", source.commit).unwrap();
    writeln!(&mut file, "head\t{}", source.commit).unwrap();
    for (id, &spec) in &source.inventory {
        let body_bytes = match spec {
            ObjectSpec::Blob(_) => source.blob_bytes,
            ObjectSpec::Tree => tree_body(&source.blob_ids).len(),
            ObjectSpec::Commit => commit_body(source.tree).len(),
        };
        writeln!(
            &mut file,
            "object\t{id}\t{}\t{body_bytes}",
            spec.kind().label()
        )
        .unwrap();
    }
    let sha256: String = receipt
        .bundle_sha256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    writeln!(&mut file, "bundle_sha256\t{sha256}").unwrap();
    writeln!(&mut file, "pack_checksum\t{}", receipt.pack_checksum()).unwrap();
    writeln!(&mut file, "bundle_bytes\t{}", receipt.bundle_bytes()).unwrap();
    file.flush().unwrap();
    eprintln!("native_stream_inventory\t{}", path.display());
}

fn file_round_trip(format: ObjectFormat, count: usize, blob_bytes: usize, minimum: usize) {
    let started = Instant::now();
    let written = Cell::new(0);
    let source = GeneratedSource::new(format, count, blob_bytes, &written);
    let selected: Vec<_> = source.inventory.keys().copied().collect();
    let references = [BundleReference::new(
        source.commit,
        RefName::try_new(b"refs/heads/main").unwrap(),
    )];
    let mut limits = StreamFullBundleLimits::default();
    limits.pack.max_entries = u32::try_from(selected.len()).unwrap();
    limits.pack.max_index_entries = selected.len();
    limits.pack.max_object_bytes = blob_bytes;
    limits.pack.max_total_expanded_bytes = source.total_bytes;
    limits.pack.max_input_bytes = source.total_bytes * 2 + SCRATCH_BYTES;
    limits.pack.max_inflate_work = u64::try_from(blob_bytes).unwrap() * 16;
    limits.envelope.max_bundle_bytes = limits.pack.max_input_bytes + 1024;
    limits.envelope.max_header_bytes = 1024;
    limits.envelope.max_references = references.len() + 1; // HEAD is a record too.
    limits.max_graph_edges = count + 1;
    limits.max_compression_work = u64::try_from(source.total_bytes).unwrap() * 16;

    let (artifact, file) = BundleFile::create(format);
    let mut sink = FileSink {
        file,
        written: &written,
    };
    let receipt = write_full_bundle_stream(
        format,
        &references,
        Some(source.commit),
        &selected,
        &source,
        &limits,
        &mut || true,
        &mut sink,
    )
    .unwrap();
    sink.flush().unwrap();
    drop(sink);
    assert_eq!(receipt.object_count() as usize, selected.len());
    assert_eq!(receipt.total_object_bytes(), source.total_bytes);
    assert_eq!(receipt.bundle_bytes(), written.get());
    assert_eq!(
        fs::metadata(&artifact.path).unwrap().len(),
        u64::try_from(receipt.bundle_bytes()).unwrap()
    );
    assert!(receipt.total_object_bytes() > minimum);
    assert!(receipt.pack_bytes() > minimum);
    assert!(receipt.bundle_bytes() > minimum);
    assert_eq!(*source.loaded.borrow(), selected);
    assert_eq!(source.largest_body.get(), blob_bytes);

    let mut reader = BufReader::with_capacity(
        SCRATCH_BYTES,
        HashingRead {
            reader: File::open(&artifact.path).unwrap(),
            hash: Sha256Hasher::new(),
            bytes: 0,
        },
    );
    let header = FullBundleHeader::read(&mut reader, limits.envelope, &mut || true).unwrap();
    assert_eq!(header.format(), format);
    assert_eq!(header.references(), references);
    assert_eq!(header.head(), Some(source.commit));
    assert!(header.prerequisites().is_empty());
    assert_eq!(header.header_bytes(), receipt.header_bytes());
    let mut recovered_count = 0;
    let mut recovered_bytes = 0;
    let native = read_streamed_pack(
        &mut reader,
        format,
        &limits.pack,
        &mut || true,
        |entry| -> Result<(), io::Error> {
            assert!(!matches!(
                entry.entry.header.kind,
                EntryKind::OfsDelta | EntryKind::RefDelta
            ));
            let kind = object_type_from_base_entry(entry.entry.header.kind).unwrap();
            let body = &entry.entry.inflated;
            let id = fgit_crypto::git_object_id(format, kind, body);
            assert_eq!(id, selected[recovered_count]);
            let spec = source.inventory[&id];
            assert_eq!(kind, spec.kind());
            source.verify_body(spec, body);
            recovered_count += 1;
            recovered_bytes += body.len();
            // Only counters survive this callback; the native reader owns
            // validation of the trailer and exact EOF after the final object.
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(recovered_count, selected.len());
    assert_eq!(recovered_bytes, source.total_bytes);
    assert_eq!(native.header().object_count, receipt.object_count());
    assert_eq!(native.trailer(), receipt.pack_checksum());
    assert_eq!(
        native.pack_bytes(),
        u64::try_from(receipt.pack_bytes()).unwrap()
    );
    assert!(reader.buffer().is_empty());
    let read = reader.into_inner();
    assert_eq!(read.bytes, receipt.bundle_bytes());
    assert_eq!(read.hash.finish(), receipt.bundle_sha256());
    write_expected_inventory(&artifact, &source, &receipt);
    eprintln!(
        "native_stream_file format={format:?} objects={} payload_bytes={} bundle_bytes={} pack_checksum={} commit={} elapsed_ms={} retained={} path={}",
        receipt.object_count(),
        receipt.total_object_bytes(),
        receipt.bundle_bytes(),
        receipt.pack_checksum(),
        source.commit,
        started.elapsed().as_millis(),
        artifact.retain,
        artifact.path.display(),
    );
}

#[test]
fn generated_graph_streams_to_a_real_file_in_both_native_formats() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        file_round_trip(format, 5, SCRATCH_BYTES, 0);
    }
}

#[test]
#[ignore = "generates and verifies >128 MiB per format; run explicitly with --ignored"]
fn generated_graph_above_128_mib_streams_to_a_real_file_in_both_native_formats() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        file_round_trip(format, 33, 4 * MIB, OLD_BUNDLE_CEILING);
    }
}
