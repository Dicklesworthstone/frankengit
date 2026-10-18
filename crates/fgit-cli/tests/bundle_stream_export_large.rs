#![forbid(unsafe_code)]
#![cfg(unix)]
//! Explicit real-command gate beyond the buffered bundle ceiling.
//!
//! Run with:
//! `cargo test -p fgit-cli --release --test bundle_stream_export_large --locked -- --ignored --nocapture --test-threads=1`
//!
//! Three independently bounded imports create 33 distinct 4 MiB blobs, three
//! trees and three branch commits. The real fg process must stream their combined
//! source graph into a >128 MiB bundle, verify it with file-backed resolution and
//! recover a native bare repository. Both Git hash formats run independently.
//! Fixture bodies are generated on demand; no corpus or full export is buffered
//! here. The <=128 MiB legacy imports retain their own existing finite buffers.
//! This is an opt-in integration gate, not a throughput, RSS, 1 GiB, forge-backup
//! or power-loss claim. Blocking filesystem I/O remains cooperative.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fgit_crypto::{
    DigestHasher, GitHashAlgorithm as HashAlgorithm, GitObjectHasher, GitObjectKind,
    NativeObjectIdentity, Sha1, Sha256, Sha256Hasher, git_object_id, lowercase_hex,
};
use fgit_pack::full_bundle::FullBundleHeader;
use fgit_pack::full_bundle::stream::{StreamFullBundleLimits, write_full_bundle_stream};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, PackLimits, PackWriteError,
    object_type_from_base_entry, read_streamed_pack,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
const PRINCIPAL: &str = "33333333333333333333333333333333";
const MIB: usize = 1024 * 1024;
const OLD_CEILING: usize = 128 * MIB;
const OUTPUT_CEILING: usize = 256 * MIB;
const BLOB_BYTES: usize = 4 * MIB;
const FRAGMENT_BYTES: usize = 64 * 1024;
const BATCHES: usize = 3;
const BLOBS_PER_BATCH: usize = 11;
const OBJECTS: usize = BATCHES * (BLOBS_PER_BATCH + 2);
const TIMEOUT: Duration = Duration::from_secs(3600);
const WORK_LIMIT: u64 = 4_000_000_000;

struct Fixture(PathBuf);
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fg-stream-export-large-{}-{}-{}-{}",
            format.as_str(),
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path.join("scratch")).unwrap();
        fs::set_permissions(path.join("scratch"), fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn run(&self, args: &[String]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_fg"))
            .args(["--timeout-secs", "3600"])
            .args(args)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", "")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        success(output, args)
    }

    fn refs(&self, format: GitHashAlgorithm) -> String {
        let report = self.run(&args(&[
            "refs",
            "node",
            TENANT,
            REPOSITORY,
            "--trusted-local",
            "--object-format",
            format.as_str(),
        ]));
        assert!(report.contains("\"has_more\":false"), "{report}");
        report
    }

    fn assert_no_stages(&self) {
        assert_eq!(fs::read_dir(self.0.join("scratch")).unwrap().count(), 0);
        let mut directories = vec![self.0.clone()];
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                assert!(!name.starts_with(".fg-stream-export-"), "{name}");
                assert!(!name.starts_with(".fg-bundle-"), "{name}");
                assert!(!name.ends_with(".fg-recovery-part"), "{name}");
                if entry.file_type().unwrap().is_dir() {
                    directories.push(entry.path());
                }
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn success(output: Output, args: &[String]) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "fg {args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert_eq!(report.lines().count(), 1, "{report}");
    report
}

// Only known, unescaped primitive fields of the compiled CLI's reports are read.
// The native readers below, not report parsing, authenticate artifact contents.
fn field<'a>(report: &'a str, key: &str) -> &'a str {
    let marker = format!("\"{key}\":");
    assert_eq!(report.matches(&marker).count(), 1, "{report}");
    report.split_once(&marker).unwrap().1
}
fn number(report: &str, key: &str) -> u64 {
    field(report, key)
        .split([',', '}'])
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
fn text<'a>(report: &'a str, key: &str) -> &'a str {
    let value = field(report, key)
        .strip_prefix('"')
        .unwrap()
        .split_once('"')
        .unwrap()
        .0;
    assert!(!value.contains('\\'));
    value
}

/// Deterministic incompressible-looking bytes, generated at any aligned offset.
/// Distinct global blob indices prevent accidental cross-batch deduplication.
fn fill_blob(index: usize, offset: usize, output: &mut [u8]) {
    assert_eq!(offset % 8, 0);
    let seed = 0x2545_f491_4f6c_dd1d_u64 ^ u64::try_from(index).unwrap();
    let first = u64::try_from(offset / 8).unwrap();
    for (word_index, chunk) in output.chunks_mut(8).enumerate() {
        let word_index = first + u64::try_from(word_index).unwrap();
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

fn blob_id<A: HashAlgorithm>(index: usize) -> GitOid {
    let mut hash = GitObjectHasher::<A>::new(GitObjectKind::Blob, BLOB_BYTES as u64);
    let mut fragment = [0; FRAGMENT_BYTES];
    for offset in (0..BLOB_BYTES).step_by(FRAGMENT_BYTES) {
        fill_blob(index, offset, &mut fragment);
        hash.update(&fragment).unwrap();
    }
    hash.finish().unwrap().erase()
}

#[derive(Clone)]
enum ObjectSpec {
    Blob(usize),
    Tree(Vec<GitOid>),
    Commit { tree: GitOid, batch: usize },
}
impl ObjectSpec {
    fn kind(&self) -> GitObjectKind {
        match self {
            Self::Blob(_) => GitObjectKind::Blob,
            Self::Tree(_) => GitObjectKind::Tree,
            Self::Commit { .. } => GitObjectKind::Commit,
        }
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Self::Blob(index) => {
                let mut bytes = vec![0; BLOB_BYTES];
                fill_blob(*index, 0, &mut bytes);
                bytes
            }
            Self::Tree(blobs) => {
                let mut bytes = Vec::new();
                for (index, id) in blobs.iter().enumerate() {
                    write!(&mut bytes, "100644 part-{index:03}\0").unwrap();
                    bytes.extend_from_slice(id.as_bytes());
                }
                bytes
            }
            Self::Commit { tree, batch } => format!(
                "tree {tree}\nauthor Native <native@example.invalid> 1 +0000\ncommitter Native <native@example.invalid> 1 +0000\n\nstreaming batch {batch}\n"
            ).into_bytes(),
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Blob(_) => BLOB_BYTES,
            _ => self.body().len(),
        }
    }

    fn verify(&self, actual: &[u8]) {
        if let Self::Blob(index) = self {
            assert_eq!(actual.len(), BLOB_BYTES);
            let mut fragment = [0; FRAGMENT_BYTES];
            for (index_in_blob, chunk) in actual.chunks(FRAGMENT_BYTES).enumerate() {
                fill_blob(
                    *index,
                    index_in_blob * FRAGMENT_BYTES,
                    &mut fragment[..chunk.len()],
                );
                assert!(
                    chunk == &fragment[..chunk.len()],
                    "blob {index}, fragment {index_in_blob}"
                );
            }
        } else {
            assert_eq!(actual, self.body());
        }
    }
}

struct GeneratedSource<'a> {
    inventory: &'a BTreeMap<GitOid, ObjectSpec>,
    written: &'a Cell<usize>,
    previous_write: Cell<usize>,
    loads: Cell<usize>,
    largest_body: Cell<usize>,
}
impl CanonicalObjectSource for GeneratedSource<'_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        assert!(
            self.written.get() > self.previous_write.get(),
            "seed codec buffered successive objects before file output"
        );
        self.previous_write.set(self.written.get());
        let object = self
            .inventory
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        let body = object.body();
        self.loads.set(self.loads.get() + 1);
        self.largest_body
            .set(self.largest_body.get().max(body.len()));
        Ok(CanonicalPackObject::new(
            *id,
            object.kind(),
            body,
            vec![],
            0,
            0,
        ))
    }
}

struct SeedSink<'a> {
    file: File,
    written: &'a Cell<usize>,
}
impl Write for SeedSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.file.write(bytes)?;
        self.written.set(self.written.get() + count);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn seed_batch(
    fixture: &Fixture,
    format: GitHashAlgorithm,
    batch: usize,
) -> (BundleReference, BTreeMap<GitOid, ObjectSpec>) {
    let mut inventory = BTreeMap::new();
    let mut blob_ids = Vec::new();
    for offset in 0..BLOBS_PER_BATCH {
        let index = batch * BLOBS_PER_BATCH + offset;
        let id = match format {
            GitHashAlgorithm::Sha1 => blob_id::<Sha1>(index),
            GitHashAlgorithm::Sha256 => blob_id::<Sha256>(index),
        };
        assert!(inventory.insert(id, ObjectSpec::Blob(index)).is_none());
        blob_ids.push(id);
    }
    let tree = ObjectSpec::Tree(blob_ids);
    let tree_id = git_object_id(format, tree.kind(), &tree.body());
    assert!(inventory.insert(tree_id, tree).is_none());
    let commit = ObjectSpec::Commit {
        tree: tree_id,
        batch,
    };
    let commit_id = git_object_id(format, commit.kind(), &commit.body());
    assert!(inventory.insert(commit_id, commit).is_none());
    let name = if batch == 0 {
        "refs/heads/main".to_owned()
    } else {
        format!("refs/heads/batch-{batch}")
    };
    let reference = BundleReference::new(commit_id, RefName::try_new(name.as_bytes()).unwrap());
    let selected: Vec<_> = inventory.keys().copied().collect();
    let payload: usize = inventory.values().map(ObjectSpec::bytes).sum();
    assert!(payload < OLD_CEILING);
    let written = Cell::new(0);
    let source = GeneratedSource {
        inventory: &inventory,
        written: &written,
        previous_write: Cell::new(0),
        loads: Cell::new(0),
        largest_body: Cell::new(0),
    };
    let mut limits = StreamFullBundleLimits::default();
    limits.pack.max_entries = selected.len() as u32;
    limits.pack.max_index_entries = selected.len();
    limits.pack.max_input_bytes = OLD_CEILING;
    limits.pack.max_total_expanded_bytes = OLD_CEILING;
    limits.pack.max_object_bytes = BLOB_BYTES;
    limits.envelope.max_bundle_bytes = OLD_CEILING;
    limits.envelope.max_header_bytes = 4096;
    limits.envelope.max_references = 2;
    limits.max_graph_edges = BLOBS_PER_BATCH + 1;
    limits.max_compression_work = WORK_LIMIT;
    let path = fixture.0.join(format!("seed-{batch}.bundle"));
    let mut sink = SeedSink {
        file: OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap(),
        written: &written,
    };
    let started = Instant::now();
    let receipt = write_full_bundle_stream(
        format,
        std::slice::from_ref(&reference),
        Some(commit_id),
        &selected,
        &source,
        &limits,
        &mut || started.elapsed() < TIMEOUT,
        &mut sink,
    )
    .unwrap();
    sink.flush().unwrap();
    drop(sink);
    assert_eq!(receipt.total_object_bytes(), payload);
    assert_eq!(source.loads.get(), selected.len());
    assert_eq!(source.largest_body.get(), BLOB_BYTES);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        receipt.bundle_bytes() as u64
    );
    assert!(
        receipt.bundle_bytes() < OLD_CEILING,
        "each seed must fit the existing importer"
    );
    assert!(receipt.compression_work() <= WORK_LIMIT);
    fixture.run(&args(&[
        "bundle",
        "import",
        "node",
        TENANT,
        REPOSITORY,
        path.to_str().unwrap(),
        "--trusted-local",
        "--object-format",
        format.as_str(),
        "--principal",
        PRINCIPAL,
        "--idempotency-key",
        &format!("seed-large-stream-{batch}"),
    ]));
    fs::remove_file(path).unwrap();
    (reference, inventory)
}

struct HashingRead<R> {
    input: R,
    hash: Sha256Hasher,
    bytes: u64,
}
impl<R: Read> Read for HashingRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(bytes)?;
        self.hash.update(&bytes[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
}

fn read_inventory(
    input: &mut impl BufRead,
    format: GitHashAlgorithm,
    expected: &BTreeMap<GitOid, ObjectSpec>,
) -> String {
    let limits = PackLimits {
        max_entries: OBJECTS as u32,
        max_index_entries: OBJECTS,
        max_input_bytes: OUTPUT_CEILING,
        max_total_expanded_bytes: OUTPUT_CEILING,
        max_object_bytes: BLOB_BYTES,
        ..Default::default()
    };
    let started = Instant::now();
    let mut seen = BTreeSet::new();
    let mut payload = 0;
    let verified = read_streamed_pack(
        input,
        format,
        &limits,
        &mut || started.elapsed() < TIMEOUT,
        |entry| -> Result<(), io::Error> {
            let kind = object_type_from_base_entry(entry.entry.header.kind).unwrap();
            let body = &entry.entry.inflated;
            let id = git_object_id(format, kind, body);
            let object = expected
                .get(&id)
                .expect("unexpected object in recovered inventory");
            assert_eq!(kind, object.kind());
            object.verify(body);
            assert!(seen.insert(id), "duplicate recovered object");
            payload += body.len();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(seen, expected.keys().copied().collect());
    assert_eq!(
        payload,
        expected.values().map(ObjectSpec::bytes).sum::<usize>()
    );
    assert!(payload > OLD_CEILING);
    assert_eq!(verified.header().object_count, OBJECTS as u32);
    verified.trailer().to_string()
}

fn verify_bundle_bytes(
    path: &Path,
    format: GitHashAlgorithm,
    references: &[BundleReference],
    main: GitOid,
    inventory: &BTreeMap<GitOid, ObjectSpec>,
) -> (String, String, u64) {
    let mut reader = BufReader::with_capacity(
        FRAGMENT_BYTES,
        HashingRead {
            input: File::open(path).unwrap(),
            hash: Sha256Hasher::new(),
            bytes: 0,
        },
    );
    let mut limits = StreamFullBundleLimits::default();
    limits.envelope.max_bundle_bytes = OUTPUT_CEILING;
    limits.envelope.max_references = BATCHES + 1;
    let started = Instant::now();
    let header = FullBundleHeader::read(&mut reader, limits.envelope, &mut || {
        started.elapsed() < TIMEOUT
    })
    .unwrap();
    assert_eq!(header.format(), format);
    assert_eq!(header.references(), references);
    assert_eq!(header.head(), Some(main));
    let checksum = read_inventory(&mut reader, format, inventory);
    assert!(reader.buffer().is_empty());
    let read = reader.into_inner();
    assert_eq!(read.bytes, fs::metadata(path).unwrap().len());
    assert!(read.bytes > OLD_CEILING as u64);
    (lowercase_hex(&read.hash.finish()), checksum, read.bytes)
}

fn verification_args(
    format: GitHashAlgorithm,
    digest: &str,
    references: &[BundleReference],
) -> Vec<String> {
    let mut values = args(&[
        "--file-backed",
        "--scratch-dir",
        "scratch",
        "--max-input-mib",
        "256",
        "--max-expanded-mib",
        "256",
        "--max-objects",
        "39",
        "--max-refs",
        "4",
        "--timeout-secs",
        "3600",
        "--expect-sha256",
        digest,
        "--expect-format",
        format.as_str(),
        "--exact-refs",
    ]);
    for reference in references {
        values.extend([
            "--expect-ref".to_owned(),
            format!(
                "{}={}",
                std::str::from_utf8(reference.name().as_bytes()).unwrap(),
                reference.target()
            ),
        ]);
    }
    values
}

#[test]
#[ignore = "real fg imports/exports/verifies/recovers >128 MiB for both formats; explicit release run"]
fn real_fg_streams_above_128_mib_and_recovers_exact_source_in_both_hash_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let started = Instant::now();
        let fixture = Fixture::new(format);
        fixture.run(&args(&[
            "init",
            "node",
            TENANT,
            REPOSITORY,
            format.as_str(),
        ]));
        let mut references = Vec::new();
        let mut inventory = BTreeMap::new();
        let mut main = None;
        for batch in 0..BATCHES {
            let (reference, objects) = seed_batch(&fixture, format, batch);
            if batch == 0 {
                main = Some(*reference.target());
            }
            references.push(reference);
            for (id, object) in objects {
                assert!(
                    inventory.insert(id, object).is_none(),
                    "batches must have disjoint objects"
                );
            }
        }
        let main = main.unwrap();
        references.sort_by(|left, right| left.name().cmp(right.name()));
        assert_eq!(inventory.len(), OBJECTS);
        let source_bytes: usize = inventory.values().map(ObjectSpec::bytes).sum();
        assert!(source_bytes > OLD_CEILING);
        let before = fixture.refs(format);
        for reference in &references {
            let row = format!(
                "{{\"reference_hex\":\"{}\",\"tip\":\"{}\"}}",
                lowercase_hex(reference.name().as_bytes()),
                reference.target()
            );
            assert!(before.contains(&row), "{before}");
        }
        assert_eq!(before.matches("\"reference_hex\":").count(), BATCHES);
        let report = fixture.run(&args(&[
            "bundle",
            "export",
            "node",
            TENANT,
            REPOSITORY,
            "stream.bundle",
            "--trusted-local",
            "--streaming",
            "--object-format",
            format.as_str(),
            "--max-output-mib",
            "256",
            "--max-expanded-mib",
            "256",
            "--max-object-mib",
            "4",
            "--max-objects",
            "39",
            "--max-refs",
            "4",
            "--max-edges",
            "36",
            "--max-compression-work",
            "4000000000",
            "--timeout-secs",
            "3600",
        ]));
        for required in [
            "\"streaming\":true",
            "\"publication_state\":\"durable\"",
            "\"bundle_created\":true",
            "\"node_closed\":true",
            "\"repository_changed\":false",
            "\"includes_forge_metadata\":false",
        ] {
            assert!(report.contains(required), "{report}");
        }
        assert_eq!(text(&report, "source_head"), text(&before, "source_head"));
        assert_eq!(number(&report, "object_count"), OBJECTS as u64);
        assert_eq!(number(&report, "total_object_bytes"), source_bytes as u64);
        assert!(number(&report, "total_object_bytes") > OLD_CEILING as u64);
        assert!(number(&report, "compression_work") <= WORK_LIMIT);
        let path = fixture.0.join("stream.bundle");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let (digest, checksum, bundle_bytes) =
            verify_bundle_bytes(&path, format, &references, main, &inventory);
        assert!(bundle_bytes > OLD_CEILING as u64);
        assert!(bundle_bytes <= OUTPUT_CEILING as u64);
        assert_eq!(number(&report, "bundle_bytes"), bundle_bytes);
        assert_eq!(text(&report, "bundle_sha256"), digest);
        assert_eq!(text(&report, "pack_checksum"), checksum);
        fixture.assert_no_stages();
        assert_eq!(fixture.refs(format), before);

        let pins = verification_args(format, &digest, &references);
        let mut verify = args(&["bundle", "verify", "stream.bundle"]);
        verify.extend(pins.clone());
        let verified = fixture.run(&verify);
        assert_eq!(number(&verified, "object_count"), OBJECTS as u64);
        assert_eq!(number(&verified, "reference_count"), BATCHES as u64);
        assert_eq!(number(&verified, "payload_bytes"), source_bytes as u64);
        assert_eq!(text(&verified, "advertised_head"), main.to_string());
        assert!(verified.contains("\"object_graph_verified\":true"));
        assert!(verified.contains("\"caller_expectations_matched\":true"));
        assert!(verified.contains("\"scratch_removed\":true"));
        fixture.assert_no_stages();

        let mut recover = args(&[
            "bundle",
            "recover",
            "stream.bundle",
            "restored.git",
            "--trusted-local",
            "--head-ref",
            "refs/heads/main",
        ]);
        recover.extend(pins);
        let recovered = fixture.run(&recover);
        assert!(recovered.contains("\"state\":\"durable\""));
        assert!(recovered.contains("\"head_published\":true"));
        assert!(recovered.contains("\"files_synchronized\":true"));
        assert!(recovered.contains("\"scratch_removed\":true"));
        assert!(recovered.contains("\"authority_changed\":false"));
        assert_eq!(number(&recovered, "object_count"), OBJECTS as u64);
        assert_eq!(number(&recovered, "reference_count"), BATCHES as u64);
        assert_eq!(text(&recovered, "pack_checksum"), checksum);
        assert_eq!(
            fs::read(fixture.0.join("restored.git/HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        let packed = fs::read_to_string(fixture.0.join("restored.git/packed-refs")).unwrap();
        let actual_refs: BTreeMap<_, _> = packed
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (id, name) = line.split_once(' ').unwrap();
                (name.to_owned(), id.to_owned())
            })
            .collect();
        let expected_refs: BTreeMap<_, _> = references
            .iter()
            .map(|reference| {
                (
                    std::str::from_utf8(reference.name().as_bytes())
                        .unwrap()
                        .to_owned(),
                    reference.target().to_string(),
                )
            })
            .collect();
        assert_eq!(actual_refs, expected_refs);
        let pack_directory = fixture.0.join("restored.git/objects/pack");
        let pack_names: BTreeSet<_> = fs::read_dir(&pack_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            pack_names,
            BTreeSet::from([
                std::ffi::OsString::from(format!("pack-{checksum}.pack")),
                std::ffi::OsString::from(format!("pack-{checksum}.idx")),
            ])
        );
        let mut recovered_pack = BufReader::with_capacity(
            FRAGMENT_BYTES,
            File::open(pack_directory.join(format!("pack-{checksum}.pack"))).unwrap(),
        );
        assert_eq!(
            read_inventory(&mut recovered_pack, format, &inventory),
            checksum
        );
        assert_eq!(
            fixture.refs(format),
            before,
            "export, verification and bare recovery must preserve source authority and refs"
        );
        fixture.assert_no_stages();
        eprintln!(
            "large_native_cli_stream format={} objects={OBJECTS} source_bytes={source_bytes} bundle_bytes={bundle_bytes} pack_checksum={checksum} source_head={} elapsed_ms={}",
            format.as_str(),
            text(&before, "source_head"),
            started.elapsed().as_millis()
        );
    }
}
