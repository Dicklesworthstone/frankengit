#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::GitObjectKind;
use fgit_node::{LooseGitImportRefusal, NodeConfig, NodeSourceImportRefusal, OneNode};
use fgit_pack::PackError;
use fgit_types::numeric::HeadGeneration;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frankengit-packed-import-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("scratch directory creates");
        Self(root)
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug)]
enum BlobStorage {
    Base,
    Loose,
    OfsDelta,
    RefDelta,
}

enum FixtureEntry {
    Base {
        type_code: u8,
        oid: GitOid,
        body: Vec<u8>,
    },
    OfsDelta {
        base_index: usize,
        oid: GitOid,
        program: Vec<u8>,
    },
    RefDelta {
        base_oid: GitOid,
        oid: GitOid,
        program: Vec<u8>,
    },
}

impl FixtureEntry {
    const fn oid(&self) -> GitOid {
        match self {
            Self::Base { oid, .. } | Self::OfsDelta { oid, .. } | Self::RefDelta { oid, .. } => {
                *oid
            }
        }
    }
}

struct PackedRepository {
    root: PathBuf,
    commit: GitOid,
    tree: GitOid,
    blob: GitOid,
    blob_body: Vec<u8>,
    pack_path: PathBuf,
    index_path: PathBuf,
}

#[derive(Clone, Copy)]
struct IndexRecord {
    oid: GitOid,
    crc32: u32,
    offset: u64,
}

fn serving_node(root: PathBuf) -> OneNode {
    let mut node = OneNode::init(NodeConfig::new(
        root,
        TenantId::from_bytes([0xa1; 16]),
        RepositoryId::from_bytes([0xb2; 16]),
    ))
    .expect("node initializes")
    .0;
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("fresh node enters service");
    node
}

fn write_packed_repository(root: &Path, storage: BlobStorage) -> PackedRepository {
    fs::create_dir_all(root.join("objects/pack")).expect("pack directory creates");
    fs::create_dir_all(root.join("refs/heads")).expect("branch directory creates");
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD writes");

    let base_blob_body = b"packed base blob\n".to_vec();
    let blob_body = b"packed reconstructed blob\n".to_vec();
    let base_blob = object_id(GitObjectKind::Blob, &base_blob_body);
    let blob = object_id(GitObjectKind::Blob, &blob_body);
    let mut tree_body = b"100644 file.txt\0".to_vec();
    tree_body.extend_from_slice(blob.as_bytes());
    let tree = object_id(GitObjectKind::Tree, &tree_body);
    let commit_body = format!(
        "tree {tree}\nauthor Test <test@example.com> 0 +0000\ncommitter Test <test@example.com> 0 +0000\n\npacked import\n"
    )
    .into_bytes();
    let commit = object_id(GitObjectKind::Commit, &commit_body);

    let mut entries = Vec::new();
    match storage {
        BlobStorage::Base => entries.push(FixtureEntry::Base {
            type_code: 3,
            oid: blob,
            body: blob_body.clone(),
        }),
        BlobStorage::Loose => write_loose_object(root, GitObjectKind::Blob, &blob_body),
        BlobStorage::OfsDelta => {
            entries.push(FixtureEntry::Base {
                type_code: 3,
                oid: base_blob,
                body: base_blob_body.clone(),
            });
            entries.push(FixtureEntry::OfsDelta {
                base_index: 0,
                oid: blob,
                program: literal_delta(&base_blob_body, &blob_body),
            });
        }
        BlobStorage::RefDelta => {
            entries.push(FixtureEntry::Base {
                type_code: 3,
                oid: base_blob,
                body: base_blob_body.clone(),
            });
            entries.push(FixtureEntry::RefDelta {
                base_oid: base_blob,
                oid: blob,
                program: literal_delta(&base_blob_body, &blob_body),
            });
        }
    }
    entries.push(FixtureEntry::Base {
        type_code: 2,
        oid: tree,
        body: tree_body,
    });
    entries.push(FixtureEntry::Base {
        type_code: 1,
        oid: commit,
        body: commit_body,
    });

    let (pack, records) = encode_pack(&entries);
    let index = encode_index(&records, &pack[pack.len() - 20..]);
    let pack_path = root.join("objects/pack/pack-fixture.pack");
    let index_path = root.join("objects/pack/pack-fixture.idx");
    fs::write(&pack_path, pack).expect("pack writes");
    fs::write(&index_path, index).expect("index writes");
    fs::write(root.join("refs/heads/main"), format!("{commit}\n")).expect("branch ref writes");

    PackedRepository {
        root: root.to_path_buf(),
        commit,
        tree,
        blob,
        blob_body,
        pack_path,
        index_path,
    }
}

fn write_loose_object(root: &Path, kind: GitObjectKind, body: &[u8]) {
    let oid = object_id(kind, body);
    let identity = oid.to_string();
    let (directory, file) = identity.split_at(2);
    let path = root.join("objects").join(directory).join(file);
    fs::create_dir_all(path.parent().expect("loose object parent exists"))
        .expect("loose object directory creates");
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    fs::write(path, zlib_stored_member(&framed)).expect("loose object writes");
}

fn object_id(kind: GitObjectKind, body: &[u8]) -> GitOid {
    fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, kind, body)
}

fn encode_pack(entries: &[FixtureEntry]) -> (Vec<u8>, Vec<IndexRecord>) {
    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(
        &u32::try_from(entries.len())
            .expect("fixture entry count fits")
            .to_be_bytes(),
    );
    let mut offsets = Vec::new();
    let mut records = Vec::new();
    for entry in entries {
        let offset = u64::try_from(pack.len()).expect("fixture offset fits");
        offsets.push(offset);
        let mut raw = Vec::new();
        match entry {
            FixtureEntry::Base {
                type_code, body, ..
            } => {
                raw.extend_from_slice(&entry_header(*type_code, body.len()));
                raw.extend_from_slice(&zlib_stored_member(body));
            }
            FixtureEntry::OfsDelta {
                base_index,
                program,
                ..
            } => {
                raw.extend_from_slice(&entry_header(6, program.len()));
                let distance = offset
                    .checked_sub(offsets[*base_index])
                    .expect("OFS base precedes its delta");
                raw.extend_from_slice(&ofs_distance(distance));
                raw.extend_from_slice(&zlib_stored_member(program));
            }
            FixtureEntry::RefDelta {
                base_oid, program, ..
            } => {
                raw.extend_from_slice(&entry_header(7, program.len()));
                raw.extend_from_slice(base_oid.as_bytes());
                raw.extend_from_slice(&zlib_stored_member(program));
            }
        }
        records.push(IndexRecord {
            oid: entry.oid(),
            crc32: ieee_crc32(&raw),
            offset,
        });
        pack.extend_from_slice(&raw);
    }
    let checksum = fgit_crypto::sha1_digest(&pack);
    pack.extend_from_slice(&checksum);
    (pack, records)
}

fn encode_index(records: &[IndexRecord], pack_checksum: &[u8]) -> Vec<u8> {
    let mut records = records.to_vec();
    records.sort_by(|left, right| left.oid.as_bytes().cmp(right.oid.as_bytes()));
    let mut index = vec![0xff, b't', b'O', b'c'];
    index.extend_from_slice(&2_u32.to_be_bytes());
    let mut cumulative = 0_u32;
    for first_byte in 0_u16..=255 {
        cumulative += u32::try_from(
            records
                .iter()
                .filter(|record| u16::from(record.oid.as_bytes()[0]) == first_byte)
                .count(),
        )
        .expect("fixture fanout count fits");
        index.extend_from_slice(&cumulative.to_be_bytes());
    }
    for record in &records {
        index.extend_from_slice(record.oid.as_bytes());
    }
    for record in &records {
        index.extend_from_slice(&record.crc32.to_be_bytes());
    }
    for record in &records {
        index.extend_from_slice(
            &u32::try_from(record.offset)
                .expect("small fixture offset uses direct idx encoding")
                .to_be_bytes(),
        );
    }
    index.extend_from_slice(pack_checksum);
    let checksum = fgit_crypto::sha1_digest(&index);
    index.extend_from_slice(&checksum);
    index
}

fn entry_header(type_code: u8, size: usize) -> Vec<u8> {
    let mut remaining = u64::try_from(size).expect("fixture size fits");
    let mut first = u8::try_from(remaining & 0x0f).expect("low nibble fits") | (type_code << 4);
    remaining >>= 4;
    if remaining != 0 {
        first |= 0x80;
    }
    let mut output = vec![first];
    while remaining != 0 {
        let mut byte = u8::try_from(remaining & 0x7f).expect("seven bits fit");
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        output.push(byte);
    }
    output
}

fn ofs_distance(distance: u64) -> Vec<u8> {
    assert_ne!(distance, 0, "OFS delta distance is positive");
    let mut bytes = vec![u8::try_from(distance & 0x7f).expect("seven bits fit")];
    let mut value = distance >> 7;
    while value != 0 {
        value -= 1;
        bytes.push(u8::try_from(value & 0x7f).expect("seven bits fit") | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

fn literal_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut program = variable_length_integer(base.len());
    program.extend_from_slice(&variable_length_integer(target.len()));
    for chunk in target.chunks(127) {
        program.push(u8::try_from(chunk.len()).expect("literal delta chunk fits"));
        program.extend_from_slice(chunk);
    }
    program
}

fn variable_length_integer(value: usize) -> Vec<u8> {
    let mut value = u64::try_from(value).expect("fixture size fits");
    let mut output = Vec::new();
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("seven bits fit");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

fn zlib_stored_member(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("fixture fits one stored block");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn ieee_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        let mut low = (crc ^ u32::from(*byte)) & 0xff;
        for _ in 0..8 {
            low = if low & 1 == 0 {
                low >> 1
            } else {
                (low >> 1) ^ 0xedb8_8320
            };
        }
        crc = (crc >> 8) ^ low;
    }
    !crc
}

fn import_and_assert(storage: BlobStorage) {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let repository = write_packed_repository(&source, storage);
    let node = serving_node(scratch.0.join("node"));
    let request = node.request_context();
    let admission = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([0xc3; 16]),
            format!("packed-import-{storage:?}").as_bytes(),
        ))
        .expect("verified packed closure publishes through source admission");
    assert_eq!(admission.commands.len(), 1);
    assert!(matches!(
        admission.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));

    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("authority-selected packed import materializes");
    let main = RefName::try_new(b"refs/heads/main").expect("fixed branch parses");
    assert_eq!(
        materialized.snapshot().refs.get(&main),
        Some(&repository.commit)
    );
    assert_eq!(
        materialized.selected_closure().closure().objects(),
        &BTreeSet::from([repository.commit, repository.tree, repository.blob])
    );
    assert_eq!(
        node.read_git_object(repository.blob)
            .expect("reconstructed blob reaches immutable fabric")
            .payload(),
        repository.blob_body
    );
    node.shutdown().expect("node drains");
}

#[test]
fn durable_import_publishes_a_pack_only_commit_tree_and_blob_closure() {
    import_and_assert(BlobStorage::Base);
}

#[test]
fn durable_import_follows_one_closure_across_loose_and_packed_storage() {
    import_and_assert(BlobStorage::Loose);
}

#[test]
fn durable_import_resolves_and_verifies_ofs_and_ref_delta_objects() {
    import_and_assert(BlobStorage::OfsDelta);
    import_and_assert(BlobStorage::RefDelta);
}

#[test]
fn corrupt_index_checksum_refuses_before_pack_publication() {
    assert_corruption_refuses(
        |repository| {
            let mut index = fs::read(&repository.index_path).expect("index reads");
            *index.last_mut().expect("index has checksum") ^= 0x01;
            fs::write(&repository.index_path, index).expect("corrupt index writes");
        },
        |error| matches!(error, PackError::IndexChecksumMismatch),
    );
}

#[test]
fn corrupt_pack_trailer_refuses_before_pack_publication() {
    assert_corruption_refuses(
        |repository| {
            let mut pack = fs::read(&repository.pack_path).expect("pack reads");
            *pack.last_mut().expect("pack has checksum") ^= 0x01;
            fs::write(&repository.pack_path, pack).expect("corrupt pack writes");
        },
        |error| matches!(error, PackError::TrailerChecksumMismatch),
    );
}

#[test]
fn corrupt_idx_crc_association_refuses_before_pack_publication() {
    assert_corruption_refuses(
        |repository| {
            let mut index = fs::read(&repository.index_path).expect("index reads");
            let object_count = 3_usize;
            let crc_start = 8 + (256 * 4) + (object_count * 20);
            index[crc_start] ^= 0x01;
            let checksum_start = index.len() - 20;
            let checksum = fgit_crypto::sha1_digest(&index[..checksum_start]);
            index[checksum_start..].copy_from_slice(&checksum);
            fs::write(&repository.index_path, index).expect("CRC-mutated index writes");
        },
        |error| matches!(error, PackError::IndexEntryCrcMismatch { .. }),
    );
}

#[test]
fn mismatched_idx_to_pack_checksum_refuses_before_pack_publication() {
    assert_corruption_refuses(
        |repository| {
            let mut index = fs::read(&repository.index_path).expect("index reads");
            let pack_checksum_start = index.len() - 40;
            index[pack_checksum_start] ^= 0x01;
            refresh_index_checksum(&mut index);
            fs::write(&repository.index_path, index).expect("mismatched index writes");
        },
        |error| matches!(error, PackError::TrailerChecksumMismatch),
    );
}

#[test]
fn malformed_pack_entry_refuses_before_pack_publication() {
    assert_corruption_refuses(
        |repository| {
            let mut pack = fs::read(&repository.pack_path).expect("pack reads");
            pack[12] = (pack[12] & 0x8f) | (5 << 4);
            refresh_pack_and_index_checksums(repository, &mut pack);
        },
        |error| matches!(error, PackError::InvalidEntryType(5)),
    );
}

#[test]
fn missing_reachable_object_refuses_without_advancing_authority() {
    assert_source_refusal(
        |repository| {
            fs::write(
                repository.root.join("refs/heads/main"),
                "1111111111111111111111111111111111111111\n",
            )
            .expect("missing-object ref writes");
        },
        |refusal| matches!(refusal, LooseGitImportRefusal::ObjectMissing(_)),
    );
}

#[test]
fn missing_pack_pair_refuses_without_advancing_authority() {
    assert_source_refusal(
        |repository| fs::remove_file(&repository.index_path).expect("index removes"),
        |refusal| matches!(refusal, LooseGitImportRefusal::PackPairMissing(_)),
    );
}

#[test]
fn alternates_refuse_without_advancing_authority() {
    assert_source_refusal(
        |repository| {
            let alternates = repository.root.join("objects/info/alternates");
            fs::create_dir_all(alternates.parent().expect("alternates parent exists"))
                .expect("alternates parent creates");
            fs::write(alternates, "/undeclared/object/source\n").expect("alternates writes");
        },
        |refusal| {
            matches!(
                refusal,
                LooseGitImportRefusal::ObjectAlternatesUnsupported(_)
            )
        },
    );
}

#[cfg(unix)]
#[test]
fn pack_symlink_refuses_without_advancing_authority() {
    assert_source_refusal(
        |repository| {
            let outside = repository.root.join("outside.pack");
            fs::rename(&repository.pack_path, &outside).expect("pack moves outside object source");
            std::os::unix::fs::symlink(outside, &repository.pack_path)
                .expect("pack symlink creates");
        },
        |refusal| matches!(refusal, LooseGitImportRefusal::SymbolicLink(_)),
    );
}

#[test]
fn pack_pair_count_is_bounded_before_any_invalid_index_is_parsed() {
    assert_source_refusal(
        |repository| {
            fs::remove_dir_all(repository.root.join("objects/pack"))
                .expect("fixture pack directory removes");
            let pack_directory = repository.root.join("objects/pack");
            fs::create_dir_all(&pack_directory).expect("pack directory recreates");
            for index in 0..129 {
                fs::write(
                    pack_directory.join(format!("pack-{index:03}.idx")),
                    b"invalid",
                )
                .expect("bounded-count index writes");
                fs::write(
                    pack_directory.join(format!("pack-{index:03}.pack")),
                    b"invalid",
                )
                .expect("bounded-count pack writes");
            }
        },
        |refusal| {
            matches!(
                refusal,
                LooseGitImportRefusal::PackFileLimitExceeded { limit: 128 }
            )
        },
    );
}

#[test]
fn selected_pack_input_bytes_are_bounded_before_reading_the_file() {
    assert_source_refusal(
        |repository| {
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&repository.pack_path)
                .expect("pack opens for sparse resize")
                .set_len((64 * 1024 * 1024) + 1)
                .expect("sparse oversized pack creates");
        },
        |refusal| {
            matches!(
                refusal,
                LooseGitImportRefusal::PackInputBytesExceeded {
                    limit: 67_108_864,
                    observed: 67_108_865,
                    ..
                }
            )
        },
    );
}

fn refresh_pack_and_index_checksums(repository: &PackedRepository, pack: &mut [u8]) {
    let pack_checksum_start = pack.len() - 20;
    let checksum = fgit_crypto::sha1_digest(&pack[..pack_checksum_start]);
    pack[pack_checksum_start..].copy_from_slice(&checksum);
    fs::write(&repository.pack_path, &*pack).expect("mutated pack writes");

    let mut index = fs::read(&repository.index_path).expect("index reads");
    let index_pack_checksum_start = index.len() - 40;
    index[index_pack_checksum_start..index_pack_checksum_start + 20].copy_from_slice(&checksum);
    refresh_index_checksum(&mut index);
    fs::write(&repository.index_path, index).expect("index with refreshed checksums writes");
}

fn refresh_index_checksum(index: &mut [u8]) {
    let checksum_start = index.len() - 20;
    let checksum = fgit_crypto::sha1_digest(&index[..checksum_start]);
    index[checksum_start..].copy_from_slice(&checksum);
}

fn assert_corruption_refuses(
    corrupt: impl FnOnce(&PackedRepository),
    expected: impl FnOnce(&PackError) -> bool,
) {
    assert_source_refusal(corrupt, |staging| {
        let LooseGitImportRefusal::PackedObject { source, .. } = staging else {
            return false;
        };
        expected(source)
    });
}

fn assert_source_refusal(
    mutate: impl FnOnce(&PackedRepository),
    expected: impl FnOnce(&LooseGitImportRefusal) -> bool,
) {
    let scratch = ScratchDirectory::new();
    let source = scratch.0.join("source.git");
    let repository = write_packed_repository(&source, BlobStorage::Base);
    mutate(&repository);
    let node = serving_node(scratch.0.join("node"));
    let request = node.request_context();
    let refusal = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([0xc3; 16]),
            b"corrupt-packed-import",
        ))
        .expect_err("corrupt idx/pack material cannot publish");
    let NodeSourceImportRefusal::Staging(staging) = refusal else {
        panic!("corrupt pack must retain the staging boundary, got {refusal:?}");
    };
    assert!(
        expected(staging.as_ref()),
        "unexpected staging refusal: {staging:?}"
    );

    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("genesis remains materializable after staging refusal");
    assert_eq!(materialized.basis().generation(), HeadGeneration::FIRST);
    assert!(materialized.snapshot().refs.is_empty());
    assert!(
        materialized
            .selected_closure()
            .closure()
            .objects()
            .is_empty()
    );
    node.shutdown().expect("node drains");
}
