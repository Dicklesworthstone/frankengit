#![forbid(unsafe_code)]

//! FG-052 standard pack-bitmap V1 materialization tests.
//!
//! The corpus is a real strict Git commit/tree/blob closure, planned and
//! promoted through `PackWriter::materialize`.  BITM positions therefore come
//! from the actual writer-owned pack order rather than an invented test map.
//! These tests decode the produced V1/EWAH bytes directly; they do not claim a
//! pinned-Git differential run.

use fgit_crypto::sha1_digest;
use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackBitmapLimits,
    PackBitmapRefusal, PackBitmapSource, PackBitmapV1, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};
use std::collections::BTreeMap;

const SHA1_BYTES: usize = 20;
const BITMAP_HEADER_BYTES: usize = 32;

#[derive(Clone)]
struct Object {
    id: ObjectId,
    object_type: ObjectType,
    body: Vec<u8>,
    references: Vec<ObjectId>,
    recency: u64,
}

struct Source {
    objects: BTreeMap<ObjectId, Object>,
}

impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let object = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            object.id,
            object.object_type,
            object.body.clone(),
            object.references.clone(),
            object.recency,
            0,
        ))
    }
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x54; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8054).expect("fixture algorithm code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x54; 32]).expect("fixture digest is long enough"),
    )
}

fn bitmap_source(commit: ObjectId) -> PackBitmapSource {
    PackBitmapSource::new(repository_id(), rcr_id(), commit)
        .expect("fixture source commit is a nonzero native identity")
}

fn native(object_type: ObjectType, body: &[u8]) -> ObjectId {
    ObjectId::from(native_object_oid::<Sha1>(object_type, body))
}

fn commit(tree: ObjectId, parents: &[ObjectId], time: u64, recency: u64) -> Object {
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(
        format!(
            "author Bitmap <bitmap@invalid> {time} +0000\ncommitter Bitmap <bitmap@invalid> {time} +0000\n\nbitmap fixture\n"
        )
        .as_bytes(),
    );
    Object {
        id: native(ObjectType::Commit, &body),
        object_type: ObjectType::Commit,
        body,
        references: parents.iter().copied().chain([tree]).collect(),
        recency,
    }
}

fn source_with_two_commits() -> (Source, ObjectId, ObjectId) {
    let blob_body = b"bitmap payload\n".to_vec();
    let blob = Object {
        id: native(ObjectType::Blob, &blob_body),
        object_type: ObjectType::Blob,
        body: blob_body,
        references: Vec::new(),
        recency: 1,
    };
    let mut tree_body = b"100644 leaf\0".to_vec();
    tree_body.extend_from_slice(blob.id.as_bytes());
    let tree = Object {
        id: native(ObjectType::Tree, &tree_body),
        object_type: ObjectType::Tree,
        body: tree_body,
        references: vec![blob.id],
        recency: 2,
    };
    let root = commit(tree.id, &[], 10, 10);
    let tip = commit(tree.id, &[root.id], 20, 20);
    let mut objects = BTreeMap::new();
    for object in [blob, tree, root.clone(), tip.clone()] {
        objects.insert(object.id, object);
    }
    (Source { objects }, root.id, tip.id)
}

fn materialized_pack(source: &Source, tip: ObjectId) -> fgit_pack::MaterializedPack {
    let mut live = || true;
    let plan = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    )
    .plan(source, &[tip], &mut live)
    .expect("fixture is one closed canonical object graph");
    let mut write_live = || true;
    PackWriter::new(PackLimits::default())
        .materialize(&plan, &mut write_live)
        .expect("the plan promotes a real pack before bitmap materialization")
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("fixture includes a complete u16"),
    )
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixture includes a complete u32"),
    )
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixture includes a complete u64"),
    )
}

fn ewah_len(object_count: usize) -> usize {
    16 + 8 * object_count.div_ceil(64)
}

fn ewah_literal(input: &[u8], offset: usize, object_count: usize) -> u64 {
    assert_eq!(
        read_u32(input, offset),
        u32::try_from(object_count).expect("fixture object count fits u32")
    );
    assert_eq!(read_u32(input, offset + 4), 2, "one RLW plus one literal");
    assert_eq!(read_u64(input, offset + 8), 1_u64 << 33);
    assert_eq!(read_u32(input, offset + 20), 0, "RLW points at itself");
    read_u64(input, offset + 16)
}

#[test]
fn bitmap_v1_binds_real_pack_order_and_encodes_full_commit_closure() {
    let (source, root, tip) = source_with_two_commits();
    let materialized = materialized_pack(&source, tip);
    let object_count = materialized.plan().entries().len();
    let mut live = || true;
    let bitmap = PackBitmapV1::write(
        bitmap_source(tip),
        &materialized,
        PackBitmapLimits::default(),
        &mut live,
    )
    .expect("writer-bound closed pack materializes a full-DAG bitmap");

    assert_eq!(&bitmap.bytes()[..4], b"BITM");
    assert_eq!(read_u16(bitmap.bytes(), 4), 1);
    assert_eq!(read_u16(bitmap.bytes(), 6), 1, "FULL_DAG is mandatory");
    assert_eq!(read_u32(bitmap.bytes(), 8), object_count as u32);
    assert_eq!(
        &bitmap.bytes()[12..32],
        materialized.receipt().checksum.as_bytes(),
        "header names the exact writer-produced pack trailer"
    );
    assert_eq!(
        bitmap.receipt().checksum(),
        &sha1_digest(&bitmap.bytes()[..bitmap.bytes().len() - SHA1_BYTES])
    );
    assert_eq!(bitmap.receipt().object_count(), object_count);
    assert_eq!(bitmap.receipt().commit_count(), 2);

    let ewah = ewah_len(object_count);
    for (type_index, object_type) in [
        ObjectType::Commit,
        ObjectType::Tree,
        ObjectType::Blob,
        ObjectType::Tag,
    ]
    .iter()
    .enumerate()
    {
        let expected = materialized
            .plan()
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.object().object_type() == *object_type)
            .fold(0_u64, |bits, (position, _)| bits | (1_u64 << position));
        assert_eq!(
            ewah_literal(
                bitmap.bytes(),
                BITMAP_HEADER_BYTES + type_index * ewah,
                object_count
            ),
            expected,
            "type bitmap preserves writer pack-order positions"
        );
    }

    let entries = BITMAP_HEADER_BYTES + 4 * ewah;
    let commit_positions = materialized
        .plan()
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(position, entry)| {
            (entry.object().object_type() == ObjectType::Commit)
                .then_some((position, entry.object().id()))
        })
        .collect::<Vec<_>>();
    for (row, (position, _)) in commit_positions.iter().enumerate() {
        let offset = entries + row * (6 + ewah);
        assert_eq!(read_u32(bitmap.bytes(), offset), *position as u32);
        assert_eq!(bitmap.bytes()[offset + 4], 0, "no XOR dependency");
        assert_eq!(bitmap.bytes()[offset + 5], 1, "entry is reusable");
        let bits = ewah_literal(bitmap.bytes(), offset + 6, object_count);
        assert_ne!(bits & (1_u64 << position), 0, "a commit reaches itself");
        if commit_positions[row].1 == tip {
            assert_eq!(
                bits,
                (1_u64 << object_count) - 1,
                "tip closure reaches both commits, their tree, and blob"
            );
        }
    }
    assert!(
        commit_positions.iter().any(|(_, id)| *id == root),
        "fixture's parent commit remains non-vacuous"
    );
}

#[test]
fn bitmap_output_order_is_deterministic_and_output_bound_refuses_before_emit() {
    let (source, _, tip) = source_with_two_commits();
    let first_pack = materialized_pack(&source, tip);
    let second_pack = materialized_pack(&source, tip);
    let mut first_live = || true;
    let first = PackBitmapV1::write(
        bitmap_source(tip),
        &first_pack,
        PackBitmapLimits::default(),
        &mut first_live,
    )
    .expect("first writer-produced pack materializes");
    let mut second_live = || true;
    let second = PackBitmapV1::write(
        bitmap_source(tip),
        &second_pack,
        PackBitmapLimits::default(),
        &mut second_live,
    )
    .expect("same canonical plan/order materializes identical bytes");
    assert_eq!(first.bytes(), second.bytes());
    assert_eq!(first.receipt(), second.receipt());

    let mut limits = PackBitmapLimits::default();
    limits.max_output_bytes = first.bytes().len() - 1;
    let mut bounded_live = || true;
    assert!(matches!(
        PackBitmapV1::write(bitmap_source(tip), &first_pack, limits, &mut bounded_live),
        Err(PackBitmapRefusal::OutputBytesExceeded { .. })
    ));
}

#[test]
fn bitmap_refuses_source_coordinate_that_is_not_a_commit() {
    let (source, _, tip) = source_with_two_commits();
    let materialized = materialized_pack(&source, tip);
    let blob = materialized
        .plan()
        .entries()
        .iter()
        .find(|entry| entry.object().object_type() == ObjectType::Blob)
        .expect("fixture includes a blob")
        .object()
        .id();
    let mut live = || true;
    assert!(matches!(
        PackBitmapV1::write(
            bitmap_source(blob),
            &materialized,
            PackBitmapLimits::default(),
            &mut live,
        ),
        Err(PackBitmapRefusal::SourceCommitIsNotCommit { .. })
    ));
}
