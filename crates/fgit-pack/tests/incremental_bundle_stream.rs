#![forbid(unsafe_code)]
//! Incremental streaming preserves exact native graph checks across a
//! caller-validated prerequisite boundary and never loads omitted bodies.
//! Streaming Git transfer slice of frankengit-root-doctrine-x2mv.4.21.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Write};
use std::rc::Rc;

use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::stream::{
    STREAM_FULL_BUNDLE_PROFILE, STREAM_INCREMENTAL_BUNDLE_PROFILE, StreamFullBundleError,
    StreamFullBundleLimits, StreamFullBundleReceipt, write_full_bundle_stream,
    write_incremental_bundle_stream,
};
use fgit_pack::full_bundle::{FullBundleError, FullBundleInput, MAX_BUNDLE_PREREQUISITES};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, EntryKind, ObjectFormat, ObjectId,
    PackError, PackWriteError, read_streamed_pack,
};
use fgit_types::RefName;

#[derive(Default)]
struct Source {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
    loaded: RefCell<Vec<ObjectId>>,
}

impl Source {
    fn add(&mut self, format: ObjectFormat, kind: ObjectType, body: Vec<u8>) -> ObjectId {
        let id = fgit_crypto::git_object_id(format, kind, &body);
        // Empty source metadata must not conceal native edges from the codec.
        self.objects
            .insert(id, CanonicalPackObject::new(id, kind, body, vec![], 0, 0));
        id
    }

    fn ids(&self) -> Vec<ObjectId> {
        self.objects.keys().copied().collect()
    }
}

impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.loaded.borrow_mut().push(*id);
        self.objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

fn reference(id: ObjectId, name: &[u8]) -> BundleReference {
    BundleReference::new(id, RefName::try_new(name).unwrap())
}

fn tree_entry(mode: &[u8], name: &[u8], id: ObjectId) -> Vec<u8> {
    let mut body = mode.to_vec();
    body.push(b' ');
    body.extend_from_slice(name);
    body.push(0);
    body.extend_from_slice(id.as_bytes());
    body
}

fn commit_body(tree: ObjectId, parent: Option<ObjectId>, message: &str) -> Vec<u8> {
    let parent = parent.map_or_else(String::new, |id| format!("parent {id}\n"));
    format!(
        "tree {tree}\n{parent}author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\n{message}\n"
    )
    .into_bytes()
}

struct Fixture {
    format: ObjectFormat,
    source: Source,
    external: BTreeMap<ObjectId, ObjectType>,
    base: ObjectId,
    base_tree: ObjectId,
    base_blob: ObjectId,
    refs: Vec<BundleReference>,
}

fn fixture(format: ObjectFormat) -> Fixture {
    // These real native bytes belong to the caller's independently verified
    // old history. None of them is available from the output object's source.
    let base_blob = fgit_crypto::git_object_id(format, ObjectType::Blob, b"base\n");
    let base_tree = fgit_crypto::git_object_id(
        format,
        ObjectType::Tree,
        &tree_entry(b"100644", b"base", base_blob),
    );
    let base = fgit_crypto::git_object_id(
        format,
        ObjectType::Commit,
        &commit_body(base_tree, None, "base"),
    );
    let external = BTreeMap::from([
        (base, ObjectType::Commit),
        (base_tree, ObjectType::Tree),
        (base_blob, ObjectType::Blob),
    ]);
    let mut source = Source::default();
    let blob = source.add(format, ObjectType::Blob, b"changed\0\xff\n".to_vec());
    let mut tree = tree_entry(b"100644", b"base", base_blob);
    tree.extend_from_slice(&tree_entry(b"100644", b"changed", blob));
    let tree = source.add(format, ObjectType::Tree, tree);
    let tip = source.add(
        format,
        ObjectType::Commit,
        commit_body(tree, Some(base), "change"),
    );
    let tag = source.add(
        format,
        ObjectType::Tag,
        format!(
            "object {tip}\ntype commit\ntag v2\ntagger A <a@example.invalid> 2 +0000\n\nv2\n"
        )
        .into_bytes(),
    );
    Fixture {
        format,
        source,
        external,
        base,
        base_tree,
        base_blob,
        refs: vec![
            reference(tag, b"refs/tags/v2"),
            reference(tip, b"refs/heads/\xff"),
        ],
    }
}

fn export(
    fixture: &Fixture,
    limits: &StreamFullBundleLimits,
) -> Result<(Vec<u8>, StreamFullBundleReceipt), StreamFullBundleError> {
    let mut bytes = Vec::new();
    let receipt = write_incremental_bundle_stream(
        fixture.format,
        &fixture.refs,
        &[fixture.base],
        &fixture.source.ids(),
        &fixture.external,
        &fixture.source,
        limits,
        &mut || true,
        &mut bytes,
    )?;
    Ok((bytes, receipt))
}

fn refuses_before_io(
    fixture: &Fixture,
    references: &[BundleReference],
    prerequisites: &[ObjectId],
    selected: &[ObjectId],
    external: &BTreeMap<ObjectId, ObjectType>,
    limits: &StreamFullBundleLimits,
) {
    fixture.source.loaded.borrow_mut().clear();
    let mut bytes = Vec::new();
    assert!(
        write_incremental_bundle_stream(
            fixture.format,
            references,
            prerequisites,
            selected,
            external,
            &fixture.source,
            limits,
            &mut || true,
            &mut bytes,
        )
        .is_err()
    );
    assert!(bytes.is_empty(), "invalid frontier/header must not write");
    assert!(
        fixture.source.loaded.borrow().is_empty(),
        "invalid frontier/header must not read object bodies"
    );
}

#[test]
fn both_domains_omit_old_history_and_round_trip_exact_native_bytes_in_oid_order() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let ids = fixture.source.ids();
        let (bytes, receipt) = export(&fixture, &limits).unwrap();
        assert_eq!(receipt.format(), format);
        assert_eq!(receipt.profile_id(), STREAM_INCREMENTAL_BUNDLE_PROFILE);
        assert_eq!(receipt.prerequisite_count(), 1);
        assert_eq!(receipt.external_object_count(), fixture.external.len());
        assert_eq!(receipt.object_count() as usize, ids.len());
        assert_eq!(receipt.bundle_bytes(), bytes.len());
        assert_eq!(receipt.bundle_sha256(), fgit_crypto::sha256_digest(&bytes));
        assert_eq!(receipt.header_bytes() + receipt.pack_bytes(), bytes.len());
        assert_eq!(
            receipt.total_object_bytes(),
            fixture.source.objects.values().map(|o| o.body().len()).sum::<usize>()
        );
        assert_eq!(*fixture.source.loaded.borrow(), ids);
        assert!(
            ids.iter()
                .all(|id| !fixture.external.contains_key(id))
        );
        let input =
            FullBundleInput::parse_incremental(&bytes, limits.envelope, &mut || true).unwrap();
        assert_eq!(input.prerequisites(), &[fixture.base]);
        assert_eq!(input.head(), None);
        input.verify_pack_framing(&limits.pack, &mut || true).unwrap();
        assert!(FullBundleInput::parse(&bytes, limits.envelope, &mut || true).is_err());
        let mut recovered = Vec::new();
        let decoded = read_streamed_pack(
            &mut Cursor::new(input.pack_bytes()),
            format,
            &limits.pack,
            &mut || true,
            |entry| -> Result<(), io::Error> {
                assert!(!matches!(
                    entry.entry.header.kind,
                    EntryKind::OfsDelta | EntryKind::RefDelta
                ));
                let kind = fgit_pack::object_type_from_base_entry(entry.entry.header.kind).unwrap();
                let id = fgit_crypto::git_object_id(format, kind, &entry.entry.inflated);
                assert_eq!(entry.entry.inflated, fixture.source.objects[&id].body());
                recovered.push(id);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered, ids);
        assert_eq!(decoded.trailer(), receipt.pack_checksum());
        assert_eq!(decoded.pack_bytes() as usize, receipt.pack_bytes());

        let mut selected = ids;
        selected.reverse();
        let mut refs = fixture.refs.clone();
        refs.reverse();
        let mut second = Vec::new();
        let second_receipt = write_incremental_bundle_stream(
            format,
            &refs,
            &[fixture.base],
            &selected,
            &fixture.external,
            &fixture.source,
            &limits,
            &mut || true,
            &mut second,
        )
        .unwrap();
        assert_eq!(second, bytes);
        assert_eq!(second_receipt, receipt);

        // A complete native stream ends exactly at its checksum. Neither
        // truncation, trailing bytes nor a modified trailer can be accepted.
        for damaged in [
            input.pack_bytes()[..input.pack_bytes().len() - 1].to_vec(),
            {
                let mut extra = input.pack_bytes().to_vec();
                extra.push(0);
                extra
            },
            {
                let mut corrupt = input.pack_bytes().to_vec();
                *corrupt.last_mut().unwrap() ^= 1;
                corrupt
            },
        ] {
            assert!(
                read_streamed_pack(
                    &mut Cursor::new(damaged),
                    format,
                    &limits.pack,
                    &mut || true,
                    |_| -> Result<(), io::Error> { Ok(()) },
                )
                .is_err()
            );
        }
    }
}

#[test]
fn already_present_advertisements_emit_a_valid_empty_pack_without_source_reads() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let source = Source::default();
        let mut limits = StreamFullBundleLimits::default();
        limits.pack.max_entries = 0;
        limits.pack.max_index_entries = 0;
        limits.pack.max_object_bytes = 0;
        limits.pack.max_total_expanded_bytes = 0;
        limits.pack.max_input_bytes = 12 + format.digest_len();
        limits.max_graph_edges = 0;
        let mut bytes = Vec::new();
        let receipt = write_incremental_bundle_stream(
            format,
            &[reference(fixture.base, b"refs/heads/main")],
            &[fixture.base],
            &[],
            &fixture.external,
            &source,
            &limits,
            &mut || true,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(receipt.object_count(), 0);
        assert_eq!(receipt.total_object_bytes(), 0);
        assert_eq!(receipt.compression_work(), 0);
        assert_eq!(receipt.pack_bytes(), 12 + format.digest_len());
        assert_eq!(receipt.prerequisite_count(), 1);
        assert!(source.loaded.borrow().is_empty());
        let input =
            FullBundleInput::parse_incremental(&bytes, limits.envelope, &mut || true).unwrap();
        read_streamed_pack(
            &mut Cursor::new(input.pack_bytes()),
            format,
            &limits.pack,
            &mut || true,
            |_| -> Result<(), io::Error> { panic!("empty pack must have no entries") },
        )
        .unwrap();
    }
}

#[test]
fn malformed_frontiers_and_external_branch_kinds_refuse_before_io() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let ids = fixture.source.ids();
        let base = [fixture.base];
        refuses_before_io(
            &fixture, &fixture.refs, &[], &ids, &fixture.external, &limits,
        );
        refuses_before_io(
            &fixture,
            &fixture.refs,
            &[fixture.base, fixture.base],
            &ids,
            &fixture.external,
            &limits,
        );
        let wrong_format = match format {
            ObjectFormat::Sha1 => ObjectFormat::Sha256,
            ObjectFormat::Sha256 => ObjectFormat::Sha1,
        };
        let wrong = fgit_crypto::git_object_id(wrong_format, ObjectType::Blob, b"wrong domain");
        let zero = ObjectId::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        for id in [wrong, zero] {
            let mut external = fixture.external.clone();
            external.insert(id, ObjectType::Commit);
            refuses_before_io(&fixture, &fixture.refs, &base, &ids, &external, &limits);
            refuses_before_io(
                &fixture, &fixture.refs, &[id], &ids, &fixture.external, &limits,
            );
        }
        let mut overlap = fixture.external.clone();
        overlap.insert(ids[0], fixture.source.objects[&ids[0]].object_type());
        refuses_before_io(&fixture, &fixture.refs, &base, &ids, &overlap, &limits);
        let mut missing = fixture.external.clone();
        missing.remove(&fixture.base);
        refuses_before_io(&fixture, &fixture.refs, &base, &ids, &missing, &limits);
        let mut wrong_kind = fixture.external.clone();
        wrong_kind.insert(fixture.base, ObjectType::Tree);
        refuses_before_io(&fixture, &fixture.refs, &base, &ids, &wrong_kind, &limits);
        refuses_before_io(
            &fixture,
            &[reference(fixture.base_blob, b"refs/heads/main")],
            &base,
            &[],
            &fixture.external,
            &limits,
        );
        // The same native blob is a legitimate direct lightweight tag.
        let mut bytes = Vec::new();
        write_incremental_bundle_stream(
            format,
            &[reference(fixture.base_blob, b"refs/tags/blob")],
            &base,
            &[],
            &fixture.external,
            &fixture.source,
            &limits,
            &mut || true,
            &mut bytes,
        )
        .unwrap();
        let absent = fgit_crypto::git_object_id(format, ObjectType::Blob, b"not in either closure");
        refuses_before_io(
            &fixture,
            &[reference(absent, b"refs/tags/missing")],
            &base,
            &ids,
            &fixture.external,
            &limits,
        );
        let mut duplicate_refs = fixture.refs.clone();
        duplicate_refs.push(fixture.refs[0].clone());
        refuses_before_io(
            &fixture, &duplicate_refs, &base, &ids, &fixture.external, &limits,
        );
        let mut short_header = limits.clone();
        short_header.envelope.max_header_bytes = 1;
        refuses_before_io(
            &fixture, &fixture.refs, &base, &ids, &fixture.external, &short_header,
        );
    }
}

#[test]
fn prerequisite_count_boundary_and_header_order_are_exact() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let mut external = BTreeMap::from([
            (fixture.base_tree, ObjectType::Tree),
            (fixture.base_blob, ObjectType::Blob),
        ]);
        let mut prerequisites = Vec::new();
        for index in 0..=MAX_BUNDLE_PREREQUISITES {
            let id = fgit_crypto::git_object_id(
                format,
                ObjectType::Commit,
                &commit_body(fixture.base_tree, None, &format!("frontier {index}")),
            );
            external.insert(id, ObjectType::Commit);
            prerequisites.push(id);
        }
        let refs = [reference(prerequisites[0], b"refs/heads/main")];
        refuses_before_io(
            &fixture, &refs, &prerequisites, &[], &external, &limits,
        );
        let excess = prerequisites.pop().unwrap();
        external.remove(&excess);
        let mut bytes = Vec::new();
        let receipt = write_incremental_bundle_stream(
            format,
            &refs,
            &prerequisites,
            &[],
            &external,
            &fixture.source,
            &limits,
            &mut || true,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(receipt.prerequisite_count(), MAX_BUNDLE_PREREQUISITES);
        prerequisites.reverse();
        let mut reordered = Vec::new();
        write_incremental_bundle_stream(
            format,
            &refs,
            &prerequisites,
            &[],
            &external,
            &fixture.source,
            &limits,
            &mut || true,
            &mut reordered,
        )
        .unwrap();
        assert_eq!(bytes, reordered);
        prerequisites.sort_unstable();
        let input =
            FullBundleInput::parse_incremental(&bytes, limits.envelope, &mut || true).unwrap();
        assert_eq!(input.prerequisites(), prerequisites.as_slice());
    }
}

#[test]
fn omitted_edge_kinds_and_missing_dependencies_are_checked_from_native_bodies() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let limits = StreamFullBundleLimits::default();
        for (kind, body, external_target, wrong_kind) in [
            (
                ObjectType::Commit,
                commit_body(fixture.base_tree, Some(fixture.base), "same tree"),
                fixture.base_tree,
                ObjectType::Blob,
            ),
            (
                ObjectType::Tree,
                tree_entry(b"100644", b"borrowed-base", fixture.base_blob),
                fixture.base_blob,
                ObjectType::Tree,
            ),
            (
                ObjectType::Tag,
                format!(
                    "object {}\ntype tree\ntag old-tree\n\nold tree\n",
                    fixture.base_tree
                )
                .into_bytes(),
                fixture.base_tree,
                ObjectType::Blob,
            ),
        ] {
            let mut source = Source::default();
            let root = source.add(format, kind, body);
            let refs = [reference(root, b"refs/tags/root")];
            write_incremental_bundle_stream(
                format,
                &refs,
                &[fixture.base],
                &[root],
                &fixture.external,
                &source,
                &limits,
                &mut || true,
                &mut Vec::new(),
            )
            .unwrap();
            let mut wrong = fixture.external.clone();
            wrong.insert(external_target, wrong_kind);
            assert!(matches!(
                write_incremental_bundle_stream(
                    format, &refs, &[fixture.base], &[root], &wrong, &source, &limits,
                    &mut || true, &mut Vec::new(),
                ),
                Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
                    "graph edge target kind"
                )))
            ));
            let mut missing = fixture.external.clone();
            missing.remove(&external_target);
            assert!(matches!(
                write_incremental_bundle_stream(
                    format, &refs, &[fixture.base], &[root], &missing, &source, &limits,
                    &mut || true, &mut Vec::new(),
                ),
                Err(StreamFullBundleError::Bundle(FullBundleError::MissingObject(id)))
                    if id == external_target
            ));
            assert!(source.loaded.borrow().iter().all(|id| *id == root));
        }

        let mut source = Source::default();
        let bad_parent = source.add(
            format,
            ObjectType::Commit,
            commit_body(fixture.base_tree, Some(fixture.base_blob), "wrong parent"),
        );
        assert!(matches!(
            write_incremental_bundle_stream(
                format,
                &[reference(bad_parent, b"refs/heads/main")],
                &[fixture.base],
                &[bad_parent],
                &fixture.external,
                &source,
                &limits,
                &mut || true,
                &mut Vec::new(),
            ),
            Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
                "graph edge target kind"
            )))
        ));
    }
}

#[test]
fn unreachable_selected_objects_and_corrupt_native_sources_cannot_complete() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut fixture = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let extra = fixture.source.add(
            format,
            ObjectType::Blob,
            b"unrelated retained secret".to_vec(),
        );
        assert!(matches!(
            export(&fixture, &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::UnreachableObject(id)))
                if id == extra
        ));
        fixture.source.objects.remove(&extra);
        export(&fixture, &limits).unwrap();
        let selected = fixture.source.ids()[0];
        let original = fixture.source.objects[&selected].clone();
        fixture.source.objects.insert(
            selected,
            CanonicalPackObject::new(
                selected, original.object_type(), b"changed bytes".to_vec(), vec![], 0, 0,
            ),
        );
        assert!(matches!(
            export(&fixture, &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::NativeObjectIdMismatch
            )))
        ));
        let wrong_body = b"another complete native object".to_vec();
        let wrong_id = fgit_crypto::git_object_id(format, ObjectType::Blob, &wrong_body);
        fixture.source.objects.insert(
            selected,
            CanonicalPackObject::new(wrong_id, ObjectType::Blob, wrong_body, vec![], 0, 0),
        );
        assert!(matches!(
            export(&fixture, &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::Write(
                PackWriteError::SourceIdentityMismatch { requested, returned }
            ))) if requested == selected && returned == wrong_id
        ));
        fixture.source.objects.insert(selected, original);
        export(&fixture, &limits).unwrap();
    }
}

#[test]
fn exact_independent_budgets_include_edges_into_omitted_history() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let baseline = StreamFullBundleLimits::default();
        let (_, receipt) = export(&fixture, &baseline).unwrap();
        let mut exact = baseline;
        exact.pack.max_entries = receipt.object_count();
        exact.pack.max_index_entries = fixture.source.objects.len();
        exact.pack.max_object_bytes = fixture.source.objects.values()
            .map(|object| object.body().len()).max().unwrap();
        exact.pack.max_total_expanded_bytes = receipt.total_object_bytes();
        exact.pack.max_input_bytes = receipt.pack_bytes();
        exact.envelope.max_bundle_bytes = receipt.bundle_bytes();
        exact.envelope.max_header_bytes = receipt.header_bytes();
        exact.envelope.max_references = fixture.refs.len();
        // Selected tree: two blobs; commit: tree + external parent; tag: commit.
        exact.max_graph_edges = 5;
        exact.max_compression_work = receipt.compression_work();
        assert_eq!(export(&fixture, &exact).unwrap().1, receipt);
        let reductions: [fn(&mut StreamFullBundleLimits); 10] = [
            |l| l.pack.max_entries -= 1,
            |l| l.pack.max_index_entries -= 1,
            |l| l.pack.max_object_bytes -= 1,
            |l| l.pack.max_total_expanded_bytes -= 1,
            |l| l.pack.max_input_bytes -= 1,
            |l| l.envelope.max_bundle_bytes -= 1,
            |l| l.envelope.max_header_bytes -= 1,
            |l| l.envelope.max_references -= 1,
            |l| l.max_graph_edges -= 1,
            |l| l.max_compression_work -= 1,
        ];
        for reduce in reductions {
            let mut refused = exact.clone();
            reduce(&mut refused);
            assert!(export(&fixture, &refused).is_err(), "{refused:?}");
        }
    }
}

#[test]
fn cancellation_is_sticky_across_frontier_parsing_compression_and_final_output() {
    let fixture = fixture(ObjectFormat::Sha256);
    let limits = StreamFullBundleLimits::default();
    let ids = fixture.source.ids();
    let mut checkpoints = 0_usize;
    write_incremental_bundle_stream(
        fixture.format,
        &fixture.refs,
        &[fixture.base],
        &ids,
        &fixture.external,
        &fixture.source,
        &limits,
        &mut || {
            checkpoints += 1;
            true
        },
        &mut Vec::new(),
    )
    .unwrap();
    for cancel_at in [
        1, 5, 15, checkpoints / 3, checkpoints / 2, checkpoints - 1, checkpoints,
    ] {
        let mut count = 0;
        let result = write_incremental_bundle_stream(
            fixture.format,
            &fixture.refs,
            &[fixture.base],
            &ids,
            &fixture.external,
            &fixture.source,
            &limits,
            &mut || {
                count += 1;
                count != cancel_at
            },
            &mut Vec::new(),
        );
        assert!(result.is_err(), "cancellation checkpoint {cancel_at}");
        assert_eq!(count, cancel_at, "cancellation must never revive");
    }
    export(&fixture, &limits).unwrap();
}

struct ShortWriter {
    bytes: Vec<u8>,
    interrupt: bool,
    fail_after: Option<usize>,
    zero: bool,
}

impl Write for ShortWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        assert!(input.len() <= 16 * 1024);
        if self.interrupt {
            self.interrupt = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.zero {
            return Ok(0);
        }
        if self.fail_after.is_some_and(|limit| self.bytes.len() >= limit) {
            return Err(io::Error::other("injected output failure"));
        }
        let length = input.len().min(3);
        self.bytes.extend_from_slice(&input[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("only the staged artifact owner may flush");
    }
}

#[test]
fn short_interrupted_and_failed_writes_preserve_exact_byte_and_error_semantics() {
    let fixture = fixture(ObjectFormat::Sha1);
    let limits = StreamFullBundleLimits::default();
    let (expected, expected_receipt) = export(&fixture, &limits).unwrap();
    for (fail_after, zero) in [
        (None, false),
        (Some(expected_receipt.header_bytes() + 16), false),
        (None, true),
    ] {
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            interrupt: true,
            fail_after,
            zero,
        };
        let result = write_incremental_bundle_stream(
            fixture.format,
            &fixture.refs,
            &[fixture.base],
            &fixture.source.ids(),
            &fixture.external,
            &fixture.source,
            &limits,
            &mut || true,
            &mut writer,
        );
        if fail_after.is_some() || zero {
            assert!(matches!(result, Err(StreamFullBundleError::Io(_))));
            assert!(writer.bytes.len() < expected.len());
        } else {
            assert_eq!(result.unwrap(), expected_receipt);
            assert_eq!(writer.bytes, expected);
        }
    }
}

struct GeneratedSource {
    format: ObjectFormat,
    ids: BTreeMap<ObjectId, usize>,
    progress: Rc<Cell<usize>>,
    previous_output: Cell<usize>,
    loaded: RefCell<Vec<ObjectId>>,
}

fn generated_body(index: usize) -> Vec<u8> {
    let mut body = vec![b'x'; 32 * 1024];
    body[..8].copy_from_slice(&(index as u64).to_be_bytes());
    body
}

impl CanonicalObjectSource for GeneratedSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert_eq!(id.algorithm(), self.format);
        assert!(self.progress.get() > self.previous_output.get());
        self.previous_output.set(self.progress.get());
        assert!(!self.loaded.borrow().contains(id), "source loaded twice");
        self.loaded.borrow_mut().push(*id);
        let index = self.ids.get(id).ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id, ObjectType::Blob, generated_body(*index), vec![], 0, 0,
        ))
    }
}

struct ProgressWriter(Rc<Cell<usize>>);

impl Write for ProgressWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.set(self.0.get() + bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("codec must not publish or flush");
    }
}

#[test]
fn generated_bodies_are_emitted_before_the_next_load_and_external_objects_are_not_read() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let ids: BTreeMap<_, _> = (0..8)
            .map(|index| {
                (
                    fgit_crypto::git_object_id(format, ObjectType::Blob, &generated_body(index)),
                    index,
                )
            })
            .collect();
        let selected: Vec<_> = ids.keys().copied().collect();
        let refs: Vec<_> = selected.iter().enumerate()
            .map(|(index, id)| reference(*id, format!("refs/tags/blob-{index}").as_bytes()))
            .collect();
        let progress = Rc::new(Cell::new(0));
        let source = GeneratedSource {
            format,
            ids,
            progress: Rc::clone(&progress),
            previous_output: Cell::new(0),
            loaded: RefCell::new(Vec::new()),
        };
        let receipt = write_incremental_bundle_stream(
            format, &refs, &[fixture.base], &selected, &fixture.external, &source,
            &StreamFullBundleLimits::default(), &mut || true,
            &mut ProgressWriter(Rc::clone(&progress)),
        )
        .unwrap();
        assert_eq!(*source.loaded.borrow(), selected);
        assert_eq!(receipt.bundle_bytes(), progress.get());
        assert_eq!(receipt.total_object_bytes(), 8 * 32 * 1024);
    }
}

#[test]
fn full_profile_keeps_zero_prerequisite_counts_and_the_same_pack_encoding() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let fixture = fixture(format);
        let mut source = Source::default();
        let blob = source.add(format, ObjectType::Blob, b"complete object\n".to_vec());
        let refs = [reference(blob, b"refs/tags/blob")];
        let limits = StreamFullBundleLimits::default();
        let mut full_bytes = Vec::new();
        let full = write_full_bundle_stream(
            format, &refs, None, &[blob], &source, &limits, &mut || true, &mut full_bytes,
        )
        .unwrap();
        assert_eq!(full.profile_id(), STREAM_FULL_BUNDLE_PROFILE);
        assert_eq!(full.prerequisite_count(), 0);
        assert_eq!(full.external_object_count(), 0);
        let mut incremental_bytes = Vec::new();
        let incremental = write_incremental_bundle_stream(
            format, &refs, &[fixture.base], &[blob], &fixture.external, &source,
            &limits, &mut || true, &mut incremental_bytes,
        )
        .unwrap();
        let full_input =
            FullBundleInput::parse(&full_bytes, limits.envelope, &mut || true).unwrap();
        let incremental_input =
            FullBundleInput::parse_incremental(&incremental_bytes, limits.envelope, &mut || true)
                .unwrap();
        assert_eq!(full_input.pack_bytes(), incremental_input.pack_bytes());
        assert_eq!(full.pack_checksum(), incremental.pack_checksum());
        assert_eq!(full.compression_work(), incremental.compression_work());
        assert_ne!(full.profile_id(), incremental.profile_id());
    }
}
