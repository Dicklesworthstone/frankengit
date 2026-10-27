#![forbid(unsafe_code)]
//! Streaming output must have the same native graph obligations as a complete
//! bundle while retaining no all-object body plan or complete pack buffer.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Write};
use std::rc::Rc;

use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::stream::{
    STREAM_FULL_BUNDLE_PROFILE, StreamFullBundleError, StreamFullBundleLimits,
    StreamFullBundleReceipt, write_full_bundle_stream,
};
use fgit_pack::full_bundle::{FullBundleError, FullBundleInput};
use fgit_pack::{
    BundleReference, CanonicalObjectSource, CanonicalPackObject, EntryKind, ObjectFormat, ObjectId,
    PackError, PackWriteError, read_streamed_pack,
};
use fgit_types::RefName;

struct Source {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
    loaded: RefCell<Vec<ObjectId>>,
}
impl Source {
    const fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            loaded: RefCell::new(Vec::new()),
        }
    }
    fn add(&mut self, format: ObjectFormat, kind: ObjectType, body: Vec<u8>) -> ObjectId {
        let id = fgit_crypto::git_object_id(format, kind, &body);
        // Deliberately empty metadata: native graph validation must examine
        // body bytes, rather than believe the source omitted all local edges.
        self.objects
            .insert(id, CanonicalPackObject::new(id, kind, body, vec![], 0, 0));
        id
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
fn corpus(format: ObjectFormat) -> (Source, Vec<BundleReference>, ObjectId) {
    let mut source = Source::new();
    let blob = source.add(format, ObjectType::Blob, b"native bytes\0\xff\n".to_vec());
    let mut tree = b"100644 file\0".to_vec();
    tree.extend_from_slice(blob.as_bytes());
    let tree = source.add(format, ObjectType::Tree, tree);
    let commit = source.add(format, ObjectType::Commit,
        format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\ninitial\n").into_bytes());
    let tag = source.add(
        format,
        ObjectType::Tag,
        format!(
            "object {commit}\ntype commit\ntag v1\ntagger A <a@example.invalid> 1 +0000\n\nv1\n"
        )
        .into_bytes(),
    );
    let refs = vec![
        reference(tag, b"refs/tags/v1"),
        reference(commit, b"refs/heads/\xff"),
    ];
    (source, refs, commit)
}
fn export(
    source: &Source,
    format: ObjectFormat,
    refs: &[BundleReference],
    head: Option<ObjectId>,
    selected: &[ObjectId],
    limits: &StreamFullBundleLimits,
) -> Result<(Vec<u8>, StreamFullBundleReceipt), StreamFullBundleError> {
    let mut bytes = Vec::new();
    let receipt = write_full_bundle_stream(
        format,
        refs,
        head,
        selected,
        source,
        limits,
        &mut || true,
        &mut bytes,
    )?;
    Ok((bytes, receipt))
}

#[test]
fn both_native_domains_round_trip_exact_graph_bytes_and_deterministic_oid_order() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (source, mut refs, commit) = corpus(format);
        let mut ids: Vec<_> = source.objects.keys().copied().collect();
        let limits = StreamFullBundleLimits::default();
        let (bytes, receipt) = export(&source, format, &refs, Some(commit), &ids, &limits).unwrap();
        assert_eq!(receipt.format(), format);
        assert_eq!(receipt.profile_id(), STREAM_FULL_BUNDLE_PROFILE);
        assert_eq!(receipt.object_count() as usize, ids.len());
        assert_eq!(
            receipt.total_object_bytes(),
            source
                .objects
                .values()
                .map(|object| object.body().len())
                .sum()
        );
        assert_eq!(receipt.bundle_bytes(), bytes.len());
        assert_eq!(receipt.bundle_sha256(), fgit_crypto::sha256_digest(&bytes));
        assert_eq!(receipt.pack_bytes() + receipt.header_bytes(), bytes.len());
        assert!(receipt.compression_work() > 0);
        let input = FullBundleInput::parse(&bytes, limits.envelope, &mut || true).unwrap();
        assert_eq!(input.format(), format);
        assert_eq!(input.head(), Some(commit));
        assert_eq!(input.pack_bytes().len(), receipt.pack_bytes());
        assert_eq!(
            &input.pack_bytes()[input.pack_bytes().len() - format.digest_len()..],
            receipt.pack_checksum().as_bytes()
        );
        input
            .verify_pack_framing(&limits.pack, &mut || true)
            .unwrap();
        let mut recovered = Vec::new();
        read_streamed_pack(
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
                assert_eq!(entry.entry.inflated, source.objects[&id].body());
                recovered.push(id);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered, ids);
        assert_eq!(*source.loaded.borrow(), ids);
        ids.reverse();
        refs.reverse();
        let (reordered, second) =
            export(&source, format, &refs, Some(commit), &ids, &limits).unwrap();
        assert_eq!(bytes, reordered);
        assert_eq!(receipt, second);
    }
}

#[test]
fn identity_domains_duplicate_ids_and_header_errors_refuse_before_load_or_output() {
    let format = ObjectFormat::Sha1;
    let (source, refs, _) = corpus(format);
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let limits = StreamFullBundleLimits::default();
    let foreign = fgit_crypto::git_object_id(ObjectFormat::Sha256, ObjectType::Blob, b"foreign");
    for selected in [vec![foreign], vec![ids[0], ids[0]]] {
        let mut bytes = Vec::new();
        assert!(
            write_full_bundle_stream(
                format,
                &refs,
                None,
                &selected,
                &source,
                &limits,
                &mut || true,
                &mut bytes
            )
            .is_err()
        );
        assert!(bytes.is_empty());
        assert!(source.loaded.borrow().is_empty());
    }
    for bad_refs in [
        Vec::new(),
        vec![refs[0].clone(), refs[0].clone()],
        vec![reference(foreign, b"refs/tags/foreign")],
    ] {
        let mut bytes = Vec::new();
        assert!(
            write_full_bundle_stream(
                format,
                &bad_refs,
                None,
                &ids,
                &source,
                &limits,
                &mut || true,
                &mut bytes
            )
            .is_err()
        );
        assert!(bytes.is_empty());
        assert!(source.loaded.borrow().is_empty());
    }
    let (bytes, _) = export(&source, format, &refs, None, &ids, &limits).unwrap();
    assert!(!bytes.is_empty());
}

#[test]
fn native_graph_edges_cannot_be_hidden_by_empty_source_metadata_and_extras_refuse() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let (mut source, refs, _) = corpus(format);
        let ids: Vec<_> = source.objects.keys().copied().collect();
        let limits = StreamFullBundleLimits::default();
        let omitted = source
            .objects
            .iter()
            .find(|(_, object)| object.object_type() == ObjectType::Blob)
            .unwrap()
            .0;
        let missing: Vec<_> = ids.iter().copied().filter(|id| id != omitted).collect();
        assert!(
            matches!(export(&source, format, &refs, None, &missing, &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::MissingObject(id))) if id == *omitted)
        );
        export(&source, format, &refs, None, &ids, &limits).unwrap();
        let extra = source.add(
            format,
            ObjectType::Blob,
            b"private unreachable history".to_vec(),
        );
        let with_extra: Vec<_> = source.objects.keys().copied().collect();
        assert!(
            matches!(export(&source, format, &refs, None, &with_extra, &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::UnreachableObject(id))) if id == extra)
        );
    }
}

#[test]
fn wrong_edge_and_branch_target_kinds_refuse_even_with_valid_native_ids() {
    let format = ObjectFormat::Sha1;
    let mut source = Source::new();
    let blob = source.add(format, ObjectType::Blob, b"not a tree".to_vec());
    let commit = source.add(
        format,
        ObjectType::Commit,
        format!("tree {blob}\n\ninvalid graph\n").into_bytes(),
    );
    let ids = vec![blob, commit];
    let limits = StreamFullBundleLimits::default();
    assert!(matches!(
        export(
            &source,
            format,
            &[reference(commit, b"refs/heads/main")],
            None,
            &ids,
            &limits
        ),
        Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
            "graph edge target kind"
        )))
    ));
    assert!(matches!(
        export(
            &source,
            format,
            &[reference(blob, b"refs/heads/main")],
            None,
            &[blob],
            &limits
        ),
        Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
            "branch target kind"
        )))
    ));
    export(
        &source,
        format,
        &[reference(blob, b"refs/tags/blob")],
        None,
        &[blob],
        &limits,
    )
    .unwrap();
    let bad_tag = source.add(
        format,
        ObjectType::Tag,
        format!("object {blob}\ntype commit\ntag v1\n\ninvalid graph\n").into_bytes(),
    );
    assert!(matches!(
        export(
            &source,
            format,
            &[reference(bad_tag, b"refs/tags/v1")],
            None,
            &[blob, bad_tag],
            &limits
        ),
        Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
            "graph edge target kind"
        )))
    ));
}

#[test]
fn padded_gitlinks_stay_foreign_but_consume_the_shared_edge_allowance() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut source = Source::new();
        let foreign = fgit_crypto::git_object_id(format, ObjectType::Commit, b"another repository");
        let mut tree = b"0160000 dependency\0".to_vec();
        tree.extend_from_slice(foreign.as_bytes());
        let root = source.add(format, ObjectType::Tree, tree);
        let refs = [reference(root, b"refs/tags/tree")];
        let mut limits = StreamFullBundleLimits {
            max_graph_edges: 1,
            ..Default::default()
        };
        export(&source, format, &refs, None, &[root], &limits).unwrap();
        assert!(!source.loaded.borrow().contains(&foreign));
        limits.max_graph_edges = 0;
        assert!(matches!(
            export(&source, format, &refs, None, &[root], &limits),
            Err(StreamFullBundleError::Bundle(FullBundleError::Limit(
                "graph edges"
            )))
        ));
    }
}

#[test]
fn corrupt_source_id_or_bytes_cannot_produce_a_receipt() {
    let format = ObjectFormat::Sha1;
    let mut source = Source::new();
    let root = source.add(format, ObjectType::Blob, b"original".to_vec());
    let refs = [reference(root, b"refs/tags/blob")];
    let limits = StreamFullBundleLimits::default();
    export(&source, format, &refs, None, &[root], &limits).unwrap();
    source.objects.insert(
        root,
        CanonicalPackObject::new(root, ObjectType::Blob, b"changed".to_vec(), vec![], 0, 0),
    );
    assert!(matches!(
        export(&source, format, &refs, None, &[root], &limits),
        Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
            PackError::NativeObjectIdMismatch
        )))
    ));
    let wrong = fgit_crypto::git_object_id(format, ObjectType::Blob, b"different");
    source.objects.insert(
        root,
        CanonicalPackObject::new(wrong, ObjectType::Blob, b"different".to_vec(), vec![], 0, 0),
    );
    assert!(matches!(
        export(&source, format, &refs, None, &[root], &limits),
        Err(StreamFullBundleError::Bundle(FullBundleError::Write(
            PackWriteError::SourceIdentityMismatch { .. }
        )))
    ));
}

#[test]
fn independent_budgets_are_aggregate_and_the_exact_permitted_boundary_succeeds() {
    let format = ObjectFormat::Sha1;
    let (source, refs, commit) = corpus(format);
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let baseline = StreamFullBundleLimits::default();
    let (_, receipt) = export(&source, format, &refs, Some(commit), &ids, &baseline).unwrap();
    let largest = source
        .objects
        .values()
        .map(|object| object.body().len())
        .max()
        .unwrap();
    let mut exact = baseline;
    exact.pack.max_entries = receipt.object_count();
    exact.pack.max_index_entries = ids.len();
    exact.pack.max_object_bytes = largest;
    exact.pack.max_total_expanded_bytes = receipt.total_object_bytes();
    exact.pack.max_input_bytes = receipt.pack_bytes();
    exact.envelope.max_bundle_bytes = receipt.bundle_bytes();
    exact.envelope.max_header_bytes = receipt.header_bytes();
    exact.envelope.max_references = refs.len() + 1;
    exact.max_graph_edges = 3;
    exact.max_compression_work = receipt.compression_work();
    let (_, permitted) = export(&source, format, &refs, Some(commit), &ids, &exact).unwrap();
    assert_eq!(receipt, permitted);
    let variations: Vec<fn(&mut StreamFullBundleLimits)> = vec![
        |limits| limits.pack.max_entries -= 1,
        |limits| limits.pack.max_index_entries -= 1,
        |limits| limits.pack.max_object_bytes -= 1,
        |limits| limits.pack.max_total_expanded_bytes -= 1,
        |limits| limits.pack.max_input_bytes -= 1,
        |limits| limits.envelope.max_bundle_bytes -= 1,
        |limits| limits.envelope.max_header_bytes -= 1,
        |limits| limits.envelope.max_references -= 1,
        |limits| limits.max_graph_edges -= 1,
        |limits| limits.max_compression_work -= 1,
    ];
    for reduce in variations {
        let mut refused = exact.clone();
        reduce(&mut refused);
        assert!(
            export(&source, format, &refs, Some(commit), &ids, &refused).is_err(),
            "{refused:?}"
        );
    }
}

#[test]
fn cancellation_at_preflight_source_hashing_compression_or_output_never_completes() {
    let format = ObjectFormat::Sha1;
    let (source, refs, _) = corpus(format);
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let limits = StreamFullBundleLimits::default();
    let probes = Cell::new(0_usize);
    write_full_bundle_stream(
        format,
        &refs,
        None,
        &ids,
        &source,
        &limits,
        &mut || {
            probes.set(probes.get() + 1);
            true
        },
        &mut Vec::new(),
    )
    .unwrap();
    for cancel_at in [
        1,
        5,
        15,
        probes.get() / 3,
        probes.get() / 2,
        probes.get() - 1,
        probes.get(),
    ] {
        let mut count = 0;
        let mut bytes = Vec::new();
        let result = write_full_bundle_stream(
            format,
            &refs,
            None,
            &ids,
            &source,
            &limits,
            &mut || {
                count += 1;
                count != cancel_at
            },
            &mut bytes,
        );
        assert!(result.is_err(), "single cancellation pulse {cancel_at}");
        assert_eq!(
            count, cancel_at,
            "cancellation is latched, never polled back to live"
        );
    }
}

struct CountingWriter {
    bytes: Rc<Cell<usize>>,
    short: usize,
    fail_after: Option<usize>,
}
impl Write for CountingWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self
            .fail_after
            .is_some_and(|limit| self.bytes.get() >= limit)
        {
            return Err(io::Error::other("injected output failure"));
        }
        assert!(input.len() <= 16 * 1024);
        let length = input.len().min(self.short);
        self.bytes.set(self.bytes.get() + length);
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("only the staged artifact owner may flush and publish");
    }
}

#[test]
fn short_writes_complete_and_mid_output_failure_is_preserved() {
    let format = ObjectFormat::Sha1;
    let (source, refs, _) = corpus(format);
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let limits = StreamFullBundleLimits::default();
    for fail_after in [None, Some(100)] {
        let bytes = Rc::new(Cell::new(0));
        let mut writer = CountingWriter {
            bytes: Rc::clone(&bytes),
            short: 3,
            fail_after,
        };
        let result = write_full_bundle_stream(
            format,
            &refs,
            None,
            &ids,
            &source,
            &limits,
            &mut || true,
            &mut writer,
        );
        if fail_after.is_some() {
            assert!(matches!(result, Err(StreamFullBundleError::Io(_))));
            assert!(bytes.get() >= 100);
        } else {
            assert_eq!(result.unwrap().bundle_bytes(), bytes.get());
        }
    }
}

struct StreamingSource {
    ids: BTreeMap<ObjectId, usize>,
    output: Rc<Cell<usize>>,
    previous_output: Cell<usize>,
    loads: Cell<usize>,
}
impl CanonicalObjectSource for StreamingSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert!(
            self.output.get() > self.previous_output.get(),
            "each previous object must reach the stream before loading the next"
        );
        self.previous_output.set(self.output.get());
        self.loads.set(self.loads.get() + 1);
        let body = generated_body(self.ids[id]);
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body,
            vec![],
            0,
            0,
        ))
    }
}
fn generated_body(index: usize) -> Vec<u8> {
    let mut body = vec![b'x'; 64 * 1024];
    body[..8].copy_from_slice(&(index as u64).to_be_bytes());
    body
}

#[test]
fn many_generated_objects_are_loaded_once_and_written_before_the_next_body_load() {
    let format = ObjectFormat::Sha256;
    let ids: BTreeMap<_, _> = (0..32)
        .map(|index| {
            (
                fgit_crypto::git_object_id(format, ObjectType::Blob, &generated_body(index)),
                index,
            )
        })
        .collect();
    let selected: Vec<_> = ids.keys().copied().collect();
    let refs: Vec<_> = selected
        .iter()
        .enumerate()
        .map(|(index, id)| reference(*id, format!("refs/tags/blob-{index}").as_bytes()))
        .collect();
    let output = Rc::new(Cell::new(0));
    let source = StreamingSource {
        ids,
        output: Rc::clone(&output),
        previous_output: Cell::new(0),
        loads: Cell::new(0),
    };
    let mut writer = CountingWriter {
        bytes: Rc::clone(&output),
        short: usize::MAX,
        fail_after: None,
    };
    let receipt = write_full_bundle_stream(
        format,
        &refs,
        None,
        &selected,
        &source,
        &StreamFullBundleLimits::default(),
        &mut || true,
        &mut writer,
    )
    .unwrap();
    assert_eq!(receipt.total_object_bytes(), 32 * 64 * 1024);
    assert_eq!(source.loads.get(), selected.len());
    assert_eq!(receipt.bundle_bytes(), output.get());
}
