//! Real native source imports with blob bodies above the metadata read ceiling.
use super::*;
use fgit_pack::read_streamed_pack;
use std::collections::BTreeSet;
use std::io::{self, Cursor, Seek, SeekFrom, Write};

const METADATA_BYTES: usize = 64 * 1024;
const BLOB_BYTES: usize = 512 * 1024 + 17;

struct LargeSource {
    node: OneNode,
    base: GitOid,
    child: GitOid,
    tree: GitOid,
    empty_tree: GitOid,
    blob: GitOid,
    tag_blob: GitOid,
}

// Use ordinary native loose objects and the real directory importer. Stored
// DEFLATE blocks keep fixture construction independent of the exporter codec.
fn loose_blob(root: &Path, format: GitHashAlgorithm, body: &[u8]) -> GitOid {
    let id = git_object_id(format, GitObjectKind::Blob, body);
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    let mut output = fs::File::create(directory.join(&text[2..])).unwrap();
    output.write_all(&[0x78, 0x01]).unwrap();
    let header = format!("blob {}\0", body.len());
    let pieces = std::iter::once(header.as_bytes()).chain(body.chunks(65_535));
    let mut pieces = pieces.peekable();
    let (mut a, mut b) = (1_u32, 0_u32);
    while let Some(piece) = pieces.next() {
        let length = u16::try_from(piece.len()).unwrap();
        output
            .write_all(&[u8::from(pieces.peek().is_none())])
            .unwrap();
        output.write_all(&length.to_le_bytes()).unwrap();
        output.write_all(&(!length).to_le_bytes()).unwrap();
        output.write_all(piece).unwrap();
        for byte in piece {
            a = (a + u32::from(*byte)) % 65_521;
            b = (b + a) % 65_521;
        }
    }
    output.write_all(&((b << 16) | a).to_be_bytes()).unwrap();
    id
}

fn large_source(scratch: &Scratch, format: GitHashAlgorithm) -> LargeSource {
    let root = scratch.0.join("large-source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::create_dir_all(root.join("refs/tags")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        root.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let mut state = 0x1f49_2eabu32;
    let mut body = vec![0; BLOB_BYTES];
    for byte in &mut body {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }
    let blob = loose_blob(&root, format, &body);
    body[0] ^= 1;
    let tag_blob = loose_blob(&root, format, &body);
    drop(body);
    let empty_tree = loose(&root, format, GitObjectKind::Tree, "tree", b"");
    let tree = loose(
        &root,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 large\0".as_slice(), blob.as_bytes()].concat(),
    );
    let base = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        format!("tree {empty_tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n").as_bytes(),
    );
    let child = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        format!("tree {tree}\nparent {base}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nlarge blob\n").as_bytes(),
    );
    fs::write(root.join("refs/heads/main"), format!("{child}\n")).unwrap();
    fs::write(root.join("refs/tags/blob"), format!("{tag_blob}\n")).unwrap();
    let (mut node, _) = OneNode::init(
        scratch
            .config(format)
            .with_max_object_bytes(2 * 1024 * 1024),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.import_request_context(None);
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            principal(),
            b"large-stream-source",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    node.shutdown().unwrap();
    // The exporter must work with a genuinely smaller eager-read ceiling;
    // raising it to the blob length would conceal a buffered discovery read.
    let mut node = OneNode::open_existing(
        scratch
            .config(format)
            .with_max_object_bytes(METADATA_BYTES as u64)
            .with_selected_pack_blob_limit(BLOB_BYTES),
    )
    .unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    assert!(node.read_git_object(blob).is_err());
    LargeSource {
        node,
        base,
        child,
        tree,
        empty_tree,
        blob,
        tag_blob,
    }
}

fn query() -> StreamBundleExportQuery {
    let mut query = StreamBundleExportQuery::default();
    query.limits.pack.max_object_bytes = METADATA_BYTES;
    query.limits.max_streamed_blob_bytes = BLOB_BYTES;
    query
}

fn export_into(
    source: &LargeSource,
    names: Option<&[RefName]>,
    visibility: &RefVisibility,
    query: StreamBundleExportQuery,
    output: &mut impl Write,
) -> Result<SelectedStreamBundleExport, StreamBundleExportRefusal> {
    let request = source.node.request_context();
    match names {
        Some(names) => {
            source
                .node
                .runtime()
                .block_on(source.node.export_incremental_git_bundle_stream_in(
                    &request,
                    names,
                    &[source.base],
                    visibility,
                    query,
                    output,
                ))
        }
        None => source.node.runtime().block_on(
            source
                .node
                .export_full_git_bundle_stream_in(&request, visibility, query, output),
        ),
    }
}

fn identities(bytes: &[u8]) -> BTreeSet<GitOid> {
    let header =
        FullBundleInput::parse_incremental(bytes, FullBundleLimits::default(), &mut || true)
            .unwrap();
    let mut input = Cursor::new(header.pack_bytes());
    let mut limits = query().limits.pack;
    limits.max_object_bytes = BLOB_BYTES;
    let mut ids = BTreeSet::new();
    read_streamed_pack(
        &mut input,
        header.format(),
        &limits,
        &mut || true,
        |entry| -> Result<(), io::Error> {
            let kind = fgit_pack::object_type_from_base_entry(entry.entry.header.kind).unwrap();
            assert!(ids.insert(git_object_id(header.format(), kind, &entry.entry.inflated)));
            Ok(())
        },
    )
    .unwrap();
    ids
}

#[test]
fn both_profiles_stream_real_blob_objects_above_the_metadata_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = large_source(&root, format);
        let before = snapshot(&source.node);
        let main = [reference("refs/heads/main")];
        let tag = [reference("refs/tags/blob")];
        for (index, names, expected) in [
            (
                0,
                None,
                BTreeSet::from([
                    source.base,
                    source.child,
                    source.tree,
                    source.empty_tree,
                    source.blob,
                    source.tag_blob,
                ]),
            ),
            (
                1,
                Some(main.as_slice()),
                BTreeSet::from([source.child, source.tree, source.blob]),
            ),
            (2, Some(tag.as_slice()), BTreeSet::from([source.tag_blob])),
        ] {
            let path = root.0.join(format!("private-{index}.bundle"));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let selected =
                export_into(&source, names, &RefVisibility::new(), query(), &mut file).unwrap();
            drop(file);
            let bytes = fs::read(&path).unwrap();
            assert_eq!(identities(&bytes), expected);
            assert_eq!(selected.head(), before.basis().id());
            assert_eq!(selected.receipt().object_count() as usize, expected.len());
            assert_eq!(selected.receipt().bundle_bytes(), bytes.len());
            assert_eq!(
                selected.receipt().bundle_sha256(),
                fgit_crypto::sha256_digest(&bytes)
            );
            let mut repeat = Vec::new();
            let retried =
                export_into(&source, names, &RefVisibility::new(), query(), &mut repeat).unwrap();
            assert_eq!(repeat, bytes);
            assert_eq!(retried.receipt(), selected.receipt());
        }
        assert_eq!(snapshot(&source.node).basis(), before.basis());
        assert_staging_empty(&source.node);
        source.node.shutdown().unwrap();
    }
}

#[test]
fn blob_metadata_and_total_limits_refuse_before_output_independently() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = large_source(&root, format);
        let before = snapshot(&source.node);
        let main = [reference("refs/heads/main")];
        for names in [None, Some(main.as_slice())] {
            let mut baseline = Vec::new();
            let selected = export_into(
                &source,
                names,
                &RefVisibility::new(),
                query(),
                &mut baseline,
            )
            .unwrap();
            let payload = selected.receipt().total_object_bytes();
            let mut exact = query();
            exact.limits.pack.max_total_expanded_bytes = payload;
            let mut output = Vec::new();
            export_into(
                &source,
                names,
                &RefVisibility::new(),
                exact.clone(),
                &mut output,
            )
            .unwrap();
            assert_eq!(output, baseline);
            let mut blob = exact.clone();
            blob.limits.max_streamed_blob_bytes = BLOB_BYTES - 1;
            let mut metadata = exact.clone();
            metadata.limits.pack.max_object_bytes = 1;
            let mut total = exact;
            total.limits.pack.max_total_expanded_bytes = payload - 1;
            for limited in [blob, metadata, total] {
                let mut output = Vec::new();
                assert!(
                    export_into(&source, names, &RefVisibility::new(), limited, &mut output)
                        .is_err()
                );
                assert!(
                    output.is_empty(),
                    "preflight must precede emitted bundle framing"
                );
            }
        }
        assert_eq!(snapshot(&source.node).basis(), before.basis());
        source.node.shutdown().unwrap();
        let mut node = OneNode::open_existing(
            root.config(format)
                .with_max_object_bytes(METADATA_BYTES as u64)
                .with_selected_pack_blob_limit(BLOB_BYTES - 1),
        )
        .unwrap();
        node.bring_into_service(before.basis().generation())
            .unwrap();
        let source = LargeSource { node, ..source };
        for names in [None, Some(main.as_slice())] {
            let mut output = Vec::new();
            assert!(
                export_into(&source, names, &RefVisibility::new(), query(), &mut output).is_err()
            );
            assert!(
                output.is_empty(),
                "a query cannot widen the node's blob policy"
            );
        }
        source.node.shutdown().unwrap();
    }
}

fn object_path(node: &OneNode, id: GitOid) -> PathBuf {
    let name = id.to_string();
    let mut pending = vec![node.storage_root().join("objects")];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().to_str() == Some(name.as_str()) {
                return entry.path();
            }
        }
    }
    panic!("fixture object is not placed: {id}");
}

fn flip_last(path: &Path) {
    use std::io::Read;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&byte).unwrap();
}

#[test]
fn corrupt_streams_never_receipt_and_hidden_blob_roots_are_not_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let source = large_source(&root, format);
        let before = snapshot(&source.node);
        let main = [reference("refs/heads/main")];
        let blob_path = object_path(&source.node, source.blob);
        flip_last(&blob_path);
        for names in [None, Some(main.as_slice())] {
            let mut small = query();
            small.limits.max_streamed_blob_bytes = BLOB_BYTES - 1;
            let mut output = Vec::new();
            let error =
                export_into(&source, names, &RefVisibility::new(), small, &mut output).unwrap_err();
            assert!(format!("{error:?}").contains("ObjectSizeLimit"));
            assert!(
                output.is_empty(),
                "size policy must precede corrupt payload reads"
            );
            let mut output = Vec::new();
            assert!(
                export_into(&source, names, &RefVisibility::new(), query(), &mut output).is_err()
            );
            assert!(
                !output.is_empty(),
                "blob content is checked during streaming output"
            );
        }
        flip_last(&blob_path);
        let tag_path = object_path(&source.node, source.tag_blob);
        fs::remove_file(&tag_path).unwrap();
        let mut hidden = RefVisibility::new();
        hidden
            .push_rule(b"refs/tags/blob", &Default::default())
            .unwrap();
        for names in [None, Some(main.as_slice())] {
            let mut output = Vec::new();
            export_into(&source, names, &hidden, query(), &mut output).unwrap();
            assert!(!identities(&output).contains(&source.tag_blob));
        }
        assert_eq!(snapshot(&source.node).basis(), before.basis());
        assert_staging_empty(&source.node);
        source.node.shutdown().unwrap();
    }
}

struct ProgressFile<'a> {
    file: fs::File,
    bytes: &'a Cell<usize>,
}
impl Write for ProgressFile<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.bytes.set(self.bytes.get() + written);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("node export does not publish caller-owned output");
    }
}

#[test]
fn cancellation_during_blob_output_preserves_the_parent_and_private_file() {
    let root = Scratch::new();
    let source = large_source(&root, GitHashAlgorithm::Sha256);
    let before = snapshot(&source.node);
    let names = [reference("refs/heads/main")];
    for incremental in [false, true] {
        let request = source.node.request_context();
        let written = Cell::new(0);
        let stops = Cell::new(0);
        let path = root.0.join(format!("cancelled-{incremental}.bundle"));
        let mut output = ProgressFile {
            file: fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap(),
            bytes: &written,
        };
        let mut live = || {
            if written.get() >= 96 * 1024 && stops.get() == 0 {
                stops.set(1);
                false
            } else {
                true
            }
        };
        let result = if incremental {
            source.node.runtime().block_on(
                source
                    .node
                    .export_incremental_git_bundle_stream_controlled_in(
                        &request,
                        &names,
                        &[source.base],
                        &RefVisibility::new(),
                        query(),
                        &mut output,
                        &mut live,
                    ),
            )
        } else {
            source
                .node
                .runtime()
                .block_on(source.node.export_full_git_bundle_stream_controlled_in(
                    &request,
                    &RefVisibility::new(),
                    query(),
                    &mut output,
                    &mut live,
                ))
        };
        assert!(matches!(
            result,
            Err(StreamBundleExportRefusal::Cancelled { exhaustion: None })
        ));
        assert_eq!(stops.get(), 1);
        assert!(written.get() >= 96 * 1024);
        drop(output);
        assert_eq!(fs::metadata(&path).unwrap().len(), written.get() as u64);
        assert!(matches!(
            crate::checkpoint_pack_context(request.authority()),
            crate::PackContextCheckpoint::Live
        ));
        let mut retry = Vec::new();
        let selected = if incremental {
            source
                .node
                .runtime()
                .block_on(source.node.export_incremental_git_bundle_stream_in(
                    &request,
                    &names,
                    &[source.base],
                    &RefVisibility::new(),
                    query(),
                    &mut retry,
                ))
        } else {
            source
                .node
                .runtime()
                .block_on(source.node.export_full_git_bundle_stream_in(
                    &request,
                    &RefVisibility::new(),
                    query(),
                    &mut retry,
                ))
        }
        .unwrap();
        assert_eq!(selected.head(), before.basis().id());
        assert!(identities(&retry).contains(&source.blob));
    }
    assert_eq!(snapshot(&source.node).basis(), before.basis());
    source.node.shutdown().unwrap();
}
