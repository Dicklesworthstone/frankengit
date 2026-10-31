//! Real native packs and source streams exercise retained incremental custody.
//! No test manufactures a receipt, an authenticated span or source-import proof.

use super::*;
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::incremental::IncrementalBundleImportPlan;
use super::super::resolve::NativeEntryHash;
use fgit_treefs::integrity::GraphRefusal;

struct ScratchPath(PathBuf);
impl ScratchPath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "fgit-incremental-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory.join("objects.scratch"))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for ScratchPath {
    fn drop(&mut self) {
        let _file = fs::remove_file(&self.0);
        let _directory = fs::remove_dir(self.0.parent().unwrap());
    }
}

#[derive(Clone)]
enum Body {
    Bytes(Vec<u8>),
    Repeated(usize),
}
impl Body {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Repeated(length) => *length,
        }
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> usize {
        let take = (self.len() - offset).min(out.len());
        match self {
            Self::Bytes(bytes) => out[..take].copy_from_slice(&bytes[offset..offset + take]),
            Self::Repeated(_) => out[..take].fill(b'x'),
        }
        take
    }
    fn identity(&self, format: GitHashAlgorithm, kind: ObjectKind) -> GitOid {
        let mut hash = NativeEntryHash::new(format, kind, self.len());
        let mut output = [0_u8; 8192];
        let mut offset = 0;
        while offset < self.len() {
            let count = self.read(offset, &mut output);
            hash.update(&output[..count]).unwrap();
            offset += count;
        }
        hash.finish().unwrap()
    }
}

#[derive(Clone)]
struct Originals {
    prerequisites: Vec<GitOid>,
    facts: BTreeMap<GitOid, BundleOriginalObject>,
    bodies: BTreeMap<GitOid, Body>,
    completed: BTreeSet<GitOid>,
    discovery: usize,
    corrupt: Option<GitOid>,
    late_error: Option<GitOid>,
    truncate: Option<GitOid>,
    stop: Option<(Rc<Cell<bool>>, GitOid)>,
    root: GitOid,
    tree: GitOid,
    blob: GitOid,
}
impl Originals {
    fn history(format: GitHashAlgorithm, blob: Body) -> Self {
        let blob_id = blob.identity(format, ObjectKind::Blob);
        let mut tree = b"100644 original\0".to_vec();
        tree.extend_from_slice(blob_id.as_bytes());
        let tree_id = git_object_id(format, ObjectKind::Tree, &tree);
        let commit = commit(tree_id, None, "original");
        let root = git_object_id(format, ObjectKind::Commit, &commit);
        let rows = [
            (blob_id, ObjectKind::Blob, blob),
            (tree_id, ObjectKind::Tree, Body::Bytes(tree)),
            (root, ObjectKind::Commit, Body::Bytes(commit)),
        ];
        Self {
            prerequisites: vec![root],
            facts: rows
                .iter()
                .map(|(id, kind, body)| {
                    (
                        *id,
                        BundleOriginalObject {
                            kind: *kind,
                            length: body.len(),
                        },
                    )
                })
                .collect(),
            bodies: rows.into_iter().map(|(id, _, body)| (id, body)).collect(),
            completed: BTreeSet::new(),
            discovery: 13,
            corrupt: None,
            late_error: None,
            truncate: None,
            stop: None,
            root,
            tree: tree_id,
            blob: blob_id,
        }
    }
    fn budget(&self) -> usize {
        self.discovery
            + self
                .facts
                .values()
                .map(|object| object.length)
                .sum::<usize>()
    }
    fn remove(&mut self, id: GitOid) {
        self.facts.remove(&id);
        self.bodies.remove(&id);
    }
}
impl BundleOriginalSource for Originals {
    fn prerequisites(&self) -> &[GitOid] {
        &self.prerequisites
    }
    fn objects(&self) -> &BTreeMap<GitOid, BundleOriginalObject> {
        &self.facts
    }
    fn discovery_read_bytes(&self) -> usize {
        self.discovery
    }
    fn read_into(
        &mut self,
        identity: GitOid,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), BundleVerifyError>,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        let body = self
            .bodies
            .get(&identity)
            .ok_or(BundleVerifyError::SourceChanged)?;
        let mut chunk = [0_u8; 8192];
        let mut offset = 0;
        while offset < body.len() {
            if !live() {
                return Err(BundleVerifyError::Stopped);
            }
            let count = body.read(offset, &mut chunk);
            if self.corrupt == Some(identity) && offset == 0 {
                chunk[0] ^= 1;
            }
            sink(&chunk[..count])?;
            offset += count;
            if self.truncate == Some(identity) {
                return Ok(());
            }
            if let Some((stop, selected)) = &self.stop {
                if *selected == identity {
                    stop.set(false);
                }
            }
        }
        if !live() {
            return Err(BundleVerifyError::Stopped);
        }
        if self.late_error == Some(identity) {
            return Err(BundleVerifyError::Io {
                operation: "original authenticated EOF",
                kind: io::ErrorKind::InvalidData,
            });
        }
        self.completed.insert(identity);
        Ok(())
    }
}

fn commit(tree: GitOid, parent: Option<GitOid>, message: &str) -> Vec<u8> {
    let parent = parent.map_or_else(String::new, |id| {
        format!("parent {}\n", lowercase_hex(id.as_bytes()))
    });
    format!(
        "tree {}\n{}author A <a@example.test> 0 +0000\ncommitter A <a@example.test> 0 +0000\n\n{}\n",
        lowercase_hex(tree.as_bytes()), parent, message,
    ).into_bytes()
}
fn incremental(
    format: GitHashAlgorithm,
    records: &[Vec<u8>],
    target: GitOid,
    prerequisites: &[GitOid],
) -> Vec<u8> {
    let complete = bundle(format, records, target);
    let prefix = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".len(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".len(),
    };
    let mut bytes = complete[..prefix].to_vec();
    for id in prerequisites {
        bytes.extend(format!("-{} prerequisite\n", lowercase_hex(id.as_bytes())).as_bytes());
    }
    bytes.extend_from_slice(&complete[prefix..]);
    bytes
}
fn varint(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(if value == 0 { byte } else { byte | 128 });
        if value == 0 {
            return bytes;
        }
    }
}
fn copy_delta(base_size: usize, copied: u8, suffix: Option<u8>) -> Vec<u8> {
    let mut bytes = varint(base_size);
    bytes.extend(varint(usize::from(copied) + usize::from(suffix.is_some())));
    bytes.extend([0x90, copied]);
    if let Some(byte) = suffix {
        bytes.extend([1, byte]);
    }
    bytes
}
fn limits() -> BundleVerifyLimits {
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_object_bytes = 512;
    limits.graph.max_object_bytes = 512;
    limits.max_streamed_blob_bytes = 8192;
    limits
}
fn prepare(
    input: &[u8],
    format: GitHashAlgorithm,
    scratch: &ScratchPath,
    source: &mut Originals,
    original_bytes: usize,
    limits: &BundleVerifyLimits,
) -> Result<IncrementalBundleImportPlan, BundleVerifyError> {
    prepare_incremental_bundle_import_reader(
        &mut Cursor::new(input),
        format,
        scratch.path(),
        source,
        original_bytes,
        limits,
        &mut || true,
    )
}
fn blob(plan: &mut IncrementalBundleImportPlan, identity: GitOid) -> Vec<u8> {
    let mut live = || true;
    let mut reader = plan.open_blob(identity, &mut live).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn thin_native_updates_borrow_only_declared_originals_and_stage_only_selected_uploads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Originals::history(format, Body::Repeated(4096));
        let result = [vec![b'x'; 16], vec![b'!']].concat();
        let result_id = git_object_id(format, ObjectKind::Blob, &result);
        let mut tree = b"100644 changed\0".to_vec();
        tree.extend_from_slice(result_id.as_bytes());
        let tree_id = git_object_id(format, ObjectKind::Tree, &tree);
        let commit = commit(tree_id, Some(source.root), "new");
        let commit_id = git_object_id(format, ObjectKind::Commit, &commit);
        let input = incremental(
            format,
            &[
                record(1, &commit, &[]),
                record(7, &copy_delta(4096, 16, Some(b'!')), source.blob.as_bytes()),
                record(3, b"unselected but verified", &[]),
                record(2, &tree, &[]),
            ],
            commit_id,
            &source.prerequisites,
        );
        let scratch = ScratchPath::new();
        let budget = source.budget();
        let mut plan = prepare(&input, format, &scratch, &mut source, budget, &limits()).unwrap();
        assert_eq!(plan.header().prerequisites(), source.prerequisites);
        assert_eq!(plan.receipt().header().object_count, 4);
        assert_eq!(plan.receipt().format(), format);
        assert_eq!(
            plan.selected_ids(),
            &BTreeSet::from([
                commit_id,
                tree_id,
                result_id,
                source.root,
                source.tree,
                source.blob,
            ])
        );
        assert_eq!(
            plan.uploaded_ids(),
            &BTreeSet::from([commit_id, tree_id, result_id])
        );
        assert_eq!(source.completed.len(), 3);
        assert!(plan.object(source.blob).is_none());
        assert_eq!(blob(&mut plan, result_id), result);
        assert_eq!(plan.read_metadata(commit_id, &mut || true).unwrap(), commit);
        assert_eq!(plan.read_metadata(tree_id, &mut || true).unwrap(), tree);
        assert_eq!(
            plan.total_selected_bytes(),
            (result.len() + commit.len() + tree.len()) as u64
        );
        plan.finish().unwrap();
        assert!(!scratch.path().exists());
    }
}

#[test]
fn empty_pack_reuse_and_identical_uploaded_overlap_keep_honest_native_counts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for supplied in [false, true] {
            let mut source = Originals::history(format, Body::Bytes(b"original blob".to_vec()));
            let rows = if supplied {
                vec![record(3, b"original blob", &[])]
            } else {
                Vec::new()
            };
            let input = incremental(format, &rows, source.root, &source.prerequisites);
            let scratch = ScratchPath::new();
            let budget = source.budget();
            let mut limits = limits();
            limits.graph.max_objects = 3;
            let mut plan = prepare(&input, format, &scratch, &mut source, budget, &limits).unwrap();
            assert_eq!(plan.receipt().header().object_count, u32::from(supplied));
            assert_eq!(plan.selected_ids().len(), 3);
            assert_eq!(plan.uploaded_ids().len(), usize::from(supplied));
            if supplied {
                assert_eq!(blob(&mut plan, source.blob), b"original blob");
            } else {
                assert_eq!(plan.total_selected_bytes(), 0);
                assert!(plan.object(source.root).is_none());
            }
            plan.finish().unwrap();
        }
    }
}

#[test]
fn source_roots_extra_objects_and_missing_original_edges_cannot_authorize_bases() {
    let format = GitHashAlgorithm::Sha256;
    let source = Originals::history(format, Body::Bytes(b"original".to_vec()));
    let input = incremental(
        format,
        &[record(3, b"original", &[])],
        source.root,
        &source.prerequisites,
    );
    for case in 0..4 {
        let mut source = source.clone();
        match case {
            0 => source.prerequisites.clear(),
            1 => source.remove(source.blob),
            2 => {
                let extra = git_object_id(format, ObjectKind::Blob, b"unrelated stored body");
                source.facts.insert(
                    extra,
                    BundleOriginalObject {
                        kind: ObjectKind::Blob,
                        length: 21,
                    },
                );
                source
                    .bodies
                    .insert(extra, Body::Bytes(b"unrelated stored body".to_vec()));
            }
            _ => {
                source.prerequisites = vec![source.blob];
            }
        }
        let selected_input = if case == 3 {
            incremental(
                format,
                &[record(3, b"original", &[])],
                source.blob,
                &source.prerequisites,
            )
        } else {
            input.clone()
        };
        let budget = source.budget();
        let scratch = ScratchPath::new();
        assert!(
            prepare(
                &selected_input,
                format,
                &scratch,
                &mut source,
                budget,
                &limits()
            )
            .is_err()
        );
        assert!(!scratch.path().exists());
    }
    // A full header has no borrowing permission, even if the source presents
    // a physically valid body that could resolve this REF delta.
    let mut source = source;
    let output = b"result";
    let target = git_object_id(format, ObjectKind::Blob, output);
    let input = bundle(
        format,
        &[record(
            7,
            &delta(b"original", output),
            source.blob.as_bytes(),
        )],
        target,
    );
    let budget = source.budget();
    let scratch = ScratchPath::new();
    assert!(matches!(
        prepare(&input, format, &scratch, &mut source, budget, &limits()),
        Err(BundleVerifyError::SourceChanged)
    ));
}

#[test]
fn complete_original_health_includes_unused_blobs_and_authenticated_eof() {
    let format = GitHashAlgorithm::Sha1;
    let original = Originals::history(format, Body::Repeated(16_385));
    let target = git_object_id(format, ObjectKind::Blob, b"independent uploaded body");
    let input = incremental(
        format,
        &[record(3, b"independent uploaded body", &[])],
        target,
        &original.prerequisites,
    );
    let mut limits = limits();
    limits.max_streamed_blob_bytes = 32_768;
    for case in 0..3 {
        let mut source = original.clone();
        match case {
            0 => source.corrupt = Some(source.blob),
            1 => source.late_error = Some(source.blob),
            _ => source.truncate = Some(source.blob),
        }
        let budget = source.budget();
        let scratch = ScratchPath::new();
        assert!(prepare(&input, format, &scratch, &mut source, budget, &limits).is_err());
        assert!(!scratch.path().exists());
    }
    let mut source = original;
    let budget = source.budget();
    let scratch = ScratchPath::new();
    let plan = prepare(&input, format, &scratch, &mut source, budget, &limits).unwrap();
    assert_eq!(source.completed.len(), 3);
    assert_eq!(plan.selected_ids(), &BTreeSet::from([target]));
    plan.finish().unwrap();
}

#[test]
fn original_read_budget_continues_discovery_and_cannot_reset_at_capture() {
    let format = GitHashAlgorithm::Sha256;
    let source = Originals::history(format, Body::Repeated(4096));
    let input = incremental(format, &[], source.root, &source.prerequisites);
    let exact = source.budget();
    for (budget, succeeds) in [
        (exact - 1, false),
        (exact, true),
        (source.discovery - 1, false),
    ] {
        let mut source = source.clone();
        let scratch = ScratchPath::new();
        let result = prepare(&input, format, &scratch, &mut source, budget, &limits());
        match result {
            Ok(plan) => {
                assert!(succeeds);
                plan.finish().unwrap();
            }
            Err(error) => {
                assert!(!succeeds);
                assert!(matches!(
                    error,
                    BundleVerifyError::Graph(GraphRefusal::Limit("original read bytes"))
                ));
                assert!(source.completed.is_empty());
            }
        }
        assert!(!scratch.path().exists());
    }
}

#[test]
fn original_prepayment_preserves_exact_uploaded_expansion_budget_for_shared_bases() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for base_size in [16, 4096] {
            let original = Originals::history(format, Body::Repeated(base_size));
            let first = vec![b'x'; 8];
            let second = [first.clone(), vec![b'!']].concat();
            let target = git_object_id(format, ObjectKind::Blob, &second);
            let input = incremental(
                format,
                &[
                    record(7, &copy_delta(base_size, 8, None), original.blob.as_bytes()),
                    record(
                        7,
                        &copy_delta(base_size, 8, Some(b'!')),
                        original.blob.as_bytes(),
                    ),
                ],
                target,
                &original.prerequisites,
            );
            for (expanded, succeeds) in [(17, true), (16, false)] {
                let mut source = original.clone();
                let budget = source.budget();
                let scratch = ScratchPath::new();
                let mut limits = limits();
                limits.pack.max_total_expanded_bytes = expanded;
                limits.graph.max_payload_bytes = 17;
                let result = prepare(&input, format, &scratch, &mut source, budget, &limits);
                match result {
                    Ok(mut plan) => {
                        assert!(succeeds);
                        assert_eq!(plan.receipt().header().object_count, 2);
                        assert_eq!(source.completed.len(), 3);
                        assert_eq!(plan.uploaded_ids(), &BTreeSet::from([target]));
                        assert_eq!(blob(&mut plan, target), second);
                        plan.finish().unwrap();
                    }
                    Err(error) => {
                        assert!(!succeeds, "{error}");
                        assert!(
                            matches!(
                                error,
                                BundleVerifyError::Pack(
                                    fgit_pack::PackError::TotalExpandedLimit { .. }
                                )
                            ),
                            "{error}"
                        );
                    }
                }
                assert!(!scratch.path().exists());
            }
        }
    }
}

#[test]
fn large_original_blob_is_captured_and_used_without_a_resident_body() {
    let format = GitHashAlgorithm::Sha256;
    let length = 33 * 1024 * 1024 + 17;
    let mut source = Originals::history(format, Body::Repeated(length));
    let result = [vec![b'x'; 16], vec![b'!']].concat();
    let target = git_object_id(format, ObjectKind::Blob, &result);
    let input = incremental(
        format,
        &[record(
            7,
            &copy_delta(length, 16, Some(b'!')),
            source.blob.as_bytes(),
        )],
        target,
        &source.prerequisites,
    );
    let budget = source.budget();
    let scratch = ScratchPath::new();
    let mut limits = limits();
    limits.max_streamed_blob_bytes = length;
    limits.pack.max_total_expanded_bytes = result.len();
    limits.graph.max_payload_bytes = result.len() as u64;
    let mut plan = prepare(&input, format, &scratch, &mut source, budget, &limits).unwrap();
    assert_eq!(source.completed.len(), 3);
    assert_eq!(plan.receipt().header().object_count, 1);
    assert_eq!(plan.selected_ids(), &BTreeSet::from([target, source.blob]));
    assert_eq!(plan.uploaded_ids(), &BTreeSet::from([target]));
    assert_eq!(blob(&mut plan, target), result);
    plan.finish().unwrap();
    assert!(!scratch.path().exists());
}

#[test]
fn original_cancellation_and_retained_reader_failure_clean_original_custody() {
    let format = GitHashAlgorithm::Sha1;
    let mut source = Originals::history(format, Body::Repeated(4096));
    let target = git_object_id(format, ObjectKind::Blob, b"upload");
    let input = incremental(
        format,
        &[record(3, b"upload", &[])],
        target,
        &source.prerequisites,
    );
    let live = Rc::new(Cell::new(true));
    source.stop = Some((Rc::clone(&live), source.blob));
    let budget = source.budget();
    let scratch = ScratchPath::new();
    assert!(matches!(
        prepare_incremental_bundle_import_reader(
            &mut Cursor::new(&input),
            format,
            scratch.path(),
            &mut source,
            budget,
            &limits(),
            &mut || live.get(),
        ),
        Err(BundleVerifyError::Stopped)
    ));
    assert!(!scratch.path().exists());
    source.stop = None;
    for corrupt in [false, true] {
        let mut plan = prepare(&input, format, &scratch, &mut source, budget, &limits()).unwrap();
        if corrupt {
            let mut file = OpenOptions::new().write(true).open(scratch.path()).unwrap();
            file.write_all(b"!").unwrap();
        }
        let mut live = || true;
        let mut reader = plan.open_blob(target, &mut live).unwrap();
        let mut output = [0_u8; 1];
        assert_eq!(reader.read(&mut output).unwrap(), 1);
        if corrupt {
            assert!(reader.read_to_end(&mut Vec::new()).is_err());
        }
        // The non-corrupt case abandons the original stream before EOF.
        drop(reader);
        assert!(plan.finish().is_err());
        assert!(!scratch.path().exists());
    }
}

#[test]
fn combined_original_and_upload_inventory_obeys_one_distinct_object_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = Originals::history(format, Body::Bytes(b"original".to_vec()));
        let target = git_object_id(format, ObjectKind::Blob, b"new upload");
        let input = incremental(
            format,
            &[record(3, b"new upload", &[])],
            target,
            &original.prerequisites,
        );
        for (maximum, succeeds) in [(3, false), (4, true)] {
            let mut source = original.clone();
            let budget = source.budget();
            let scratch = ScratchPath::new();
            let mut limits = limits();
            limits.graph.max_objects = maximum;
            let result = prepare(&input, format, &scratch, &mut source, budget, &limits);
            match result {
                Ok(plan) => {
                    assert!(succeeds);
                    assert_eq!(plan.selected_ids(), &BTreeSet::from([target]));
                    plan.finish().unwrap();
                }
                Err(error) => {
                    assert!(!succeeds, "{error}");
                    assert!(matches!(
                        error,
                        BundleVerifyError::Graph(GraphRefusal::Limit("objects"))
                    ));
                }
            }
            assert!(!scratch.path().exists());
        }
    }
}
