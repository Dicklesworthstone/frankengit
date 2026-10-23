//! Actual embedded authority and staged original Git objects. Candidate bytes
//! are independent pack fixtures and are NEVER staged by the operation tested.
use super::*;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{sha1_digest, sha256_digest};
use fgit_forge::review::ReviewContent;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
#[path = "frontier_header_tests.rs"]
mod frontier_header_tests;
#[path = "pack_local_tests.rs"]
mod pack_local_tests;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Fixture {
    base: GitOid,
    target: GitOid,
    source: GitOid,
    original: GitOid,
    secret: GitOid,
    keep: GitOid,
}
fn target() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn incoming() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}
fn body(tree: GitOid, parents: &[GitOid], label: &str) -> Vec<u8> {
    let mut value = format!("tree {tree}\n");
    for parent in parents {
        value.push_str(&format!("parent {parent}\n"));
    }
    value.push_str(&format!("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n"));
    value.into_bytes()
}
fn tree(file: GitOid, keep: GitOid) -> Vec<u8> {
    [
        b"100644 file\0".as_slice(),
        file.as_bytes(),
        b"100644 keep\0",
        keep.as_bytes(),
    ]
    .concat()
}
fn fixture(format: GitHashAlgorithm) -> (Scratch, OneNode, Fixture) {
    let root = std::env::temp_dir().join(format!(
        "fg-inspect-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let (mut node, _) = OneNode::init(
        crate::NodeConfig::new(
            root.clone(),
            TenantId::from_bytes([0x81; 16]),
            RepositoryId::from_bytes([0x82; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut ids = BTreeSet::new();
    let mut put = |kind, bytes| {
        let id = node.put_git_object(kind, bytes).unwrap().identity();
        ids.insert(id);
        id
    };
    let original = put(ObjectType::Blob, b"original\n".to_vec());
    let keep = put(ObjectType::Blob, b"preserved sibling\n".to_vec());
    let root_tree = put(ObjectType::Tree, tree(original, keep));
    let base = put(ObjectType::Commit, body(root_tree, &[], "base"));
    let target = put(ObjectType::Commit, body(root_tree, &[base], "target"));
    let source_blob = put(ObjectType::Blob, b"source-side only\n".to_vec());
    let source_tree = put(ObjectType::Tree, tree(source_blob, keep));
    let source = put(ObjectType::Commit, body(source_tree, &[base], "source"));
    let secret = put(ObjectType::Blob, b"unrelated secret\n".to_vec());
    let secret_tree = put(ObjectType::Tree, tree(secret, keep));
    let secret_commit = put(ObjectType::Commit, body(secret_tree, &[], "other ref"));
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let updates = [
        SourceRefUpdate {
            old: zero,
            new: target,
            ref_name: b"refs/heads/main".to_vec(),
        },
        SourceRefUpdate {
            old: zero,
            new: source,
            ref_name: b"refs/heads/topic".to_vec(),
        },
        SourceRefUpdate {
            old: zero,
            new: secret_commit,
            ref_name: b"refs/heads/private".to_vec(),
        },
    ];
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: u32::try_from(ids.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            ids.clone(),
        ))
        .unwrap(),
        objects: ids,
    };
    let imported = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        principal_id: PrincipalId::from_bytes([0x83; 16]),
        idempotency_key: IdempotencyKey::new(b"inspect-fixture".to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let outcome = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &imported,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(
        outcome
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (
        Scratch(root),
        node,
        Fixture {
            base,
            target,
            source,
            original,
            secret,
            keep,
        },
    )
}

enum Entry {
    Direct(u8, Vec<u8>),
    Ref(GitOid, Vec<u8>),
    Ofs(usize, Vec<u8>),
}
fn zlib(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut result = vec![0x78, 0x01, 1];
    result.extend(size.to_le_bytes());
    result.extend((!size).to_le_bytes());
    result.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    result.extend(((b << 16) | a).to_be_bytes());
    result
}
fn pack(format: GitHashAlgorithm, entries: &[Entry]) -> Vec<u8> {
    let mut output = b"PACK".to_vec();
    output.extend(2u32.to_be_bytes());
    output.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    let mut offsets = Vec::new();
    for entry in entries {
        let at = output.len();
        offsets.push(at);
        let (kind, bytes, base) = match entry {
            Entry::Direct(kind, bytes) => (*kind, bytes, Vec::new()),
            Entry::Ref(base, bytes) => (7, bytes, base.as_bytes().to_vec()),
            Entry::Ofs(index, bytes) => {
                let mut distance = at - offsets[*index];
                let mut encoded = vec![(distance & 127) as u8];
                while {
                    distance >>= 7;
                    distance != 0
                } {
                    distance -= 1;
                    encoded.push(0x80 | (distance & 127) as u8);
                }
                encoded.reverse();
                (6, bytes, encoded)
            }
        };
        let mut size = bytes.len();
        let mut byte = (kind << 4) | (size & 15) as u8;
        size >>= 4;
        while size != 0 {
            output.push(byte | 128);
            byte = (size & 127) as u8;
            size >>= 7;
        }
        output.push(byte);
        output.extend(base);
        output.extend(zlib(bytes));
    }
    match format {
        GitHashAlgorithm::Sha1 => output.extend(sha1_digest(&output)),
        GitHashAlgorithm::Sha256 => output.extend(sha256_digest(&output)),
    }
    output
}
fn envelope(
    format: GitHashAlgorithm,
    base: GitOid,
    candidate: GitOid,
    entries: &[Entry],
) -> Vec<u8> {
    let mut header = format!(
        "# v3 git bundle\n@object-format={}\n-{base} parent\n{candidate} refs/heads/main\n\n",
        format.as_str()
    )
    .into_bytes();
    header.extend(pack(format, entries));
    header
}
fn candidate(
    format: GitHashAlgorithm,
    f: &Fixture,
    parents: &[GitOid],
    content: &[u8],
) -> (GitOid, Vec<u8>, Vec<Entry>) {
    let blob = git_object_id(format, ObjectType::Blob, content);
    let tree_body = tree(blob, f.keep);
    let tree = git_object_id(format, ObjectType::Tree, &tree_body);
    let commit = body(tree, parents, "exact candidate metadata");
    let oid = git_object_id(format, ObjectType::Commit, &commit);
    (
        oid,
        commit.clone(),
        vec![
            Entry::Direct(3, content.to_vec()),
            Entry::Direct(2, tree_body),
            Entry::Direct(1, commit),
        ],
    )
}
fn inspection(
    node: &OneNode,
    f: &Fixture,
    candidate: GitOid,
    bytes: &[u8],
) -> Result<BundleInspection, BundleInspectionRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.inspect_workspace_bundle_in(
        &request,
        &target(),
        f.target,
        candidate,
        bytes,
        &RefVisibility::new(),
        None,
        &ReviewOptions::default(),
    ))
}
fn copy_then_exclaim(base: &[u8]) -> Vec<u8> {
    let length = u8::try_from(base.len()).unwrap();
    assert!(length < 127);
    vec![length, length + 1, 0x90, length, 1, b'!']
}

fn sparse_input_bodies<A: fgit_crypto::GitHashAlgorithm>(
    node: &OneNode,
    f: &Fixture,
    candidate: GitOid,
    bytes: &[u8],
    merge: Option<(&NativeMerge, fgit_forge::preparation::MergeCommitStyle)>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BundleInspectionRefusal> {
    use fgit_treefs::{SparseLimits, TreeCapability, TreePath, WorkspaceId};

    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([0x93; 16]),
        node.repository_id(),
        [b"file".as_slice(), b"keep"]
            .into_iter()
            .map(|path| TreePath::parse_default(path).unwrap())
            .collect(),
        Vec::new(),
    );
    let limits = SparseLimits {
        max_entries: 8,
        max_entry_bytes: 4096,
        max_payload_bytes: 8192,
    };
    let request = node.request_context();
    let (_, manifest, digest) = if let Some((merge, style)) = merge {
        node.runtime()
            .block_on(node.sparse_merge_candidate_manifest_with_style_in::<A>(
                &request,
                merge,
                bytes,
                &RefVisibility::new(),
                None,
                &mut capability,
                0,
                limits,
                style,
            ))?
    } else {
        node.runtime()
            .block_on(node.sparse_candidate_manifest_in::<A>(
                &request,
                &target(),
                f.target,
                candidate,
                bytes,
                &RefVisibility::new(),
                None,
                &mut capability,
                0,
                limits,
            ))?
    };
    assert_eq!(digest, sha256_digest(bytes));
    Ok(manifest
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.path().as_bytes().to_vec(),
                entry.kind().body().unwrap().to_vec(),
            )
        })
        .collect())
}

fn sparse_inputs(
    format: GitHashAlgorithm,
    node: &OneNode,
    f: &Fixture,
    candidate: GitOid,
    bytes: &[u8],
    merge: Option<(&NativeMerge, fgit_forge::preparation::MergeCommitStyle)>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BundleInspectionRefusal> {
    match format {
        GitHashAlgorithm::Sha1 => {
            sparse_input_bodies::<fgit_crypto::Sha1>(node, f, candidate, bytes, merge)
        }
        GitHashAlgorithm::Sha256 => {
            sparse_input_bodies::<fgit_crypto::Sha256>(node, f, candidate, bytes, merge)
        }
    }
}

#[test]
fn minimal_and_thick_workspace_merge_and_squash_have_identical_reviews_and_sparse_inputs() {
    use fgit_forge::preparation::MergeCommitStyle;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        for mode in 0..3 {
            let style = if mode == 1 {
                MergeCommitStyle::TwoParent
            } else {
                MergeCommitStyle::Squash
            };
            let parents = if mode == 1 {
                vec![f.target, f.source]
            } else {
                vec![f.target]
            };
            let (id, _, mut entries) = candidate(format, &f, &parents, b"reviewed result\n");
            let merge = NativeMerge {
                source_ref: incoming(),
                source_tip: f.source,
                target_ref: target(),
                target_tip_before: f.target,
                base_tip: f.base,
                merge_commit: id,
            };
            let bundle = |entries: &[Entry]| {
                let mut header = format!(
                    "# v3 git bundle\n@object-format={}\n-{} target\n",
                    format.as_str(),
                    f.target
                );
                if mode != 0 {
                    header.push_str(&format!("-{} source\n", f.source));
                }
                header.push_str(&format!("{id} refs/heads/main\n\n"));
                [header.into_bytes(), pack(format, entries)].concat()
            };
            let minimal = bundle(&entries);
            // A thick artifact may repeat existing parent-reachable bytes.
            // The unchanged sibling is candidate content, not delta-only data.
            entries.push(Entry::Direct(3, b"preserved sibling\n".to_vec()));
            let thick = bundle(&entries);
            let inspect = |bytes: &[u8]| {
                if mode == 0 {
                    inspection(&node, &f, id, bytes)
                } else {
                    node.runtime().block_on(node.inspect_merge_bundle_in(
                        &request,
                        &merge,
                        bytes,
                        &RefVisibility::new(),
                        Some(before.basis().id()),
                        &ReviewOptions::default(),
                    ))
                }
            };
            let first = inspect(&minimal).unwrap();
            let second = inspect(&thick).unwrap();
            assert_eq!(first.review.comparison, second.review.comparison);
            assert_eq!(first.candidate_commit_body, second.candidate_commit_body);
            assert_eq!(first.parents, second.parents);
            assert_eq!(first.closure_objects, second.closure_objects);
            assert_eq!(first.transport_only_objects, 0);
            assert_eq!(second.transport_only_objects, 0);
            assert_eq!(first.pack_objects + 1, second.pack_objects);
            let coordinates = (mode != 0).then_some((&merge, style));
            let first_inputs = sparse_inputs(format, &node, &f, id, &minimal, coordinates).unwrap();
            let second_inputs = sparse_inputs(format, &node, &f, id, &thick, coordinates).unwrap();
            assert_eq!(first_inputs, second_inputs);
            assert_eq!(
                first_inputs,
                vec![
                    (b"file".to_vec(), b"reviewed result\n".to_vec()),
                    (b"keep".to_vec(), b"preserved sibling\n".to_vec()),
                ]
            );
            assert!(node.read_git_object(id).is_err());
        }
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn uploaded_selected_hidden_tree_cannot_disclose_omitted_descendants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let hidden_tree_body = tree(f.secret, f.keep);
        let hidden_tree = git_object_id(format, ObjectType::Tree, &hidden_tree_body);
        assert!(
            before
                .selected_closure()
                .closure()
                .objects()
                .contains(&hidden_tree)
        );
        let candidate_body = body(hidden_tree, &[f.target], "uploaded selected hidden tree");
        let id = git_object_id(format, ObjectType::Commit, &candidate_body);
        let mut entries = vec![
            Entry::Direct(2, hidden_tree_body),
            Entry::Direct(1, candidate_body),
        ];
        let incomplete = envelope(format, f.target, id, &entries);
        assert!(matches!(
            inspection(&node, &f, id, &incomplete),
            Err(BundleInspectionRefusal::Source(
                MergeSourceError::OutsideSelection
            ))
        ));
        assert!(matches!(
            sparse_inputs(format, &node, &f, id, &incomplete, None),
            Err(BundleInspectionRefusal::Source(
                MergeSourceError::OutsideSelection
            ))
        ));
        // Supplying the actual bytes is permitted. Their presence elsewhere
        // in the selected repository did not authorize the omitted-body twin.
        entries.push(Entry::Direct(3, b"unrelated secret\n".to_vec()));
        let complete = envelope(format, f.target, id, &entries);
        let inspected = inspection(&node, &f, id, &complete).unwrap();
        assert_eq!(inspected.transport_only_objects, 0);
        assert_eq!(inspected.review.comparison.entries.len(), 1);
        let bodies = sparse_inputs(format, &node, &f, id, &complete, None).unwrap();
        assert_eq!(
            bodies[0],
            (b"file".to_vec(), b"unrelated secret\n".to_vec())
        );
        assert!(node.read_git_object(id).is_err());
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn unchanged_large_parent_content_is_not_read_for_review_or_sparse_candidate_inputs() {
    let format = GitHashAlgorithm::Sha256;
    let (_scratch, node, mut f) = fixture(format);
    let request = node.request_context();
    let initial = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut ids = initial.selected_closure().closure().objects().clone();
    let mut large_tree_body = Vec::new();
    // Each body fits the existing 32 MiB object ceiling, but their inherited
    // total exceeds the old 128 MiB eager-parent validation ceiling. Place
    // one body at a time so the fixture does not retain all payloads in RAM.
    const BLOB_BYTES: usize = 20 * 1024 * 1024;
    const BLOB_COUNT: usize = 7;
    assert!(BLOB_BYTES * BLOB_COUNT > MAX_ORIGINAL_READ_BYTES);
    for index in 0..BLOB_COUNT {
        let id = node
            .put_git_object(ObjectType::Blob, vec![b'A' + index as u8; BLOB_BYTES])
            .unwrap()
            .identity();
        ids.insert(id);
        large_tree_body.extend_from_slice(format!("100644 file-{index}\0").as_bytes());
        large_tree_body.extend_from_slice(id.as_bytes());
    }
    let large_tree = node
        .put_git_object(ObjectType::Tree, large_tree_body)
        .unwrap()
        .identity();
    ids.insert(large_tree);
    let keep = f.keep;
    let root_body = |file| {
        let mut bytes = tree(file, keep);
        bytes.extend_from_slice(b"40000 large\0");
        bytes.extend_from_slice(large_tree.as_bytes());
        bytes
    };
    let root_tree = node
        .put_git_object(ObjectType::Tree, root_body(f.original))
        .unwrap()
        .identity();
    ids.insert(root_tree);
    let new_target = node
        .put_git_object(
            ObjectType::Commit,
            body(root_tree, &[f.target], "large target"),
        )
        .unwrap()
        .identity();
    let new_source = node
        .put_git_object(
            ObjectType::Commit,
            body(root_tree, &[f.source], "large source"),
        )
        .unwrap()
        .identity();
    ids.extend([new_target, new_source]);
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: u32::try_from(ids.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            ids.clone(),
        ))
        .unwrap(),
        objects: ids,
    };
    let imported = validate_source_import(
        &[
            SourceRefUpdate {
                old: f.target,
                new: new_target,
                ref_name: target().as_bytes().to_vec(),
            },
            SourceRefUpdate {
                old: f.source,
                new: new_source,
                ref_name: incoming().as_bytes().to_vec(),
            },
        ],
        &receipt,
        closure,
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        principal_id: PrincipalId::from_bytes([0x83; 16]),
        idempotency_key: IdempotencyKey::new(b"large-inspection-fixture".to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let outcome = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &imported,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(
        outcome
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.target = new_target;
    f.source = new_source;
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    {
        let exhaustion = Cell::new(None);
        let budget = ReadBudget {
            bytes: Cell::new(0),
            exhausted: Cell::new(false),
        };
        let original = OriginalSource::with_parents(
            VerifiedFabricPackSource {
                fabric: &node.fabric,
                object_format: format,
                maximum_object_bytes: 32 * 1024 * 1024,
                database_context: request.authority(),
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            before.selected_closure().closure().objects(),
            &budget,
            &[f.target],
            MergeObjectLimits::default(),
        )
        .unwrap();
        assert!(
            validate_commit_closure(
                &original,
                f.target,
                MergeObjectLimits::default(),
                &mut || original.live().is_ok(),
            )
            .is_err(),
            "the former full-parent validation cannot fit the inherited payload"
        );
        assert_eq!(original.live(), Err(MergeSourceError::BudgetExceeded));
    }
    let changed = b"small reviewed edit\n";
    let changed_id = git_object_id(format, ObjectType::Blob, changed);
    let candidate_tree_body = root_body(changed_id);
    let candidate_tree = git_object_id(format, ObjectType::Tree, &candidate_tree_body);
    let candidate_body = body(candidate_tree, &[f.target], "bounded review");
    let candidate_id = git_object_id(format, ObjectType::Commit, &candidate_body);
    let bytes = envelope(
        format,
        f.target,
        candidate_id,
        &[
            Entry::Direct(3, changed.to_vec()),
            Entry::Direct(2, candidate_tree_body),
            Entry::Direct(1, candidate_body),
        ],
    );
    let inspected = inspection(&node, &f, candidate_id, &bytes).unwrap();
    assert_eq!(inspected.review.comparison.entries.len(), 1);
    assert_eq!(inspected.review.comparison.entries[0].path, b"file");
    let ReviewContent::Text { hunks, .. } = &inspected.review.comparison.entries[0].content else {
        panic!("small file must have its actual text diff");
    };
    assert_eq!(hunks[0].before, b"original\n");
    assert_eq!(hunks[0].after, changed);
    let bodies = sparse_inputs(format, &node, &f, candidate_id, &bytes, None).unwrap();
    assert_eq!(bodies[0], (b"file".to_vec(), changed.to_vec()));
    assert_eq!(bodies.len(), 2);
    assert!(node.read_git_object(candidate_id).is_err());
    assert!(node.read_git_object(candidate_tree).is_err());
    let request = node.request_context();
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    node.shutdown().unwrap();
}

#[test]
fn inspect_workspace_and_merge_reads_actual_result_and_never_stages_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        for merging in [false, true] {
            let parents = if merging {
                vec![f.target, f.source]
            } else {
                vec![f.target]
            };
            let (id, commit, entries) =
                candidate(format, &f, &parents, b"actual reviewed result\n");
            let bytes = envelope(format, f.target, id, &entries);
            assert!(node.read_git_object(id).is_err());
            let result = if merging {
                let merge = NativeMerge {
                    source_ref: incoming(),
                    source_tip: f.source,
                    target_ref: target(),
                    target_tip_before: f.target,
                    base_tip: f.base,
                    merge_commit: id,
                };
                node.runtime()
                    .block_on(node.inspect_merge_bundle_in(
                        &request,
                        &merge,
                        &bytes,
                        &RefVisibility::new(),
                        Some(before.basis().id()),
                        &ReviewOptions::default(),
                    ))
                    .unwrap()
            } else {
                inspection(&node, &f, id, &bytes).unwrap()
            };
            assert_eq!(result.review.source_head, before.basis().id());
            assert_eq!(result.review.comparison.requested_before, f.target);
            assert_eq!(result.review.comparison.requested_after, id);
            assert_eq!(result.parents, parents);
            assert_eq!(result.candidate_commit_body, commit);
            assert_eq!(result.bundle_sha256, sha256_digest(&bytes));
            assert_eq!(result.pack_objects, 3);
            assert_eq!(result.transport_only_objects, 0);
            let changed = &result.review.comparison.entries;
            assert_eq!(changed.len(), 1);
            assert_eq!(changed[0].path, b"file");
            let ReviewContent::Text { hunks, .. } = &changed[0].content else {
                panic!("text review");
            };
            assert_eq!(hunks[0].before, b"original\n");
            assert_eq!(hunks[0].after, b"actual reviewed result\n");
            assert!(
                node.read_git_object(id).is_err(),
                "inspection cannot stage even a valid candidate"
            );
            assert_eq!(
                node.runtime()
                    .block_on(node.materialize_admission_in(&request))
                    .unwrap()
                    .basis(),
                before.basis()
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn forward_ref_ofs_and_visible_thin_bases_use_existing_delta_resolver() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let original = b"original\n";
        let base = b"transport-only base\n";
        for mode in 0..3 {
            let source: &[u8] = if mode == 0 { original } else { base };
            let content = [source, b"!"].concat();
            let (id, _, mut entries) = candidate(format, &f, &[f.target], &content);
            let delta = copy_then_exclaim(source);
            let base_id = git_object_id(format, ObjectType::Blob, source);
            if mode == 0 {
                assert_eq!(base_id, f.original);
                entries[0] = Entry::Ref(base_id, delta);
            } else if mode == 1 {
                entries[0] = Entry::Ref(base_id, delta);
                entries.push(Entry::Direct(3, source.to_vec()));
            } else {
                entries[0] = Entry::Ofs(0, delta);
                entries.insert(0, Entry::Direct(3, source.to_vec()));
            }
            let bytes = envelope(format, f.target, id, &entries);
            let result = inspection(&node, &f, id, &bytes).unwrap();
            assert_eq!(result.transport_only_objects, usize::from(mode != 0));
            assert!(node.read_git_object(id).is_err());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn unrelated_selected_ref_is_not_an_external_delta_capability() {
    let format = GitHashAlgorithm::Sha256;
    let (_scratch, node, f) = fixture(format);
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert!(
        before
            .selected_closure()
            .closure()
            .objects()
            .contains(&f.secret)
    );
    let base = b"unrelated secret\n";
    let (id, _, mut entries) =
        candidate(format, &f, &[f.target], &[base.as_slice(), b"!"].concat());
    entries[0] = Entry::Ref(f.secret, copy_then_exclaim(base));
    let bytes = envelope(format, f.target, id, &entries);
    assert!(matches!(
        inspection(&node, &f, id, &bytes),
        Err(BundleInspectionRefusal::Pack(_))
    ));
    assert!(node.read_git_object(id).is_err());
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    node.shutdown().unwrap();
}

#[test]
fn checksum_parent_scope_and_extra_object_failures_return_no_partial_result() {
    let format = GitHashAlgorithm::Sha1;
    let (_scratch, node, f) = fixture(format);
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let (id, _, entries) = candidate(format, &f, &[f.target], b"result\n");
    let bytes = envelope(format, f.target, id, &entries);
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(inspection(&node, &f, id, &damaged).is_err());
    let (wrong, _, entries) = candidate(format, &f, &[f.source], b"result\n");
    assert!(
        inspection(
            &node,
            &f,
            wrong,
            &envelope(format, f.target, wrong, &entries)
        )
        .is_err()
    );
    let (id, _, mut entries) = candidate(format, &f, &[f.target], b"result\n");
    entries.push(Entry::Direct(3, b"unrelated uploaded blob".to_vec()));
    assert!(matches!(
        inspection(&node, &f, id, &envelope(format, f.target, id, &entries)),
        Err(BundleInspectionRefusal::InvalidCandidate(_))
    ));
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    assert!(matches!(
        node.runtime().block_on(node.inspect_workspace_bundle_in(
            &request,
            &target(),
            f.target,
            id,
            &bytes,
            &hidden,
            None,
            &ReviewOptions::default()
        )),
        Err(BundleInspectionRefusal::RefUnavailable)
    ));
    let mut options = ReviewOptions::default();
    options.limits.max_diff_work = 1;
    assert!(
        node.runtime()
            .block_on(node.inspect_workspace_bundle_in(
                &request,
                &target(),
                f.target,
                id,
                &bytes,
                &RefVisibility::new(),
                None,
                &options
            ))
            .is_err()
    );
    options.mode = ComparisonMode::MergeBase;
    assert!(
        node.runtime()
            .block_on(node.inspect_workspace_bundle_in(
                &request,
                &target(),
                f.target,
                id,
                &bytes,
                &RefVisibility::new(),
                None,
                &options
            ))
            .is_err()
    );
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    node.shutdown().unwrap();
}
