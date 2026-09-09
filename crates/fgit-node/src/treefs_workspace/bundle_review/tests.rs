//! Actual embedded authority and staged original Git objects. Candidate bytes
//! are independent pack fixtures and are NEVER staged by the operation tested.
use super::*;
use fgit_admission::{AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root, validate_source_import};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{sha1_digest, sha256_digest};
use fgit_forge::review::ReviewContent;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
struct Fixture { base: GitOid, target: GitOid, source: GitOid, original: GitOid, secret: GitOid, keep: GitOid }
fn target() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn incoming() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn body(tree: GitOid, parents: &[GitOid], label: &str) -> Vec<u8> {
    let mut value = format!("tree {tree}\n");
    for parent in parents { value.push_str(&format!("parent {parent}\n")); }
    value.push_str(&format!("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n"));
    value.into_bytes()
}
fn tree(file: GitOid, keep: GitOid) -> Vec<u8> {
    [b"100644 file\0".as_slice(), file.as_bytes(), b"100644 keep\0", keep.as_bytes()].concat()
}
fn fixture(format: GitHashAlgorithm) -> (Scratch, OneNode, Fixture) {
    let root = std::env::temp_dir().join(format!("fg-inspect-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let (mut node, _) = OneNode::init(crate::NodeConfig::new(root.clone(), TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16])).with_object_format(format).with_worker_threads(2)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut ids = BTreeSet::new();
    let mut put = |kind, bytes| { let id = node.put_git_object(kind, bytes).unwrap().identity(); ids.insert(id); id };
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
    let updates = [SourceRefUpdate { old: zero, new: target, ref_name: b"refs/heads/main".to_vec() },
        SourceRefUpdate { old: zero, new: source, ref_name: b"refs/heads/topic".to_vec() },
        SourceRefUpdate { old: zero, new: secret_commit, ref_name: b"refs/heads/private".to_vec() }];
    let receipt = SourceImportReceipt { object_format: format, object_count: u32::try_from(ids.len()).unwrap(),
        delete_only: false, origin: SourceImportOrigin::LocalGitDirectory };
    let closure = ValidatedClosure { object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(ids.clone())).unwrap(), objects: ids };
    let imported = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext { head_key: node.head_key.clone(), tenant_id: node.tenant_id,
        repository_id: node.repository_id, principal_id: PrincipalId::from_bytes([0x83; 16]),
        idempotency_key: IdempotencyKey::new(b"inspect-fixture".to_vec()).unwrap(), object_format: format };
    let request = node.request_context();
    let outcome = node.runtime().block_on(node.admit_validated_source_import_durable_in(&request, &context, &imported, AdmissionLimits::default())).unwrap();
    assert!(outcome.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (Scratch(root), node, Fixture { base, target, source, original, secret, keep })
}

enum Entry { Direct(u8, Vec<u8>), Ref(GitOid, Vec<u8>), Ofs(usize, Vec<u8>) }
fn zlib(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut result = vec![0x78, 0x01, 1];
    result.extend(size.to_le_bytes()); result.extend((!size).to_le_bytes()); result.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| { let a = (a + u32::from(*byte)) % 65_521; (a, (b + a) % 65_521) });
    result.extend(((b << 16) | a).to_be_bytes()); result
}
fn pack(format: GitHashAlgorithm, entries: &[Entry]) -> Vec<u8> {
    let mut output = b"PACK".to_vec(); output.extend(2u32.to_be_bytes());
    output.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    let mut offsets = Vec::new();
    for entry in entries {
        let at = output.len(); offsets.push(at);
        let (kind, bytes, base) = match entry {
            Entry::Direct(kind, bytes) => (*kind, bytes, Vec::new()),
            Entry::Ref(base, bytes) => (7, bytes, base.as_bytes().to_vec()),
            Entry::Ofs(index, bytes) => {
                let mut distance = at - offsets[*index];
                let mut encoded = vec![(distance & 127) as u8];
                while { distance >>= 7; distance != 0 } {
                    distance -= 1; encoded.push(0x80 | (distance & 127) as u8);
                }
                encoded.reverse(); (6, bytes, encoded)
            }
        };
        let mut size = bytes.len(); let mut byte = (kind << 4) | (size & 15) as u8; size >>= 4;
        while size != 0 { output.push(byte | 128); byte = (size & 127) as u8; size >>= 7; }
        output.push(byte); output.extend(base); output.extend(zlib(bytes));
    }
    match format {
        GitHashAlgorithm::Sha1 => output.extend(sha1_digest(&output)),
        GitHashAlgorithm::Sha256 => output.extend(sha256_digest(&output)),
    }
    output
}
fn envelope(format: GitHashAlgorithm, base: GitOid, candidate: GitOid, entries: &[Entry]) -> Vec<u8> {
    let mut header = format!("# v3 git bundle\n@object-format={}\n-{base} parent\n{candidate} refs/heads/main\n\n", format.as_str()).into_bytes();
    header.extend(pack(format, entries)); header
}
fn candidate(format: GitHashAlgorithm, f: &Fixture, parents: &[GitOid], content: &[u8]) -> (GitOid, Vec<u8>, Vec<Entry>) {
    let blob = git_object_id(format, ObjectType::Blob, content);
    let tree_body = tree(blob, f.keep); let tree = git_object_id(format, ObjectType::Tree, &tree_body);
    let commit = body(tree, parents, "exact candidate metadata");
    let oid = git_object_id(format, ObjectType::Commit, &commit);
    (oid, commit.clone(), vec![Entry::Direct(3, content.to_vec()), Entry::Direct(2, tree_body), Entry::Direct(1, commit)])
}
fn inspection(node: &OneNode, f: &Fixture, candidate: GitOid, bytes: &[u8]) -> Result<BundleInspection, BundleInspectionRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &target(), f.target, candidate,
        bytes, &RefVisibility::new(), None, &ReviewOptions::default()))
}
fn copy_then_exclaim(base: &[u8]) -> Vec<u8> {
    let length = u8::try_from(base.len()).unwrap(); assert!(length < 127);
    vec![length, length + 1, 0x90, length, 1, b'!']
}

#[test]
fn inspect_workspace_and_merge_reads_actual_result_and_never_stages_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, f) = fixture(format);
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        for merging in [false, true] {
            let parents = if merging { vec![f.target, f.source] } else { vec![f.target] };
            let (id, commit, entries) = candidate(format, &f, &parents, b"actual reviewed result\n");
            let bytes = envelope(format, f.target, id, &entries);
            assert!(node.read_git_object(id).is_err());
            let result = if merging {
                let merge = NativeMerge { source_ref: incoming(), source_tip: f.source, target_ref: target(),
                    target_tip_before: f.target, base_tip: f.base, merge_commit: id };
                node.runtime().block_on(node.inspect_merge_bundle_in(&request, &merge, &bytes,
                    &RefVisibility::new(), Some(before.basis().id()), &ReviewOptions::default())).unwrap()
            } else { inspection(&node, &f, id, &bytes).unwrap() };
            assert_eq!(result.review.source_head, before.basis().id());
            assert_eq!(result.review.comparison.requested_before, f.target);
            assert_eq!(result.review.comparison.requested_after, id);
            assert_eq!(result.parents, parents); assert_eq!(result.candidate_commit_body, commit);
            assert_eq!(result.bundle_sha256, sha256_digest(&bytes)); assert_eq!(result.pack_objects, 3);
            assert_eq!(result.transport_only_objects, 0);
            let changed = &result.review.comparison.entries;
            assert_eq!(changed.len(), 1); assert_eq!(changed[0].path, b"file");
            let ReviewContent::Text { hunks, .. } = &changed[0].content else { panic!("text review"); };
            assert_eq!(hunks[0].before, b"original\n"); assert_eq!(hunks[0].after, b"actual reviewed result\n");
            assert!(node.read_git_object(id).is_err(), "inspection cannot stage even a valid candidate");
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
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
                assert_eq!(base_id, f.original); entries[0] = Entry::Ref(base_id, delta);
            } else if mode == 1 {
                entries[0] = Entry::Ref(base_id, delta); entries.push(Entry::Direct(3, source.to_vec()));
            } else {
                entries[0] = Entry::Ofs(0, delta); entries.insert(0, Entry::Direct(3, source.to_vec()));
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
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert!(before.selected_closure().closure().objects().contains(&f.secret));
    let base = b"unrelated secret\n";
    let (id, _, mut entries) = candidate(format, &f, &[f.target], &[base.as_slice(), b"!"].concat());
    entries[0] = Entry::Ref(f.secret, copy_then_exclaim(base));
    let bytes = envelope(format, f.target, id, &entries);
    assert!(matches!(inspection(&node, &f, id, &bytes), Err(BundleInspectionRefusal::Pack(_))));
    assert!(node.read_git_object(id).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn checksum_parent_scope_and_extra_object_failures_return_no_partial_result() {
    let format = GitHashAlgorithm::Sha1;
    let (_scratch, node, f) = fixture(format);
    let request = node.request_context();
    let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let (id, _, entries) = candidate(format, &f, &[f.target], b"result\n");
    let bytes = envelope(format, f.target, id, &entries);
    let mut damaged = bytes.clone(); *damaged.last_mut().unwrap() ^= 1;
    assert!(inspection(&node, &f, id, &damaged).is_err());
    let (wrong, _, entries) = candidate(format, &f, &[f.source], b"result\n");
    assert!(inspection(&node, &f, wrong, &envelope(format, f.target, wrong, &entries)).is_err());
    let (id, _, mut entries) = candidate(format, &f, &[f.target], b"result\n");
    entries.push(Entry::Direct(3, b"unrelated uploaded blob".to_vec()));
    assert!(matches!(inspection(&node, &f, id, &envelope(format, f.target, id, &entries)),
        Err(BundleInspectionRefusal::InvalidCandidate(_))));
    let mut hidden = RefVisibility::new(); hidden.push_rule(b"refs/heads/main", &Default::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &target(), f.target, id,
        &bytes, &hidden, None, &ReviewOptions::default())), Err(BundleInspectionRefusal::RefUnavailable)));
    let mut options = ReviewOptions::default(); options.limits.max_diff_work = 1;
    assert!(node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &target(), f.target, id,
        &bytes, &RefVisibility::new(), None, &options)).is_err());
    options.mode = ComparisonMode::MergeBase;
    assert!(node.runtime().block_on(node.inspect_workspace_bundle_in(&request, &target(), f.target, id,
        &bytes, &RefVisibility::new(), None, &options)).is_err());
    assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
    node.shutdown().unwrap();
}
