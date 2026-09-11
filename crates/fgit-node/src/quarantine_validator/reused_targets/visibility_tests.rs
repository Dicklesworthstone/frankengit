//! Source-scope tests use real native hashes, packs and file-backed fabric.
//! Unit tests explicitly choose synthetic visible roots; the integration test
//! derives the disconnected-history case from actual import and ref deletion.
use super::*;
use crate::{ClosureSelectionSource, LoopbackReceiveSession, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{IdentityDomain, git_object_id};
use fgit_pack::{NativeChecksumVerifier, read_verified_pack};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionOutcome, DigestBytes, HeadGeneration,
    PrincipalId, RefName, RepositoryCommitId, RepositoryId, TenantId};
use fgit_wire::receive::ReceiveCommand;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-input-visibility-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16])).with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
#[derive(Clone)]
struct Raw { id: GitOid, kind: ObjectType, body: Vec<u8> }
fn raw(format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> Raw {
    Raw { id: git_object_id(format, kind, &body), kind, body }
}
fn tree(format: GitHashAlgorithm, entries: &[(&str, GitOid)]) -> Raw {
    let mut body = Vec::new();
    for (name, id) in entries {
        body.extend(format!("100644 {name}\0").as_bytes()); body.extend(id.as_bytes());
    }
    raw(format, ObjectType::Tree, body)
}
fn commit(format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> Raw {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str(&format!("author T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\n{label}\n"));
    raw(format, ObjectType::Commit, body.into_bytes())
}
fn stored(body: &[u8]) -> Vec<u8> {
    let n = u16::try_from(body.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(n.to_le_bytes()); out.extend((!n).to_le_bytes()); out.extend(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521; (a, (a + b) % 65521)
    });
    out.extend(((b << 16) | a).to_be_bytes()); out
}
fn header(kind: u8, mut size: usize) -> Vec<u8> {
    let mut out = Vec::new(); let mut byte = (kind << 4) | (size & 15) as u8; size >>= 4;
    while size != 0 { out.push(byte | 128); byte = (size & 127) as u8; size >>= 7; }
    out.push(byte); out
}
fn full(object: &Raw) -> Vec<u8> {
    let kind = match object.kind { ObjectType::Commit => 1, ObjectType::Tree => 2,
        ObjectType::Blob => 3, ObjectType::Tag => 4 };
    [header(kind, object.body.len()), stored(&object.body)].concat()
}
fn ref_copy(base: &Raw, suffix: &[u8]) -> Vec<u8> {
    assert!(base.body.len() < 100 && !base.body.is_empty() && suffix.len() < 20);
    let mut program = vec![base.body.len() as u8, (base.body.len() + suffix.len()) as u8,
        0x90, base.body.len() as u8];
    if !suffix.is_empty() { program.push(suffix.len() as u8); program.extend(suffix); }
    [header(7, program.len()), base.id.as_bytes().to_vec(), stored(&program)].concat()
}
fn packed(format: GitHashAlgorithm, entries: &[Vec<u8>]) -> (QuarantinedPack, QuarantineReceipt) {
    let mut bytes = b"PACK\0\0\0\x02".to_vec(); bytes.extend((entries.len() as u32).to_be_bytes());
    for entry in entries { bytes.extend(entry); }
    let checksum = match format { GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&bytes).to_vec() };
    bytes.extend(checksum);
    let pack = read_verified_pack(&bytes, format, &PackLimits::default(), &mut || true,
        &NativeChecksumVerifier).unwrap();
    (pack, QuarantineReceipt { object_format: format, object_count: entries.len() as u32,
        pack_bytes: bytes.len(), delete_only: false })
}
fn zero(format: GitHashAlgorithm) -> GitOid {
    GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap()
}
fn request(format: GitHashAlgorithm, old: GitOid, new: GitOid, name: &str) -> ReceiveRequest {
    assert_eq!(old.algorithm(), format);
    ReceiveRequest { commands: vec![ReceiveCommand { old, new, ref_name: name.as_bytes().to_vec() }],
        capabilities: Vec::new(), push_options: Vec::new(), certificate: None }
}
fn fixture_validator<'a>(node: &'a OneNode, originals: &[Raw], roots: &[GitOid], limits: PackLimits)
    -> ProductionQuarantineValidator<'a>
{
    let closure = PermittedObjectClosure::new(originals.iter().map(|o| o.id).collect());
    let selected_closure = AuthoritySelectedClosure { root: permitted_object_closure_root(&closure).unwrap(), closure,
        source: ClosureSelectionSource::RepositoryCommit(RepositoryCommitId::from_digest(
            IdentityDomain::RepositoryCommitRecord.algorithm().id(), CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x61; 32]).unwrap())) };
    ProductionQuarantineValidator { node, selected_closure, visible_roots: roots.iter().copied().collect(),
        pack_limits: limits, parse_limits: ParseLimits { tree_reference_bytes: node.object_format.digest_len(),
            ..ParseLimits::default() } }
}
fn put(node: &OneNode, objects: &[Raw]) {
    for object in objects { assert_eq!(node.put_git_object(object.kind, object.body.clone()).unwrap().identity(), object.id); }
}
fn check(v: &ProductionQuarantineValidator<'_>, entries: &[Vec<u8>], target: GitOid)
    -> Result<ValidatedClosure, RefusalCode>
{
    let format = v.node.object_format; let (pack, receipt) = packed(format, entries);
    v.validate(&request(format, zero(format), target, "refs/tags/result"), Some(&pack), &receipt, &mut || true)
}

#[test]
fn uploaded_wrappers_cannot_publish_hidden_only_graph_inputs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
        let empty = tree(format, &[]); let public = commit(format, empty.id, &[], "public");
        let secret = raw(format, ObjectType::Blob, b"not visible\r\n".to_vec());
        let private_tree = tree(format, &[("secret", secret.id)]);
        let private = commit(format, private_tree.id, &[], "private");
        let originals = [empty, public.clone(), secret.clone(), private_tree.clone(), private.clone()];
        put(&node, &originals);
        let v = fixture_validator(&node, &originals, &[public.id], PackLimits::default());
        let wrapper_tree = tree(format, &[("copied", secret.id)]);
        let wrapper = commit(format, wrapper_tree.id, &[public.id], "wrapper");
        let parent_wrapper = commit(format, private_tree.id, &[private.id], "hidden parent");
        for (entries, id) in [(vec![full(&wrapper_tree), full(&wrapper)], wrapper.id),
            (vec![full(&parent_wrapper)], parent_wrapper.id)] {
            assert_eq!(check(&v, &entries, id), Err(RefusalCode::ObjectClosureIncomplete));
            assert!(node.read_git_object(id).is_err());
        }
        assert!(node.read_git_object(wrapper_tree.id).is_err());
        let shared = fixture_validator(&node, &originals, &[public.id, private.id], PackLimits::default());
        assert!(check(&shared, &[full(&wrapper_tree), full(&wrapper)], wrapper.id).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn copying_a_hidden_delta_base_including_its_exact_oid_does_not_prove_upload_ownership() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
        let public = raw(format, ObjectType::Blob, b"public".to_vec());
        let secret = raw(format, ObjectType::Blob, b"hidden base".to_vec());
        let originals = [public.clone(), secret.clone()]; put(&node, &originals);
        let v = fixture_validator(&node, &originals, &[public.id], PackLimits::default());
        for suffix in [b"!".as_slice(), b"".as_slice()] {
            let target = raw(format, ObjectType::Blob, [secret.body.as_slice(), suffix].concat());
            let (pack, _) = packed(format, &[ref_copy(&secret, suffix)]);
            let bases = v.external_bases(&pack, &mut || true).unwrap();
            let (_, ids) = v.verified_pack_objects(&pack, &bases, &mut || true).unwrap();
            assert!(!independent_uploads(&pack, &ids, &mut || true).unwrap().contains(&secret.id));
            assert_eq!(check(&v, &[ref_copy(&secret, suffix)], target.id), Err(RefusalCode::ObjectClosureIncomplete));
            if target.id != secret.id { assert!(node.read_git_object(target.id).is_err()); }
            let allowed = fixture_validator(&node, &originals, &[secret.id], PackLimits::default());
            assert!(check(&allowed, &[ref_copy(&secret, suffix)], target.id).is_ok());
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn complete_uploaded_bodies_and_forward_deltas_remain_valid_without_visible_originals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
        let base = raw(format, ObjectType::Blob, b"known uploaded bytes".to_vec());
        put(&node, &[base.clone()]);
        let v = fixture_validator(&node, &[base.clone()], &[], PackLimits::default());
        let result = raw(format, ObjectType::Blob, [base.body.as_slice(), b"!"].concat());
        for entries in [vec![full(&result)], vec![full(&base), ref_copy(&base, b"!")],
            vec![ref_copy(&base, b"!"), full(&base)]] {
            assert!(check(&v, &entries, result.id).unwrap().objects.contains(&result.id));
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn one_visibility_walk_and_kind_cache_keep_the_original_byte_limit_inclusive() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
    let base = raw(format, ObjectType::Blob, b"shared original".to_vec()); put(&node, &[base.clone()]);
    let result = raw(format, ObjectType::Blob, [base.body.as_slice(), b"!"].concat());
    let new_tree = tree(format, &[("a", base.id), ("b", result.id), ("c", base.id)]);
    let entries = [ref_copy(&base, b"!"), full(&new_tree)];
    for (bytes, allowed) in [(base.body.len() - 1, false), (base.body.len(), true)] {
        let v = fixture_validator(&node, &[base.clone()], &[base.id], PackLimits {
            max_cached_bytes: bytes, ..PackLimits::default() });
        let answer = check(&v, &entries, new_tree.id);
        if allowed { assert_eq!(answer.unwrap().objects, BTreeSet::from([result.id, new_tree.id])); }
        else {
            assert_eq!(answer, Err(RefusalCode::ResourceBudgetExceeded));
            assert!(node.read_git_object(new_tree.id).is_err());
        }
    }
    node.shutdown().unwrap();
}

#[test]
fn irrelevant_visible_blob_contents_are_not_copied_to_prove_another_dependency() {
    let format = GitHashAlgorithm::Sha1;
    let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
    let huge = raw(format, ObjectType::Blob, vec![b'x'; 8192]);
    let needed = raw(format, ObjectType::Blob, b"wanted".to_vec());
    let old_tree = tree(format, &[("a-needed", needed.id), ("z-large", huge.id)]);
    let tip = commit(format, old_tree.id, &[], "visible");
    let originals = [huge, needed.clone(), old_tree.clone(), tip.clone()]; put(&node, &originals);
    let exact = old_tree.body.len() + tip.body.len() + needed.body.len();
    let v = fixture_validator(&node, &originals, &[tip.id], PackLimits { max_cached_bytes: exact,
        ..PackLimits::default() });
    let upload = tree(format, &[("copy", needed.id)]);
    assert_eq!(check(&v, &[full(&upload)], upload.id).unwrap().objects, BTreeSet::from([upload.id]));
    node.shutdown().unwrap();
}

#[test]
fn incomplete_visibility_proof_and_cancellation_never_grant_cached_partial_inputs() {
    let format = GitHashAlgorithm::Sha1;
    let scratch = Scratch::new(); let node = OneNode::init(scratch.config(format)).unwrap().0;
    let public = raw(format, ObjectType::Blob, b"public".to_vec());
    let private = raw(format, ObjectType::Blob, b"private".to_vec());
    let originals = [public.clone(), private.clone()]; put(&node, &originals);
    let v = fixture_validator(&node, &originals, &[public.id], PackLimits::default());
    let bases = ExternalBases { bases: BTreeMap::new(), read_bytes: 0 };
    let mut frontier = OriginalFrontier::new(&v, &bases).unwrap();
    let mut budget = 10;
    assert_eq!(frontier.authorize(&BTreeSet::from([public.id, private.id]), &mut budget, &mut || true),
        Err(RefusalCode::ObjectClosureIncomplete));
    assert_eq!(frontier.kind(public.id, &mut || true), Err(RefusalCode::ObjectClosureIncomplete));
    frontier.authorize(&BTreeSet::from([public.id]), &mut budget, &mut || true).unwrap();
    assert_eq!(frontier.kind(public.id, &mut || true).unwrap(), ObjectType::Blob);
    assert_eq!(frontier.authorize(&BTreeSet::from([public.id]), &mut budget, &mut || false),
        Err(RefusalCode::CancellationInProgress));
    assert_eq!(frontier.kind(public.id, &mut || true), Err(RefusalCode::ObjectClosureIncomplete));
    node.shutdown().unwrap();
}

fn loose(root: &Path, object: &Raw) {
    let hex = object.id.to_string(); let path = root.join("objects").join(&hex[..2]).join(&hex[2..]);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = [format!("{} {}\0", object.kind.label(), object.body.len()).as_bytes(), object.body.as_slice()].concat();
    std::fs::write(path, stored(&bytes)).unwrap();
}
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xd3; 16]) }

#[test]
fn production_factory_cannot_republish_disconnected_history_through_an_uploaded_wrapper() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let root = scratch.0.join("source");
        std::fs::create_dir_all(root.join("refs/heads")).unwrap();
        std::fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        std::fs::write(root.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
            GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
        }).unwrap();
        let empty = tree(format, &[]); let public = commit(format, empty.id, &[], "public");
        let secret = raw(format, ObjectType::Blob, b"detached content".to_vec());
        let private_tree = tree(format, &[("secret", secret.id)]);
        let private = commit(format, private_tree.id, &[], "private");
        for object in [&empty, &public, &secret, &private_tree, &private] { loose(&root, object); }
        std::fs::write(root.join("refs/heads/main"), format!("{}\n", public.id)).unwrap();
        std::fs::write(root.join("refs/heads/private"), format!("{}\n", private.id)).unwrap();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let cx = node.request_context();
        let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &cx, &root, principal(), b"visibility-import")).unwrap();
        assert!(imported.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
        let before = node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap();
        let validator = node.production_quarantine_validator(&before, PackLimits::default(),
            ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() }).unwrap();
        let delete = request(format, private.id, zero(format), "refs/heads/private");
        let receipt = QuarantineReceipt { object_format: format, object_count: 0, pack_bytes: 0, delete_only: true };
        let proof = validate_receive_at_basis(&delete, None, &receipt, before.basis(), &validator, &mut || true).unwrap();
        let session = LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(b"detach-private".to_vec()).unwrap());
        let deleted = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &cx, &session, &proof, fgit_admission::AdmissionLimits::default())).unwrap();
        assert!(matches!(deleted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let cx = node.request_context(); let before = node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap();
        assert!(before.selected_closure().closure().objects().contains(&secret.id));
        assert!(!before.snapshot().refs.contains_key(&RefName::try_new(b"refs/heads/private").unwrap()));
        let v = node.production_quarantine_validator(&before, PackLimits::default(),
            ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() }).unwrap();
        let new_tree = tree(format, &[("stolen", secret.id)]);
        let candidate = commit(format, new_tree.id, &[public.id], "new visible wrapper");
        assert_eq!(check(&v, &[full(&new_tree), full(&candidate)], candidate.id), Err(RefusalCode::ObjectClosureIncomplete));
        assert!(node.read_git_object(candidate.id).is_err() && node.read_git_object(new_tree.id).is_err());
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap().basis(), before.basis());
        // Supplying the actual bytes is a different, permitted input: the
        // caller no longer asks the repository to disclose detached content.
        let (pack, receipt) = packed(format, &[full(&secret), full(&new_tree), full(&candidate)]);
        let update = request(format, public.id, candidate.id, "refs/heads/main");
        let proof = validate_receive_at_basis(&update, Some(&pack), &receipt, before.basis(), &v, &mut || true).unwrap();
        let session = LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(b"supplied-content".to_vec()).unwrap());
        let applied = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &cx, &session, &proof, fgit_admission::AdmissionLimits::default())).unwrap();
        assert!(matches!(applied.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap().snapshot().refs[
            &RefName::try_new(b"refs/heads/main").unwrap()], candidate.id);
        node.shutdown().unwrap();
    }
}
