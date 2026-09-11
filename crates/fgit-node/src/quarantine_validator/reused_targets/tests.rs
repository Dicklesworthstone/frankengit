//! Native hashes, real pack framing and file-backed fabric. Unit selection
//! stand-ins are explicit; the final test obtains selection through real
//! local-source import and uses the production SANS-I/O receive handoff.
use super::*;
use crate::{ClosureSelectionSource, LoopbackReceiveSession, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{IdentityDomain, git_object_id};
use fgit_pack::{NativeChecksumVerifier, read_verified_pack};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionOutcome, DigestBytes, HeadGeneration,
    PrincipalId, RefName, RepositoryCommitId, RepositoryId, TenantId};
use fgit_wire::receive::{ReceiveCommand, ReceiveContext, ReceiveLimits, ReceivePack, SignedPushProfile};
use fgit_wire::{Capabilities, Packet, encode_packets};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-reused-target-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16])).with_object_format(format).with_worker_threads(2)
    }
    fn node(&self, format: GitHashAlgorithm) -> OneNode {
        OneNode::init(self.config(format)).unwrap().0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
#[derive(Clone)]
struct Raw { id: GitOid, kind: ObjectType, bytes: Vec<u8> }
fn raw(format: GitHashAlgorithm, kind: ObjectType, bytes: Vec<u8>) -> Raw {
    Raw { id: git_object_id(format, kind, &bytes), kind, bytes }
}
fn commit(format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> Raw {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str(&format!("author T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\n{label}\n"));
    raw(format, ObjectType::Commit, body.into_bytes())
}
fn tree(format: GitHashAlgorithm, entries: &[(&str, GitOid)]) -> Raw {
    let mut body = Vec::new();
    for (name, id) in entries {
        body.extend_from_slice(format!("100644 {name}\0").as_bytes());
        body.extend_from_slice(id.as_bytes());
    }
    raw(format, ObjectType::Tree, body)
}
fn tag(format: GitHashAlgorithm, target: &Raw, label: &str) -> Raw {
    raw(format, ObjectType::Tag, format!("object {}\ntype {}\ntag {label}\ntagger T <t@example.invalid> 1 +0000\n\n{label}\n",
        target.id, target.kind.label()).into_bytes())
}
fn stored(bytes: &[u8]) -> Vec<u8> {
    let n = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(n.to_le_bytes()); out.extend((!n).to_le_bytes()); out.extend(bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521; (a, (b + a) % 65521)
    });
    out.extend(((b << 16) | a).to_be_bytes()); out
}
fn pack(format: GitHashAlgorithm, objects: &[Raw]) -> Vec<u8> {
    let mut out = b"PACK\0\0\0\x02".to_vec();
    out.extend(u32::try_from(objects.len()).unwrap().to_be_bytes());
    for object in objects {
        let kind = match object.kind { ObjectType::Commit => 1, ObjectType::Tree => 2,
            ObjectType::Blob => 3, ObjectType::Tag => 4 };
        let mut size = object.bytes.len();
        let mut byte = (kind << 4) | u8::try_from(size & 15).unwrap(); size >>= 4;
        while size != 0 {
            out.push(byte | 128); byte = u8::try_from(size & 127).unwrap(); size >>= 7;
        }
        out.push(byte); out.extend(stored(&object.bytes));
    }
    let checksum = match format { GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&out).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&out).to_vec() };
    out.extend(checksum); out
}
fn request(format: GitHashAlgorithm, roots: &[GitOid]) -> ReceiveRequest {
    ReceiveRequest { commands: roots.iter().enumerate().map(|(index, id)| ReceiveCommand {
        old: zero(format), new: *id, ref_name: format!("refs/tags/reused-{index}").into_bytes(),
    }).collect(), capabilities: Vec::new(), push_options: Vec::new(), certificate: None }
}
fn zero(format: GitHashAlgorithm) -> GitOid {
    GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap()
}
fn validator<'a>(node: &'a OneNode, objects: &[Raw], roots: &[GitOid], limits: PackLimits)
    -> ProductionQuarantineValidator<'a>
{
    // This test helper explicitly supplies a selection stand-in, not a proof
    // minted by a caller. The production constructor takes a materialization.
    let closure = PermittedObjectClosure::new(objects.iter().map(|object| object.id).collect());
    let selected = AuthoritySelectedClosure {
        root: permitted_object_closure_root(&closure).unwrap(), closure,
        source: ClosureSelectionSource::RepositoryCommit(RepositoryCommitId::from_digest(
            IdentityDomain::RepositoryCommitRecord.algorithm().id(), CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x61; 32]).unwrap())),
    };
    let mut validator = ProductionQuarantineValidator::new(node, selected, limits,
        ParseLimits { tree_reference_bytes: node.object_format.digest_len(), ..ParseLimits::default() });
    validator.visible_roots = roots.iter().copied().collect(); validator
}
fn put(node: &OneNode, objects: &[Raw]) {
    for object in objects { assert_eq!(node.put_git_object(object.kind, object.bytes.clone()).unwrap().identity(), object.id); }
}
fn validate(v: &ProductionQuarantineValidator<'_>, objects: &[Raw], roots: &[GitOid])
    -> Result<ValidatedClosure, RefusalCode>
{
    let format = v.node.object_format; let bytes = pack(format, objects);
    let quarantined = read_verified_pack(&bytes, format, &PackLimits::default(), &mut || true,
        &NativeChecksumVerifier).unwrap();
    let receipt = QuarantineReceipt { object_format: format, object_count: objects.len() as u32,
        pack_bytes: bytes.len(), delete_only: false };
    v.validate(&request(format, roots), Some(&quarantined), &receipt, &mut || true)
}

#[test]
fn verified_empty_packs_reuse_visible_tips_without_fabric_placement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = scratch.node(format);
        let empty = tree(format, &[]); let tip = commit(format, empty.id, &[], "existing");
        let objects = [empty.clone(), tip.clone()]; put(&node, &objects);
        let v = validator(&node, &objects, &[tip.id], PackLimits::default());
        let admitted = validate(&v, &[], &[tip.id, tip.id]).unwrap();
        assert_eq!(admitted.objects, BTreeSet::from([tip.id]));
        assert_eq!(admitted.object_closure_root,
            permitted_object_closure_root(&PermittedObjectClosure::new(admitted.objects.clone())).unwrap());
        let mut damaged = pack(format, &[]); *damaged.last_mut().unwrap() ^= 1;
        assert!(read_verified_pack(&damaged, format, &PackLimits::default(), &mut || true,
            &NativeChecksumVerifier).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn historical_ancestors_and_nested_tag_targets_are_proven_from_visible_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = scratch.node(format);
        let empty = tree(format, &[]); let base = commit(format, empty.id, &[], "base");
        let tip = commit(format, empty.id, &[base.id], "tip");
        let inner = tag(format, &tip, "inner"); let outer = tag(format, &inner, "outer");
        let objects = [empty, base.clone(), tip.clone(), inner.clone(), outer.clone()]; put(&node, &objects);
        let v = validator(&node, &objects, &[outer.id], PackLimits::default());
        for id in [base.id, tip.id, inner.id, outer.id] {
            assert_eq!(validate(&v, &[], &[id]).unwrap().objects, BTreeSet::from([id]));
        }
        assert_eq!(validate(&v, &[], &[base.id, inner.id]).unwrap().objects,
            BTreeSet::from([base.id, inner.id]));
        node.shutdown().unwrap();
    }
}

#[test]
fn hidden_only_disconnected_and_merely_present_targets_cannot_be_resurrected() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = scratch.node(format);
        let empty = tree(format, &[]); let visible = commit(format, empty.id, &[], "visible");
        let hidden = commit(format, empty.id, &[], "hidden-only");
        let stray = commit(format, empty.id, &[], "unselected presence");
        let objects = [empty, visible.clone(), hidden.clone()]; put(&node, &objects); put(&node, &[stray.clone()]);
        let v = validator(&node, &objects, &[visible.id], PackLimits::default());
        for id in [hidden.id, stray.id] {
            assert_eq!(validate(&v, &[], &[id]), Err(RefusalCode::ObjectClosureIncomplete));
        }
        let no_visible = validator(&node, &objects, &[], PackLimits::default());
        assert_eq!(validate(&no_visible, &[], &[visible.id]), Err(RefusalCode::ObjectClosureIncomplete));
        let allowed = validator(&node, &objects, &[hidden.id], PackLimits::default());
        assert!(validate(&allowed, &[], &[hidden.id]).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn mixed_uploaded_and_reused_roots_keep_only_the_requested_witness() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = scratch.node(format);
        let empty = tree(format, &[]); let old = commit(format, empty.id, &[], "old");
        let originals = [empty.clone(), old.clone()]; put(&node, &originals);
        let new = commit(format, empty.id, &[old.id], "new");
        let unrelated = raw(format, ObjectType::Blob, b"not requested".to_vec());
        let v = validator(&node, &originals, &[old.id], PackLimits::default());
        let got = validate(&v, &[new.clone(), unrelated.clone()], &[old.id, new.id]).unwrap();
        assert_eq!(got.objects, BTreeSet::from([old.id, new.id]));
        assert!(node.read_git_object(new.id).is_ok());
        assert!(node.read_git_object(unrelated.id).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_selected_bytes_and_bad_reused_roots_fail_before_staging_any_upload() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new(); let node = scratch.node(format);
    let absent = raw(format, ObjectType::Blob, b"selected but missing".to_vec());
    let upload = raw(format, ObjectType::Blob, b"valid new upload".to_vec());
    let v = validator(&node, &[absent.clone()], &[absent.id], PackLimits::default());
    assert_eq!(validate(&v, &[upload.clone()], &[upload.id, absent.id]), Err(RefusalCode::EvidenceMissing));
    assert!(node.read_git_object(upload.id).is_err());
    put(&node, &[absent.clone()]);
    assert_eq!(validate(&v, &[upload.clone()], &[upload.id, absent.id]).unwrap().objects,
        BTreeSet::from([upload.id, absent.id]));
    node.shutdown().unwrap();
}

#[test]
fn duplicate_targets_and_uploaded_frontiers_share_one_inclusive_original_byte_budget() {
    let format = GitHashAlgorithm::Sha1;
    let scratch = Scratch::new(); let node = scratch.node(format);
    let blob = raw(format, ObjectType::Blob, vec![b'x'; 1024]); put(&node, &[blob.clone()]);
    let uploaded = tree(format, &[("a", blob.id), ("b", blob.id)]);
    let bounded = validator(&node, &[blob.clone()], &[blob.id], PackLimits {
        max_cached_bytes: 1023, max_total_expanded_bytes: 1023, ..PackLimits::default()
    });
    assert_eq!(validate(&bounded, &[uploaded.clone()], &[blob.id, blob.id, uploaded.id]),
        Err(RefusalCode::ResourceBudgetExceeded));
    assert!(node.read_git_object(uploaded.id).is_err());
    let inclusive = validator(&node, &[blob.clone()], &[blob.id], PackLimits {
        max_cached_bytes: 1024, max_total_expanded_bytes: 1024, ..PackLimits::default()
    });
    assert_eq!(validate(&inclusive, &[uploaded.clone()], &[blob.id, blob.id, uploaded.id]).unwrap().objects,
        BTreeSet::from([blob.id, uploaded.id]));
    node.shutdown().unwrap();
}

#[test]
fn visibility_walk_checks_required_kinds_and_cannot_follow_gitlinks() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new(); let node = scratch.node(format);
    let empty = tree(format, &[]);
    let wrong = commit(format, empty.id, &[empty.id], "tree used as parent");
    let foreign = commit(format, empty.id, &[], "external");
    let mut bytes = b"160000 external\0".to_vec(); bytes.extend(foreign.id.as_bytes());
    let link = raw(format, ObjectType::Tree, bytes);
    let visible = commit(format, link.id, &[], "gitlink");
    let objects = [empty.clone(), wrong.clone(), foreign.clone(), link, visible.clone()]; put(&node, &objects);
    let bad = validator(&node, &objects, &[wrong.id], PackLimits::default());
    assert_eq!(validate(&bad, &[], &[empty.id]), Err(RefusalCode::EvidenceInvalid));
    let linked = validator(&node, &objects, &[visible.id], PackLimits::default());
    assert_eq!(validate(&linked, &[], &[foreign.id]), Err(RefusalCode::ObjectClosureIncomplete));
    node.shutdown().unwrap();
}

#[test]
fn missing_pack_stays_distinct_and_cancellation_precedes_original_reads() {
    let format = GitHashAlgorithm::Sha1;
    let scratch = Scratch::new(); let node = scratch.node(format);
    let absent = raw(format, ObjectType::Blob, b"selected absent".to_vec());
    let v = validator(&node, &[absent.clone()], &[absent.id], PackLimits::default());
    let bytes = pack(format, &[]);
    let quarantined = read_verified_pack(&bytes, format, &PackLimits::default(), &mut || true,
        &NativeChecksumVerifier).unwrap();
    let receipt = QuarantineReceipt { object_format: format, object_count: 0,
        pack_bytes: bytes.len(), delete_only: false };
    let input = request(format, &[absent.id]);
    assert_eq!(v.validate(&input, Some(&quarantined), &receipt, &mut || false),
        Err(RefusalCode::CancellationInProgress));
    let missing = QuarantineReceipt { pack_bytes: 0, ..receipt };
    assert_eq!(fgit_admission::validate_receive(&input, None, &missing, &v, &mut || true),
        Err(RefusalCode::ObjectClosureIncomplete));
    node.shutdown().unwrap();
}

fn principal() -> PrincipalId { PrincipalId::from_bytes([0xb3; 16]) }
fn write_source(root: &Path, format: GitHashAlgorithm, objects: &[Raw], tip: GitOid) {
    std::fs::create_dir_all(root.join("refs/heads")).unwrap();
    std::fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    std::fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    for object in objects {
        let text = object.id.to_string(); let path = root.join("objects").join(&text[..2]);
        std::fs::create_dir_all(&path).unwrap();
        let framed = [format!("{} {}\0", object.kind.label(), object.bytes.len()).as_bytes(), &object.bytes].concat();
        std::fs::write(path.join(&text[2..]), stored(&framed)).unwrap();
    }
    std::fs::write(root.join("refs/heads/main"), format!("{tip}\n")).unwrap();
}
fn wire_proof(node: &OneNode, old: GitOid, new: GitOid, objects: &[Raw]) -> BasisBoundValidatedReceive {
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let limits = ReceiveLimits::default();
    let capabilities = format!("report-status object-format={}", node.object_format.as_str());
    let advertised = Capabilities::parse_v1(capabilities.as_bytes(), &limits.wire).unwrap();
    let validator = node.production_quarantine_validator(&selected, limits.pack.clone(),
        ParseLimits { tree_reference_bytes: node.object_format.digest_len(), ..ParseLimits::default() }).unwrap();
    let command = format!("{old} {new} refs/heads/copied\0{capabilities}").into_bytes();
    let prefix = encode_packets(&[Packet::Data(command), Packet::Flush], &limits.wire).unwrap();
    let context = ReceiveContext::new(node.object_format, advertised, limits, SignedPushProfile::Refuse).unwrap();
    let mut receiver = ReceivePack::new(context).unwrap();
    receiver.push_bytes(&prefix).unwrap(); receiver.push_bytes(&pack(node.object_format, objects)).unwrap();
    let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
    receiver.finish_with_handoff(&mut handoff, &mut || true).unwrap();
    handoff.into_validated_receive().unwrap()
}

#[test]
fn empty_wire_pack_creates_historical_branch_and_recovers_after_advance_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let empty = tree(format, &[]);
        let base = commit(format, empty.id, &[], "root");
        let tip = commit(format, empty.id, &[base.id], "current advertised tip");
        let source = scratch.0.join("source");
        write_source(&source, format, &[empty.clone(), base.clone(), tip.clone()], tip.id);
        let mut node = scratch.node(format); node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &request, &source, principal(), b"reused-fixture")).unwrap();
        assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        let proof = wire_proof(&node, zero(format), base.id, &[]);
        let session = LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(b"copy-existing".to_vec()).unwrap());
        let applied = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &request, &session, &proof, fgit_admission::AdmissionLimits::default())).unwrap();
        let original = applied.commands[0].terminal.clone();
        assert!(matches!(original.outcome, DecisionOutcome::Committed { .. }));
        let child = commit(format, empty.id, &[base.id], "later copied branch");
        let advance = wire_proof(&node, base.id, child.id, &[child.clone()]);
        let later = LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(b"advance-existing".to_vec()).unwrap());
        let result = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &request, &later, &advance, fgit_admission::AdmissionLimits::default())).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let copied = RefName::try_new(b"refs/heads/copied").unwrap();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let recovered = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &request, &session, &proof, fgit_admission::AdmissionLimits::default())).unwrap();
        assert_eq!(recovered.commands[0].terminal, original);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context(); let proof = wire_proof(&node, zero(format), base.id, &[]);
        let retry = node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &request, &session, &proof, fgit_admission::AdmissionLimits::default())).unwrap();
        assert_eq!(retry.commands[0].terminal, original);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().refs[&copied], child.id);
        node.shutdown().unwrap();
    }
}
