//! Real native hashes, pack parsing and file-backed fabric. Wrong-kind fixtures
//! are checksum-valid packs of individually parseable objects, not corrupt IDs.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::IdentityDomain;
use fgit_pack::{NativeChecksumVerifier, read_verified_pack};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestBytes, RepositoryCommitId, RepositoryId, TenantId};
use fgit_wire::receive::ReceiveCommand;
use crate::{ClosureSelectionSource, NodeConfig};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RefName};
use crate::LoopbackReceiveSession;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct ScratchDirectory(PathBuf);
impl ScratchDirectory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-typed-quarantine-{}-{}",
            std::process::id(), NEXT.fetch_add(1,Ordering::Relaxed))))
    }
    fn path(&self) -> &Path { &self.0 }
}
impl Drop for ScratchDirectory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let len=u16::try_from(bytes.len()).unwrap();
    let mut output=vec![0x78,0x01,0x01];
    output.extend_from_slice(&len.to_le_bytes()); output.extend_from_slice(&(!len).to_le_bytes());
    output.extend_from_slice(bytes);
    let (a,b)=bytes.iter().fold((1u32,0u32),|(a,b),byte| {
        let a=(a+u32::from(*byte))%65521; (a,(b+a)%65521)
    });
    output.extend_from_slice(&((b<<16)|a).to_be_bytes()); output
}
// Unit frontier fixtures explicitly supply an authenticated-selection stand-in.
// The final handoff test instead obtains real selection from the node authority.
fn selected_closure(objects: BTreeSet<GitOid>) -> AuthoritySelectedClosure {
    let closure=PermittedObjectClosure::new(objects);
    AuthoritySelectedClosure { root:permitted_object_closure_root(&closure).unwrap(), closure,
        source:ClosureSelectionSource::RepositoryCommit(RepositoryCommitId::from_digest(
            IdentityDomain::RepositoryCommitRecord.algorithm().id(),CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[0x61;32]).unwrap())) }
}

#[derive(Clone)]
struct Raw { id: GitOid, kind: ObjectType, body: Vec<u8> }
fn raw(format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> Raw {
    Raw { id: fgit_crypto::git_object_id(format, kind, &body), kind, body }
}
fn commit(format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> Raw {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str(&format!("author T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\n{label}\n"));
    raw(format, ObjectType::Commit, body.into_bytes())
}
fn tree(format: GitHashAlgorithm, entries: &[(&str, &str, GitOid)]) -> Raw {
    let mut body = Vec::new();
    for (mode, name, id) in entries {
        body.extend_from_slice(format!("{mode} {name}\0").as_bytes());
        body.extend_from_slice(id.as_bytes());
    }
    raw(format, ObjectType::Tree, body)
}
fn tag(format: GitHashAlgorithm, target: GitOid, kind: &str) -> Raw {
    raw(format, ObjectType::Tag, format!("object {target}\ntype {kind}\ntag typed\ntagger T <t@example.invalid> 1 +0000\n\nlabel\n").into_bytes())
}
fn header(kind: u8, mut size: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = (kind << 4) | (size as u8 & 15); size >>= 4;
    while size != 0 { bytes.push(byte | 128); byte = size as u8 & 127; size >>= 7; }
    bytes.push(byte); bytes
}
fn full(object: &Raw) -> Vec<u8> {
    let kind = match object.kind { ObjectType::Commit => 1, ObjectType::Tree => 2,
        ObjectType::Blob => 3, ObjectType::Tag => 4 };
    [header(kind, object.body.len()), zlib_stored(&object.body)].concat()
}
fn varint(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop { let byte = value as u8 & 127; value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}
fn delta(base: &Raw, target: &Raw) -> Vec<u8> {
    assert_eq!(base.kind, target.kind);
    let mut program = [varint(base.body.len()), varint(target.body.len())].concat();
    for chunk in target.body.chunks(127) { program.push(chunk.len() as u8); program.extend_from_slice(chunk); }
    [header(7, program.len()), base.id.as_bytes().to_vec(), zlib_stored(&program)].concat()
}
fn packed(format: GitHashAlgorithm, entries: &[Vec<u8>]) -> (QuarantinedPack, QuarantineReceipt) {
    let mut bytes = b"PACK\0\0\0\x02".to_vec();
    bytes.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
    for entry in entries { bytes.extend_from_slice(entry); }
    match format {
        GitHashAlgorithm::Sha1 => bytes.extend_from_slice(&fgit_crypto::sha1_digest(&bytes)),
        GitHashAlgorithm::Sha256 => bytes.extend_from_slice(&fgit_crypto::sha256_digest(&bytes)),
    }
    let pack = read_verified_pack(&bytes, format, &PackLimits::default(), &mut || true, &NativeChecksumVerifier).unwrap();
    let receipt = QuarantineReceipt { object_format: format, object_count: u32::try_from(entries.len()).unwrap(),
        pack_bytes: bytes.len(), delete_only: false };
    (pack, receipt)
}
fn request(format: GitHashAlgorithm, roots: &[GitOid]) -> ReceiveRequest {
    ReceiveRequest { commands: roots.iter().enumerate().map(|(n,id)| ReceiveCommand {
        old: GitOid::from_hex(format, &"0".repeat(2 * format.digest_len())).unwrap(), new: *id,
        ref_name: format!("refs/tags/test-{n}").into_bytes(),
    }).collect(), capabilities: Vec::new(), push_options: Vec::new(), certificate: None }
}
fn node(format: GitHashAlgorithm, scratch: &ScratchDirectory) -> OneNode {
    OneNode::init(NodeConfig::new(scratch.path().to_path_buf(), TenantId::from_bytes([0x71;16]),
        RepositoryId::from_bytes([0x72;16])).with_object_format(format).with_worker_threads(2)).unwrap().0
}
fn selected_validator<'a>(node: &'a OneNode, format: GitHashAlgorithm, originals: &[GitOid], limits: PackLimits)
    -> ProductionQuarantineValidator<'a>
{
    ProductionQuarantineValidator::new(node, selected_closure(originals.iter().copied().collect()), limits,
        ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() })
}
fn check(validator: &ProductionQuarantineValidator<'_>, objects: &[Raw], roots: &[GitOid])
    -> Result<ValidatedClosure, RefusalCode>
{
    let format = validator.node.object_format;
    let (pack, receipt) = packed(format, &objects.iter().map(full).collect::<Vec<_>>());
    validator.validate(&request(format, roots), Some(&pack), &receipt, &mut || true)
}

#[test]
fn uploaded_commit_tree_and_parent_edges_cannot_name_other_native_kinds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new(); let node = node(format, &scratch);
        let validator = selected_validator(&node, format, &[], PackLimits::default());
        let blob = raw(format, ObjectType::Blob, b"not a tree or commit".to_vec());
        let empty = tree(format, &[]); let parent = commit(format, empty.id, &[], "parent");
        let wrong_tree = commit(format, blob.id, &[], "wrong tree");
        let wrong_parent = commit(format, empty.id, &[blob.id], "wrong parent");
        let tree_parent = commit(format, empty.id, &[empty.id], "tree is not a parent");
        for bad in [&wrong_tree, &wrong_parent, &tree_parent] {
            assert_eq!(check(&validator, &[blob.clone(), empty.clone(), bad.clone()], &[bad.id]), Err(RefusalCode::EvidenceInvalid));
            assert!(node.read_git_object(bad.id).is_err());
            assert!(node.read_git_object(blob.id).is_err() && node.read_git_object(empty.id).is_err());
        }
        let good = commit(format, empty.id, &[parent.id], "valid child");
        assert_eq!(check(&validator, &[empty.clone(), parent.clone(), good.clone()], &[good.id]).unwrap().objects,
            BTreeSet::from([empty.id, parent.id, good.id]));
        node.shutdown().unwrap();
    }
}

#[test]
fn tree_modes_and_all_tag_target_types_require_the_actual_kind() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new(); let node = node(format, &scratch);
        let validator = selected_validator(&node, format, &[], PackLimits::default());
        let blob = raw(format, ObjectType::Blob, b"blob".to_vec());
        let empty = tree(format, &[]); let root = commit(format, empty.id, &[], "root");
        let inner = tag(format, root.id, "commit");
        let objects = [blob.clone(), empty.clone(), root.clone(), inner.clone()];
        for (mode, wrong, good) in [("40000", &blob, &empty), ("100644", &empty, &blob),
            ("100755", &root, &blob), ("120000", &inner, &blob)]
        {
            let bad = tree(format, &[(mode, "entry", wrong.id)]);
            let mut offered = objects.to_vec(); offered.push(bad.clone());
            assert_eq!(check(&validator, &offered, &[bad.id]), Err(RefusalCode::EvidenceInvalid));
            assert!(node.read_git_object(bad.id).is_err());
            let allowed = tree(format, &[(mode, "entry", good.id)]);
            *offered.last_mut().unwrap() = allowed.clone();
            assert!(check(&validator, &offered, &[allowed.id]).unwrap().objects.contains(&good.id));
        }
        for (declared, expected) in [("blob",ObjectType::Blob), ("tree",ObjectType::Tree),
            ("commit",ObjectType::Commit), ("tag",ObjectType::Tag)]
        {
            for actual in &objects {
                let outer = tag(format, actual.id, declared);
                let mut offered = objects.to_vec();
                if !offered.iter().any(|o| o.id == outer.id) { offered.push(outer.clone()); }
                let result = check(&validator, &offered, &[outer.id]);
                if actual.kind == expected { assert!(result.unwrap().objects.contains(&actual.id)); }
                else { assert_eq!(result, Err(RefusalCode::EvidenceInvalid)); }
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn selected_frontier_requires_real_typed_bytes_and_never_uses_unselected_presence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new(); let node = node(format, &scratch);
        let blob = node.put_git_object(ObjectType::Blob, b"present, wrong kind".to_vec()).unwrap().identity();
        let empty = node.put_git_object(ObjectType::Tree, Vec::new()).unwrap().identity();
        let absent = raw(format, ObjectType::Tree, tree(format, &[("100644","missing",blob)]).body).id;
        let selected = selected_validator(&node, format, &[blob, empty, absent], PackLimits::default());
        for (id, expected) in [(blob, RefusalCode::EvidenceInvalid), (absent, RefusalCode::EvidenceMissing)] {
            let bad = commit(format, id, &[], "bad frontier");
            assert_eq!(check(&selected, &[bad.clone()], &[bad.id]), Err(expected));
            assert!(node.read_git_object(bad.id).is_err());
        }
        let allowed = commit(format, empty, &[], "selected tree");
        let unselected = selected_validator(&node, format, &[], PackLimits::default());
        assert_eq!(check(&unselected, &[allowed.clone()], &[allowed.id]), Err(RefusalCode::ObjectClosureIncomplete));
        assert!(node.read_git_object(allowed.id).is_err());
        assert_eq!(check(&selected, &[allowed.clone()], &[allowed.id]).unwrap().objects, BTreeSet::from([allowed.id]));
        node.shutdown().unwrap();
    }
}

#[test]
fn ambiguous_required_headers_and_zero_edges_refuse_without_selecting_a_convenient_view() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new(); let node = node(format, &scratch);
        let validator = selected_validator(&node, format, &[], PackLimits::default());
        let empty = tree(format, &[]); let good = commit(format, empty.id, &[], "ordinary");
        let text = String::from_utf8(good.body.clone()).unwrap();
        let line = format!("tree {}\n",empty.id);
        for body in [text.replacen(&line,&format!("{line}{line}"),1),
            text.replacen(&line,&format!("{line} continuation\n"),1),
            text.replacen(&line,&format!("{line}parent {}\n continuation\n", good.id),1),
            text.replacen(&line,&format!("tree {}\n", "0".repeat(2*format.digest_len())),1)]
        {
            let bad = raw(format,ObjectType::Commit,body.into_bytes());
            assert_eq!(check(&validator,&[empty.clone(),good.clone(),bad.clone()],&[bad.id]), Err(RefusalCode::ObjectHeaderInvalid));
            assert!(node.read_git_object(bad.id).is_err());
        }
        let valid_tag = tag(format,good.id,"commit");
        let text = String::from_utf8(valid_tag.body.clone()).unwrap();
        for body in [text.replace("type commit\n","type commit\ntype blob\n"),
            text.replace("type commit\n","type commit\n continuation\n")]
        {
            let bad=raw(format,ObjectType::Tag,body.into_bytes());
            assert_eq!(check(&validator,&[empty.clone(),good.clone(),bad.clone()],&[bad.id]), Err(RefusalCode::ObjectHeaderInvalid));
        }
        assert!(check(&validator,&[empty,good,valid_tag.clone()],&[valid_tag.id]).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn repeated_frontier_kinds_and_noncanonical_gitlink_modes_preserve_valid_graphs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch=ScratchDirectory::new(); let node=node(format,&scratch);
        let blob=node.put_git_object(ObjectType::Blob,vec![b'x';4096]).unwrap().identity();
        let missing=GitOid::from_hex(format,&"1".repeat(2*format.digest_len())).unwrap();
        let tree=tree(format,&[("100644","a",blob),("100755","b",blob),("120000","c",blob),
            ("160000","submodule",missing),("0160000","submodule2",missing)]);
        let tip=commit(format,tree.id,&[],"repeated frontier");
        let validator=selected_validator(&node,format,&[blob],PackLimits {
            max_cached_bytes:4096,max_total_expanded_bytes:4096,..PackLimits::default() });
        assert_eq!(check(&validator,&[tree.clone(),tip.clone()],&[tip.id]).unwrap().objects,
            BTreeSet::from([tree.id,tip.id]));
        assert!(node.read_git_object(missing).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn delta_inputs_and_native_frontier_share_one_budget_and_do_not_charge_reused_bases_twice() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch=ScratchDirectory::new(); let node=node(format,&scratch);
        let base=raw(format,ObjectType::Blob,vec![b'b';1024]);
        let other=raw(format,ObjectType::Blob,vec![b'o';2048]);
        for original in [&base,&other] { node.put_git_object(original.kind,original.body.clone()).unwrap(); }
        let result=raw(format,ObjectType::Blob,b"x".to_vec());
        let tree=tree(format,&[("100644","base",base.id),("100644","delta",result.id),("100644","other",other.id)]);
        let tip=commit(format,tree.id,&[],"one shared input ledger");
        let (pack,receipt)=packed(format,&[delta(&base,&result),full(&tree),full(&tip)]);
        let mut limits=PackLimits {max_cached_bytes:3071,max_total_expanded_bytes:3071,..PackLimits::default()};
        let bounded=selected_validator(&node,format,&[base.id,other.id],limits.clone());
        assert_eq!(bounded.validate(&request(format,&[tip.id]),Some(&pack),&receipt,&mut || true),Err(RefusalCode::ResourceBudgetExceeded));
        for object in [&result,&tree,&tip] { assert!(node.read_git_object(object.id).is_err()); }
        limits.max_cached_bytes=3072; limits.max_total_expanded_bytes=3072;
        let allowed=selected_validator(&node,format,&[base.id,other.id],limits);
        assert_eq!(allowed.validate(&request(format,&[tip.id]),Some(&pack),&receipt,&mut || true).unwrap().objects,
            BTreeSet::from([result.id,tree.id,tip.id]));
        node.shutdown().unwrap();
    }
}

#[test]
fn forward_delta_native_edges_are_verified_without_losing_transport_only_dependencies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch=ScratchDirectory::new(); let node=node(format,&scratch);
        let validator=selected_validator(&node,format,&[],PackLimits::default());
        let empty=tree(format,&[]); let blob=raw(format,ObjectType::Blob,b"not a tree".to_vec());
        let base=commit(format,empty.id,&[],"transport base");
        let bad=commit(format,blob.id,&[],"reconstructed wrong tree");
        let (pack,receipt)=packed(format,&[delta(&base,&bad),full(&empty),full(&blob),full(&base)]);
        assert_eq!(validator.validate(&request(format,&[bad.id]),Some(&pack),&receipt,&mut || true),Err(RefusalCode::EvidenceInvalid));
        for id in [bad.id,empty.id,blob.id,base.id] { assert!(node.read_git_object(id).is_err()); }
        let good=commit(format,empty.id,&[],"reconstructed good tree");
        let (pack,receipt)=packed(format,&[delta(&base,&good),full(&empty),full(&blob),full(&base)]);
        assert_eq!(validator.validate(&request(format,&[good.id]),Some(&pack),&receipt,&mut || true).unwrap().objects,
            BTreeSet::from([good.id,base.id,empty.id]));
        assert!(node.read_git_object(blob.id).is_err());
        node.shutdown().unwrap();
    }
}

#[test]
fn contradictory_kind_requirements_refuse_in_either_command_order() {
    let format=GitHashAlgorithm::Sha256;
    let scratch=ScratchDirectory::new(); let node=node(format,&scratch);
    let validator=selected_validator(&node,format,&[],PackLimits::default());
    let blob=raw(format,ObjectType::Blob,b"shared".to_vec());
    let good=tree(format,&[("100644","file",blob.id)]);
    let bad=tree(format,&[("40000","directory",blob.id)]);
    for roots in [[good.id,bad.id],[bad.id,good.id]] {
        assert_eq!(check(&validator,&[blob.clone(),good.clone(),bad.clone()],&roots),Err(RefusalCode::EvidenceInvalid));
        for id in [blob.id,good.id,bad.id] { assert!(node.read_git_object(id).is_err()); }
    }
    node.shutdown().unwrap();
}

#[test]
fn typed_handoff_enters_real_admission_and_recovers_without_a_second_decision() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let scratch=ScratchDirectory::new(); let mut node=node(format,&scratch);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let cx=node.request_context();
        let before=node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap();
        let blob=raw(format,ObjectType::Blob,b"published bytes\n".to_vec());
        let tree=tree(format,&[("100644","file",blob.id)]);
        let tip=commit(format,tree.id,&[],"typed publish");
        let bad=commit(format,blob.id,&[],"bad handoff");
        let (bad_pack,bad_receipt)=packed(format,&[full(&bad),full(&blob)]);
        let bad_validator=node.production_quarantine_validator(&before,PackLimits::default(),
            ParseLimits {tree_reference_bytes:format.digest_len(),..ParseLimits::default()}).unwrap();
        let mut rejected=ProductionReceiveQuarantineHandoff::new(bad_validator,before.basis().clone());
        assert_eq!(rejected.handoff_with_deadline(&request(format,&[bad.id]),Some(&bad_pack),&bad_receipt,&mut || true),
            Err(ReceiveError::AuthoritativeRefusal(RefusalCode::EvidenceInvalid)));
        assert!(rejected.into_validated_receive().is_err());
        assert!(node.read_git_object(bad.id).is_err() && node.read_git_object(blob.id).is_err());
        let (pack,receipt)=packed(format,&[full(&tip),full(&blob),full(&tree)]);
        let mut requested=request(format,&[tip.id]); requested.commands[0].ref_name=b"refs/heads/main".to_vec();
        let validator=node.production_quarantine_validator(&before,PackLimits::default(),
            ParseLimits {tree_reference_bytes:format.digest_len(),..ParseLimits::default()}).unwrap();
        let mut handoff=ProductionReceiveQuarantineHandoff::new(validator,before.basis().clone());
        handoff.handoff_with_deadline(&requested,Some(&pack),&receipt,&mut || true).unwrap();
        let validated=handoff.into_validated_receive().unwrap();
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap().basis(),before.basis(),
            "staging is not canonical publication");
        let session=LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x73;16]),IdempotencyKey::new(b"typed-graph".to_vec()).unwrap());
        let result=node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &cx,&session,&validated,fgit_admission::AdmissionLimits::default())).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome,DecisionOutcome::Committed {..}));
        let after=node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap();
        assert_eq!(after.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],tip.id);
        let retry=node.runtime().block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &cx,&session,&validated,fgit_admission::AdmissionLimits::default())).unwrap();
        assert_eq!(retry.commands[0].terminal,result.commands[0].terminal);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&cx)).unwrap().basis(),after.basis());
        node.shutdown().unwrap();
    }
}
