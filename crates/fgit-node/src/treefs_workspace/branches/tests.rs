use super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use crate::{MaterializedAdmission, NodeConfig};
use std::{fs, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-branches-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xc1;16]), RepositoryId::from_bytes([0xc2;16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xc3;16]) }
fn reference(text: &str) -> RefName { RefName::try_new(text.as_bytes()).unwrap() }
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn create(name: &str, oid: GitOid) -> RefCommand {
    RefCommand { name: reference(name), expected_old: ExpectedOld::Absent, proposed_new: ProposedNew::Update(oid), force: false }
}
fn delete(name: &str, oid: GitOid) -> RefCommand {
    RefCommand { name: reference(name), expected_old: ExpectedOld::Exactly(oid), proposed_new: ProposedNew::Delete, force: false }
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap(); let mut encoded = vec![0x78,0x01,0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a,b) = raw.iter().fold((1_u32,0_u32), |(a,b),v| { let a=(a+u32::from(*v))%65521; (a,(b+a)%65521) });
    encoded.extend(((b<<16)|a).to_be_bytes()); let text=id.to_string();
    let dir=root.join("objects").join(&text[..2]); fs::create_dir_all(&dir).unwrap(); fs::write(dir.join(&text[2..]),encoded).unwrap(); id
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid, GitOid) {
    let (mut node,_) = OneNode::init(scratch.config(format)).unwrap(); node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root=scratch.0.join("source"); fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"),b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"),match format {
        GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob=loose(&root,format,GitObjectKind::Blob,"blob",b"branch fixture\n");
    let tree=loose(&root,format,GitObjectKind::Tree,"tree",&[b"100644 file\0".as_slice(),blob.as_bytes()].concat());
    let body=format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n");
    let base=loose(&root,format,GitObjectKind::Commit,"commit",body.as_bytes());
    let child=loose(&root,format,GitObjectKind::Commit,"commit",format!("tree {tree}\nparent {base}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nchild\n").as_bytes());
    fs::write(root.join("refs/heads/main"),format!("{child}\n")).unwrap();
    let request=node.request_context();
    let imported=node.runtime().block_on(node.import_loose_git_directory_durable_in(&request,&root,principal(),b"branch-fixture")).unwrap();
    assert!(imported.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Committed{..})));
    (node,base,child,blob)
}
fn apply(node: &OneNode, commands: &[RefCommand], key: &str) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request=node.request_context(); node.runtime().block_on(node.admit_branch_updates_durable_in(&request,&session(key),commands,AdmissionLimits::default()))
}
fn accepted(result: Result<AdmissionResult,NodeWorkspaceRefusal>) -> AdmissionResult {
    let result=result.unwrap(); assert!(result.session.atomic); assert_eq!(result.session.tx_ids.len(),1);
    assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome,DecisionOutcome::Committed{..})),"{result:?}"); result
}
fn snapshot(node:&OneNode)->MaterializedAdmission {
    let request=node.request_context();node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}

#[test]
fn branch_lifecycle_is_atomic_and_exact_retries_survive_reopen_and_deleted_sources() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let scratch=Scratch::new();let (node,base,child,_)=fixture(&scratch,format);
        let original=snapshot(&node);
        let created=accepted(apply(&node,&[create("refs/heads/topic",base)],"create"));
        let updated=RefCommand{name:reference("refs/heads/topic"),expected_old:ExpectedOld::Exactly(base),proposed_new:ProposedNew::Update(child),force:false};
        accepted(apply(&node,&[updated.clone()],"advance"));
        let rename=[delete("refs/heads/topic",child),create("refs/heads/renamed",child)];
        let renamed=accepted(apply(&node,&rename,"rename"));
        assert_eq!(renamed.commands.len(),2);assert_eq!(renamed.commands[0],renamed.commands[1]);
        let after=snapshot(&node);assert!(!after.snapshot().refs.contains_key(&reference("refs/heads/topic")));
        assert_eq!(after.snapshot().refs.get(&reference("refs/heads/renamed")),Some(&child));
        assert_eq!(after.snapshot().head_target,original.snapshot().head_target);
        assert_eq!(after.snapshot().outbox,original.snapshot().outbox);
        assert_eq!(after.basis().body().forge_position_root,original.basis().body().forge_position_root);
        assert_eq!(after.selected_closure().closure(),original.selected_closure().closure());
        let removed=accepted(apply(&node,&[delete("refs/heads/renamed",child)],"delete"));
        let settled=snapshot(&node);
        assert_eq!(apply(&node,&[create("refs/heads/topic",base)],"create").unwrap(),created);
        assert_eq!(apply(&node,&rename,"rename").unwrap(),renamed);
        assert_eq!(snapshot(&node).basis(),settled.basis());node.shutdown().unwrap();
        let mut reopened=OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(apply(&reopened,&rename,"rename").unwrap(),renamed);
        assert_eq!(apply(&reopened,&[delete("refs/heads/renamed",child)],"delete").unwrap(),removed);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(),settled.basis());reopened.shutdown().unwrap();
    }
}

#[test]
fn rename_cannot_overwrite_an_existing_destination_or_delete_a_changed_source() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let scratch=Scratch::new();let (node,base,child,_)=fixture(&scratch,format);
        accepted(apply(&node,&[create("refs/heads/source",base)],"source"));
        accepted(apply(&node,&[create("refs/heads/destination",child)],"destination"));
        let before=snapshot(&node);
        let conflict=[delete("refs/heads/source",base),create("refs/heads/destination",base)];
        let refused=apply(&node,&conflict,"conflict").unwrap();
        assert!(refused.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Refused{..})));
        assert_eq!(snapshot(&node).snapshot().refs,before.snapshot().refs);
        assert_eq!(apply(&node,&conflict,"conflict").unwrap(),refused);
        let stale=[delete("refs/heads/source",child),create("refs/heads/new",child)];
        let refused=apply(&node,&stale,"stale").unwrap();
        assert!(refused.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Refused{..})));
        assert_eq!(snapshot(&node).snapshot().refs,before.snapshot().refs);
        let head=snapshot(&node);
        assert!(apply(&node,&[create("refs/heads/changed-input",child)],"source").is_err());
        assert_eq!(snapshot(&node).basis(),head.basis());node.shutdown().unwrap();
    }
}

#[test]
fn branch_guards_preserve_authority_and_terminal_retries_precede_quota() {
    let scratch=Scratch::new();let (mut node,base,child,blob)=fixture(&scratch,GitHashAlgorithm::Sha1);
    let before=snapshot(&node);
    assert!(matches!(apply(&node,&[create("refs/heads/blob",blob)],"blob"),Err(NodeWorkspaceRefusal::CommitRequired)));
    assert!(apply(&node,&[delete("refs/heads/main",child)],"default-delete").is_err());
    assert!(apply(&node,&[delete("refs/heads/main",child),create("refs/heads/other",child)],"default-rename").is_err());
    let request=node.request_context();request.authority().cancel();
    assert!(node.runtime().block_on(node.admit_branch_updates_durable_in(&request,&session("cancel"),&[create("refs/heads/cancel",base)],AdmissionLimits::default())).is_err());
    assert_eq!(snapshot(&node).basis(),before.basis());
    let permitted=accepted(apply(&node,&[create("refs/heads/permitted",base)],"permit"));
    node.push_quota.limit.max_events=0;
    assert_eq!(apply(&node,&[create("refs/heads/permitted",base)],"permit").unwrap(),permitted);
    let head=snapshot(&node);assert!(apply(&node,&[create("refs/heads/new",base)],"new").is_err());
    assert_eq!(snapshot(&node).basis(),head.basis());node.shutdown().unwrap();
}

#[test]
fn branch_pages_are_byte_sorted_visibility_filtered_and_snapshot_pinned() {
    let scratch=Scratch::new();let (node,base,_,_)=fixture(&scratch,GitHashAlgorithm::Sha256);
    for name in ["refs/heads/z","refs/heads/a"] {accepted(apply(&node,&[create(name,base)],name));}
    let request=node.request_context();let empty=RefVisibility::default();
    let (head,first,next)=node.runtime().block_on(node.list_branch_refs_in(&request,&empty,None,1,None)).unwrap();
    assert_eq!(first[0].0,reference("refs/heads/a"));assert_eq!(next,Some(reference("refs/heads/a")));
    assert!(node.runtime().block_on(node.list_branch_refs_in(&request,&empty,next.as_ref(),1,None)).is_err());
    let (_,second,next)=node.runtime().block_on(node.list_branch_refs_in(&request,&empty,next.as_ref(),2,Some(head))).unwrap();
    assert_eq!(second.iter().map(|(r,_)|r.clone()).collect::<Vec<_>>(),vec![reference("refs/heads/main"),reference("refs/heads/z")]);assert!(next.is_none());
    let mut hidden=RefVisibility::default();hidden.push_rule(b"refs/heads/main",&Default::default()).unwrap();
    let (_,rows,_)=node.runtime().block_on(node.list_branch_refs_in(&request,&hidden,None,100,Some(head))).unwrap();
    assert_eq!(rows.len(),2);assert!(rows.iter().all(|(name,_)|name!=&reference("refs/heads/main")));
    accepted(apply(&node,&[create("refs/heads/new",base)],"new"));
    assert!(node.runtime().block_on(node.list_branch_refs_in(&request,&empty,Some(&reference("refs/heads/a")),1,Some(head))).is_err());
    node.shutdown().unwrap();
}

#[test]
fn malformed_branch_requests_cannot_weaken_expected_old_or_atomic_rename() {
    let oid=GitOid::from_hex(GitHashAlgorithm::Sha1,&"1".repeat(40)).unwrap();
    let good=create("refs/heads/a",oid);assert!(branch_request(GitHashAlgorithm::Sha1,&[good.clone()]).is_ok());
    let mut unsafe_command=good.clone();unsafe_command.expected_old=ExpectedOld::Unspecified;
    assert!(branch_request(GitHashAlgorithm::Sha1,&[unsafe_command]).is_err());
    let mut force=good.clone();force.force=true;assert!(branch_request(GitHashAlgorithm::Sha1,&[force]).is_err());
    assert!(branch_request(GitHashAlgorithm::Sha1,&[create("refs/tags/a",oid)]).is_err());
    assert!(branch_request(GitHashAlgorithm::Sha1,&[good.clone(),create("refs/heads/b",oid)]).is_err());
    assert!(branch_request(GitHashAlgorithm::Sha1,&[delete("refs/heads/a",oid),good]).is_err());
    assert!(branch_request(GitHashAlgorithm::Sha256,&[create("refs/heads/a",oid)]).is_err());
    let rename=[delete("refs/heads/a",oid),create("refs/heads/b",oid)];
    assert_eq!(branch_request(GitHashAlgorithm::Sha1,&rename).unwrap(),branch_request(GitHashAlgorithm::Sha1,&[rename[1].clone(),rename[0].clone()]).unwrap());
}
