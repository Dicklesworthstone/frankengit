use super::*;
use fgit_authority::IdempotencyKey;
use fgit_crypto::git_object_id;
use fgit_forge::tags::TagMetadata;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use crate::{MaterializedAdmission, NodeConfig};
use std::{fs, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, node: Option<OneNode>, format: GitHashAlgorithm, commit: GitOid, tree: GitOid, blob: GitOid, orphan: GitOid }
fn name(bytes: &[u8]) -> RefName { RefName::try_new(bytes).unwrap() }
fn actor() -> PrincipalId { PrincipalId::from_bytes([0xbc;16]) }
fn session(key: &[u8]) -> LoopbackReceiveSession { LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.to_vec()).unwrap()) }
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id=git_object_id(format,kind,body);
    let raw=[format!("{} {}\0",kind.label(),body.len()).as_bytes(),body].concat();
    let n=u16::try_from(raw.len()).unwrap();let mut bytes=vec![0x78,0x01,0x01];
    bytes.extend(n.to_le_bytes());bytes.extend((!n).to_le_bytes());bytes.extend(&raw);
    let (a,b)=raw.iter().fold((1u32,0u32),|(a,b),v|{let a=(a+u32::from(*v))%65521;(a,(b+a)%65521)});
    bytes.extend(((b<<16)|a).to_be_bytes());let hex=id.to_string();
    let dir=root.join("objects").join(&hex[..2]);fs::create_dir_all(&dir).unwrap();fs::write(dir.join(&hex[2..]),bytes).unwrap();id
}
impl Fixture {
    fn config(&self)->NodeConfig { NodeConfig::new(self.root.join("node"),TenantId::from_bytes([0xba;16]),RepositoryId::from_bytes([0xbb;16]))
        .with_object_format(self.format).with_worker_threads(2) }
    fn new(format:GitHashAlgorithm)->Self {
        let root=std::env::temp_dir().join(format!("fg-native-tags-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        let source=root.join("source");fs::create_dir_all(source.join("refs/heads")).unwrap();fs::create_dir_all(source.join("refs/tags")).unwrap();
        fs::write(source.join("HEAD"),b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"),match format { GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n" }).unwrap();
        let blob=loose(&source,format,GitObjectKind::Blob,b"tag data\n");
        let orphan=loose(&source,format,GitObjectKind::Blob,b"private orphan\n");
        let tree=loose(&source,format,GitObjectKind::Tree,&[b"100644 file\0".as_slice(),blob.as_bytes()].concat());
        let commit=loose(&source,format,GitObjectKind::Commit,format!("tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nfixture\n").as_bytes());
        fs::write(source.join("refs/heads/main"),format!("{commit}\n")).unwrap();
        fs::write(source.join("refs/tags/private"),format!("{orphan}\n")).unwrap();
        let mut f=Self{root,node:None,format,commit,tree,blob,orphan};
        let (mut node,_)=OneNode::init(f.config()).unwrap();node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let r=node.request_context();let result=node.runtime().block_on(node.import_loose_git_directory_durable_in(&r,&source,actor(),b"tag-fixture")).unwrap();
        assert!(result.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Committed{..})));
        f.node=Some(node);f
    }
    fn node(&self)->&OneNode {self.node.as_ref().unwrap()}
    fn snapshot(&self)->MaterializedAdmission {let n=self.node();let r=n.request_context();n.runtime().block_on(n.materialize_admission_in(&r)).unwrap()}
    fn apply(&self,command:&TagCommand,key:&[u8])->Result<AdmissionResult,NodeWorkspaceRefusal>{
        let n=self.node();let r=n.request_context();n.runtime().block_on(n.admit_tag_durable_in(&r,&session(key),command,AdmissionLimits::default()))
    }
    fn read(&self,reference:&RefName,head:Option<RepositoryAuthorityHeadId>,limits:TagReadLimits)->Result<TagRead,NodeWorkspaceRefusal>{
        let n=self.node();let r=n.request_context();n.runtime().block_on(n.read_tag_in(&r,reference,&RefVisibility::default(),head,limits))
    }
    fn reopen(&mut self,serve:bool){self.node.take().unwrap().shutdown().unwrap();let mut n=OneNode::open_existing(self.config()).unwrap();
        if serve {n.bring_into_service(HeadGeneration::FIRST).unwrap();}self.node=Some(n);}
}
impl Drop for Fixture{fn drop(&mut self){if let Some(n)=self.node.take(){n.shutdown().unwrap();}fs::remove_dir_all(&self.root).unwrap();}}
fn annotated(reference:&[u8],target:GitOid,kind:GitObjectKind)->TagCommand{TagCommand::Annotated{name:name(reference),target,target_kind:kind,
    metadata:TagMetadata{tagger:"Release Author <release@example.invalid>".into(),timestamp:7,message:b"release\r\nwithout-final".to_vec()}}}
fn committed(result:Result<AdmissionResult,NodeWorkspaceRefusal>)->AdmissionResult{let value=result.unwrap();assert!(value.session.atomic);assert_eq!(value.commands.len(),1);
    assert!(matches!(value.commands[0].terminal.outcome,DecisionOutcome::Committed{..}),"{value:?}");value}

#[test]
fn native_tags_to_every_kind_peel_exact_bytes_and_survive_reopen(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let mut f=Fixture::new(format);let original=f.snapshot();
        for (suffix,target,kind) in [(b"commit".as_slice(),f.commit,GitObjectKind::Commit),(b"tree",f.tree,GitObjectKind::Tree),(b"blob",f.blob,GitObjectKind::Blob)]{
            let reference=[b"refs/tags/".as_slice(),suffix].concat();let command=annotated(&reference,target,kind);
            let prepared=command.prepare(format).unwrap();let expected=prepared.object.unwrap();committed(f.apply(&command,&reference));
            let read=f.read(command.reference(),None,TagReadLimits::default()).unwrap();assert_eq!(read.tip,expected.id);assert_eq!(read.peeled,target);assert_eq!(read.peeled_kind,kind);
            assert_eq!(read.annotations.len(),1);assert_eq!(read.annotations[0].body,expected.body);assert_eq!(read.annotations[0].signature,TagSignatureState::Absent);
        }
        let inner=f.read(&name(b"refs/tags/commit"),None,TagReadLimits::default()).unwrap();
        let outer=annotated(b"refs/tags/outer",inner.tip,GitObjectKind::Tag);committed(f.apply(&outer,b"outer"));
        let tip=outer.prepare(format).unwrap().object.unwrap().id;
        let light=TagCommand::Lightweight{name:name(b"refs/tags/raw/\xff"),target:tip};committed(f.apply(&light,b"alias"));
        let read=f.read(light.reference(),None,TagReadLimits::default()).unwrap();assert_eq!(read.annotations.len(),2);assert_eq!(read.tip,tip);assert_eq!(read.peeled,f.commit);
        let current=f.snapshot();assert_eq!(original.snapshot().head_target,current.snapshot().head_target);
        assert_eq!(original.snapshot().outbox,current.snapshot().outbox);assert_eq!(original.basis().body().forge_position_root,current.basis().body().forge_position_root);
        let head=read.head;f.reopen(true);assert_eq!(f.read(light.reference(),Some(head),TagReadLimits::default()).unwrap(),read);
    }
}

#[test]
fn tag_terminal_replays_precede_stopped_cell_and_exhausted_quota(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let mut f=Fixture::new(format);let command=annotated(b"refs/tags/version",f.commit,GitObjectKind::Commit);
        let created=committed(f.apply(&command,b"create"));
        let id=command.prepare(format).unwrap().object.unwrap().id;
        let deletion=TagCommand::Delete{name:command.reference().clone(),expected:id};let deleted=committed(f.apply(&deletion,b"delete"));
        let head=f.snapshot().basis().id();assert_eq!(f.apply(&command,b"create").unwrap(),created);assert_eq!(f.snapshot().basis().id(),head);
        f.reopen(false);assert_eq!(f.apply(&command,b"create").unwrap(),created);assert_eq!(f.apply(&deletion,b"delete").unwrap(),deleted);
        assert!(f.apply(&command,b"fresh-stopped").is_err());
        let n=f.node.as_mut().unwrap();n.bring_into_service(HeadGeneration::FIRST).unwrap();n.push_quota.limit.max_events=0;
        assert_eq!(f.apply(&command,b"create").unwrap(),created);assert!(f.apply(&command,b"fresh-quota").is_err());assert_eq!(f.snapshot().basis().id(),head);
        let mut changed=command.clone();if let TagCommand::Annotated{metadata,..}=&mut changed{metadata.message.push(b'!');}
        assert!(f.apply(&changed,b"create").is_err());assert_eq!(f.snapshot().basis().id(),head);
    }
}

#[test]
fn existing_names_and_wrong_expected_delete_produce_stable_canonical_refusals(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let f=Fixture::new(format);let command=TagCommand::Lightweight{name:name(b"refs/tags/stable"),target:f.commit};committed(f.apply(&command,b"first"));
        let original=f.snapshot();let refused=f.apply(&command,b"collision").unwrap();assert!(matches!(refused.commands[0].terminal.outcome,DecisionOutcome::Refused{..}));
        assert_eq!(f.apply(&command,b"collision").unwrap(),refused);assert_eq!(f.snapshot().snapshot().refs,original.snapshot().refs);
        let wrong=TagCommand::Delete{name:command.reference().clone(),expected:f.blob};let refused=f.apply(&wrong,b"wrong-delete").unwrap();
        assert!(matches!(refused.commands[0].terminal.outcome,DecisionOutcome::Refused{..}));assert_eq!(f.snapshot().snapshot().refs,original.snapshot().refs);
    }
}

#[test]
fn deleted_only_originals_and_wrong_declared_kinds_never_publish(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let f=Fixture::new(format);committed(f.apply(&TagCommand::Delete{name:name(b"refs/tags/private"),expected:f.orphan},b"hide-orphan"));
        let head=f.snapshot().basis().id();
        for command in [TagCommand::Lightweight{name:name(b"refs/tags/leak"),target:f.orphan},
            annotated(b"refs/tags/leak-annotation",f.orphan,GitObjectKind::Blob),
            annotated(b"refs/tags/wrong-kind",f.blob,GitObjectKind::Commit)] {
            assert!(f.apply(&command,command.reference().as_bytes()).is_err());assert_eq!(f.snapshot().basis().id(),head);
        }
        committed(f.apply(&annotated(b"refs/tags/allowed",f.blob,GitObjectKind::Blob),b"allowed"));
    }
}

#[test]
fn tag_reads_are_snapshot_bound_budgeted_and_signature_presence_is_never_trust(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let f=Fixture::new(format);let mut inner=annotated(b"refs/tags/signed",f.blob,GitObjectKind::Blob);
        if let TagCommand::Annotated{metadata,..}=&mut inner{metadata.message=b"opaque\n-----BEGIN SSH SIGNATURE-----\nnot-a-signature\n-----END SSH SIGNATURE-----\n".to_vec();}
        committed(f.apply(&inner,b"inner"));let id=inner.prepare(format).unwrap().object.unwrap().id;
        let outer=annotated(b"refs/tags/outer",id,GitObjectKind::Tag);committed(f.apply(&outer,b"outer"));
        let report=f.read(outer.reference(),None,TagReadLimits::default()).unwrap();assert_eq!(report.annotations[1].signature,TagSignatureState::OpaqueUnverifiable);
        let bytes=report.annotations.iter().map(|a|a.body.len()).sum::<usize>()+b"tag data\n".len();
        let exact=TagReadLimits{max_tags:2,max_total_bytes:bytes,..TagReadLimits::default()};assert!(f.read(outer.reference(),Some(report.head),exact).is_ok());
        assert!(f.read(outer.reference(),None,TagReadLimits{max_total_bytes:bytes-1,..exact}).is_err());
        assert!(matches!(f.read(outer.reference(),None,TagReadLimits{max_tags:1,..exact}),Err(NodeWorkspaceRefusal::Tag(TagRefusal::Budget(_)))));
        assert!(f.read(outer.reference(),None,TagReadLimits{max_object_bytes:1,..exact}).is_err());
        let mut hidden=RefVisibility::default();hidden.push_rule(b"refs/tags/outer",&Default::default()).unwrap();
        let r=f.node().request_context();assert!(matches!(f.node().runtime().block_on(f.node().read_tag_in(&r,outer.reference(),&hidden,None,exact)),Err(NodeWorkspaceRefusal::RefUnavailable)));
        assert!(matches!(f.read(&name(b"refs/tags/absent"),None,exact),Err(NodeWorkspaceRefusal::RefUnavailable)));
        committed(f.apply(&TagCommand::Lightweight{name:name(b"refs/tags/next"),target:f.commit},b"next"));
        assert!(matches!(f.read(outer.reference(),Some(report.head),exact),Err(NodeWorkspaceRefusal::Tag(TagRefusal::SnapshotMoved))));
    }
}

#[test]
fn tag_inventory_filters_before_pagination_and_cancelled_requests_preserve_authority(){
    let f=Fixture::new(GitHashAlgorithm::Sha256);let command=TagCommand::Lightweight{name:name(b"refs/tags/a"),target:f.commit};committed(f.apply(&command,b"a"));
    let head=f.snapshot().basis().id();let r=f.node().request_context();
    let (selected,rows,next)=f.node().runtime().block_on(f.node().list_tag_refs_in(&r,&RefVisibility::default(),None,1,None)).unwrap();
    assert_eq!(selected,head);assert_eq!(rows,vec![(name(b"refs/tags/a"),f.commit)]);assert_eq!(next,Some(name(b"refs/tags/a")));
    assert!(f.node().runtime().block_on(f.node().list_tag_refs_in(&r,&RefVisibility::default(),next.as_ref(),1,None)).is_err());
    let (_,rows,next)=f.node().runtime().block_on(f.node().list_tag_refs_in(&r,&RefVisibility::default(),next.as_ref(),1,Some(head))).unwrap();
    assert_eq!(rows,vec![(name(b"refs/tags/private"),f.orphan)]);assert!(next.is_none());
    let r=f.node().request_context();r.authority().cancel();
    assert!(f.node().runtime().block_on(f.node().read_tag_in(&r,command.reference(),&Default::default(),None,Default::default())).is_err());
    assert!(f.node().runtime().block_on(f.node().admit_tag_durable_in(&r,&session(b"cancel"),&command,Default::default())).is_err());
    assert_eq!(f.snapshot().basis().id(),head);
}
