#![forbid(unsafe_code)]
//! Real file-backed source navigation: no host checkout or Git process.
use fgit_crypto::{GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_forge::source_browse::{SourceBrowseAction as Action, SourceBrowseQuery as Query,
    SourceBrowseContent as Content, SourceBrowseReport as Report, SourceBrowseError as Error,
    SourceEntryKind as Kind};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode, LoopbackReceiveSession};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, IdempotencyKey};
use fgit_treefs::{TreeCapability, TreePath, WorkspaceId, SymlinkPolicy};
use fgit_types::{ByteCount, DecisionOutcome, GitHashAlgorithm as Format, GitOid, HeadGeneration,
    PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::visibility::RefVisibility;
use std::{fs, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

const REPO: RepositoryId = RepositoryId::from_bytes([0xa8; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, node: Option<OneNode>, commit: GitOid, tree: GitOid, directory: GitOid, format: Format }
fn config(path: &Path, format: Format) -> NodeConfig {
    NodeConfig::new(path.join("node"), TenantId::from_bytes([0xa7;16]), REPO)
        .with_object_format(format).with_worker_threads(2)
}
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn actor() -> PrincipalId { PrincipalId::from_bytes([0xa9;16]) }
fn loose(root: &Path, format: Format, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [format!("{} {}\0", kind.label(), body.len()).as_bytes(), body].concat();
    let n = u16::try_from(raw.len()).unwrap(); let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes()); bytes.extend((!n).to_le_bytes()); bytes.extend(&raw);
    let (a,b) = raw.iter().fold((1u32,0u32), |(a,b), v| { let a=(a+u32::from(*v))%65521; (a,(b+a)%65521) });
    bytes.extend(((b<<16)|a).to_be_bytes()); let hex=oid.to_string();
    let dir=root.join("objects").join(&hex[..2]); fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]),bytes).unwrap(); oid
}
impl Fixture {
    fn new(format: Format, empty: bool) -> Self {
        let root=std::env::temp_dir().join(format!("fg-browse-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        let source=root.join("source"); fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            Format::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
            Format::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let binary=loose(&source,format,GitObjectKind::Blob,b"\0\xff\r\nbytes");
        let text=loose(&source,format,GitObjectKind::Blob,b"one\r\ntwo\nwithout-final");
        let blank=loose(&source,format,GitObjectKind::Blob,b"");
        let link=loose(&source,format,GitObjectKind::Blob,b"/etc/passwd");
        let directory=loose(&source,format,GitObjectKind::Tree,&[
            b"100644 alpha.txt\0".as_slice(),text.as_bytes(),b"100644 beta\0",binary.as_bytes(),
        ].concat());
        let external=GitOid::from_hex(format,&"6a".repeat(format.digest_len())).unwrap();
        let tree_bytes=[b"100755 bin\0".as_slice(),binary.as_bytes(),b"100644 dir.c\0",text.as_bytes(),
            b"40000 dir\0",directory.as_bytes(),b"100644 empty\0",blank.as_bytes(),b"120000 link\0",link.as_bytes(),
            b"100644 private\0",text.as_bytes(),b"160000 sub\0",external.as_bytes(),b"100644 \xff\0",binary.as_bytes()].concat();
        let tree=loose(&source,format,GitObjectKind::Tree,if empty {b""} else {&tree_bytes});
        let commit=loose(&source,format,GitObjectKind::Commit,format!(
            "tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nbrowse\n").as_bytes());
        fs::write(source.join("refs/heads/main"),format!("{commit}\n")).unwrap();
        let (mut node,_)=OneNode::init(config(&root,format)).unwrap(); node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request=node.request_context();
        let result=node.runtime().block_on(node.import_loose_git_directory_durable_in(&request,&source,actor(),b"browse-fixture")).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome,DecisionOutcome::Committed{..}));
        Self{root,node:Some(node),commit,tree,directory,format}
    }
    fn node(&self)->&OneNode {self.node.as_ref().unwrap()}
    fn browse(&self,query:&Query)->Result<Report,NodeWorkspaceRefusal>{
        let node=self.node();let request=node.request_context();
        node.runtime().block_on(node.browse_source_local_in(&request,&reference(),query))
    }
    fn scoped(&self,query:&Query,capability:&mut TreeCapability,visibility:&RefVisibility)->Result<Report,NodeWorkspaceRefusal>{
        let node=self.node();let request=node.request_context();
        match self.format {
            Format::Sha1=>node.runtime().block_on(node.browse_source_in::<Sha1>(&request,&reference(),visibility,capability,0,query)),
            Format::Sha256=>node.runtime().block_on(node.browse_source_in::<Sha256>(&request,&reference(),visibility,capability,0,query)),
        }
    }
    fn head(&self)->fgit_types::RepositoryAuthorityHeadId {
        let n=self.node();let r=n.request_context();n.runtime().block_on(n.materialize_admission_in(&r)).unwrap().basis().id()
    }
}
impl Drop for Fixture {fn drop(&mut self){if let Some(n)=self.node.take(){n.shutdown().unwrap();}fs::remove_dir_all(&self.root).unwrap();}}
fn list(path:Option<&[u8]>,limit:u16)->Query {Query{path:path.map(<[u8]>::to_vec),expected_head:None,expected_commit:None,action:Action::List{after:None,limit}}}
fn read(path:&[u8],limit:u32)->Query {Query{path:Some(path.to_vec()),expected_head:None,expected_commit:None,action:Action::Read{offset:0,limit}}}
fn cap(repo:RepositoryId)->TreeCapability{TreeCapability::new(WorkspaceId::from_bytes([0xab;16]),repo,vec![TreePath::parse_default(b"dir").unwrap()],vec![])}

#[test]
fn both_formats_page_exact_raw_names_and_read_binary_without_mutating_authority(){
    for format in [Format::Sha1,Format::Sha256]{
        let mut f=Fixture::new(format,false);let before=f.head();
        let mut query=list(None,2);let mut names=Vec::new();
        loop {
            let result=f.browse(&query).unwrap();assert_eq!(result.source_head,before);assert_eq!(result.source_commit,f.commit);
            assert_eq!(result.root_tree,f.tree);assert_eq!(result.object_id,f.tree);
            let Content::Directory{entries,next_after}=result.content else {panic!()};
            names.extend(entries.into_iter().map(|e|e.name));
            let Some(after)=next_after else {break};
            query.expected_head=Some(before);query.action=Action::List{after:Some(after),limit:2};
        }
        assert_eq!(names,vec![b"bin".to_vec(),b"dir".to_vec(),b"dir.c".to_vec(),b"empty".to_vec(),b"link".to_vec(),b"private".to_vec(),b"sub".to_vec(),vec![255]]);
        let nested=f.browse(&list(Some(b"dir"),10)).unwrap();assert_eq!(nested.object_id,f.directory);
        let Content::Directory{entries,..}=nested.content else {panic!()};assert_eq!(entries.len(),2);
        let mut query=read(b"bin",3);let mut body=Vec::new();
        loop {
            let report=f.browse(&query).unwrap();
            let Content::Blob{kind,bytes,total_bytes,next_offset,..}=report.content else {panic!()};
            assert_eq!(kind,Kind::Executable);assert_eq!(total_bytes,9);body.extend(bytes);
            let Some(offset)=next_offset else {break};query.expected_head=Some(before);query.action=Action::Read{offset,limit:3};
        }
        assert_eq!(body,b"\0\xff\r\nbytes");
        let original=f.browse(&read(b"dir/alpha.txt",100)).unwrap();
        f.node.take().unwrap().shutdown().unwrap();let mut node=OneNode::open_existing(config(&f.root,format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();f.node=Some(node);
        assert_eq!(f.browse(&read(b"dir/alpha.txt",100)).unwrap(),original);assert_eq!(f.head(),before);
    }
}

#[test]
fn capability_filtering_precedes_disclosure_and_denied_reads_preserve_budget(){
    for format in [Format::Sha1,Format::Sha256]{
        let f=Fixture::new(format,false);let mut allowed=cap(REPO);let visible=RefVisibility::new();
        let report=f.scoped(&list(None,100),&mut allowed,&visible).unwrap();
        let Content::Directory{entries,next_after}=report.content else {panic!()};
        assert_eq!(entries.len(),1);assert_eq!(entries[0].name,b"dir");assert_eq!(next_after,None);
        let spent=allowed.fetched_bytes();
        assert!(f.scoped(&read(b"private",10),&mut allowed,&visible).is_err());assert_eq!(allowed.fetched_bytes(),spent);
        assert!(f.scoped(&read(b"dir/alpha.txt",10),&mut allowed,&visible).is_ok());
        let mut other=cap(RepositoryId::from_bytes([0;16]));
        assert!(matches!(f.scoped(&read(b"dir/alpha.txt",10),&mut other,&visible),Err(NodeWorkspaceRefusal::RepositoryMismatch)));
        assert_eq!(other.fetched_bytes(),0);
        let mut hidden=RefVisibility::new();hidden.push_rule(b"refs/heads/main",&Default::default()).unwrap();
        assert!(matches!(f.scoped(&list(None,100),&mut cap(REPO),&hidden),Err(NodeWorkspaceRefusal::RefUnavailable)));
        let mut expired=cap(REPO).with_expiry(0);assert!(f.scoped(&list(None,100),&mut expired,&visible).is_err());
        let mut revoked=cap(REPO);revoked.revoke();assert!(f.scoped(&list(None,100),&mut revoked,&visible).is_err());
        let mut bounded=cap(REPO).with_fetch_budget(ByteCount::try_new("read",1,1).unwrap());
        assert!(f.scoped(&read(b"dir/alpha.txt",1),&mut bounded,&visible).is_err());
        let mut one=cap(REPO).with_file_budget(1);assert!(f.scoped(&read(b"dir/alpha.txt",1),&mut one,&visible).is_err());
    }
}

#[test]
fn symlinks_are_bytes_gitlinks_are_opaque_and_empty_files_are_complete(){
    for format in [Format::Sha1,Format::Sha256]{
        let f=Fixture::new(format,false);
        let Content::Blob{kind,bytes,..}=f.browse(&read(b"link",100)).unwrap().content else {panic!()};
        assert_eq!(kind,Kind::Symlink);assert_eq!(bytes,b"/etc/passwd");
        assert!(f.browse(&read(b"link/anything",100)).is_err());assert!(f.browse(&read(b"sub",100)).is_err());
        assert!(f.browse(&read(b"dir",100)).is_err());assert!(f.browse(&list(Some(b"bin"),10)).is_err());
        let Content::Blob{bytes,total_bytes,next_offset,..}=f.browse(&read(b"empty",10)).unwrap().content else {panic!()};
        assert!(bytes.is_empty());assert_eq!(total_bytes,0);assert_eq!(next_offset,None);
        let mut capability=TreeCapability::new(WorkspaceId::from_bytes([1;16]),REPO,vec![TreePath::parse_default(b"link").unwrap()],vec![])
            .with_symlink_policy(SymlinkPolicy::Refuse);
        assert!(f.scoped(&read(b"link",100),&mut capability,&RefVisibility::new()).is_err());
        let empty=Fixture::new(format,true);assert!(matches!(empty.browse(&list(None,100)).unwrap().content,
            Content::Directory{entries,next_after:None} if entries.is_empty()));
    }
}

#[test]
fn stale_continuations_wrong_commit_ranges_and_cancelled_contexts_never_return_pages(){
    let f=Fixture::new(Format::Sha1,false);let head=f.head();
    let mut query=read(b"bin",3);query.expected_head=Some(head);query.action=Action::Read{offset:9,limit:10};
    assert!(matches!(f.browse(&query).unwrap().content,Content::Blob{bytes,next_offset:None,..} if bytes.is_empty()));
    query.action=Action::Read{offset:10,limit:10};assert!(matches!(f.browse(&query),Err(NodeWorkspaceRefusal::SourceBrowse(e)) if matches!(*e,Error::RangeOutsideFile)));
    query.action=Action::Read{offset:u64::MAX,limit:10};assert!(f.browse(&query).is_err());
    query.expected_head=None;assert!(f.browse(&query).is_err());
    query=read(b"bin",10);query.expected_commit=Some(f.tree);
    assert!(matches!(f.browse(&query),Err(NodeWorkspaceRefusal::SourceBrowse(e)) if matches!(*e,Error::CommitMoved)));
    let node=f.node();let request=node.request_context();request.cancel();
    assert!(node.runtime().block_on(node.browse_source_local_in(&request,&reference(),&read(b"bin",10))).is_err());
    assert_eq!(f.head(),head);
    let request=node.request_context();let session=LoopbackReceiveSession::authenticated(actor(),IdempotencyKey::new(b"move-head".to_vec()).unwrap());
    let commands=[RefCommand{name:RefName::try_new(b"refs/heads/extra").unwrap(),expected_old:ExpectedOld::Absent,proposed_new:ProposedNew::Update(f.commit),force:false}];
    let outcome=node.runtime().block_on(node.admit_branch_updates_durable_in(&request,&session,&commands,Default::default())).unwrap();
    assert!(matches!(outcome.commands[0].terminal.outcome,DecisionOutcome::Committed{..}));
    let mut query=list(None,1);query.expected_head=Some(head);query.action=Action::List{after:Some(b"bin".to_vec()),limit:1};
    assert!(matches!(f.browse(&query),Err(NodeWorkspaceRefusal::SourceBrowse(e)) if matches!(*e,Error::SnapshotMoved)));
    assert!(f.browse(&list(None,1)).is_ok());
}
