use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_crypto::git_object_id;
use fgit_forge::source_search::SearchCase;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use crate::NodeConfig;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-source-search-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn loose(root: &Path, format: Format, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let size = u16::try_from(raw.len()).unwrap();
    let mut z = vec![0x78, 0x01, 0x01];
    z.extend(size.to_le_bytes()); z.extend((!size).to_le_bytes()); z.extend(&raw);
    let (a,b) = raw.iter().fold((1u32,0u32), |(a,b),x| { let a=(a+u32::from(*x))%65521; (a,(b+a)%65521) });
    z.extend(((b<<16)|a).to_be_bytes());
    let hex=id.to_string(); let parent=root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&parent).unwrap(); fs::write(parent.join(&hex[2..]),z).unwrap(); id
}
fn tree(entries: &[(&str,&str,GitOid)]) -> Vec<u8> {
    let mut result=Vec::new();
    for (mode,name,id) in entries { result.extend(format!("{mode} {name}\0").as_bytes()); result.extend(id.as_bytes()); }
    result
}
fn fixture(scratch: &Scratch, format: Format) -> (OneNode, GitOid) {
    let root=scratch.0.join("source"); fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"),b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        Format::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
        Format::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let text=loose(&root,format,GitObjectKind::Blob,"blob","éneedle\r\nNEEDLE needle\n".as_bytes());
    let other=loose(&root,format,GitObjectKind::Blob,"blob",b"private needle\n");
    let binary=loose(&root,format,GitObjectKind::Blob,"blob",b"\0needle\xff");
    let link=loose(&root,format,GitObjectKind::Blob,"blob",b"src/file.rs");
    let src=loose(&root,format,GitObjectKind::Tree,"tree",&tree(&[("100644","file.rs",text)]));
    let src2=loose(&root,format,GitObjectKind::Tree,"tree",&tree(&[("100644","secret.rs",other)]));
    let root_tree=loose(&root,format,GitObjectKind::Tree,"tree",&tree(&[
        ("100644","binary",binary),("120000","link",link),("40000","src",src),("40000","src2",src2)]));
    let commit=loose(&root,format,GitObjectKind::Commit,"commit",format!(
        "tree {root_tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nsearch source\n").as_bytes());
    fs::write(root.join("refs/heads/main"),format!("{commit}\n")).unwrap();
    let (mut node,_)=OneNode::init(NodeConfig::new(scratch.0.join("node"),
        TenantId::from_bytes([0xc1;16]),RepositoryId::from_bytes([0xc2;16])).with_object_format(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request=node.request_context();
    let import=node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request,&root,PrincipalId::from_bytes([0xc3;16]),b"search-fixture")).unwrap();
    assert!(import.commands.iter().all(|c| matches!(c.terminal.outcome,DecisionOutcome::Committed {..})));
    (node,commit)
}
fn query(prefixes: &[Vec<u8>]) -> SourceQuery { SourceQuery::new(b"needle",SearchCase::AsciiInsensitive,prefixes).unwrap() }
fn local(node: &OneNode, query: &SourceQuery, limits: SearchLimits) -> Result<SourceSearchReport,NodeWorkspaceRefusal> {
    let request=node.request_context();
    node.runtime().block_on(node.search_source_local_in(&request,&reference(),query,limits))
}
fn scoped<A: GitHashAlgorithm>(node: &OneNode, cap: &mut TreeCapability, visibility: &RefVisibility)
    -> Result<SourceSearchReport,NodeWorkspaceRefusal>
{
    let request=node.request_context();
    node.runtime().block_on(node.search_source_in::<A>(&request,&reference(),visibility,cap,0,&query(&[]),SearchLimits::default()))
}
fn cap(repository: RepositoryId) -> TreeCapability {
    TreeCapability::new(WorkspaceId::from_bytes([0xc4;16]),repository,
        vec![TreePath::parse_default(b"src").unwrap()],Vec::new())
}

#[test]
fn real_node_search_is_pinned_ordered_and_read_only_in_both_formats() {
    for format in [Format::Sha1,Format::Sha256] {
        let scratch=Scratch::new(); let (node,commit)=fixture(&scratch,format);
        let request=node.request_context();
        let before=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let result=local(&node,&query(&[]),SearchLimits::default()).unwrap();
        assert_eq!(result.source_commit,commit);
        assert_eq!(result.completion,SearchCompletion::Complete);
        assert_eq!(result.files_read,3); assert_eq!(result.matches.len(),5);
        assert_eq!(result.non_regular_entries,1);
        assert_eq!(result.matches[0].path,b"binary"); assert_eq!(result.matches[0].byte_offset,1);
        assert_eq!(result.matches[1].path,b"src/file.rs");
        assert_eq!((result.matches[1].byte_offset,result.matches[1].line,result.matches[1].byte_column),(2,1,3));
        assert!(result.matches[1].excerpt.starts_with("é".as_bytes()));
        let after=node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_eq!(before.basis(),after.basis());
        assert_eq!(local(&node,&query(&[]),SearchLimits::default()).unwrap(),result);
        node.shutdown().unwrap();
    }
}

#[test]
fn path_prefixes_and_capabilities_do_not_disclose_neighboring_content() {
    for format in [Format::Sha1,Format::Sha256] {
        let scratch=Scratch::new(); let (node,_)=fixture(&scratch,format);
        let selected=local(&node,&query(&[b"src".to_vec()]),SearchLimits::default()).unwrap();
        assert_eq!(selected.files_selected,1); assert_eq!(selected.matches.len(),3);
        assert!(selected.matches.iter().all(|hit| hit.path==b"src/file.rs"));
        let mut capability=cap(node.repository_id());
        let scoped=match format {
            Format::Sha1=>scoped::<Sha1>(&node,&mut capability,&RefVisibility::new()),
            Format::Sha256=>scoped::<Sha256>(&node,&mut capability,&RefVisibility::new()),
        }.unwrap();
        assert_eq!(scoped.matches,selected.matches); assert_eq!(scoped.non_regular_entries,0);
        let absent=local(&node,&query(&[b"absent".to_vec()]),SearchLimits::default()).unwrap();
        assert!(absent.matches.is_empty()); assert_eq!(absent.completion,SearchCompletion::Complete);
        node.shutdown().unwrap();
    }
}

#[test]
fn matching_limit_uses_lookahead_and_budget_errors_never_claim_absence() {
    let scratch=Scratch::new(); let (node,_)=fixture(&scratch,Format::Sha1);
    let q=query(&[b"src".to_vec()]);
    let limited=local(&node,&q,SearchLimits{max_matches:2,..SearchLimits::default()}).unwrap();
    assert_eq!(limited.matches.len(),2); assert_eq!(limited.completion,SearchCompletion::MatchLimit);
    let exact=local(&node,&q,SearchLimits{max_matches:3,..SearchLimits::default()}).unwrap();
    assert_eq!(exact.matches.len(),3); assert_eq!(exact.completion,SearchCompletion::Complete);
    assert!(local(&node,&q,SearchLimits{max_total_bytes:1,..SearchLimits::default()}).is_err());
    let absent=SourceQuery::new(b"absent",SearchCase::Exact,&[]).unwrap();
    let result=local(&node,&absent,SearchLimits::default()).unwrap();
    assert!(result.matches.is_empty()); assert_eq!(result.completion,SearchCompletion::Complete);
    node.shutdown().unwrap();
}

#[test]
fn revoked_foreign_and_hidden_ref_scopes_fail_closed() {
    let scratch=Scratch::new(); let (node,_)=fixture(&scratch,Format::Sha1);
    let mut foreign=cap(RepositoryId::from_bytes([0x55;16]));
    assert!(matches!(scoped::<Sha1>(&node,&mut foreign,&RefVisibility::new()),Err(NodeWorkspaceRefusal::RepositoryMismatch)));
    let mut revoked=cap(node.repository_id()); revoked.revoke();
    assert!(scoped::<Sha1>(&node,&mut revoked,&RefVisibility::new()).is_err());
    let mut hidden=RefVisibility::new();
    hidden.push_rule(reference().as_bytes(),&fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(scoped::<Sha1>(&node,&mut cap(node.repository_id()),&hidden),Err(NodeWorkspaceRefusal::RefUnavailable)));
    let request=node.request_context();
    assert!(matches!(node.runtime().block_on(node.search_source_local_in(&request,
        &RefName::try_new(b"refs/heads/absent").unwrap(),&query(&[]),SearchLimits::default())),Err(NodeWorkspaceRefusal::RefUnavailable)));
    node.shutdown().unwrap();
}
