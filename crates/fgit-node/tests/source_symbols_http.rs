#![forbid(unsafe_code)]
//! Real imported trees, native patch admission, OneNode and authenticated TCP.
//! The Rust scanner and storage are production implementations, not doubles.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_crypto::{GitHashAlgorithm as NativeFormat, GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::{SearchCompletion, SearchLimits};
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolKind, SymbolMatchMode, SymbolQuery,
    SymbolReadError, SymbolSearchReport, SymbolSyntaxErrorKind};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_treefs::{TreeCapability, TreePath, WorkspaceId};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName, RepositoryId};
use fgit_wire::visibility::RefVisibility;

const A: &[u8] = b"// fn ThingFake() {}\r\n#[allow(dead_code)]\r\npub struct Thing;\r\npub fn ThingWorker() { let _ = \"fn ThingString(){}\"; }\r\nmacro_rules! ThingMaker { () => { fn ThingGenerated(){} } }\r\n";
const B: &[u8] = b"fn ThingLocal() {}\nfn r#type() {}\n";
const RAW_PATH: &[u8] = b"raw\xff.rs";
const RAW: &[u8] = b"pub fn ThingRaw() {}\n";
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn query(name: &[u8], mode: SymbolMatchMode, kinds: &[SymbolKind], prefixes: &[Vec<u8>]) -> SymbolQuery {
    SymbolQuery::new(name,mode,kinds,prefixes,MAX_SYMBOL_WORK).unwrap()
}
fn local(node: &OneNode, q: &SymbolQuery, limits: SearchLimits) -> Result<SymbolSearchReport,SymbolReadError<NodeWorkspaceRefusal>> {
    node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&node.request_context(),&reference(),None,None,q,limits)).map(|(_,r)|r)
}
fn quoted_path(prefix: char, path: &[u8]) -> String {
    let mut out=format!("\"{prefix}/");
    for b in path { if b.is_ascii_alphanumeric() || b"/._-".contains(b) {out.push(char::from(*b));} else {out.push_str(&format!("\\{b:03o}"));} }
    out.push('"');out
}
fn add_files(node: &OneNode, base: GitOid, files: &[(&[u8],&[u8])], key: &[u8]) -> GitOid {
    let mut patch=Vec::new();
    for (path,body) in files {
        let old=quoted_path('a',path);let new=quoted_path('b',path);
        patch.extend_from_slice(format!("diff --git {old} {new}\nnew file mode 100644\n").as_bytes());
        if !body.is_empty(){
            assert!(body.ends_with(b"\n"));
            let lines=body.iter().filter(|b|**b==b'\n').count();
            patch.extend_from_slice(format!("--- /dev/null\n+++ {new}\n@@ -0,0 +1,{lines} @@\n").as_bytes());
            for line in body.split_inclusive(|b|*b==b'\n'){patch.push(b'+');patch.extend_from_slice(line);}
        }
    }
    let metadata=MergeMetadata {author:"Fixture <fixture@example.invalid>".into(),committer:"Fixture <fixture@example.invalid>".into(),timestamp:2,message:b"symbol fixtures\n".to_vec()};
    let request=node.request_context();
    let candidate=node.runtime().block_on(node.prepare_trusted_patch_in(&request,&reference(),base,[0x76;16],&patch,&metadata,PatchLimits::default())).unwrap();
    let result=node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request,OWNER,key,&reference(),base,candidate.candidate_commit,candidate.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Committed {..})));
    candidate.candidate_commit
}
fn symbols(root:&Scratch,format:GitHashAlgorithm)->(OneNode,GitOid){
    let(node,base)=fixture(root,format);
    let commit=add_files(&node,base,&[(b"src/a.rs",A),(b"src/b.rs",B),(RAW_PATH,RAW)],b"symbol-fixture");(node,commit)
}
fn form(format:GitHashAlgorithm)->String{format!("{}&name_hex={}&match=prefix",common(format),hex(b"Thing"))}

#[test]
fn native_symbols_match_exact_source_spans_and_reopen_without_authority_mutation(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let config=root.config(format);let(node,commit)=symbols(&root,format);let before=generation(&node);
        let q=query(b"Thing",SymbolMatchMode::Prefix,&[],&[]);
        let (head,report)=node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&node.request_context(),&reference(),None,Some(commit),&q,Default::default())).unwrap();
        assert_eq!(report.files_selected,8);assert_eq!(report.files_read,3);assert_eq!(report.unsupported_language_files,5);
        assert_eq!(report.non_regular_entries,2);assert_eq!(report.bytes_read,A.len()+B.len()+RAW.len());
        assert_eq!(report.bytes_searched,report.bytes_read);assert_eq!(report.declarations_examined,6);
        assert_eq!(report.attributes_skipped,1);assert_eq!(report.macro_bodies_skipped,1);assert_eq!(report.completion,SearchCompletion::Complete);
        assert_eq!(report.matches.iter().map(|r|r.name.as_slice()).collect::<Vec<_>>(),
            vec![b"ThingRaw".as_slice(),b"Thing",b"ThingWorker",b"ThingMaker",b"ThingLocal"]);
        for row in &report.matches {
            let body=match row.location.path.as_slice(){RAW_PATH=>RAW,b"src/a.rs"=>A,b"src/b.rs"=>B,_=>panic!("unexpected path")};
            assert_eq!(row.location.blob,git_object_id(format,GitObjectKind::Blob,body));
            assert_eq!(&body[row.location.byte_offset..row.location.byte_offset+row.location.match_length],row.name);
            assert_eq!(&body[row.location.excerpt_offset..row.location.excerpt_offset+row.location.excerpt.len()],row.location.excerpt);
        }
        let raw=local(&node,&query(b"type",SymbolMatchMode::Exact,&[SymbolKind::Function],&[]),Default::default()).unwrap();
        assert_eq!(raw.matches.len(),1);assert!(raw.matches[0].raw_identifier);assert_eq!(raw.matches[0].location.line,2);
        assert_eq!(generation(&node),before);node.shutdown().unwrap();
        let node=reopen(&config);
        let again=node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&node.request_context(),&reference(),Some(head),Some(commit),&q,Default::default())).unwrap();
        assert_eq!(again,(head,report));assert_eq!(generation(&node),before);node.shutdown().unwrap();
    }
}
fn scoped<A:NativeFormat>(node:&OneNode,capability:&mut TreeCapability,visibility:&RefVisibility,q:&SymbolQuery)
    ->Result<SymbolSearchReport,SymbolReadError<NodeWorkspaceRefusal>>{
    node.runtime().block_on(node.search_source_symbols_in::<A>(&node.request_context(),&reference(),visibility,capability,0,q,Default::default()))
}
#[test]
fn native_capability_visibility_kind_and_component_filters_never_widen_reads(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let(node,_)=symbols(&root,format);
        let cap=|repo|TreeCapability::new(WorkspaceId::from_bytes([0x77;16]),repo,vec![TreePath::parse_default(b"src").unwrap()],Vec::new());
        let q=query(b"Thing",SymbolMatchMode::Prefix,&[],&[]);let repo=RepositoryId::from_bytes([0x32;16]);
        let run=|cap:&mut TreeCapability,v:&RefVisibility|match format{GitHashAlgorithm::Sha1=>scoped::<Sha1>(&node,cap,v,&q),GitHashAlgorithm::Sha256=>scoped::<Sha256>(&node,cap,v,&q)};
        let r=run(&mut cap(repo),&RefVisibility::new()).unwrap();assert_eq!(r.matches.len(),4);assert_eq!(r.files_selected,2);
        assert!(r.matches.iter().all(|m|m.location.path.starts_with(b"src/")));
        assert!(run(&mut cap(RepositoryId::from_bytes([0x99;16])),&RefVisibility::new()).is_err());
        let mut revoked=cap(repo);revoked.revoke();assert!(run(&mut revoked,&RefVisibility::new()).is_err());
        let mut hidden=RefVisibility::new();hidden.push_rule(reference().as_bytes(),&Default::default()).unwrap();assert!(run(&mut cap(repo),&hidden).is_err());
        let r=local(&node,&query(b"Thing",SymbolMatchMode::Prefix,&[SymbolKind::Struct],&[b"src".to_vec()]),Default::default()).unwrap();
        assert_eq!(r.matches.len(),1);assert_eq!(r.matches[0].name,b"Thing");
        assert!(local(&node,&query(b"Thing",SymbolMatchMode::Prefix,&[],&[b"sr".to_vec()]),Default::default()).unwrap().matches.is_empty());
        node.shutdown().unwrap();
    }
}
#[test]
fn native_limits_cancellation_and_invalid_pins_never_return_partial_success(){
    let root=Scratch::new();let(node,commit)=symbols(&root,GitHashAlgorithm::Sha1);let before=generation(&node);
    let q=query(b"Thing",SymbolMatchMode::Prefix,&[],&[]);
    let limited=local(&node,&q,SearchLimits{max_matches:2,..Default::default()}).unwrap();assert_eq!(limited.matches.len(),2);assert_eq!(limited.completion,SearchCompletion::MatchLimit);
    let exact=local(&node,&q,SearchLimits{max_matches:5,..Default::default()}).unwrap();assert_eq!(exact.completion,SearchCompletion::Complete);
    assert!(local(&node,&q,SearchLimits{max_total_bytes:1,..Default::default()}).is_err());
    let tiny=SymbolQuery::new(b"Thing",SymbolMatchMode::Prefix,&[],&[],1).unwrap();
    assert!(matches!(local(&node,&tiny,Default::default()),Err(SymbolReadError::Syntax{error,..}) if error.kind==SymbolSyntaxErrorKind::WorkLimit));
    let request=node.request_context();request.cancel();
    assert!(node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&request,&reference(),None,Some(commit),&q,Default::default())).is_err());
    let clean=node.request_context();drop(node.search_source_symbols_snapshot_local_in(&clean,&reference(),None,None,&q,Default::default()));
    let wrong=GitOid::from_hex(GitHashAlgorithm::Sha256,&"a".repeat(64)).unwrap();
    assert!(node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&clean,&reference(),None,Some(wrong),&q,Default::default())).is_err());
    assert_eq!(generation(&node),before);assert!(local(&node,&q,Default::default()).is_ok());node.shutdown().unwrap();
}
#[test]
fn unsupported_source_is_distinct_from_an_empty_supported_search(){
    let root=Scratch::new();let(node,base)=fixture(&root,GitHashAlgorithm::Sha1);
    let q=query(b"Thing",SymbolMatchMode::Prefix,&[],&[]);
    let empty=local(&node,&q,Default::default()).unwrap();assert_eq!(empty.unsupported_language_files,5);assert_eq!(empty.files_read,0);assert!(empty.matches.is_empty());
    let commit=add_files(&node,base,&[(b"src/good.rs",b"fn Thing(){}\n"),(b"z.rs",b"fn Thing(){} /* unterminated\n")],b"bad-symbol-source");
    assert_ne!(commit,base);
    assert!(matches!(local(&node,&q,Default::default()),Err(SymbolReadError::Syntax{error,..}) if error.kind==SymbolSyntaxErrorKind::UnterminatedComment));
    let narrowed=local(&node,&query(b"Thing",SymbolMatchMode::Exact,&[],&[b"src".to_vec()]),Default::default()).unwrap();assert_eq!(narrowed.matches.len(),1);
    node.shutdown().unwrap();
}
#[test]
fn authenticated_http_returns_same_snapshot_bytes_for_fixed_and_chunked_requests(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let config=root.config(format);let(node,commit)=symbols(&root,format);let before=generation(&node);
        let path=root.0.join("credentials");credentials(&node,&path);let server=Server::start(node,&path,5,true,false);
        let form=form(format);let first=post(&server.client,"search-symbols",'a',&form,false);status(&first,200);
        assert_eq!(text(&first.body,"type"),"source_search_symbols");assert_eq!(text(&first.body,"profile"),"rust-declaration-heads-v1");
        assert_eq!(number(&first.body,"returned_matches"),5);assert_eq!(number(&first.body,"unsupported_language_files"),5);
        assert!(first.body.contains(&hex(RAW_PATH)));assert!(first.body.contains("\"compiler_resolved\":false"));assert!(first.body.contains("\"transaction_created\":false"));
        let pinned=format!("{form}&expected_head={}&expected_commit={commit}",token(&first));
        assert_eq!(post(&server.client,"search-symbols",'a',&pinned,true),first);
        let limited=post(&server.client,"search-symbols",'a',&(form.clone()+"&max_matches=2"),false);status(&limited,200);assert_eq!(text(&limited.body,"completion"),"match_limit");
        let exact=post(&server.client,"search-symbols",'a',&(form.clone()+"&max_matches=5"),false);status(&exact,200);assert_eq!(text(&exact.body,"completion"),"complete");
        status(&post(&server.client,"search-symbols",'a',&(form+"&max_work=1"),false),413);
        assert_eq!(server.finish().accepted_sessions(),5);let node=reopen(&config);assert_eq!(generation(&node),before);node.shutdown().unwrap();
    }
}
#[test]
fn http_authorization_revocation_source_switch_and_transaction_boundary_precede_disclosure(){
    let root=Scratch::new();let config=root.config(GitHashAlgorithm::Sha1);let(node,_)=symbols(&root,GitHashAlgorithm::Sha1);let before=generation(&node);
    let path=root.0.join("credentials");let header=credentials(&node,&path);let server=Server::start(node,&path,5,true,false);let form=form(GitHashAlgorithm::Sha1);
    for (token,code) in [('b',403),('c',403),('f',401)]{let r=post(&server.client,"search-symbols",token,&form,false);status(&r,code);assert!(!r.body.contains("\"matches\""));}
    let r=exchange(&server.client,&request(&server.client,"/api/v1/source/search-symbols",'a',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: not-a-write\r\n",form.len()),form.as_bytes()),true);status(&r,400);
    replace(&path,&(header+&row('b',FOREIGN,"receive")));status(&post(&server.client,"search-symbols",'a',&form,false),401);
    assert_eq!(server.finish().accepted_sessions(),5);let node=reopen(&config);assert_eq!(generation(&node),before);credentials(&node,&path);
    let server=Server::start(node,&path,1,false,false);status(&post(&server.client,"search-symbols",'a',&form,false),403);assert_eq!(server.finish().accepted_sessions(),1);
}
#[test]
fn http_snapshot_pins_refuse_intervening_forge_write_and_new_query_can_reselect(){
    let root=Scratch::new();let(node,commit)=symbols(&root,GitHashAlgorithm::Sha1);let path=root.0.join("credentials");credentials(&node,&path);
    let server=Server::start(node,&path,4,true,true);let form=form(GitHashAlgorithm::Sha1);
    let first=post(&server.client,"search-symbols",'a',&form,false);status(&first,200);
    let body=b"expected_version=0&title=New+forge+position&body=";
    let written=exchange(&server.client,&request(&server.client,"/api/v1/issues/1/open",'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: symbols-forge-write\r\n",body.len()),body),true);status(&written,200);
    let stale=post(&server.client,"search-symbols",'a',&format!("{form}&expected_head={}&expected_commit={commit}",token(&first)),false);status(&stale,409);
    assert!(stale.body.contains("source_snapshot_moved"));assert!(!stale.body.contains("\"matches\""));
    let current=post(&server.client,"search-symbols",'a',&format!("{form}&expected_commit={commit}"),false);status(&current,200);assert_ne!(token(&first),token(&current));
    assert_eq!(number(&current.body,"returned_matches"),5);assert_eq!(server.finish().accepted_sessions(),4);
}
#[test]
fn http_unsupported_source_refuses_without_disclosing_diagnostic_paths_or_falling_back(){
    let root=Scratch::new();let(node,base)=fixture(&root,GitHashAlgorithm::Sha1);
    add_files(&node,base,&[(b"src/good.rs",b"fn Thing(){}\n"),(b"private.rs","fn naïve(){}\n".as_bytes())],b"unsupported-ident");
    let path=root.0.join("credentials");credentials(&node,&path);let server=Server::start(node,&path,3,true,false);let form=form(GitHashAlgorithm::Sha1);
    let error=post(&server.client,"search-symbols",'a',&form,false);status(&error,409);assert_eq!(text(&error.body,"code"),"symbol_source_unsupported");
    assert!(!error.body.contains("private") && !error.body.contains("\"matches\""));
    let good=post(&server.client,"search-symbols",'a',&(form.clone()+"&path_prefix_hex=737263"),false);status(&good,200);assert_eq!(number(&good.body,"returned_matches"),1);
    status(&post(&server.client,"search-symbols",'a',&(form+"&kind=reference"),false),400);assert_eq!(server.finish().accepted_sessions(),3);
}
