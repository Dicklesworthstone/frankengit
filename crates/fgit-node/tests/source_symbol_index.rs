#![forbid(unsafe_code)]
//! Actual native trees, index publication, Fsqlite reopen, operator and TCP.
//! These tests do not substitute a fake index or storage backend.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolKind, SymbolMatchMode, SymbolQuery};
use fgit_forge::source_symbols::index::{self as data, AccessError};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GenerationRecovery};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, RefName};

type Failure = AccessError<NodeWorkspaceRefusal,GenerationAuthorityError>;
const A:&[u8]=b"// fn ThingFake() {}\r\n#[allow(dead_code)]\r\npub struct Thing;\r\npub fn ThingWorker() { let _ = \"fn ThingString(){}\"; }\r\nmacro_rules! ThingMaker { () => { fn ThingGenerated(){} } }\r\n";
const B:&[u8]=b"fn ThingLocal() {}\nfn r#type() {}\n";
const RAW_PATH:&[u8]=b"raw\xff.rs";
const RAW:&[u8]=b"pub fn ThingRaw() {}\n";
fn reference()->RefName{RefName::try_new(b"refs/heads/main").unwrap()}
fn query(name:&[u8],mode:SymbolMatchMode,kinds:&[SymbolKind],prefixes:&[Vec<u8>])->SymbolQuery{
    SymbolQuery::new(name,mode,kinds,prefixes,MAX_SYMBOL_WORK).unwrap()
}
fn ordinary()->SymbolQuery{query(b"Thing",SymbolMatchMode::Prefix,&[],&[])}
fn build(node:&OneNode,previous:Option<&GenerationActivation>)->GenerationActivation{
    node.runtime().block_on(node.build_source_symbol_index_local_in(&node.outbox_delivery_context(),&reference(),
        None,None,previous.map(|p|p.generation_id),Default::default())).unwrap().1
}
fn search(node:&OneNode,query:&SymbolQuery,limits:SearchLimits,bytes:usize)->Result<data::Report,Failure>{
    node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),&reference(),
        None,None,None,query,limits,bytes))
}
fn quoted(prefix:char,path:&[u8])->String{
    let mut out=format!("\"{prefix}/");
    for b in path{if b.is_ascii_alphanumeric()||b"/._-".contains(b){out.push(char::from(*b));}else{out.push_str(&format!("\\{b:03o}"));}}
    out.push('"');out
}
fn add_files(node:&OneNode,base:GitOid,files:&[(&[u8],&[u8])],key:&[u8])->GitOid{
    let mut patch=Vec::new();
    for (path,body) in files{
        let old=quoted('a',path);let new=quoted('b',path);
        patch.extend_from_slice(format!("diff --git {old} {new}\nnew file mode 100644\n").as_bytes());
        if !body.is_empty(){
            assert!(body.ends_with(b"\n"));let n=body.iter().filter(|b|**b==b'\n').count();
            patch.extend_from_slice(format!("--- /dev/null\n+++ {new}\n@@ -0,0 +1,{n} @@\n").as_bytes());
            for line in body.split_inclusive(|b|*b==b'\n'){patch.push(b'+');patch.extend_from_slice(line);}
        }
    }
    let metadata=MergeMetadata{author:"Fixture <fixture@example.invalid>".into(),committer:"Fixture <fixture@example.invalid>".into(),timestamp:2,message:b"persistent symbols\n".to_vec()};
    let request=node.request_context();
    let candidate=node.runtime().block_on(node.prepare_trusted_patch_in(&request,&reference(),base,[0x76;16],&patch,&metadata,PatchLimits::default())).unwrap();
    let result=node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request,OWNER,key,&reference(),base,candidate.candidate_commit,candidate.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c|matches!(c.terminal.outcome,DecisionOutcome::Committed{..})));candidate.candidate_commit
}
fn symbols(root:&Scratch,format:GitHashAlgorithm)->(OneNode,GitOid){
    let(node,base)=fixture(root,format);
    let commit=add_files(&node,base,&[(b"src/a.rs",A),(b"src/b.rs",B),(RAW_PATH,RAW)],b"stored-symbol-fixture");(node,commit)
}
fn form(format:GitHashAlgorithm)->String{format!("{}&name_hex={}&match=prefix",common(format),hex(b"Thing"))}

#[test]
fn native_persisted_symbols_match_live_scans_and_survive_reopen_in_both_formats(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let config=root.config(format);let(node,commit)=symbols(&root,format);let before=generation(&node);
        assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Uninitialized)));
        // A build's match limit cannot truncate its inventory.
        let(source,activation)=node.runtime().block_on(node.build_source_symbol_index_local_in(&node.outbox_delivery_context(),
            &reference(),None,Some(commit),None,SearchLimits{max_matches:1,..Default::default()})).unwrap();
        let report=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
        let(_,live)=node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&node.request_context(),
            &reference(),Some(source.head),Some(commit),&ordinary(),Default::default())).unwrap();
        assert_eq!(report.matches,live.matches);assert!(report.complete);assert_eq!(report.indexed_files,3);
        assert_eq!(report.indexed_declarations,6);assert_eq!(report.unsupported_language_files,5);assert_eq!(report.non_regular_entries,2);
        assert_eq!(report.indexed_source_bytes,A.len()+B.len()+RAW.len());assert_eq!(report.tables_read,3);
        assert_eq!(report.generation,*activation.generation_id.as_internal_object_id());
        let raw=search(&node,&query(b"type",SymbolMatchMode::Exact,&[SymbolKind::Function],&[]),Default::default(),data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(raw.matches.len(),1);assert!(raw.matches[0].raw_identifier);
        assert_eq!(generation(&node),before);node.shutdown().unwrap();
        let node=reopen(&config);let again=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(again.source,report.source);assert_eq!(again.generation,report.generation);assert_eq!(again.matches,report.matches);
        assert_eq!(generation(&node),before);node.shutdown().unwrap();
    }
}
#[test]
fn shared_payload_source_file_and_result_bounds_have_permitted_twins(){
    let root=Scratch::new();let(node,_)=symbols(&root,GitHashAlgorithm::Sha1);build(&node,None);
    let full=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    assert!(search(&node,&ordinary(),Default::default(),full.payload_bytes_read).is_ok());
    assert!(search(&node,&ordinary(),Default::default(),full.payload_bytes_read-1).is_err());
    assert!(search(&node,&ordinary(),SearchLimits{max_files:1,..Default::default()},data::MAX_INDEX_BYTES).is_err());
    assert!(search(&node,&ordinary(),SearchLimits{max_total_bytes:1,..Default::default()},data::MAX_INDEX_BYTES).is_err());
    let limited=search(&node,&ordinary(),SearchLimits{max_matches:4,..Default::default()},data::MAX_INDEX_BYTES).unwrap();
    assert!(!limited.complete);assert_eq!(limited.matches.len(),4);
    let exact=search(&node,&ordinary(),SearchLimits{max_matches:5,..Default::default()},data::MAX_INDEX_BYTES).unwrap();
    assert!(exact.complete);assert_eq!(exact.matches.len(),5);
    let scoped=query(b"Thing",SymbolMatchMode::Prefix,&[],&[b"src/b.rs".to_vec()]);
    let report=search(&node,&scoped,SearchLimits{max_files:1,..Default::default()},data::MAX_INDEX_BYTES).unwrap();
    assert!(report.complete);assert_eq!(report.tables_read,1);assert_eq!(report.matches.len(),1);
    let none=search(&node,&query(b"Missing",SymbolMatchMode::Exact,&[],&[]),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    assert!(none.complete&&none.matches.is_empty());node.shutdown().unwrap();
}
#[test]
fn write_ahead_barrier_precedes_effects_and_retains_candidate_after_cancellation(){
    let root=Scratch::new();let(node,_)=symbols(&root,GitHashAlgorithm::Sha256);let before=generation(&node);let mut saved=None;
    let request=node.outbox_delivery_context();
    let error=node.runtime().block_on(node.build_source_symbol_index_guarded_local_in(&request,&reference(),None,None,None,
        Default::default(),&mut|candidate|{saved=Some(candidate);Err(NodeWorkspaceRefusal::RefUnavailable)})).unwrap_err();
    assert!(matches!(error,AccessError::Source(NodeWorkspaceRefusal::RefUnavailable)));let candidate=saved.unwrap();
    assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Uninitialized)));
    let request=node.outbox_delivery_context();
    let error=node.runtime().block_on(node.build_source_symbol_index_guarded_local_in(&request,&reference(),None,None,None,
        Default::default(),&mut|id|{assert_eq!(id,candidate);request.cancel();Ok(())})).unwrap_err();
    assert!(matches!(error,AccessError::Publication{candidate:id,..}if id==*candidate.as_internal_object_id()));
    let activation=build(&node,None);assert_eq!(activation.generation_id,candidate);
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),&reference(),candidate,None,Default::default())).unwrap(),GenerationRecovery::Active{..}));
    assert_eq!(generation(&node),before);node.shutdown().unwrap();
}
#[test]
fn same_source_rebuilds_keep_independent_checkpoints_and_recover_old_candidates(){
    let root=Scratch::new();let(node,_)=symbols(&root,GitHashAlgorithm::Sha1);let first=build(&node,None);let second=build(&node,Some(&first));
    let report=node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),&reference(),
        None,None,Some(&first),&ordinary(),Default::default(),data::MAX_INDEX_BYTES)).unwrap();
    assert_eq!(report.generation,*second.generation_id.as_internal_object_id());
    let wrong=GenerationActivation{generation_id:first.generation_id,authority_generation:HeadGeneration::try_new(second.authority_generation.get()+1).unwrap()};
    assert!(node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),&reference(),
        None,None,Some(&wrong),&ordinary(),Default::default(),data::MAX_INDEX_BYTES)).is_err());
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),&reference(),
        first.generation_id,Some(&second),Default::default())).unwrap(),GenerationRecovery::Superseded{activation,..}if activation==first));
    node.shutdown().unwrap();
}
#[test]
fn canonical_edits_make_old_index_stale_until_an_explicit_predecessor_bound_build(){
    let root=Scratch::new();let(node,commit)=symbols(&root,GitHashAlgorithm::Sha256);let first=build(&node,None);
    let old=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    let next=add_files(&node,commit,&[(b"extra.rs",b"fn ThingAdded() {}\n")],b"stored-symbol-new-file");
    assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Stale)));
    assert!(node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),&reference(),
        Some(old.source.head),Some(commit),None,&ordinary(),Default::default(),data::MAX_INDEX_BYTES)).is_err());
    assert!(node.runtime().block_on(node.build_source_symbol_index_local_in(&node.outbox_delivery_context(),&reference(),None,None,None,Default::default())).is_err());
    let second=build(&node,Some(&first));let report=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    assert_eq!(report.source.commit,next);assert_eq!(report.matches.len(),6);assert_eq!(report.generation,*second.generation_id.as_internal_object_id());node.shutdown().unwrap();
}
#[test]
fn malformed_source_cannot_publish_a_partial_successor_index(){
    let root=Scratch::new();let(node,commit)=symbols(&root,GitHashAlgorithm::Sha1);let first=build(&node,None);
    add_files(&node,commit,&[(b"broken.rs",b"fn Broken() {\n")],b"stored-symbol-broken-source");
    let error=node.runtime().block_on(node.build_source_symbol_index_local_in(&node.outbox_delivery_context(),&reference(),None,None,Some(first.generation_id),Default::default())).unwrap_err();
    assert!(matches!(error,AccessError::Index(data::Error::Table(_))));
    let recovered=node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),&reference(),first.generation_id,None,Default::default())).unwrap();
    assert!(matches!(recovered,GenerationRecovery::Active{..}));
    assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Stale)));node.shutdown().unwrap();
}
#[test]
fn invalid_refs_formats_cancelled_and_unpolled_operations_do_not_initialize_an_index(){
    let root=Scratch::new();let(node,_)=symbols(&root,GitHashAlgorithm::Sha1);let before=generation(&node);let request=node.request_context();
    let pinned_ref=reference();
    let future=node.build_source_symbol_index_local_in(&request,&pinned_ref,None,None,None,Default::default());drop(future);
    request.cancel();assert!(node.runtime().block_on(node.build_source_symbol_index_local_in(&request,&reference(),None,None,None,Default::default())).is_err());
    let missing=RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),&missing,
        None,None,None,&ordinary(),Default::default(),data::MAX_INDEX_BYTES)),Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
    let foreign=GitOid::from_hex(GitHashAlgorithm::Sha256,&"a".repeat(64)).unwrap();
    assert!(matches!(node.runtime().block_on(node.build_source_symbol_index_local_in(&node.request_context(),&reference(),None,Some(foreign),None,Default::default())),Err(AccessError::Source(NodeWorkspaceRefusal::ObjectFormatMismatch))));
    assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Uninitialized)));
    assert_eq!(generation(&node),before);build(&node,None);node.shutdown().unwrap();
}
#[test]
fn http_distinguishes_an_unbuilt_index_from_an_authenticated_empty_inventory(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let config=root.config(format);let(node,_)=fixture(&root,format);let path=root.0.join("credentials");credentials(&node,&path);
        let server=Server::start(node,&path,1,true,false);let missing=post(&server.client,"search-symbols-index",'a',&form(format),false);
        status(&missing,409);assert!(missing.body.contains("symbol_index_uninitialized"));server.finish();
        let node=reopen(&config);let first=build(&node,None);let server=Server::start(node,&path,2,true,false);
        for chunked in [false,true]{let reply=post(&server.client,"search-symbols-index",'a',&form(format),chunked);status(&reply,200);
            assert!(reply.body.contains("\"complete\":true"));assert!(reply.body.contains("\"matches\":[]"));assert_eq!(number(&reply.body,"source_blobs_read"),0);assert_eq!(number(&reply.body,"indexed_files"),0);}
        server.finish();let node=reopen(&config);let result=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(result.generation,*first.generation_id.as_internal_object_id());node.shutdown().unwrap();
    }
}
#[test]
fn authenticated_indexed_http_preserves_native_results_scopes_budgets_and_revocation(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let(node,_)=symbols(&root,format);build(&node,None);let path=root.0.join("credentials");let header=credentials(&node,&path);
        let server=Server::start(node,&path,8,true,false);
        let first=post(&server.client,"search-symbols-index",'a',&form(format),false);status(&first,200);
        assert_eq!(number(&first.body,"returned_matches"),5);assert_eq!(number(&first.body,"source_blobs_read"),0);
        assert!(first.body.contains(&hex(RAW_PATH)));assert!(first.body.contains("rust-declaration-tables-v1"));
        let pinned=format!("{}&expected_head={}&expected_commit={}&minimum_index_token={}&minimum_index_number={}",
            form(format),token(&first),text(&first.body,"source_commit"),text(&first.body,"index_token"),number(&first.body,"index_number"));
        let next=post(&server.client,"search-symbols-index",'a',&pinned,true);status(&next,200);assert_eq!(next.body,first.body);
        let higher=format!("{}&minimum_index_token={}&minimum_index_number={}",form(format),text(&first.body,"index_token"),number(&first.body,"index_number")+1);
        let refused=post(&server.client,"search-symbols-index",'a',&higher,false);status(&refused,409);assert!(refused.body.contains("index_checkpoint_unavailable"));
        status(&post(&server.client,"search-symbols-index",'a',&(form(format)+"&after=1"),false),400);
        status(&post(&server.client,"search-symbols-index",'b',&form(format),false),403);
        let body=form(format);let bytes=request(&server.client,"/api/v1/source/search-symbols-index",'a',
            &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-read-key\r\n",body.len()),body.as_bytes());
        status(&exchange(&server.client,&bytes,true),400);
        status(&post(&server.client,"search-symbols-index",'a',&(form(format)+"&max_work=1"),false),413);
        replace(&path,&(header+&row('c',OWNER,"outcomes-read")));
        status(&post(&server.client,"search-symbols-index",'a',&form(format),false),401);
        assert_eq!(server.finish().accepted_sessions(),8);
    }
}
#[test]
fn forge_only_write_invalidates_http_index_without_implicitly_rebuilding_it(){
    let format=GitHashAlgorithm::Sha1;let root=Scratch::new();let config=root.config(format);let(node,commit)=symbols(&root,format);
    let first=build(&node,None);let path=root.0.join("credentials");credentials(&node,&path);let server=Server::start(node,&path,2,true,true);
    let body=b"expected_version=0&title=Symbol+index+staleness&body=";
    let written=exchange(&server.client,&request(&server.client,"/api/v1/issues/1/open",'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: symbols-index-forge-write\r\n",body.len()),body),true);status(&written,200);
    let stale=post(&server.client,"search-symbols-index",'a',&form(format),false);status(&stale,409);assert!(stale.body.contains("symbol_index_stale"));server.finish();
    let node=reopen(&config);let second=build(&node,Some(&first));let report=search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    assert_eq!(report.source.commit,commit);assert_eq!(report.generation,*second.generation_id.as_internal_object_id());node.shutdown().unwrap();
}
#[test]
fn operator_build_query_and_original_candidate_recovery_use_existing_nodes(){
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256]{
        let root=Scratch::new();let config=root.config(format);let(node,_)=symbols(&root,format);let before=generation(&node);node.shutdown().unwrap();
        let run=|tail:&[&str]|std::process::Command::new(env!("CARGO_BIN_EXE_fg-symbol-index"))
            .arg(root.0.join("node")).args(["31313131313131313131313131313131","32323232323232323232323232323232",format.as_str(),"refs/heads/main"])
            .args(tail).output().unwrap();
        let built=run(&["build","genesis"]);assert!(built.status.success(),"{}",String::from_utf8_lossy(&built.stderr));
        let body=String::from_utf8(built.stdout).unwrap();let index=text(&body,"index_token");
        let query=run(&["query","prefix","Thing"]);assert!(query.status.success(),"{}",String::from_utf8_lossy(&query.stderr));
        let body=String::from_utf8(query.stdout).unwrap();assert_eq!(number(&body,"source_blobs_read"),0);assert!(body.contains(&hex(b"ThingWorker")));
        let recovery=run(&["recover",index]);assert!(recovery.status.success());assert!(String::from_utf8(recovery.stdout).unwrap().contains("\"state\":\"active\""));
        assert!(!run(&["build","genesis"]).status.success());
        let node=reopen(&config);assert_eq!(generation(&node),before);assert_eq!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap().matches.len(),5);node.shutdown().unwrap();
    }
}
