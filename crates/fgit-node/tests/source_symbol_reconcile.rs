#![forbid(unsafe_code)]
//! Real native imports, patch admission, persisted indexes and operator floors.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolMatchMode, SymbolQuery};
use fgit_forge::source_symbols::index::{self as data, AccessError};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, RefName};

type Failure = AccessError<NodeWorkspaceRefusal,GenerationAuthorityError>;
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn reconcile(node: &OneNode, floor: Option<&GenerationActivation>) -> Result<(data::Source,GenerationActivation),Failure> {
    node.runtime().block_on(node.reconcile_source_symbol_index_local_in(&node.outbox_delivery_context(),
        &reference(),None,floor,Default::default(),Default::default()))
}
fn search(node: &OneNode) -> Result<data::Report,Failure> {
    let query = SymbolQuery::new(b"Thing",SymbolMatchMode::Prefix,&[],&[],MAX_SYMBOL_WORK).unwrap();
    node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),
        &reference(),None,None,None,&query,Default::default(),data::MAX_INDEX_BYTES))
}
fn add_file(node: &OneNode, base: GitOid, path: &str, body: &[u8], key: &[u8]) -> GitOid {
    assert!(body.ends_with(b"\n"));
    let lines = body.iter().filter(|b| **b == b'\n').count();
    let mut patch = format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{lines} @@\n").into_bytes();
    for line in body.split_inclusive(|b| *b == b'\n') { patch.push(b'+'); patch.extend_from_slice(line); }
    let metadata = MergeMetadata { author:"Fixture <fixture@example.invalid>".into(),
        committer:"Fixture <fixture@example.invalid>".into(),timestamp:3,message:b"symbol reconciliation\n".to_vec() };
    let request = node.request_context();
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(&request,&reference(),base,
        [0x79;16],&patch,&metadata,Default::default())).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request,OWNER,key,
        &reference(),base,candidate.candidate_commit,candidate.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome,DecisionOutcome::Committed { .. })));
    candidate.candidate_commit
}
fn symbols(root: &Scratch, format: GitHashAlgorithm) -> (OneNode,GitOid) {
    let (node,commit) = fixture(root,format);
    let commit = add_file(&node,commit,"one.rs",b"pub fn ThingOne() {}\n",b"symbol-reconcile-initial");
    (node,commit)
}
fn candidate(node: &OneNode, previous: Option<&GenerationActivation>) -> GraphGenerationId {
    let mut saved = None;
    let result = node.runtime().block_on(node.build_source_symbol_index_guarded_local_in(&node.outbox_delivery_context(),
        &reference(),None,None,previous.map(|p| p.generation_id),Default::default(),
        &mut |id| { saved = Some(id); Err(NodeWorkspaceRefusal::RefUnavailable) }));
    assert!(matches!(result,Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
    saved.unwrap()
}

#[test]
fn genesis_and_current_noop_match_full_build_and_survive_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node,commit) = symbols(&root,format); let canonical = generation(&node);
        let expected = candidate(&node,None);
        let first = reconcile(&node,None).unwrap();
        assert_eq!(first.0.commit,commit);
        assert_eq!(first.1.generation_id,expected);
        assert_eq!(first.1.authority_generation.get(),1);
        for _ in 0..2 {
            let observed = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
                &node.outbox_delivery_context(),&reference(),Some(first.0.head),Some(&first.1),
                Default::default(),Default::default(),&mut |_| panic!("current index cannot publish"))).unwrap();
            assert_eq!(observed,first);
        }
        assert_eq!(search(&node).unwrap().matches.len(),1);
        assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
        let node = reopen(&config);
        assert_eq!(reconcile(&node,Some(&first.1)).unwrap(),first);
        assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
    }
}

#[test]
fn source_edits_choose_one_predecessor_and_preserve_full_rebuild_identity() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node,commit) = symbols(&root,format);
        let first = reconcile(&node,None).unwrap();
        let next = add_file(&node,commit,"two.rs",b"fn ThingTwo() {}\n",b"symbol-reconcile-edit");
        let canonical = generation(&node);
        assert!(matches!(search(&node),Err(AccessError::Stale)));
        let expected = candidate(&node,Some(&first.1));
        let second = reconcile(&node,Some(&first.1)).unwrap();
        assert_eq!(second.0.commit,next);
        assert_eq!(second.1.generation_id,expected);
        assert_eq!(second.1.authority_generation.get(),2);
        assert_eq!(search(&node).unwrap().matches.len(),2);
        assert_eq!(reconcile(&node,Some(&first.1)).unwrap(),second);
        assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
    }
}

#[test]
fn checkpoint_failure_never_initializes_or_rolls_back_an_index() {
    let root = Scratch::new(); let (node,_) = symbols(&root,GitHashAlgorithm::Sha1);
    let first = reconcile(&node,None).unwrap();
    let higher = GenerationActivation { generation_id:first.1.generation_id,
        authority_generation:HeadGeneration::try_new(2).unwrap() };
    assert!(matches!(reconcile(&node,Some(&higher)),
        Err(AccessError::Generation(GenerationAuthorityError::CheckpointUnresolved))));
    let fresh = Scratch::new(); let (fresh_node,_) = symbols(&fresh,GitHashAlgorithm::Sha1);
    assert!(matches!(reconcile(&fresh_node,Some(&first.1)),
        Err(AccessError::Generation(GenerationAuthorityError::CheckpointUnresolved))));
    assert!(matches!(search(&fresh_node),Err(AccessError::Uninitialized)));
    fresh_node.shutdown().unwrap();
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.reconcile_source_symbol_index_local_in(&node.request_context(),
        &missing,None,Some(&higher),Default::default(),Default::default())),
        Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
    assert_eq!(reconcile(&node,Some(&first.1)).unwrap(),first); node.shutdown().unwrap();
}

#[test]
fn genesis_and_refresh_barriers_preserve_original_candidates_on_failure_and_cancel() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node,commit) = symbols(&root,format);
        let mut floor = None;
        for pass in 0..2 {
            if pass == 1 { add_file(&node,commit,"two.rs",b"fn ThingTwo() {}\n",b"symbol-reconcile-barrier"); }
            let expected = candidate(&node,floor.as_ref());
            let refused = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
                &node.outbox_delivery_context(),&reference(),None,floor.as_ref(),Default::default(),Default::default(),
                &mut |id| { assert_eq!(id,expected); Err(NodeWorkspaceRefusal::RefUnavailable) }));
            assert!(matches!(refused,Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
            let request = node.outbox_delivery_context();
            let cancelled = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
                &request,&reference(),None,floor.as_ref(),Default::default(),Default::default(),
                &mut |id| { assert_eq!(id,expected); request.cancel(); Ok(()) }));
            assert!(matches!(cancelled,Err(AccessError::Publication { candidate,.. })
                if candidate == *expected.as_internal_object_id()));
            if let Some(previous) = &floor {
                assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(
                    &node.request_context(),&reference(),previous.generation_id,None,Default::default())).unwrap(),
                    GenerationRecovery::Active { .. }));
            } else { assert!(matches!(search(&node),Err(AccessError::Uninitialized))); }
            let next = reconcile(&node,floor.as_ref()).unwrap();
            assert_eq!(next.1.generation_id,expected);
            floor = Some(next.1);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn malformed_source_pins_limits_and_unpolled_operations_never_publish() {
    let root = Scratch::new(); let (node,commit) = symbols(&root,GitHashAlgorithm::Sha256);
    let request = node.outbox_delivery_context(); let reference = reference();
    drop(node.reconcile_source_symbol_index_local_in(&request,&reference,None,None,Default::default(),Default::default()));
    assert!(matches!(search(&node),Err(AccessError::Uninitialized)));
    let first = reconcile(&node,None).unwrap();
    let invalid = SearchLimits { max_files:0,..Default::default() };
    assert!(matches!(node.runtime().block_on(node.reconcile_source_symbol_index_local_in(&request,&reference,
        None,Some(&first.1),invalid,Default::default())),Err(AccessError::Index(data::Error::Source(_)))));
    add_file(&node,commit,"broken.rs",b"fn ThingBroken() {\n",b"symbol-reconcile-malformed");
    let pinned = node.runtime().block_on(node.reconcile_source_symbol_index_local_in(&request,&reference,
        Some(first.0.head),Some(&first.1),Default::default(),Default::default()));
    assert!(matches!(pinned,Err(AccessError::Source(NodeWorkspaceRefusal::SourceBrowse(_)))));
    assert!(matches!(reconcile(&node,Some(&first.1)),Err(AccessError::Index(data::Error::Table(_)))));
    request.cancel();
    assert!(matches!(node.runtime().block_on(node.reconcile_source_symbol_index_local_in(&request,&reference,
        None,Some(&first.1),Default::default(),Default::default())),Err(AccessError::Index(data::Error::Cancelled))));
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),
        &reference,first.1.generation_id,None,Default::default())).unwrap(),GenerationRecovery::Active { .. }));
    node.shutdown().unwrap();
}

#[test]
fn forge_only_changes_are_reconciled_without_implicit_query_maintenance() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node,commit) = symbols(&root,GitHashAlgorithm::Sha1);
    let first = reconcile(&node,None).unwrap();
    let path = root.0.join("credentials"); credentials(&node,&path);
    let server = Server::start(node,&path,1,true,true);
    let body = b"expected_version=0&title=Symbol+maintenance&body=";
    let reply = exchange(&server.client,&request(&server.client,"/api/v1/issues/1/open",'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: symbol-reconcile-forge\r\n",body.len()),body),true);
    status(&reply,200); server.finish();
    let node = reopen(&config); let canonical = generation(&node);
    assert!(matches!(search(&node),Err(AccessError::Stale)));
    let second = reconcile(&node,Some(&first.1)).unwrap();
    assert_eq!(second.0.commit,commit); assert_ne!(second.0.head,first.0.head);
    assert_eq!(search(&node).unwrap().generation,*second.1.generation_id.as_internal_object_id());
    assert_eq!(reconcile(&node,Some(&first.1)).unwrap(),second);
    assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
}
