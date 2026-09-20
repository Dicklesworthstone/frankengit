//! Exercise the real authority store, native TreeFS and production scanner.
use super::*;
use fgit_graph::GraphGenerationId;

fn refresh(node: &OneNode, previous: &GenerationActivation, limits: SearchLimits)
    -> Result<(data::Source, GenerationActivation, data::RefreshStats), Failure>
{
    node.runtime().block_on(node.refresh_source_symbol_index_local_in(&node.outbox_delivery_context(),
        &reference(),None,None,previous.generation_id,limits))
}

/// A full rebuild computes the complete canonical candidate but our failed
/// write-ahead barrier prevents all staging. Comparing IDs therefore checks
/// every table/manifest byte and source binding, not just one query's matches.
fn full_candidate(node: &OneNode, previous: &GenerationActivation) -> GraphGenerationId {
    let mut candidate = None;
    let result = node.runtime().block_on(node.build_source_symbol_index_guarded_local_in(
        &node.outbox_delivery_context(),&reference(),None,None,Some(previous.generation_id),
        Default::default(),&mut |id| { candidate = Some(id); Err(NodeWorkspaceRefusal::RefUnavailable) }));
    assert!(matches!(result,Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
    candidate.unwrap()
}

fn assert_live_equivalent(node: &OneNode, source: &data::Source) -> data::Report {
    let report = search(node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap();
    let (_,live) = node.runtime().block_on(node.search_source_symbols_snapshot_local_in(&node.request_context(),
        &reference(),Some(source.head),Some(source.commit),&ordinary(),Default::default())).unwrap();
    assert_eq!(&report.source,source);
    assert_eq!(report.matches,live.matches);
    assert!(report.complete);
    report
}

/// Explicit delete/add edits also test rename reuse without relying on any
/// heuristic rename detector. The native commit/tree identities are decisive.
fn edit_files(node: &OneNode, base: GitOid,
    changes: &[(&[u8], Option<&[u8]>, Option<&[u8]>)], key: &[u8],
) -> GitOid {
    let mut patch = Vec::new();
    for (path,old,new) in changes {
        let a = quoted('a',path);
        let b = quoted('b',path);
        patch.extend_from_slice(format!("diff --git {a} {b}\n").as_bytes());
        match (old,new) {
            (None,Some(_)) => patch.extend_from_slice(b"new file mode 100644\n"),
            (Some(_),None) => patch.extend_from_slice(b"deleted file mode 100644\n"),
            (Some(_),Some(_)) => {},
            (None,None) => panic!("fixture needs an edit"),
        }
        let old_bytes = old.unwrap_or(b"");
        let new_bytes = new.unwrap_or(b"");
        if old_bytes.is_empty() && new_bytes.is_empty() { continue; }
        for bytes in [old_bytes,new_bytes] { assert!(bytes.is_empty() || bytes.ends_with(b"\n")); }
        let count = |bytes: &[u8]| bytes.iter().filter(|b| **b == b'\n').count();
        let old_count = count(old_bytes);
        let new_count = count(new_bytes);
        let old_start = usize::from(old_count != 0);
        let new_start = usize::from(new_count != 0);
        let a = if old.is_none() { "/dev/null" } else { &a };
        let b = if new.is_none() { "/dev/null" } else { &b };
        patch.extend_from_slice(format!("--- {a}\n+++ {b}\n@@ -{old_start},{old_count} +{new_start},{new_count} @@\n").as_bytes());
        for (prefix,bytes) in [(b'-',old_bytes),(b'+',new_bytes)] {
            for line in bytes.split_inclusive(|b| *b == b'\n') { patch.push(prefix); patch.extend_from_slice(line); }
        }
    }
    let metadata = MergeMetadata { author:"Fixture <fixture@example.invalid>".into(),
        committer:"Fixture <fixture@example.invalid>".into(),timestamp:3,message:b"incremental symbols\n".to_vec() };
    let request = node.request_context();
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(&request,&reference(),base,
        [0x77;16],&patch,&metadata,PatchLimits::default())).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request,OWNER,key,&reference(),
        base,candidate.candidate_commit,candidate.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome,DecisionOutcome::Committed { .. })));
    candidate.candidate_commit
}

#[test]
fn additions_and_copies_reuse_blobs_and_match_the_full_rebuild_after_reopen() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node,commit) = symbols(&root,format);
        let first = build(&node,None);
        const ADDED: &[u8] = b"fn ThingAdded() {}\n";
        let next = add_files(&node,commit,&[(b"copy.rs",RAW),(b"new.rs",ADDED)],b"symbol-refresh-add-copy");
        let before = generation(&node);
        assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Stale)));
        let expected = full_candidate(&node,&first);
        let (source,second,stats) = refresh(&node,&first,SearchLimits { max_matches:1,..Default::default() }).unwrap();
        assert_eq!(second.generation_id,expected);
        assert_eq!(source.commit,next);
        assert_eq!(stats.reused_files,4);
        assert_eq!(stats.source_blobs_read,1);
        assert_eq!(stats.source_bytes_read,ADDED.len());
        assert_eq!(stats.predecessor_tables_read,3);
        assert!(stats.predecessor_payload_bytes > 0);
        let report = assert_live_equivalent(&node,&source);
        assert_eq!(report.indexed_files,5);
        assert_eq!(generation(&node),before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let reopened = assert_live_equivalent(&node,&source);
        assert_eq!(reopened.generation,report.generation);
        assert_eq!(reopened.matches,report.matches);
        let pinned = node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),
            &reference(),None,None,Some(&first),&ordinary(),Default::default(),data::MAX_INDEX_BYTES)).unwrap();
        assert_eq!(pinned.generation,*second.generation_id.as_internal_object_id());
        // The next refresh validates each distinct blob once, even with copies.
        let (_,third,again) = refresh(&node,&second,Default::default()).unwrap();
        assert_eq!(again.reused_files,5);
        assert_eq!(again.source_blobs_read,0);
        assert_eq!(again.source_bytes_read,0);
        assert_eq!(again.predecessor_tables_read,4);
        assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),
            &reference(),second.generation_id,Some(&third),Default::default())).unwrap(),GenerationRecovery::Superseded { .. }));
        assert_eq!(generation(&node),before);
        node.shutdown().unwrap();
    }
}

#[test]
fn modified_deleted_renamed_and_empty_files_have_the_same_canonical_candidate() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node,commit) = symbols(&root,format);
        let first = build(&node,None);
        const CHANGED: &[u8] = b"fn ThingChanged() {}\n";
        let next = edit_files(&node,commit,&[
            (b"src/a.rs",Some(A),None),
            (b"src/renamed.rs",None,Some(A)),
            (b"copy.rs",None,Some(A)),
            (b"src/b.rs",Some(B),Some(CHANGED)),
            (RAW_PATH,Some(RAW),None),
            (b"empty.rs",None,Some(b"")),
        ],b"symbol-refresh-edits");
        let expected = full_candidate(&node,&first);
        let (source,second,stats) = refresh(&node,&first,Default::default()).unwrap();
        assert_eq!(second.generation_id,expected);
        assert_eq!(source.commit,next);
        assert_eq!(stats.reused_files,2);
        assert_eq!(stats.source_blobs_read,2);
        assert_eq!(stats.source_bytes_read,CHANGED.len());
        let report = assert_live_equivalent(&node,&source);
        assert_eq!(report.indexed_files,4);
        assert!(report.matches.iter().all(|m| m.location.path != RAW_PATH && m.location.path != b"src/a.rs"));
        assert!(report.matches.iter().any(|m| m.location.path == b"src/renamed.rs"));
        assert!(report.matches.iter().any(|m| m.name == b"ThingChanged"));
        node.shutdown().unwrap();
    }
}

#[test]
fn deleting_all_rust_files_publishes_authenticated_empty_not_old_matches() {
    let root = Scratch::new();
    let (node,commit) = symbols(&root,GitHashAlgorithm::Sha256);
    let first = build(&node,None);
    edit_files(&node,commit,&[(b"src/a.rs",Some(A),None),(b"src/b.rs",Some(B),None),
        (RAW_PATH,Some(RAW),None)],b"symbol-refresh-delete-all");
    let expected = full_candidate(&node,&first);
    let (source,second,stats) = refresh(&node,&first,Default::default()).unwrap();
    assert_eq!(second.generation_id,expected);
    assert_eq!(stats.reused_files,0);
    assert_eq!(stats.source_blobs_read,0);
    let report = assert_live_equivalent(&node,&source);
    assert_eq!(report.indexed_files,0);
    assert!(report.matches.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn whole_corpus_limits_cannot_be_bypassed_by_a_zero_blob_read_refresh() {
    let root = Scratch::new();
    let (node,_) = symbols(&root,GitHashAlgorithm::Sha1);
    let first = build(&node,None);
    let bytes = A.len()+B.len()+RAW.len();
    for limits in [SearchLimits { max_file_bytes:A.len()-1,..Default::default() },
        SearchLimits { max_file_bytes:bytes-1,max_total_bytes:bytes-1,..Default::default() },
        SearchLimits { max_files:1,..Default::default() }] {
        let mut barrier_called = false;
        let result = node.runtime().block_on(node.refresh_source_symbol_index_guarded_local_in(
            &node.outbox_delivery_context(),&reference(),None,None,first.generation_id,limits,
            &mut |_| { barrier_called = true; Ok(()) }));
        assert!(result.is_err());
        assert!(!barrier_called);
        assert_eq!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap().generation,
            *first.generation_id.as_internal_object_id());
    }
    let (_,_,stats) = refresh(&node,&first,SearchLimits {
        max_file_bytes:A.len(),max_total_bytes:bytes,..Default::default() }).unwrap();
    assert_eq!(stats.reused_files,3);
    assert_eq!(stats.source_blobs_read,0);
    node.shutdown().unwrap();
}

#[test]
fn refresh_requires_the_active_predecessor_and_current_visible_source() {
    let root = Scratch::new();
    let (node,commit) = symbols(&root,GitHashAlgorithm::Sha1);
    let first = build(&node,None);
    let second = build(&node,Some(&first));
    assert!(matches!(refresh(&node,&first,Default::default()),Err(AccessError::Stale)));
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.refresh_source_symbol_index_local_in(&node.outbox_delivery_context(),
        &missing,None,None,second.generation_id,Default::default())),Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
    let source = search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap().source;
    add_files(&node,commit,&[(b"new.rs",b"fn ThingNew() {}\n")],b"symbol-refresh-source-pin");
    let result = node.runtime().block_on(node.refresh_source_symbol_index_local_in(&node.outbox_delivery_context(),
        &reference(),Some(source.head),Some(commit),second.generation_id,Default::default()));
    assert!(matches!(result,Err(AccessError::Source(NodeWorkspaceRefusal::SourceBrowse(_)))));
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),
        &reference(),second.generation_id,None,Default::default())).unwrap(),GenerationRecovery::Active { .. }));
    node.shutdown().unwrap();
}

#[test]
fn failed_or_cancelled_refresh_barriers_preserve_the_original_candidate_and_root() {
    let root = Scratch::new();
    let (node,_) = symbols(&root,GitHashAlgorithm::Sha256);
    let first = build(&node,None);
    let expected = full_candidate(&node,&first);
    let error = node.runtime().block_on(node.refresh_source_symbol_index_guarded_local_in(&node.outbox_delivery_context(),
        &reference(),None,None,first.generation_id,Default::default(),
        &mut |id| { assert_eq!(id,expected); Err(NodeWorkspaceRefusal::RefUnavailable) })).unwrap_err();
    assert!(matches!(error,AccessError::Source(NodeWorkspaceRefusal::RefUnavailable)));
    let request = node.outbox_delivery_context();
    let error = node.runtime().block_on(node.refresh_source_symbol_index_guarded_local_in(&request,
        &reference(),None,None,first.generation_id,Default::default(),
        &mut |id| { assert_eq!(id,expected); request.cancel(); Ok(()) })).unwrap_err();
    assert!(matches!(error,AccessError::Publication { candidate,.. } if candidate == *expected.as_internal_object_id()));
    assert_eq!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES).unwrap().generation,
        *first.generation_id.as_internal_object_id());
    let (_,second,_) = refresh(&node,&first,Default::default()).unwrap();
    assert_eq!(second.generation_id,expected);
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),
        &reference(),expected,None,Default::default())).unwrap(),GenerationRecovery::Active { .. }));
    node.shutdown().unwrap();
}

#[test]
fn malformed_new_source_and_unpolled_refresh_do_not_publish_partial_indexes() {
    let root = Scratch::new();
    let (node,commit) = symbols(&root,GitHashAlgorithm::Sha1);
    let first = build(&node,None);
    let request = node.outbox_delivery_context();
    let reference = reference();
    let future = node.refresh_source_symbol_index_local_in(&request,&reference,None,None,first.generation_id,Default::default());
    drop(future);
    request.cancel();
    assert!(node.runtime().block_on(node.refresh_source_symbol_index_local_in(&request,&reference,None,None,
        first.generation_id,Default::default())).is_err());
    add_files(&node,commit,&[(b"broken.rs",b"fn Broken() {\n")],b"symbol-refresh-malformed");
    assert!(matches!(refresh(&node,&first,Default::default()),Err(AccessError::Index(data::Error::Table(_)))));
    assert!(matches!(node.runtime().block_on(node.recover_source_symbol_index_local_in(&node.request_context(),
        &reference,first.generation_id,None,Default::default())).unwrap(),GenerationRecovery::Active { .. }));
    assert!(matches!(search(&node,&ordinary(),Default::default(),data::MAX_INDEX_BYTES),Err(AccessError::Stale)));
    node.shutdown().unwrap();
}
