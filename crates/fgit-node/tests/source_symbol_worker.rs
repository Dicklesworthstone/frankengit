#![forbid(unsafe_code)]
#![cfg(unix)]
//! Actual operator processes, native storage and durable prepublication files.
//! Lost acknowledgements are simulated; this is not a power-loss campaign.
#[path = "source_http/support.rs"]
mod support;
#[path = "../src/bin/index_maintenance/state.rs"]
mod progress;
use support::*;
use progress::{ProgressFile, State};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolMatchMode, SymbolQuery};
use fgit_forge::source_symbols::index::{self as data, AccessError};
use fgit_graph::{GenerationAuthorityError, GraphGenerationId};
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
const REF: &[u8] = b"refs/heads/main";
fn directory(root: &Scratch, name: &str) -> std::path::PathBuf {
    let path = root.0.join(name); fs::create_dir(&path).unwrap();
    fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap(); path
}
fn worker(root: &Scratch, format: GitHashAlgorithm, state: &str, mode: &str, symbols: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fg-index-maintain"));
    if symbols { command.arg("--symbols"); }
    command.arg(root.0.join("node")).args(["31313131313131313131313131313131",
        "32323232323232323232323232323232",format.as_str()]).arg(root.0.join(state))
        .args([mode,"1","0","refs/heads/main"]).output().unwrap()
}
fn successful(output: Output) -> String {
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
fn selected(node: &OneNode) -> Result<data::Report,AccessError<NodeWorkspaceRefusal,GenerationAuthorityError>> {
    let query = SymbolQuery::new(b"Thing",SymbolMatchMode::Prefix,&[],&[],MAX_SYMBOL_WORK).unwrap();
    node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.request_context(),
        &RefName::try_new(REF).unwrap(),None,None,None,&query,Default::default(),data::MAX_INDEX_BYTES))
}
fn assert_no_lexical_index(node: &OneNode) {
    let query = LexicalQuery::new(LexicalChannel::Content,&[b"needle".to_vec()],&[]).unwrap();
    assert!(matches!(node.runtime().block_on(node.search_source_index_local_in(&node.request_context(),
        &RefName::try_new(REF).unwrap(),None,None,None,None,&query,None,Default::default(),Default::default())),
        Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e,IndexError::Uninitialized)));
}
fn add_source(node: &OneNode, base: GitOid) -> GitOid {
    let patch = b"diff --git a/new.rs b/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/new.rs\n@@ -0,0 +1 @@\n+pub fn ThingNew() {}\n";
    let metadata = MergeMetadata { author:"Fixture <fixture@example.invalid>".into(),
        committer:"Fixture <fixture@example.invalid>".into(),timestamp:3,message:b"symbol maintenance edit\n".to_vec() };
    let request = node.request_context(); let reference = RefName::try_new(REF).unwrap();
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(&request,&reference,base,
        [0x7a;16],patch,&metadata,Default::default())).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request,OWNER,b"symbol-worker-edit",
        &reference,base,candidate.candidate_commit,candidate.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome,DecisionOutcome::Committed { .. })));
    candidate.candidate_commit
}
fn digest(id: GraphGenerationId) -> [u8;32] { id.as_internal_object_id().digest().as_bytes().try_into().unwrap() }
fn setup(root: &Scratch, node: &OneNode, format: GitHashAlgorithm) -> ProgressFile {
    let path = directory(root,"symbols");
    let binding = format!("31313131313131313131313131313131 32323232323232323232323232323232 {} {} symbols1",
        node.repository_incarnation_id(),format.as_str());
    ProgressFile::open(&path,true,State::new(binding,&[REF.to_vec()]).unwrap()).unwrap()
}

#[test]
fn symbol_worker_builds_refreshes_and_resumes_without_generation_churn() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node,commit) = fixture(&root,format); node.shutdown().unwrap();
        let state = directory(&root,"symbols");
        let output = successful(worker(&root,format,"symbols","init",true));
        assert!(output.contains("\"index_kind\":\"symbols\""));
        assert!(output.contains("\"state\":\"observed_current\""));
        let first = fs::read(state.join("checkpoint")).unwrap();
        successful(worker(&root,format,"symbols","resume",true));
        assert_eq!(fs::read(state.join("checkpoint")).unwrap(),first);
        let node = reopen(&config); let initial = selected(&node).unwrap();
        assert_eq!(initial.indexed_files,0);
        let next = add_source(&node,commit); let canonical = generation(&node);
        assert!(matches!(selected(&node),Err(AccessError::Stale))); node.shutdown().unwrap();
        successful(worker(&root,format,"symbols","resume",true));
        let updated = fs::read(state.join("checkpoint")).unwrap(); assert_ne!(updated,first);
        let node = reopen(&config); let report = selected(&node).unwrap();
        assert_eq!(report.source.commit,next); assert_eq!(report.matches.len(),1);
        assert_eq!(report.matches[0].name,b"ThingNew"); assert_eq!(report.generation_number,2);
        assert_no_lexical_index(&node); assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
        successful(worker(&root,format,"symbols","resume",true));
        assert_eq!(fs::read(state.join("checkpoint")).unwrap(),updated);
        assert!(!state.join("run.lock").exists());
    }
}

#[test]
fn profile_mismatches_fail_before_index_work_and_leave_both_checkpoints_unchanged() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new(); let config = root.config(format);
    let (node,_) = fixture(&root,format); let canonical = generation(&node); node.shutdown().unwrap();
    let lexical = directory(&root,"lexical");
    successful(worker(&root,format,"lexical","init",false));
    let bytes = fs::read(lexical.join("checkpoint")).unwrap();
    let mismatch = worker(&root,format,"lexical","resume",true);
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("progress namespace mismatch"));
    assert_eq!(fs::read(lexical.join("checkpoint")).unwrap(),bytes);
    let node = reopen(&config); assert!(matches!(selected(&node),Err(AccessError::Uninitialized))); node.shutdown().unwrap();
    let symbols = directory(&root,"symbols"); successful(worker(&root,format,"symbols","init",true));
    let symbol_bytes = fs::read(symbols.join("checkpoint")).unwrap();
    assert!(!worker(&root,format,"symbols","resume",false).status.success());
    assert_eq!(fs::read(symbols.join("checkpoint")).unwrap(),symbol_bytes);
    successful(worker(&root,format,"lexical","resume",false));
    assert_eq!(fs::read(lexical.join("checkpoint")).unwrap(),bytes);
    let node = reopen(&config); assert_eq!(selected(&node).unwrap().generation_number,1);
    assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
}

#[test]
fn worker_recovers_a_lost_activation_reply_from_prepublication_symbol_progress() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node,_) = fixture(&root,format); let canonical = generation(&node);
        let mut file = setup(&root,&node,format);
        file.state.begin_preparation(REF).unwrap(); file.save().unwrap();
        let result = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
            &node.outbox_delivery_context(),&RefName::try_new(REF).unwrap(),None,None,Default::default(),Default::default(),
            &mut |candidate| { file.arm(REF,digest(candidate)).unwrap(); Ok(()) }));
        assert!(result.is_ok()); drop(result); // Deliberately do not acknowledge the successful reply.
        let pending = file.state.rows[REF].pending.unwrap();
        node.shutdown().unwrap(); file.release().unwrap(); // Explicitly establish quiescence, not stale-lock takeover.
        let output = successful(worker(&root,format,"symbols","resume",true));
        assert!(output.contains("\"state\":\"recovered\"")); assert!(!output.contains("observed_current"));
        let checkpoint = fs::read(root.0.join("symbols/checkpoint")).unwrap();
        let node = reopen(&config); let report = selected(&node).unwrap();
        assert_eq!(report.generation.digest().as_bytes(),pending.as_slice());
        assert_no_lexical_index(&node); assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
        successful(worker(&root,format,"symbols","resume",true));
        assert_eq!(fs::read(root.0.join("symbols/checkpoint")).unwrap(),checkpoint);
    }
}

#[test]
fn recorded_but_unpublished_symbol_candidates_remain_pending_without_rebuild() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node,_) = fixture(&root,format); let canonical = generation(&node);
    let mut file = setup(&root,&node,format);
    file.state.begin_preparation(REF).unwrap(); file.save().unwrap();
    let failed = node.runtime().block_on(node.reconcile_source_symbol_index_guarded_local_in(
        &node.outbox_delivery_context(),&RefName::try_new(REF).unwrap(),None,None,Default::default(),Default::default(),
        &mut |candidate| { file.arm(REF,digest(candidate)).unwrap(); Err(NodeWorkspaceRefusal::WorkspaceCapacity) }));
    assert!(failed.is_err()); node.shutdown().unwrap(); file.release().unwrap();
    let checkpoint = fs::read(root.0.join("symbols/checkpoint")).unwrap();
    for _ in 0..2 {
        let output = worker(&root,format,"symbols","resume",true); assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"state\":\"pending\""));
        assert_eq!(fs::read(root.0.join("symbols/checkpoint")).unwrap(),checkpoint);
    }
    let node = reopen(&config); assert!(matches!(selected(&node),Err(AccessError::Uninitialized)));
    assert_eq!(generation(&node),canonical); node.shutdown().unwrap();
}

#[test]
fn stop_and_stale_lock_do_not_initialize_or_reset_symbol_progress() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new(); let config = root.config(format);
    let (node,_) = fixture(&root,format); node.shutdown().unwrap();
    let path = directory(&root,"symbols");
    assert!(!worker(&root,format,"symbols","resume",true).status.success());
    assert!(!path.join("checkpoint").exists());
    fs::write(path.join("stop"),b"stop").unwrap();
    successful(worker(&root,format,"symbols","init",true));
    let checkpoint = fs::read(path.join("checkpoint")).unwrap();
    let node = reopen(&config); assert!(matches!(selected(&node),Err(AccessError::Uninitialized))); node.shutdown().unwrap();
    fs::remove_file(path.join("stop")).unwrap();
    fs::write(path.join("run.lock"),b"unresolved owner").unwrap();
    assert!(!worker(&root,format,"symbols","resume",true).status.success());
    assert_eq!(fs::read(path.join("checkpoint")).unwrap(),checkpoint);
    assert_eq!(fs::read(path.join("run.lock")).unwrap(),b"unresolved owner");
}
