#![forbid(unsafe_code)]
#![cfg(unix)]
//! Execute the actual bounded operator against the real file-backed node.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, RefName};
fn progress(root: &Scratch) -> std::path::PathBuf {
    let path = root.0.join("maintenance"); fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); path
}
fn worker(root: &Scratch, format: GitHashAlgorithm, mode: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-index-maintain"))
        .arg(root.0.join("node")).arg("31313131313131313131313131313131")
        .arg("32323232323232323232323232323232").arg(format.as_str())
        .arg(root.0.join("maintenance")).args([mode, "1", "0", "refs/heads/main"])
        .output().unwrap()
}
fn search(node: &OneNode) -> Result<fgit_graph::lexical::IndexedLexicalReport, NodeWorkspaceRefusal> {
    let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    node.runtime().block_on(node.search_source_index_local_in(&node.request_context(),
        &RefName::try_new(b"refs/heads/main").unwrap(), None, None, None, None, &query, None,
        Default::default(), Default::default()))
}
#[test]
fn foreground_worker_builds_then_resumes_without_generation_churn() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, _) = fixture(&root, format); let before = generation(&node); node.shutdown().unwrap();
        let state = progress(&root);
        let first = worker(&root, format, "init");
        assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
        assert!(String::from_utf8_lossy(&first.stdout).contains("observed_current"));
        assert!(!state.join("run.lock").exists());
        let checkpoint = fs::read(state.join("checkpoint")).unwrap();
        let node = reopen(&config); let indexed = search(&node).unwrap();
        assert_eq!(indexed.results.hits.len(), 4); assert_eq!(generation(&node), before); node.shutdown().unwrap();
        let next = worker(&root, format, "resume");
        assert!(next.status.success(), "{}", String::from_utf8_lossy(&next.stderr));
        assert_eq!(fs::read(state.join("checkpoint")).unwrap(), checkpoint);
        let node = reopen(&config); assert_eq!(search(&node).unwrap().generation, indexed.generation);
        assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}
#[test]
fn stopped_worker_never_builds_and_missing_resume_never_resets_state() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1); node.shutdown().unwrap();
    let state = progress(&root);
    assert!(!worker(&root, GitHashAlgorithm::Sha1, "resume").status.success());
    assert!(!state.join("checkpoint").exists());
    fs::write(state.join("stop"), b"operator stop").unwrap();
    assert!(worker(&root, GitHashAlgorithm::Sha1, "init").status.success());
    let node = reopen(&config);
    assert!(matches!(search(&node), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized)));
    node.shutdown().unwrap();
    fs::remove_file(state.join("stop")).unwrap();
    assert!(worker(&root, GitHashAlgorithm::Sha1, "resume").status.success());
    assert!(!worker(&root, GitHashAlgorithm::Sha1, "init").status.success());
    let node = reopen(&config); assert!(search(&node).is_ok()); node.shutdown().unwrap();
}
#[test]
fn stale_lock_blocks_a_second_worker_without_touching_checkpoint() {
    let root = Scratch::new(); let (node, _) = fixture(&root, GitHashAlgorithm::Sha1); node.shutdown().unwrap();
    let state = progress(&root); assert!(worker(&root, GitHashAlgorithm::Sha1, "init").status.success());
    let original = fs::read(state.join("checkpoint")).unwrap();
    fs::write(state.join("run.lock"), b"unresolved owner").unwrap();
    assert!(!worker(&root, GitHashAlgorithm::Sha1, "resume").status.success());
    assert_eq!(fs::read(state.join("checkpoint")).unwrap(), original);
    assert_eq!(fs::read(state.join("run.lock")).unwrap(), b"unresolved owner");
}
