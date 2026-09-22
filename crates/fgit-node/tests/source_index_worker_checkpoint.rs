#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real progress files, native publication, actual operator restart. A lost
//! acknowledgement is simulated explicitly; this is not a power-loss campaign.
#[path = "../src/bin/index_maintenance/state.rs"]
mod progress;
#[path = "source_http/support.rs"]
mod support;
use fgit_graph::GraphGenerationId;
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, RefName};
use progress::{ProgressFile, State};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use support::*;
const REF: &[u8] = b"refs/heads/main";
fn setup(root: &Scratch, node: &OneNode, format: GitHashAlgorithm) -> ProgressFile {
    let path = root.0.join("maintenance");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let binding = format!(
        "31313131313131313131313131313131 32323232323232323232323232323232 {} {}",
        node.repository_incarnation_id(),
        format.as_str()
    );
    ProgressFile::open(&path, true, State::new(binding, &[REF.to_vec()]).unwrap()).unwrap()
}
fn worker(root: &Scratch, format: GitHashAlgorithm) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-index-maintain"))
        .arg(root.0.join("node"))
        .arg("31313131313131313131313131313131")
        .arg("32323232323232323232323232323232")
        .arg(format.as_str())
        .arg(root.0.join("maintenance"))
        .args(["resume", "1", "0", "refs/heads/main"])
        .output()
        .unwrap()
}
fn digest(id: GraphGenerationId) -> [u8; 32] {
    id.as_internal_object_id()
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}
fn selected(node: &OneNode) -> Result<fgit_graph::GenerationActivation, NodeWorkspaceRefusal> {
    let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    node.runtime()
        .block_on(node.search_source_index_local_in(
            &node.request_context(),
            &RefName::try_new(REF).unwrap(),
            None,
            None,
            None,
            None,
            &query,
            None,
            Default::default(),
            Default::default(),
        ))
        .map(|r| r.generation)
}

#[test]
fn actual_worker_recovers_confirmed_publication_using_only_prepublication_progress() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = fixture(&root, format);
        let before = generation(&node);
        let mut file = setup(&root, &node, format);
        file.state.begin_preparation(REF).unwrap();
        file.save().unwrap();
        let result = node
            .runtime()
            .block_on(node.reconcile_source_index_guarded_local_in(
                &node.request_context(),
                &RefName::try_new(REF).unwrap(),
                None,
                None,
                Default::default(),
                Default::default(),
                &mut |candidate| {
                    file.arm(REF, digest(candidate)).unwrap();
                    Ok(())
                },
            ));
        assert!(result.is_ok());
        drop(result); // Lose activation reply before any progress acknowledgement.
        let expected = file.state.rows[REF].pending.unwrap();
        node.shutdown().unwrap();
        file.release().unwrap(); // Establish quiescence before relinquishing ownership.
        let restarted = worker(&root, format);
        assert!(
            restarted.status.success(),
            "{}",
            String::from_utf8_lossy(&restarted.stderr)
        );
        assert!(String::from_utf8_lossy(&restarted.stdout).contains("\"state\":\"recovered\""));
        let checkpoint = fs::read(root.0.join("maintenance/checkpoint")).unwrap();
        let node = reopen(&config);
        assert_eq!(digest(selected(&node).unwrap().generation_id), expected);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        // The next ordinary pass is a no-op, not another generation publication.
        assert!(worker(&root, format).status.success());
        assert_eq!(
            fs::read(root.0.join("maintenance/checkpoint")).unwrap(),
            checkpoint
        );
    }
}

#[test]
fn actual_worker_restarts_effect_free_preparation_and_builds_normally() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let mut file = setup(&root, &node, GitHashAlgorithm::Sha1);
    file.state.begin_preparation(REF).unwrap();
    file.save().unwrap();
    node.shutdown().unwrap();
    file.release().unwrap(); // No native build was called.
    let restarted = worker(&root, GitHashAlgorithm::Sha1);
    assert!(
        restarted.status.success(),
        "{}",
        String::from_utf8_lossy(&restarted.stderr)
    );
    let output = String::from_utf8_lossy(&restarted.stdout);
    assert!(output.contains("preparation_recovered") && output.contains("observed_current"));
    let node = reopen(&config);
    assert!(selected(&node).is_ok());
    node.shutdown().unwrap();
}

#[test]
fn actual_worker_preserves_a_recorded_but_unpublished_candidate_without_rebuilding() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha256);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = generation(&node);
    let mut file = setup(&root, &node, GitHashAlgorithm::Sha256);
    file.state.begin_preparation(REF).unwrap();
    file.save().unwrap();
    let failed = node
        .runtime()
        .block_on(node.reconcile_source_index_guarded_local_in(
            &node.request_context(),
            &RefName::try_new(REF).unwrap(),
            None,
            None,
            Default::default(),
            Default::default(),
            &mut |candidate| {
                file.arm(REF, digest(candidate)).unwrap();
                Err(NodeWorkspaceRefusal::WorkspaceCapacity)
            },
        ));
    assert!(failed.is_err());
    node.shutdown().unwrap();
    file.release().unwrap();
    let pending = fs::read(root.0.join("maintenance/checkpoint")).unwrap();
    for _ in 0..2 {
        let restarted = worker(&root, GitHashAlgorithm::Sha256);
        assert!(!restarted.status.success());
        assert!(String::from_utf8_lossy(&restarted.stdout).contains("\"state\":\"pending\""));
        assert_eq!(
            fs::read(root.0.join("maintenance/checkpoint")).unwrap(),
            pending
        );
    }
    let node = reopen(&config);
    assert!(
        matches!(selected(&node), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
    );
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn legacy_unknown_running_attempt_remains_blocked_instead_of_becoming_safe_preparation() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let mut file = setup(&root, &node, GitHashAlgorithm::Sha1);
    file.state.begin(REF).unwrap();
    file.save().unwrap();
    node.shutdown().unwrap();
    file.release().unwrap();
    let path = root.0.join("maintenance/checkpoint");
    let legacy = String::from_utf8(fs::read(&path).unwrap())
        .unwrap()
        .replacen(
            "frankengit-index-worker-v2",
            "frankengit-index-worker-v1",
            1,
        );
    fs::write(&path, &legacy).unwrap();
    assert!(!worker(&root, GitHashAlgorithm::Sha1).status.success());
    assert_eq!(fs::read(&path).unwrap(), legacy.as_bytes());
    assert!(root.0.join("maintenance/run.lock").is_file());
}
