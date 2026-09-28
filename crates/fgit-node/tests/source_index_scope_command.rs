#![forbid(unsafe_code)]
//! Launch the actual native operator binary against existing persisted nodes.
//! No substitute index, subprocess Git, or fake storage. Authored, not run here.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery};
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::{GitHashAlgorithm, RefName};
use std::process::{Command, Output};
use std::fs;

fn run(root: &Scratch, format: GitHashAlgorithm, op: &str, scope: &str, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fg-index-scope"))
        .arg(op).arg(root.0.join("node")).arg("31".repeat(16)).arg("32".repeat(16))
        .arg(format.as_str()).arg("refs/heads/main").args(["--trusted-local", "--prefix", scope])
        .args(flags).output().unwrap()
}
fn success(output: Output) -> String {
    assert!(output.status.success(), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
#[cfg(unix)]
fn private(root: &Scratch) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.0.join("records"); fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); path
}
#[test]
#[cfg(unix)]
fn binary_build_search_and_recovery_share_the_exact_persisted_scope_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format); let (node, commit) = fixture(&root, format);
        let before = generation(&node); node.shutdown().unwrap();
        let record = private(&root).join("first.json");
        let built = success(run(&root, format, "build", "dir", &["--candidate-file", record.to_str().unwrap()]));
        assert!(built.contains("\"whole_repository\":false")); assert!(built.contains("\"index_published\":true"));
        assert_eq!(text(&built, "source_commit"), commit.to_string());
        let candidate = fs::read_to_string(&record).unwrap();
        assert_eq!(text(&candidate, "candidate"), text(&built, "index_token"));
        assert!(candidate.contains("\"publication_evidence\":false"));
        let searched = success(run(&root, format, "search", "dir", &["--term", "NEEDLE"]));
        assert_eq!(text(&searched, "index_token"), text(&built, "index_token"));
        assert_eq!(text(&searched, "indexed_documents"), "1");
        assert!(searched.contains("\"complete_within_scope\":true"));
        assert!(searched.contains(&format!("\"path_hex\":\"{}\"", hex(b"dir/nested.txt"))));
        let recovered = success(run(&root, format, "recover", "dir", &["--candidate", text(&candidate, "candidate")]));
        assert_eq!(text(&recovered, "state"), "active");
        let foreign = run(&root, format, "recover", "empty", &["--candidate", text(&candidate, "candidate")]);
        assert_eq!(foreign.status.code(), Some(2));
        assert!(String::from_utf8(foreign.stdout).unwrap().contains("\"absence_proves_cancellation\":false"));
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let q = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
        let reply = node.runtime().block_on(node.search_source_index_local_in(
            &node.request_context(), &RefName::try_new(b"refs/heads/main").unwrap(), None, None,
            None, None, &q, None, Default::default(), Default::default(),
        ));
        assert!(matches!(reply, Err(NodeWorkspaceRefusal::SourceIndex(error)) if matches!(*error, IndexError::Uninitialized)));
        node.shutdown().unwrap();
    }
}
#[test]
#[cfg(unix)]
fn binary_refuses_selected_file_overflow_without_recording_or_replacing_a_candidate() {
    let format = GitHashAlgorithm::Sha1; let root = Scratch::new(); let (node, _) = fixture(&root, format);
    node.shutdown().unwrap(); let records = private(&root);
    let refused = records.join("refused.json");
    let output = run(&root, format, "build", "alpha.txt", &["--candidate-file", refused.to_str().unwrap(), "--max-file-bytes", "1"]);
    assert!(!output.status.success()); assert!(output.stdout.is_empty()); assert!(!refused.exists());
    let allowed = records.join("allowed.json");
    let built = success(run(&root, format, "build", "empty", &["--candidate-file", allowed.to_str().unwrap(), "--max-file-bytes", "1", "--max-source-bytes", "1"]));
    let saved = fs::read(&allowed).unwrap();
    let collision = run(&root, format, "build", "empty", &["--candidate-file", allowed.to_str().unwrap(), "--predecessor-token", text(&built, "index_token")]);
    assert!(!collision.status.success()); assert_eq!(fs::read(&allowed).unwrap(), saved);
    let found = success(run(&root, format, "search", "empty", &["--channel", "path", "--term", "empty"]));
    assert_eq!(text(&found, "index_token"), text(&built, "index_token"));
}
#[test]
fn invalid_commands_do_not_create_repository_state() {
    let root = Scratch::new();
    let output = run(&root, GitHashAlgorithm::Sha1, "search", "src", &["--term", "needle", "--after", "1"]);
    assert!(!output.status.success()); assert!(output.stdout.is_empty()); assert!(!root.0.join("node").exists());
    let output = Command::new(env!("CARGO_BIN_EXE_fg-index-scope"))
        .args(["search", "--force", "true"]).output().unwrap();
    assert!(!output.status.success());
}
