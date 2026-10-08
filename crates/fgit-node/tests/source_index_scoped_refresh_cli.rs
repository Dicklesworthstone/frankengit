#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real fg-index-scope process over a real native fixture. No fake binary or
//! supplied index report. The Unix-only candidate directory profile is explicit.
#[path = "source_http/support.rs"]
mod support;
use fgit_graph::lexical::scoped::LexicalScope;
use fgit_graph::lexical::{LexicalChannel, LexicalQuery};
use fgit_types::{GitHashAlgorithm, RefName};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use support::*;

fn cli(root: &Scratch, label: &str, action: &str, format: GitHashAlgorithm,
    extra: &[String]) -> (ExitStatus, String, String) {
    let stdout = root.0.join(format!("{label}.stdout"));
    let stderr = root.0.join(format!("{label}.stderr"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_fg-index-scope"))
        .arg(action).arg(root.0.join("node"))
        .args(["31".repeat(16), "32".repeat(16)])
        .args([format.as_str(), "refs/heads/main", "--trusted-local", "--prefix", "dir"])
        .args(extra).stdin(Stdio::null())
        .stdout(fs::File::create_new(&stdout).unwrap())
        .stderr(fs::File::create_new(&stderr).unwrap())
        .spawn().unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() { break status; }
        if start.elapsed() > Duration::from_secs(180) {
            let _ = child.kill(); let _ = child.wait();
            panic!("bounded native scoped-index command timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(fs::metadata(&stdout).unwrap().len() <= 8 * 1024 * 1024);
    assert!(fs::metadata(&stderr).unwrap().len() <= 64 * 1024);
    (status, fs::read_to_string(stdout).unwrap(), fs::read_to_string(stderr).unwrap())
}
// These selected fields are strictly ASCII tokens/counters, never escaped text.
fn field(json: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    assert_eq!(json.matches(&marker).count(), 1, "{json}");
    json.split_once(&marker).unwrap().1.split_once('"').unwrap().0.to_owned()
}
fn args(values: &[&str]) -> Vec<String> { values.iter().map(|v| (*v).to_owned()).collect() }
fn candidate(root: &Scratch, name: &str) -> String {
    root.0.join("private").join(name).to_str().unwrap().to_owned()
}
fn private(root: &Scratch) {
    let path = root.0.join("private");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn native_command_build_refresh_search_and_candidate_recovery_survive_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); private(&root);
        let config = root.config(format);
        let (node, source_commit) = fixture(&root, format);
        let authority_before = generation(&node); node.shutdown().unwrap();
        let build_record = candidate(&root, "build.json");
        let (status, built, error) = cli(&root, "build", "build", format,
            &args(&["--candidate-file", &build_record]));
        assert!(status.success(), "{error}");
        assert_eq!(field(&built, "type"), "scoped_index_build");
        let predecessor = field(&built, "index_token");
        let refresh_record = candidate(&root, "refresh.json");
        let (status, refreshed, error) = cli(&root, "refresh", "refresh", format, &args(&[
            "--candidate-file", &refresh_record, "--predecessor-token", &predecessor,
            "--expected-head", &field(&built, "snapshot_token"),
            "--expected-commit", &source_commit.to_string(),
            "--max-files", "1", "--max-file-bytes", "17", "--max-source-bytes", "17",
        ]));
        assert!(status.success(), "{error}");
        assert_eq!(field(&refreshed, "type"), "scoped_index_refresh");
        assert_eq!(field(&refreshed, "source_commit"), source_commit.to_string());
        assert_eq!(field(&refreshed, "scope_sha256"), field(&built, "scope_sha256"));
        assert_eq!(field(&refreshed, "reused_documents"), "1");
        assert_eq!(field(&refreshed, "rebuilt_documents"), "0");
        assert_eq!(field(&refreshed, "reused_source_bytes"), "17");
        assert_eq!(field(&refreshed, "rebuilt_source_bytes"), "0");
        assert_eq!(field(&refreshed, "prior_documents_not_reused"), "0");
        assert!(refreshed.contains("\"index_published\":true"));
        assert!(refreshed.contains("\"repository_state_changed\":false"));
        assert!(refreshed.contains("\"freshness_at_delivery_claimed\":false"));
        let recorded = fs::read_to_string(&refresh_record).unwrap();
        assert_eq!(field(&recorded, "candidate"), field(&refreshed, "index_token"));
        assert_eq!(field(&recorded, "predecessor_token"), predecessor);
        assert!(recorded.contains("\"publication_evidence\":false"));
        assert_eq!(fs::metadata(&refresh_record).unwrap().permissions().mode() & 0o777, 0o600);
        let (status, recovered, error) = cli(&root, "recover", "recover", format,
            &args(&["--candidate", &field(&recorded, "candidate")]));
        assert!(status.success(), "{error}");
        assert_eq!(field(&recovered, "state"), "active");
        assert_eq!(field(&recovered, "selected_index_token"), field(&refreshed, "index_token"));
        let (status, result, error) = cli(&root, "search", "search", format,
            &args(&["--term", "needle"]));
        assert!(status.success(), "{error}");
        assert_eq!(field(&result, "index_token"), field(&refreshed, "index_token"));
        assert_eq!(field(&result, "indexed_documents"), "1");
        let stale_record = candidate(&root, "stale.json");
        assert!(!cli(&root, "stale", "refresh", format,
            &args(&["--candidate-file", &stale_record, "--predecessor-token", &predecessor])).0.success());
        assert!(!std::path::Path::new(&stale_record).exists());
        let node = reopen(&config);
        assert_eq!(generation(&node), authority_before);
        node.shutdown().unwrap();
    }
}

#[test]
fn native_refresh_command_never_overwrites_candidates_or_publishes_on_resource_refusal() {
    let root = Scratch::new(); private(&root);
    let format = GitHashAlgorithm::Sha256;
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let scope = LexicalScope::new(&[b"dir".to_vec()]).unwrap();
    let (_, first) = node.runtime().block_on(node.build_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &reference, &scope, None, None, None, Default::default(),
    )).unwrap();
    let id = first.generation_id.as_internal_object_id();
    let token = format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()));
    let before = generation(&node); node.shutdown().unwrap();
    let existing = candidate(&root, "occupied.json");
    fs::write(&existing, b"retain this exact diagnostic").unwrap();
    assert!(!cli(&root, "occupied", "refresh", format,
        &args(&["--predecessor-token", &token, "--candidate-file", &existing])).0.success());
    assert_eq!(fs::read(&existing).unwrap(), b"retain this exact diagnostic");
    for (label, flag) in [("source-limit", "--max-file-bytes"), ("read-limit", "--max-payload-bytes")] {
        let record = candidate(&root, &format!("{label}.json"));
        let (status, _, _) = cli(&root, label, "refresh", format,
            &args(&["--predecessor-token", &token, "--candidate-file", &record, flag, "1"]));
        assert!(!status.success());
        assert!(!std::path::Path::new(&record).exists());
    }
    let node = reopen(&config);
    let report = node.runtime().block_on(node.search_scoped_source_index_local_in(
        &node.request_context(), &reference, &scope, None, None, None, None,
        &LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap(),
        None, Default::default(), Default::default(),
    )).unwrap();
    assert_eq!(report.index.generation, first);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
