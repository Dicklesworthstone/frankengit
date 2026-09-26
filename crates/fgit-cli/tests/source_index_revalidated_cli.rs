#![forbid(unsafe_code)]
//! Invoke the actual fg executable against native imported objects and persisted
//! index generations. HTTP mutations use the existing production-listener fixture.
#[path = "../../fgit-node/tests/source_http/support.rs"]
mod support;

use fgit_node::OneNode;
use fgit_node::source_retrieval::current_index::{
    GenerationActivation, LexicalSource, RevalidatedIndexRequest, LexicalQuery, LexicalChannel,
};
use fgit_types::{GitHashAlgorithm, RefName, RepositoryAuthorityHeadId};
use std::process::{Command, Output};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn build(node: &OneNode) -> (LexicalSource, GenerationActivation) {
    node.runtime()
        .block_on(node.build_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            None,
            Default::default(),
        ))
        .unwrap()
}

fn arguments(root: &Scratch, format: GitHashAlgorithm) -> Vec<String> {
    vec![
        "search".into(),
        "--indexed-current".into(),
        root.0.join("node").to_str().unwrap().into(),
        "31".repeat(16),
        "32".repeat(16),
        "refs/heads/main".into(),
        "--trusted-local".into(),
        "--term".into(),
        "needle".into(),
        "--object-format".into(),
        format.as_str().into(),
    ]
}

fn invoke(args: &[String], code: i32) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_fg"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn body(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}

fn generation_token(activation: &GenerationActivation) -> String {
    let id = activation.generation_id.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}

fn open_issue(root: &Scratch, format: GitHashAlgorithm) {
    let node = reopen(&root.config(format));
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let bytes = b"expected_version=0&title=CLI+metadata+write&body=";
    let response = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: indexed-cli-issue\r\n",
                bytes.len(),
            ),
            bytes,
        ),
        true,
    );
    status(&response, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn fg_binary_keeps_original_index_provenance_after_authenticated_metadata_write() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = fixture(&root, format);
        let (indexed, activation) = build(&node);
        node.shutdown().unwrap();
        let args = arguments(&root, format);
        let initial = invoke(&args, 0);
        assert!(body(&initial).contains("\"distinct_index_provenance\":false"));
        open_issue(&root, format);
        let node = reopen(&root.config(format));
        let before = generation(&node);
        let selected = node.runtime().block_on(node.materialize_admission_in(
            &node.request_context(),
        )).unwrap();
        let current_head = selected.basis().id();
        assert_ne!(current_head, indexed.source_head);
        drop(selected);
        node.shutdown().unwrap();
        let output = invoke(&args, 0);
        let text = body(&output);
        assert!(text.starts_with("{\"type\":\"source_index_search\""));
        assert!(text.ends_with("}\n"));
        assert!(text.contains("\"profile\":\"source-lexical-revalidated-v1\""));
        assert!(text.contains("\"distinct_index_provenance\":true"));
        // The exact current token occurs before the independently retained
        // indexed-source token, not as a replacement generation stamp.
        let current_at = text.find("\"current_source\":{").unwrap();
        let indexed_at = text.find("\"indexed_source\":{").unwrap();
        assert!(text[current_at..indexed_at].contains(&head_token(current_head)));
        assert!(text[indexed_at..].contains(&head_token(indexed.source_head)));
        assert_eq!(text.matches(&format!("\"commit\":\"{commit}\"")).count(), 2);
        assert!(text.contains(&format!(
            "\"generation\":{{\"token\":\"{}\",\"number\":\"{}\"}}",
            generation_token(&activation), activation.authority_generation.get(),
        )));
        assert_eq!(text.matches("\"document_id\":").count(), 4);
        for id in [1, 2, 3, 5] {
            assert!(text.contains(&format!("\"document_id\":\"{id}\"")));
        }
        assert!(text.contains(&format!("\"path_hex\":\"{}\"", hex(BINARY_PATH))));
        assert!(text.contains("\"complete\":true,\"next_after\":null"));
        assert!(text.contains("\"node_closed\":true,\"repository_changed\":false,\"index_changed\":false"));
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before);
        let reference = reference();
        let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
        let checked = node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), RevalidatedIndexRequest::new(&reference, &query),
        )).unwrap();
        assert_eq!(checked.index().generation, activation);
        assert_eq!(checked.index().selected_generation_head, activation);
        assert_eq!(checked.index().source, indexed);
        node.shutdown().unwrap();
    }
}

#[test]
fn fg_binary_paginates_exact_generation_and_refuses_a_stale_current_head() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let (node, commit) = fixture(&root, format);
    let (source, activation) = build(&node);
    node.shutdown().unwrap();
    let mut args = arguments(&root, format);
    args.extend(["--max-results", "2"].map(str::to_owned));
    let first = invoke(&args, 3);
    assert!(body(&first).contains("\"complete\":false,\"next_after\":\"2\""));
    assert_eq!(body(&first).matches("\"document_id\":").count(), 2);
    args.extend([
        "--expected-head".into(), head_token(source.source_head),
        "--expected-commit".into(), commit.to_string(),
        "--generation".into(), generation_token(&activation),
        "--generation-number".into(), activation.authority_generation.get().to_string(),
        "--minimum-generation".into(), generation_token(&activation),
        "--minimum-number".into(), activation.authority_generation.get().to_string(),
        "--after".into(), "2".into(),
    ]);
    let last = invoke(&args, 0);
    assert!(body(&last).contains("\"complete\":true,\"next_after\":null"));
    assert_eq!(body(&last).matches("\"document_id\":").count(), 2);
    assert!(body(&last).contains("\"document_id\":\"3\""));
    assert!(body(&last).contains("\"document_id\":\"5\""));
    open_issue(&root, format);
    let stale = invoke(&args, 2);
    assert!(stale.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("SnapshotMoved"));
    assert!(body(&invoke(&arguments(&root, format), 0))
        .contains("\"distinct_index_provenance\":true"));
}

#[test]
fn fg_binary_never_falls_back_or_builds_an_index_for_a_refused_read() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    node.shutdown().unwrap();
    let args = arguments(&root, format);
    for _ in 0..2 {
        let absent = invoke(&args, 2);
        assert!(absent.stdout.is_empty());
        assert!(String::from_utf8_lossy(&absent.stderr).contains("Uninitialized"));
    }
    let mut untrusted = args.clone();
    untrusted.retain(|arg| arg != "--trusted-local");
    let refusal = invoke(&untrusted, 2);
    assert!(refusal.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("--trusted-local"));
    let node = reopen(&root.config(format));
    assert_eq!(generation(&node), before);
    build(&node);
    node.shutdown().unwrap();
    let mut limited = args.clone();
    limited.extend(["--max-work", "1"].map(str::to_owned));
    let refusal = invoke(&limited, 2);
    assert!(refusal.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("query work"));
    let mut path = args;
    let term = path.iter().position(|arg| arg == "--term").unwrap() + 1;
    path[term] = "empty".into();
    path.extend(["--channel", "path"].map(str::to_owned));
    let result = invoke(&path, 0);
    assert!(body(&result).contains("\"channel\":\"path\""));
    assert_eq!(body(&result).matches("\"document_id\":").count(), 1);
    assert!(body(&result).contains("\"path_hex\":\"656d707479\""));
}
