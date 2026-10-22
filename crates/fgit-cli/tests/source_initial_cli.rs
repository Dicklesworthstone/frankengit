#![forbid(unsafe_code)]
//! Run the actual fg process against persisted native indexes. The local opt-in
//! is an operator attestation; these tests do not claim credential authentication.
#[path = "../../fgit-node/tests/source_http/support.rs"]
mod support;

use fgit_schema::json::{self, Value};
use fgit_types::{GitHashAlgorithm, RefName};
use std::process::{Command, Output};
use support::*;

fn arguments(root: &Scratch, format: GitHashAlgorithm, context: bool) -> Vec<String> {
    vec![
        "search".into(),
        if context { "--context" } else { "--initial" }.into(),
        root.0.join("node").to_str().unwrap().into(),
        "31".repeat(16),
        "32".repeat(16),
        "--trusted-local".into(),
        "--object-format".into(),
        format.as_str().into(),
        "ref=refs/heads/main".into(),
        "term_hex=6e6565646c65".into(),
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
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    &value.object().unwrap()[key]
}
fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(rows) => rows,
        other => panic!("array required: {other:?}"),
    }
}
fn label(value: &Value) -> &str {
    let text = value.text().unwrap();
    assert_eq!(text.len(), 64);
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    text
}
fn assert_initial(value: &Value) {
    assert_eq!(field(value, "type").text(), Some("source_search_initial"));
    let auth = field(value, "authorization");
    assert_eq!(field(auth, "host").text(), Some("trusted-local-cli"));
    assert_eq!(field(auth, "scope").text(), Some("whole-repository"));
    assert_eq!(field(auth, "reusable_capability"), &Value::Bool(false));
    let mut labels = Vec::new();
    for (channel, domain) in [("content", "source-blob-bytes"), ("path", "raw-path-bytes")] {
        for row in array(field(field(value, channel), "hits")) {
            assert_eq!(field(row, "position_domain").text(), Some(domain));
            labels.push(label(field(row, "authorization_label")).to_owned());
        }
    }
    assert_eq!(labels.len(), 4);
}

#[test]
fn initial_and_context_processes_keep_labels_and_lineage_across_reopen_and_refuse_without_opt_in() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = fixture(&root, format);
        node.runtime()
            .block_on(node.build_source_index_local_in(
                &node.outbox_delivery_context(),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
        let before = generation(&node);
        node.shutdown().unwrap();
        for context in [false, true] {
            let args = arguments(&root, format, context);
            let first = invoke(&args, 0);
            let document = json::parse(&first.stdout).unwrap();
            let retrieval = if context {
                field(&document, "retrieval")
            } else {
                &document
            };
            assert_initial(retrieval);
            if context {
                assert_eq!(
                    field(&document, "type").text(),
                    Some("source_context_initial")
                );
                let files = array(field(&document, "files"));
                assert_eq!(files.len(), 4);
                for file in files {
                    let commitment = label(field(file, "lineage_commitment"));
                    let origins: Vec<_> = array(field(file, "authorization_labels"))
                        .iter()
                        .map(label)
                        .collect();
                    assert!(!origins.is_empty());
                    let mut originals = Vec::new();
                    for channel in ["content", "path"] {
                        for row in array(field(field(retrieval, channel), "hits")) {
                            if field(row, "path_hex") == field(file, "path_hex") {
                                let saved = label(field(row, "authorization_label"));
                                if !originals.contains(&saved) {
                                    originals.push(saved);
                                }
                            }
                        }
                    }
                    assert_eq!(origins, originals);
                    for anchor in array(field(file, "anchors")) {
                        assert!(origins.contains(&label(field(anchor, "authorization_label"))));
                    }
                    for excerpt in array(field(file, "excerpts")) {
                        assert_eq!(label(field(excerpt, "lineage_commitment")), commitment);
                        assert_eq!(
                            field(excerpt, "position_domain").text(),
                            Some("source-blob-bytes")
                        );
                    }
                }
            }
            assert_eq!(invoke(&args, 0).stdout, first.stdout);
            let mut untrusted = args.clone();
            untrusted.retain(|arg| arg != "--trusted-local");
            let refused = invoke(&untrusted, 2);
            assert!(refused.stdout.is_empty());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("--trusted-local"));
            let mut limited = args;
            limited.push("max_result_bytes=1".into());
            let refused = invoke(&limited, 2);
            assert!(refused.stdout.is_empty());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("retrieval refused"));
        }
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
