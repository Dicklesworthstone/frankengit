#![forbid(unsafe_code)]
//! Run actual fg and fg-mcp processes against persisted native indexes. Local
//! opt-ins are operator attestations, not credential authentication. Initial
//! transport coverage does not implement the remaining progressive protocol.
#[path = "../../fgit-node/tests/source_http/support.rs"]
mod support;

use fgit_forge::preparation::MergeMetadata;
use fgit_node::OneNode;
use fgit_schema::json::{self, Value};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, RefName};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use support::*;

const SYMBOL_PATCH: &[u8] = b"diff --git a/src/Thing.rs b/src/Thing.rs
new file mode 100644
--- /dev/null
+++ b/src/Thing.rs
@@ -0,0 +1,2 @@
+pub fn Thing() {}
+pub fn ThingAgain() {}
diff --git a/src/comment.rs b/src/comment.rs
new file mode 100644
--- /dev/null
+++ b/src/comment.rs
@@ -0,0 +1,2 @@
+// Thing
+pub struct Other;
diff --git a/src2/Thing.rs b/src2/Thing.rs
new file mode 100644
--- /dev/null
+++ b/src2/Thing.rs
@@ -0,0 +1 @@
+pub fn Thing() {}
";

fn seeded(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (node, base) = fixture(root, format);
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let request = node.outbox_delivery_context();
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 5,
        message: b"transport symbol corpus\n".to_vec(),
    };
    let prepared = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &reference,
            base,
            [0x69; 16],
            SYMBOL_PATCH,
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let accepted = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            OWNER,
            b"transport-symbol-corpus",
            &reference,
            base,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(!accepted.commands.is_empty());
    assert!(
        accepted
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    node.runtime()
        .block_on(node.build_source_index_local_in(
            &request,
            &reference,
            None,
            None,
            None,
            Default::default(),
        ))
        .unwrap();
    node.runtime()
        .block_on(node.build_source_symbol_index_local_in(
            &request,
            &reference,
            None,
            None,
            None,
            Default::default(),
        ))
        .unwrap();
    node
}

fn arguments(
    root: &Scratch,
    format: GitHashAlgorithm,
    context: bool,
    symbols: bool,
) -> Vec<String> {
    let mut args = vec![
        "search".into(),
        if context { "--context" } else { "--initial" }.into(),
        root.0.join("node").to_str().unwrap().into(),
        "31".repeat(16),
        "32".repeat(16),
        "--trusted-local".into(),
        "--object-format".into(),
        format.as_str().into(),
        "ref=refs/heads/main".into(),
        if symbols {
            "term_hex=5468696e67"
        } else {
            "term_hex=6e6565646c65"
        }
        .into(),
    ];
    if symbols {
        args.extend([
            "symbol_name_hex=5468696e67".into(),
            "symbol_match=prefix".into(),
            "symbol_policy=required".into(),
        ]);
    }
    args
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
fn assert_initial(value: &Value, host: &str, symbols: bool) {
    assert_eq!(field(value, "type").text(), Some("source_search_initial"));
    assert_eq!(field(value, "complete"), &Value::Bool(true));
    assert_eq!(field(value, "read_only"), &Value::Bool(true));
    assert_eq!(field(value, "transaction_created"), &Value::Bool(false));
    let auth = field(value, "authorization");
    assert_eq!(
        field(auth, "profile").text(),
        Some("source-read-result-labels-v1")
    );
    assert_eq!(field(auth, "host").text(), Some(host));
    assert_eq!(field(auth, "principal"), &Value::Null);
    assert_eq!(field(auth, "scope").text(), Some("whole-repository"));
    assert_eq!(field(auth, "reusable_capability"), &Value::Bool(false));
    label(field(auth, "binding"));
    let mut labels = Vec::new();
    for (channel, domain, count) in [
        ("content", "source-blob-bytes", if symbols { 3 } else { 4 }),
        ("path", "raw-path-bytes", if symbols { 2 } else { 0 }),
    ] {
        let rows = array(field(field(value, channel), "hits"));
        assert_eq!(rows.len(), count);
        for row in rows {
            assert_eq!(field(row, "position_domain").text(), Some(domain));
            labels.push(label(field(row, "authorization_label")).to_owned());
        }
    }
    assert_eq!(labels.len(), if symbols { 5 } else { 4 });
    let symbol_channel = field(value, "symbols");
    if symbols {
        assert_eq!(field(symbol_channel, "state").text(), Some("available"));
        let matches = array(field(field(symbol_channel, "result"), "matches"));
        assert_eq!(matches.len(), 3);
        for row in matches {
            assert_eq!(
                field(row, "position_domain").text(),
                Some("source-declaration-bytes")
            );
            label(field(row, "authorization_label"));
        }
    } else {
        assert_eq!(field(symbol_channel, "state").text(), Some("not_requested"));
    }
}

fn assert_context(document: &Value, host: &str, symbols: bool) {
    assert_eq!(
        field(document, "type").text(),
        Some("source_context_initial")
    );
    assert_eq!(field(document, "complete"), &Value::Bool(true));
    assert_eq!(
        field(document, "source_material_untrusted"),
        &Value::Bool(true)
    );
    let retrieval = field(document, "retrieval");
    assert_initial(retrieval, host, symbols);
    let files = array(field(document, "files"));
    assert_eq!(files.len(), if symbols { 3 } else { 4 });
    let mut symbol_anchors = 0;
    for file in files {
        let commitment = label(field(file, "lineage_commitment"));
        let origins: Vec<_> = array(field(file, "authorization_labels"))
            .iter()
            .map(label)
            .collect();
        assert!(!origins.is_empty());
        let mut originals = Vec::new();
        let mut retain = |row: &Value| {
            if field(row, "path_hex") == field(file, "path_hex") {
                let saved = label(field(row, "authorization_label")).to_owned();
                if !originals.contains(&saved) {
                    originals.push(saved);
                }
            }
        };
        for channel in ["content", "path"] {
            for row in array(field(field(retrieval, channel), "hits")) {
                retain(row);
            }
        }
        if symbols {
            for row in array(field(
                field(field(retrieval, "symbols"), "result"),
                "matches",
            )) {
                retain(row);
            }
        }
        assert_eq!(
            origins,
            originals.iter().map(String::as_str).collect::<Vec<_>>()
        );
        for anchor in array(field(file, "anchors")) {
            assert!(origins.contains(&label(field(anchor, "authorization_label"))));
            let channel = field(anchor, "channel").text().unwrap();
            symbol_anchors += usize::from(channel == "symbol");
            assert_eq!(
                field(anchor, "position_domain").text(),
                Some(if channel == "path" {
                    "raw-path-bytes"
                } else {
                    "source-blob-bytes"
                })
            );
        }
        for excerpt in array(field(file, "excerpts")) {
            assert_eq!(label(field(excerpt, "lineage_commitment")), commitment);
            assert_eq!(
                field(excerpt, "position_domain").text(),
                Some("source-blob-bytes")
            );
        }
    }
    if symbols {
        assert_eq!(symbol_anchors, 3);
    }
}

#[test]
fn initial_and_context_processes_keep_labels_and_lineage_across_reopen_and_refuse_without_opt_in() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let node = seeded(&root, format);
        let before = generation(&node);
        node.shutdown().unwrap();
        for (context, symbols) in [(false, false), (true, false), (false, true), (true, true)] {
            let args = arguments(&root, format, context, symbols);
            let first = invoke(&args, 0);
            let document = json::parse(&first.stdout).unwrap();
            let retrieval = if context {
                field(&document, "retrieval")
            } else {
                &document
            };
            assert_initial(retrieval, "trusted-local-cli", symbols);
            if context {
                assert_context(&document, "trusted-local-cli", symbols);
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

const HANDSHAKE: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"source-label-stdio\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
const SYMBOL_ARGUMENTS: &str = "\"reference\":\"refs/heads/main\",\"terms_hex\":[\"5468696e67\"],\"symbol_name_hex\":\"5468696e67\",\"symbol_match\":\"prefix\",\"symbol_policy\":\"required\"";
// Parse the server's bounded response, including both copies of tool content
// and the complete discovery document, rather than applying request limits.
const MCP_REPLY_LIMITS: json::Limits = json::Limits {
    input: 8 * 1024 * 1024,
    depth: 32,
    nodes: 1 << 20,
    items: 1 << 18,
    string: 2 * 1024 * 1024,
};

fn mcp_call(id: u64, name: &str, fields: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{{{fields}}}}}}}\n"
    )
}

fn mcp_invoke(
    root: &Scratch,
    format: GitHashAlgorithm,
    incarnation: &str,
    source: bool,
    input: &str,
) -> Vec<Value> {
    // Match the existing real-stdio process harness. EOF follows the complete
    // bounded transcript and reaches the server's explicit node shutdown.
    let mut child = Command::new(env!("CARGO_BIN_EXE_fg-mcp"))
        .arg(root.0.join("node"))
        .args(["31".repeat(16), "32".repeat(16)])
        .args([
            "--trusted-local",
            if source {
                "--allow-source"
            } else {
                "--allow-issues"
            },
        ])
        .args([
            "--object-format",
            format.as_str(),
            "--expected-incarnation",
            incarnation,
            "--max-messages",
            "16",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert!(stdout.ends_with('\n'));
    stdout
        .lines()
        .map(|line| json::parse_with(line.as_bytes(), MCP_REPLY_LIMITS).unwrap())
        .collect()
}

fn mcp_reply(replies: &[Value], id: u64) -> &Value {
    let matches: Vec<_> = replies
        .iter()
        .filter(|reply| field(reply, "id").unsigned() == Some(id))
        .collect();
    assert_eq!(matches.len(), 1, "one complete response for request {id}");
    assert_eq!(field(matches[0], "jsonrpc").text(), Some("2.0"));
    matches[0]
}

fn mcp_document(reply: &Value, failed: bool) -> &Value {
    assert!(!reply.object().unwrap().contains_key("error"));
    let result = field(reply, "result");
    assert_eq!(field(result, "isError"), &Value::Bool(failed));
    let content = array(field(result, "content"));
    assert_eq!(content.len(), 1);
    assert_eq!(field(&content[0], "type").text(), Some("text"));
    let structured = field(result, "structuredContent");
    assert_eq!(
        json::parse_with(
            field(&content[0], "text").text().unwrap().as_bytes(),
            MCP_REPLY_LIMITS
        )
        .unwrap(),
        *structured
    );
    structured
}

fn assert_mcp_refusal(reply: &Value, code: &str) {
    let body = mcp_document(reply, true);
    assert_eq!(field(body, "code").text(), Some(code));
    assert_eq!(field(body, "complete"), &Value::Bool(false));
    // Failure is not a partly disclosed Initial/context document.
    assert_eq!(body.object().unwrap().len(), 2);
}

#[test]
fn stdio_initial_and_context_keep_all_channel_labels_and_refuse_changed_scope_source_and_budgets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let node = seeded(&root, format);
        let before = generation(&node);
        let incarnation = node.repository_incarnation_id().to_string();
        node.shutdown().unwrap();
        let initial = "frankengit_source_initial";
        let context = "frankengit_source_context";
        let input = format!(
            "{HANDSHAKE}{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{}{}{}{}{}{}{}{}{}",
            mcp_call(3, initial, SYMBOL_ARGUMENTS),
            mcp_call(4, context, SYMBOL_ARGUMENTS),
            mcp_call(
                5,
                context,
                &format!(
                    "{SYMBOL_ARGUMENTS},\"context_selection\":\"context-weighted-rrf-q16-v1\""
                )
            ),
            mcp_call(
                6,
                initial,
                &format!("{SYMBOL_ARGUMENTS},\"max_result_bytes\":1")
            ),
            mcp_call(
                7,
                context,
                &format!("{SYMBOL_ARGUMENTS},\"max_result_bytes\":1")
            ),
            mcp_call(
                8,
                initial,
                &format!("{SYMBOL_ARGUMENTS},\"principal\":\"{OWNER}\"")
            ),
            mcp_call(
                9,
                context,
                &format!("{SYMBOL_ARGUMENTS},\"principal\":\"{OWNER}\"")
            ),
            mcp_call(10, initial, SYMBOL_ARGUMENTS),
            mcp_call(11, context, SYMBOL_ARGUMENTS),
        );
        let replies = mcp_invoke(&root, format, &incarnation, true, &input);
        assert_eq!(replies.len(), 11);
        assert_eq!(
            field(field(mcp_reply(&replies, 1), "result"), "protocolVersion").text(),
            Some("2025-06-18")
        );
        let tools = array(field(field(mcp_reply(&replies, 2), "result"), "tools"));
        for name in [initial, context] {
            let tool = tools
                .iter()
                .find(|tool| field(tool, "name").text() == Some(name))
                .unwrap();
            assert_eq!(
                field(field(tool, "annotations"), "readOnlyHint"),
                &Value::Bool(true)
            );
        }
        let report = mcp_document(mcp_reply(&replies, 3), false);
        assert_initial(report, "trusted-local-mcp", true);
        assert_eq!(field(report, "phase").text(), Some("Initial"));
        assert_eq!(field(report, "streaming"), &Value::Bool(false));
        let packet = mcp_document(mcp_reply(&replies, 4), false);
        assert_context(packet, "trusted-local-mcp", true);
        let ranked = mcp_document(mcp_reply(&replies, 5), false);
        assert_context(ranked, "trusted-local-mcp", true);
        assert_eq!(
            field(ranked, "selection").text(),
            Some("context-weighted-rrf-q16-v1")
        );
        assert_eq!(
            field(field(ranked, "ranking"), "profile").text(),
            Some("context-weighted-rrf-q16-v1")
        );
        for id in [6, 7] {
            assert_mcp_refusal(mcp_reply(&replies, id), "resource_limit");
        }
        for id in [8, 9] {
            let refused = mcp_reply(&replies, id);
            assert_eq!(
                field(field(refused, "error"), "code"),
                &Value::Number("-32602".into())
            );
            assert!(!refused.object().unwrap().contains_key("result"));
        }
        assert_eq!(mcp_document(mcp_reply(&replies, 10), false), report);
        assert_eq!(mcp_document(mcp_reply(&replies, 11), false), packet);

        // Alter only the saved source pin, retaining the original beside it.
        // A fresh process also checks deterministic labels after storage reopen.
        let saved = field(report, "snapshot_token").text().unwrap();
        let mut foreign = saved.as_bytes().to_vec();
        let last = foreign.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let foreign = String::from_utf8(foreign).unwrap();
        let pinned = format!("{SYMBOL_ARGUMENTS},\"expected_head\":\"{saved}\"");
        let changed = format!("{SYMBOL_ARGUMENTS},\"expected_head\":\"{foreign}\"");
        let input = format!(
            "{HANDSHAKE}{}{}{}{}{}{}",
            mcp_call(2, initial, &pinned),
            mcp_call(3, initial, &changed),
            mcp_call(4, context, &pinned),
            mcp_call(5, context, &changed),
            mcp_call(6, initial, &pinned),
            mcp_call(7, context, &pinned),
        );
        let reopened = mcp_invoke(&root, format, &incarnation, true, &input);
        assert_eq!(reopened.len(), 7);
        for id in [2, 6] {
            assert_eq!(mcp_document(mcp_reply(&reopened, id), false), report);
        }
        for id in [4, 7] {
            assert_eq!(mcp_document(mcp_reply(&reopened, id), false), packet);
        }
        for id in [3, 5] {
            assert_mcp_refusal(mcp_reply(&reopened, id), "source_snapshot_moved");
        }

        // An issue-read launch remains valid but cannot discover or invoke
        // source tools. The otherwise identical source requests are refused.
        let input = format!(
            "{HANDSHAKE}{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{}{}",
            mcp_call(3, initial, SYMBOL_ARGUMENTS),
            mcp_call(4, context, SYMBOL_ARGUMENTS),
        );
        let denied = mcp_invoke(&root, format, &incarnation, false, &input);
        assert_eq!(denied.len(), 4);
        let tools = array(field(field(mcp_reply(&denied, 2), "result"), "tools"));
        assert!(
            tools
                .iter()
                .all(|tool| ![Some(initial), Some(context)].contains(&field(tool, "name").text()))
        );
        for id in [3, 4] {
            let refused = mcp_reply(&denied, id);
            assert_eq!(
                field(field(refused, "error"), "code"),
                &Value::Number("-32602".into())
            );
            assert!(!refused.object().unwrap().contains_key("result"));
        }
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
