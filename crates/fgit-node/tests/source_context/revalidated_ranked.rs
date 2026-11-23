//! Real native generations, authenticated HTTP and the public streaming sink.
//! Metadata may move before selection, but never between Initial and hydration.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_node::source_retrieval::authorization::SourceReadContext;
use fgit_node::source_retrieval::context::ranked::PROFILE;
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal};
use fgit_schema::json::{self, Value};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

const OUTPUT_LIMIT: usize = 1024 * 1024;

fn parse(bytes: &[u8]) -> Value {
    json::parse_with(
        bytes,
        json::Limits {
            input: OUTPUT_LIMIT,
            depth: 32,
            nodes: 32_768,
            items: 2048,
            string: OUTPUT_LIMIT,
        },
    )
    .unwrap()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.object().unwrap().get(name).unwrap()
}

fn array(value: &Value) -> &[Value] {
    let Value::Array(values) = value else {
        panic!("expected array: {value:?}");
    };
    values
}

fn records(bytes: &[u8]) -> Vec<Value> {
    assert!(bytes.is_empty() || bytes.ends_with(b"\n"));
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(parse)
        .collect()
}

fn fields(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    [
        ("ref", "refs/heads/main"),
        ("term_hex", "5468696e67"),
        ("symbol_name_hex", "5468696e67"),
        ("symbol_match", "prefix"),
        ("symbol_policy", "required"),
        ("index_source", "current-native-v1"),
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

fn form(format: GitHashAlgorithm, extra: &[(&str, &str)]) -> String {
    let mut values = fields(extra);
    values.push(("object_format".into(), format.as_str().into()));
    values
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn initial_document(node: &OneNode, read: &SourceReadContext) -> Value {
    parse(
        fgit_node::source_retrieval_json(node, read, fields(&[]), false, OUTPUT_LIMIT)
            .unwrap()
            .as_bytes(),
    )
}

fn metadata_write(node: &OneNode, number: u64) {
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(format!("revalidated-ranked-issue-{number}").into_bytes()).unwrap(),
    );
    let command = IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Metadata-only movement".into(),
            body: "The indexed main commit and tree are unchanged.".into(),
            labels: vec![],
        },
    };
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &node.outbox_delivery_context(),
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn progressive_http(client: &Endpoint, input: &str) -> Vec<Value> {
    let request = request(
        client,
        "/api/v1/source/search-progressive",
        'a',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            input.len()
        ),
        input.as_bytes(),
    );
    let mut socket = TcpStream::connect(client.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket.write_all(&request).unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    socket
        .take((OUTPUT_LIMIT + 4096) as u64)
        .read_to_string(&mut response)
        .unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(head.contains("Content-Type: application/x-ndjson\r\n"));
    assert!(head.contains("Connection: close"));
    assert!(!head.contains("Content-Length:"));
    assert_eq!(response.matches("HTTP/1.1 ").count(), 1);
    records(body.as_bytes())
}

#[test]
fn authenticated_current_ranked_and_progressive_keep_original_index_provenance_after_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = corpus(&root, format, true);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 8, true, true);
        let strict = form(format, &[]).replace("&index_source=current-native-v1", "");
        let old = post(&server.client, "search-initial", 'a', &strict, false);
        status(&old, 200);
        let old = parse(old.body.as_bytes());
        let body = b"expected_version=0&title=Metadata+only&body=";
        status(
            &exchange(
                &server.client,
                &request(
                    &server.client,
                    "/api/v1/issues/1/open",
                    'b',
                    &format!(
                        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: ranked-current-metadata\r\n",
                        body.len()
                    ),
                    body,
                ),
                true,
            ),
            200,
        );
        let input = form(format, &[]);
        let initial = post(&server.client, "search-initial", 'a', &input, false);
        status(&initial, 200);
        let initial = parse(initial.body.as_bytes());
        assert_ne!(
            field(&initial, "snapshot_token"),
            field(&old, "snapshot_token")
        );
        assert_eq!(
            field(&initial, "source_commit").text(),
            Some(commit.to_string().as_str())
        );
        assert_eq!(
            field(&initial, "generation_vector"),
            field(&old, "generation_vector")
        );
        for channel in ["lexical", "symbols"] {
            let source = field(field(&initial, "index_sources"), channel);
            assert_eq!(
                field(source, "snapshot_token"),
                field(&old, "snapshot_token")
            );
            assert_eq!(
                field(source, "source_commit"),
                field(&initial, "source_commit")
            );
            assert_eq!(field(source, "root_tree"), field(&initial, "root_tree"));
        }
        let ranked = post(
            &server.client,
            "context-initial",
            'a',
            &form(format, &[("context_selection", PROFILE)]),
            true,
        );
        status(&ranked, 200);
        let ranked = parse(ranked.body.as_bytes());
        assert_eq!(field(&ranked, "retrieval"), &initial);
        assert_eq!(field(&ranked, "selection").text(), Some(PROFILE));
        assert_eq!(field(&ranked, "complete"), &Value::Bool(true));
        assert_eq!(field(&ranked, "source_blobs_read").unsigned(), Some(4));
        assert_eq!(array(field(&ranked, "files")).len(), 4);
        assert!(!array(field(field(&ranked, "ranking"), "selected")).is_empty());
        let raw = post(&server.client, "context-initial", 'a', &input, false);
        status(&raw, 200);
        let raw = parse(raw.body.as_bytes());
        assert_eq!(field(&raw, "retrieval"), &initial);
        assert_eq!(field(&raw, "selection").text(), Some("raw-path-prefix"));
        assert_eq!(field(&raw, "files"), field(&ranked, "files"));
        assert!(!raw.object().unwrap().contains_key("ranking"));
        let strict = strict + "&context_selection=" + PROFILE;
        let refused = post(&server.client, "context-initial", 'a', &strict, false);
        status(&refused, 409);
        assert!(!refused.body.contains("\"files\":"));
        status(
            &post(
                &server.client,
                "context-initial",
                'b',
                &form(format, &[("context_selection", PROFILE)]),
                false,
            ),
            403,
        );
        let phases = progressive_http(&server.client, &input);
        assert_eq!(phases.len(), 2);
        assert_eq!(field(&phases[0], "phase").text(), Some("Initial"));
        assert_eq!(field(&phases[0], "answer"), &initial);
        assert_eq!(field(&phases[1], "phase").text(), Some("Refined"));
        assert_eq!(field(&phases[1], "answer"), &ranked);
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}

struct AtInitial<F> {
    bytes: Vec<u8>,
    action: Option<F>,
    reject_flush: bool,
    flushes: usize,
}
impl<F: FnOnce()> AtInitial<F> {
    fn new(action: F) -> Self {
        Self {
            bytes: Vec::new(),
            action: Some(action),
            reject_flush: false,
            flushes: 0,
        }
    }
}
impl<F: FnOnce()> Write for AtInitial<F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if let Some(action) = self.action.take() {
            action();
        }
        if self.reject_flush {
            Err(io::Error::other("sink cancelled after Initial"))
        } else {
            Ok(())
        }
    }
}

fn assert_failed(bytes: &[u8], initial: &Value, code: &str) {
    let phases = records(bytes);
    assert_eq!(phases.len(), 2);
    assert_eq!(field(&phases[0], "phase").text(), Some("Initial"));
    assert_eq!(field(&phases[0], "answer"), initial);
    assert_eq!(
        phases[1],
        json::object([
            ("phase", json::text("RefinementFailed")),
            ("code", json::text(code)),
        ])
    );
}

#[test]
fn metadata_or_code_movement_at_initial_flush_fails_without_reselecting_the_source() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = corpus(&root, format, true);
        metadata_write(&node, 1);
        let read = SourceReadContext::trusted_local_cli(&node);
        let initial = initial_document(&node, &read);
        let before = generation(&node);
        let mut sink = AtInitial::new(|| metadata_write(&node, 2));
        let code = node
            .write_progressive_source_context(&read, fields(&[]), OUTPUT_LIMIT, &mut sink)
            .unwrap_err();
        assert_failed(&sink.bytes, &initial, code);
        assert_eq!(sink.flushes, 2);
        assert_eq!(generation(&node), before + 1);
        // A separate invocation can revalidate the new metadata head. The
        // failed invocation must not silently adopt it after its Initial row.
        let next = initial_document(&node, &read);
        assert_ne!(
            field(&next, "snapshot_token"),
            field(&initial, "snapshot_token")
        );
        assert_eq!(
            field(&next, "generation_vector"),
            field(&initial, "generation_vector")
        );
        assert_eq!(
            field(&next, "index_sources"),
            field(&initial, "index_sources")
        );
        let mut sink = AtInitial::new(|| {
            add(
                &node,
                commit,
                &[(b"new.txt", b"Thing changed the native tree.\n")],
                b"ranked-code-at-initial",
            );
        });
        let code = node
            .write_progressive_source_context(&read, fields(&[]), OUTPUT_LIMIT, &mut sink)
            .unwrap_err();
        assert_failed(&sink.bytes, &next, code);
        assert_eq!(generation(&node), before + 2);
        // Old immutable indexes cannot answer a new code tree, even on a new
        // invocation. Refuse before publishing any Initial data.
        let mut bytes = Vec::new();
        assert!(
            node.write_progressive_source_context(&read, fields(&[]), OUTPUT_LIMIT, &mut bytes)
                .is_err()
        );
        assert!(bytes.is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn current_progressive_keeps_partial_initial_and_one_shared_budget_and_stops_on_sink_failure() {
    let root = Scratch::new();
    let (node, _) = corpus(&root, GitHashAlgorithm::Sha256, true);
    metadata_write(&node, 1);
    let before = generation(&node);
    let read = SourceReadContext::trusted_local_cli(&node);
    let initial = initial_document(&node, &read);
    let mut complete = Vec::new();
    assert_eq!(
        node.write_progressive_source_context(&read, fields(&[]), OUTPUT_LIMIT, &mut complete),
        Ok(true)
    );
    let mut source_limited = Vec::new();
    assert_eq!(
        node.write_progressive_source_context(
            &read,
            fields(&[("context_max_source_bytes", "1")]),
            OUTPUT_LIMIT,
            &mut source_limited,
        ),
        Err("resource_limit")
    );
    assert_failed(&source_limited, &initial, "resource_limit");
    let first_record_bytes = complete.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let allowance = first_record_bytes + 256;
    let mut output_limited = Vec::new();
    assert_eq!(
        node.write_progressive_source_context(&read, fields(&[]), allowance, &mut output_limited),
        Err("resource_limit")
    );
    assert_failed(&output_limited, &initial, "resource_limit");
    assert!(output_limited.len() <= allowance);
    let mut partial = Vec::new();
    assert_eq!(
        node.write_progressive_source_context(
            &read,
            fields(&[("max_results_per_channel", "1")]),
            OUTPUT_LIMIT,
            &mut partial,
        ),
        Ok(false)
    );
    let phases = records(&partial);
    assert_eq!(phases.len(), 2);
    let first = field(&phases[0], "answer");
    let last = field(&phases[1], "answer");
    assert_eq!(field(first, "complete"), &Value::Bool(false));
    assert_eq!(field(last, "complete"), &Value::Bool(false));
    assert_eq!(field(last, "retrieval"), first);
    assert_ne!(
        field(field(first, "generation_vector"), "symbols"),
        &Value::Null
    );
    let mut sink = AtInitial::new(|| {});
    sink.reject_flush = true;
    assert_eq!(
        node.write_progressive_source_context(&read, fields(&[]), OUTPUT_LIMIT, &mut sink),
        Err("source_output_failed")
    );
    assert_eq!(sink.flushes, 1);
    let phases = records(&sink.bytes);
    assert_eq!(phases.len(), 1);
    assert_eq!(field(&phases[0], "answer"), &initial);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn cancelled_current_ranked_hydration_preserves_the_permitted_report_and_original_vector() {
    let root = Scratch::new();
    let (node, commit) = corpus(&root, GitHashAlgorithm::Sha1, true);
    metadata_write(&node, 1);
    let before = generation(&node);
    let read = SourceReadContext::trusted_local_native(&node);
    let query = InitialQuery::new(&[b"Thing".to_vec()], &[])
        .unwrap()
        .with_symbols(
            b"Thing",
            SymbolMatchMode::Prefix,
            &[],
            SymbolPolicy::Required,
        )
        .unwrap();
    let report = node
        .runtime()
        .block_on(node.search_source_initial_revalidated_local_in(
            &node.outbox_delivery_context(),
            &read,
            &reference(),
            None,
            Some(commit),
            &Checkpoints::default(),
            &query,
            Default::default(),
        ))
        .unwrap();
    let request = node.outbox_delivery_context();
    drop(node.hydrate_source_initial_revalidated_ranked_local_in(
        &request,
        &read,
        report.clone(),
        Default::default(),
    ));
    request.cancel();
    assert!(matches!(
        node.runtime()
            .block_on(node.hydrate_source_initial_revalidated_ranked_local_in(
                &request,
                &read,
                report.clone(),
                Default::default()
            )),
        Err(RetrievalError::Source(
            NodeWorkspaceRefusal::Cancelled { .. }
        ))
    ));
    let permitted = node
        .runtime()
        .block_on(node.hydrate_source_initial_revalidated_ranked_local_in(
            &node.outbox_delivery_context(),
            &read,
            report.clone(),
            Default::default(),
        ))
        .unwrap();
    assert_eq!(
        permitted.context().retrieval().generations(),
        report.generations()
    );
    assert_eq!(
        permitted.context().retrieval().current_source(),
        report.current_source()
    );
    assert_eq!(permitted.context().files().len(), 4);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
