//! The actual MCP transport and native canonical read owner, in both Git formats.
use super::*;
use crate::mcp::protocol::Server;
use fgit_types::RepositoryIncarnationId;
mod fixture;
use fixture::Fixture;

fn head(backend: &NodeTools) -> RepositoryAuthorityHeadId {
    backend.node.runtime().block_on(
        backend.node.materialize_admission_in(&backend.node.request_context())
    ).unwrap().basis().id()
}

fn listed_selection(backend: &mut NodeTools) -> (Value, Object) {
    let page = backend.call(
        "frankengit_pull_checks", &args([("number", text("7")), ("limit", json::number(1))])
    ).unwrap();
    let fields = page.object().unwrap();
    let Value::Array(rows) = &fields["checks"] else { panic!("check rows") };
    assert_eq!(rows.len(), 1);
    let row = rows[0].object().unwrap();
    assert_eq!(row["conclusion"].text(), Some("failure"));
    let selected = args([
        ("number", text("7")),
        ("check", row["id"].clone()),
        ("expected_head", fields["snapshot_token"].clone()),
        ("expected_evidence_sha256", row["evidence_sha256"].clone()),
    ]);
    (page, selected)
}

fn invoke(server: &mut Server, backend: &mut NodeTools, arguments: Object) -> Value {
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(2)),
        ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(arguments))])),
    ]).encode(4096).unwrap();
    let response = server.receive(backend, message.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_ne!(result.get("isError"), Some(&Value::Bool(true)));
    result["structuredContent"].clone()
}

fn assert_no_authority(value: &Value) {
    let fields = value.object().unwrap();
    for name in ["read_only", "evidence_verified", "content_is_untrusted"] {
        assert_eq!(fields[name], Value::Bool(true), "{name}");
    }
    for name in ["transaction_created", "approval_granted"] {
        assert_eq!(fields[name], Value::Bool(false), "{name}");
    }
    assert_eq!(fields["merge_permission"], Value::Null);
}

fn grant_matrix(backend: &mut NodeTools, fixture: &Fixture, selection: &Object) {
    for (pulls, artifacts) in [(false, false), (true, false), (false, true), (true, true)] {
        backend.options.pulls = pulls;
        backend.options.artifacts = artifacts;
        assert_eq!(backend.tools().iter().any(|tool| tool.name == NAME), pulls && artifacts);
        assert!(!backend.is_mutation(NAME));
        if pulls && artifacts {
            assert!(backend.call(NAME, selection).is_ok());
        } else {
            // An invalid body must not reach parsing or the native reader when
            // either independent disclosure grant is absent.
            assert_eq!(backend.call(NAME, &Object::new()).unwrap_err().code, "tool_not_granted");
            assert_eq!(call(backend, &Object::new()).unwrap_err().code, "tool_not_granted");
        }
    }
    backend.options.agent_token_file = Some(fixture.root.join("not-a-credential"));
    assert!(backend.options.validate_access().is_err());
    assert!(!backend.tools().iter().any(|tool| tool.name == NAME));
    assert!(!backend.is_mutation(NAME));
    assert_eq!(call(backend, selection).unwrap_err().code, "tool_not_granted");
    backend.options.agent_token_file = None;
    let incarnation = backend.options.incarnation;
    backend.options.incarnation = Some(RepositoryIncarnationId::from_bytes([0x90; 16]));
    assert_eq!(call(backend, selection).unwrap_err().code, "repository_binding_mismatch");
    backend.options.incarnation = incarnation;
}

fn report_binding_and_response_bounds(backend: &NodeTools, arguments: &Object) {
    let query = parse(arguments).unwrap();
    let canonical = backend.node.runtime().block_on(
        backend.node.read_pull_request_check_evidence_in(
            &backend.node.request_context(), &Default::default(), query.number, query.check,
            query.expected_head,
        )
    ).unwrap().unwrap();
    let selected = output::Selected::new(&query, &canonical, backend.options.format).unwrap();
    assert!(report::span(backend, &selected, &|| true).is_some());
    assert!(report::span(backend, &selected, &|| false).is_none());
    for field in ["run", "attempt", "graph", "job", "source", "conclusion"] {
        let mut changed = canonical.clone();
        match field {
            "run" => changed.page.checks[0].run_id[0] ^= 1,
            "attempt" => changed.page.checks[0].attempt_id[0] ^= 1,
            "graph" => changed.page.checks[0].graph_root[0] ^= 1,
            "job" => changed.page.checks[0].job.push('x'),
            "source" => changed.page.source_tip = changed.page.target_tip,
            "conclusion" => changed.page.checks[0].conclusion = WorkflowCheckConclusion::Success,
            _ => unreachable!(),
        }
        let selected = output::Selected::new(&query, &changed, backend.options.format).unwrap();
        assert!(report::span(backend, &selected, &|| true).is_none(), "{field}");
    }
    // Future/unknown canonical evidence remains exact readable bytes, while a
    // failed optional report decoder cannot manufacture a diagnostic span.
    let unknown = observation(backend.options.format, b"\0future evidence\xff");
    let query = parse(&selection(&unknown)).unwrap();
    let selected = output::Selected::new(&query, &unknown, backend.options.format).unwrap();
    assert!(report::span(backend, &selected, &|| true).is_none());
    let value = output::render(backend, &selected, None);
    assert_eq!(value.object().unwrap()["report_span"], Value::Null);
    assert_eq!(value.object().unwrap()["content_hex"].text(), Some(hex(&unknown.evidence).as_str()));
    let maximum = observation(
        backend.options.format,
        &vec![0xff; fgit_forge::event::workflow_check::MAX_CHECK_EVIDENCE_BYTES],
    );
    let query = parse(&selection(&maximum)).unwrap();
    let selected = output::Selected::new(&query, &maximum, backend.options.format).unwrap();
    let value = output::render(backend, &selected, None);
    let fields = value.object().unwrap();
    assert_eq!(fields["content_hex"].text().unwrap().len(), 131072);
    assert_eq!(fields["byte_count"].text(), Some("65536"));
    assert_eq!(fields["next_offset"].text(), Some("65536"));
    assert!(value.encode(MAX_RESULT_BYTES).is_ok());
    let contract = fgit_schema::mcp::find_tool(NAME).unwrap();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        contract.output_fields.iter().map(|field| field.name).collect::<BTreeSet<_>>()
    );
    assert_no_authority(&value);
}

#[test]
fn native_failed_check_evidence_is_pinned_bounded_and_requires_both_grants_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let before = head(&backend);
        let (listed, arguments) = listed_selection(&mut backend);
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"check-evidence-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let full = invoke(&mut server, &mut backend, arguments.clone());
        assert_no_authority(&full);
        assert_eq!(full.object().unwrap()["page"], listed);
        assert_eq!(
            full.object().unwrap()["content_hex"].text(),
            Some(hex(&fixture.evidence).as_str())
        );
        let span = full.object().unwrap()["report_span"].object().unwrap();
        let offset = usize::try_from(json::decimal(span["offset"].text().unwrap()).unwrap()).unwrap();
        let bytes = usize::try_from(json::decimal(span["bytes"].text().unwrap()).unwrap()).unwrap();
        assert_eq!(offset + bytes, fixture.evidence.len());
        let report_text = std::str::from_utf8(&fixture.evidence[offset..]).unwrap();
        assert!(report_text.contains(&hex(b"MCP-CHECK-FAILED")));
        assert!(report_text.contains(&hex(b"MCP-CHECK-ERROR")));
        assert!(report_text.contains("\"exit_code\":7"));
        assert!(report_text.contains("\"authoritative_check\":false"));

        let mut assembled = Vec::new();
        let mut request = arguments.clone();
        request.insert("limit".into(), json::number(257));
        loop {
            request.insert("offset".into(), text(assembled.len().to_string()));
            let page = backend.call(NAME, &request).unwrap();
            let fields = page.object().unwrap();
            assert_eq!(fields["page"], listed);
            assert_eq!(fields["report_span"], full.object().unwrap()["report_span"]);
            let bytes = unhex(fields["content_hex"].text().unwrap(), 65536).unwrap();
            assert!(!bytes.is_empty() && bytes.len() <= 257);
            assert_eq!(fields["byte_count"].text(), Some(bytes.len().to_string().as_str()));
            assembled.extend(bytes);
            if fields["next_offset"] == Value::Null { break; }
            assert_eq!(fields["next_offset"].text(), Some(assembled.len().to_string().as_str()));
        }
        assert_eq!(assembled, fixture.evidence);
        request.insert("offset".into(), text(assembled.len().to_string()));
        let eof = backend.call(NAME, &request).unwrap();
        assert_eq!(eof.object().unwrap()["content_hex"].text(), Some(""));
        assert_eq!(eof.object().unwrap()["byte_count"].text(), Some("0"));
        assert_eq!(eof.object().unwrap()["next_offset"], Value::Null);
        request.insert("offset".into(), text((assembled.len() + 1).to_string()));
        assert_eq!(backend.call(NAME, &request).unwrap_err().code, "check_evidence_offset_out_of_bounds");

        let mut wrong = arguments.clone();
        wrong.insert("expected_evidence_sha256".into(), text("00".repeat(32)));
        assert_eq!(backend.call(NAME, &wrong).unwrap_err().code, "check_evidence_identity_mismatch");
        for (field, value) in [
            ("number", text("8")),
            ("check", text(WorkflowCheckId::from_bytes([0; 32]).to_string())),
        ] {
            let mut missing = arguments.clone();
            missing.insert(field.into(), value);
            assert_eq!(backend.call(NAME, &missing).unwrap_err().code, "pull_check_evidence_unavailable");
        }
        let mut wrong = arguments.clone();
        wrong.insert("expected_head".into(), text(format!("alg:2:{}", "ff".repeat(32))));
        assert_eq!(backend.call(NAME, &wrong).unwrap_err().code, "snapshot_unavailable");
        report_binding_and_response_bounds(&backend, &arguments);
        grant_matrix(&mut backend, &fixture, &arguments);
        assert_eq!(head(&backend), before, "reads cannot publish an authority head");

        fixture.advance_source(&backend);
        let moved = head(&backend);
        assert_ne!(moved, before);
        // The old canonical observation remains readable at its retained pin.
        // source_current is true relative to that pin, not the current head.
        assert_eq!(backend.call(NAME, &arguments).unwrap(), full);
        let mut stale = arguments.clone();
        stale.insert("expected_head".into(), text(head_token(moved)));
        assert_eq!(backend.call(NAME, &stale).unwrap_err().code, "pull_check_evidence_unavailable");
        assert_eq!(head(&backend), moved);
        backend.close().unwrap();

        let mut reopened = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(reopened.call(NAME, &arguments).unwrap(), full);
        assert_eq!(head(&reopened), moved);
        reopened.close().unwrap();
    }
}
