//! Real persisted node, canonical grants and MCP adapters. No credential mocks.
use super::super::super::protocol::{ReadTools, Server};
use super::*;
use fgit_identity::agent::ALL_OPERATIONS;
use fgit_node::OneNode;
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId};
use support::*;

mod history;
mod lifecycle;
mod source;
mod support;

#[test]
fn sponsored_profile_lists_only_exact_tools_even_with_operator_flags_planted() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut options = fixture.options.clone();
    // Defense in depth: even bypassing launch validation cannot widen either
    // discovery or central dispatch into broad operator groups.
    options.source = true;
    options.agent_context = true;
    options.artifacts = true;
    options.queues.read = true;
    options.queues.write = true;
    options.queues.land = true;
    options.writes.source = true;
    options.writes.notifications = true;
    options.writes.reviews = true;
    options.writes.merges = true;
    options.principal = Some(SPONSOR);
    let tools = super::super::tools_for_options(&options);
    assert_eq!(tools.len(), 49);
    for tool in &tools {
        assert!(operation(&options, tool.name).is_some());
    }
    assert!(NodeTools::open(options.clone()).is_err());
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    backend.options = options;
    for name in [
        "frankengit_milestone_list",
        "frankengit_milestone_open",
        "frankengit_notifications",
        "frankengit_pull_checks",
        "frankengit_pull_reviews",
        "frankengit_source_candidate",
        "frankengit_pull_diff",
        "frankengit_source_publish",
        "frankengit_branch_transaction",
        "frankengit_branch_create",
        "frankengit_protection_show",
        "frankengit_protection_set",
        "shell",
        "unknown_metadata_tool",
    ] {
        assert!(!tools.iter().any(|tool| tool.name == name), "{name}");
        assert_eq!(
            backend.call(name, &Object::new()).unwrap_err().code,
            "tool_not_granted",
            "{name}"
        );
    }
    assert!(backend.agent.as_ref().unwrap().request.is_none());
    assert!(backend.agent.as_ref().unwrap().response.is_none());
    backend.close().unwrap();
}

#[test]
fn canonical_scope_and_launch_ceiling_are_separate_for_all_seven_metadata_operations() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let operations = [
        (ISSUES_READ, "frankengit_issue_list"),
        (ISSUES_WRITE, "frankengit_issue_open"),
        (PULLS_READ, "frankengit_pull_list"),
        (PULLS_WRITE, "frankengit_pull_open"),
        (DISCUSSIONS_READ, "frankengit_discussion_list"),
        (DISCUSSIONS_WRITE, "frankengit_discussion_open"),
        (OUTCOMES_READ, "frankengit_transaction_outcome"),
    ];
    let administrator = NodeTools::open(fixture.options.clone()).unwrap();
    for (index, (scope, _)) in operations.iter().enumerate() {
        issue(
            &administrator.node,
            &token(index as u8 + 1),
            grant(&administrator.node, *scope),
            &format!("scope-{index}"),
        );
    }
    administrator.close().unwrap();
    for (index, (scope, allowed)) in operations.iter().enumerate() {
        // All launch ceilings are selected; only the canonical single-bit grant
        // can authorize a call. A write grant must not silently grant reads.
        let mut backend = NodeTools::open(fixture.replacement(index as u8 + 1)).unwrap();
        for (other_scope, name) in operations {
            let retry = format!("scope-{index}-operation-{other_scope}");
            let args = match other_scope {
                ISSUES_WRITE | DISCUSSIONS_WRITE => opening(index as u64 + 100, &retry),
                PULLS_WRITE => pull_opening(&fixture, index as u64 + 100, &retry),
                OUTCOMES_READ => recovery(&retry),
                _ => Object::new(),
            };
            let result = backend.call(name, &args);
            if other_scope == *scope {
                let result = result.unwrap();
                if is_write(other_scope) {
                    committed(&result);
                }
            } else {
                assert_eq!(
                    result.unwrap_err().code,
                    "agent_operation_not_granted",
                    "{allowed} must not authorize {name}"
                );
            }
            assert!(backend.agent.as_ref().unwrap().request.is_none());
        }
        backend.close().unwrap();
    }

    // The converse also holds: a full canonical credential cannot override a
    // narrower launch ceiling, and write-only discovery contains no reads.
    let mut options = fixture.options.clone();
    options.issues = false;
    options.discussions = false;
    options.pulls = false;
    options.writes.discussions = false;
    options.writes.pulls = false;
    options.outcomes = false;
    let mut backend = NodeTools::open(options).unwrap();
    assert_eq!(backend.tools().len(), 14);
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| backend.is_mutation(tool.name))
    );
    for name in [
        "frankengit_issue_list",
        "frankengit_transaction_outcome",
        "frankengit_pull_open",
        "frankengit_discussion_open",
    ] {
        assert_eq!(
            backend
                .call(name, &recovery("not-executed"))
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
    }
    committed(
        &backend
            .call("frankengit_issue_open", &opening(200, "write-only"))
            .unwrap(),
    );
    backend.close().unwrap();
}

#[test]
fn request_commitment_binds_every_argument_and_tool_without_transport_retry_ids() {
    let args = opening(7, "original-key");
    let original = request_commitment("frankengit_issue_open", &args).unwrap();
    assert_eq!(
        request_commitment("frankengit_issue_open", &args).unwrap(),
        original
    );
    for (field, value) in [
        ("number", "8"),
        ("expected_version", "1"),
        ("title", "different"),
        ("body", "different"),
        ("idempotency_key", "another-key"),
        ("unknown_argument", "not ignored"),
    ] {
        let mut altered = args.clone();
        altered.insert(field.into(), text(value));
        assert_ne!(
            request_commitment("frankengit_issue_open", &altered).unwrap(),
            original,
            "{field}"
        );
    }
    assert_ne!(
        request_commitment("frankengit_discussion_open", &args).unwrap(),
        original
    );
    let mut huge = args;
    huge.insert("body".into(), text("x".repeat(MAX_MESSAGE_BYTES + 1)));
    assert_eq!(
        request_commitment("frankengit_issue_open", &huge)
            .unwrap_err()
            .code,
        "agent_request_limit"
    );
}

#[test]
fn repository_incarnation_expiry_and_invalid_tokens_refuse_before_metadata_disclosure() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut wrong = fixture.options.clone();
    wrong.incarnation = Some(wrong_incarnation());
    assert!(NodeTools::open(wrong).is_err());
    let mut wrong = fixture.options.clone();
    wrong.repository = RepositoryId::from_bytes([0xf2; 16]);
    assert!(NodeTools::open(wrong).is_err());

    // The caller may correctly pin a different repository/incarnation. The
    // original token is still not issued in that canonical credential registry.
    for (index, repository) in [
        fixture.options.repository,
        RepositoryId::from_bytes([0xf2; 16]),
    ]
    .into_iter()
    .enumerate()
    {
        let mut foreign = fixture.options.clone();
        foreign.storage = fixture.root.join(format!("foreign-{index}"));
        foreign.repository = repository;
        let (mut node, _) = OneNode::init(config(&foreign)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        foreign.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(foreign).unwrap();
        assert_eq!(
            backend
                .call("frankengit_issue_list", &Object::new())
                .unwrap_err()
                .code,
            "agent_credential_unavailable"
        );
        backend.close().unwrap();
    }

    let administrator = NodeTools::open(fixture.options.clone()).unwrap();
    let current = now();
    for (byte, issued_at, expires_at) in [
        (0xb1, current - 3, current - 1),
        (0xb2, current + 3600, current + 7200),
    ] {
        let mut invalid_time = grant(&administrator.node, ALL_OPERATIONS);
        invalid_time.issued_at = issued_at;
        invalid_time.expires_at = expires_at;
        issue(
            &administrator.node,
            &token(byte),
            invalid_time,
            &format!("invalid-time-{byte}"),
        );
    }
    administrator.close().unwrap();
    for byte in [0xb1, 0xb2, 0xb3] {
        let mut backend = NodeTools::open(fixture.replacement(byte)).unwrap();
        for (name, args) in [
            ("frankengit_issue_list", Object::new()),
            ("frankengit_issue_open", opening(1, "must-not-publish")),
            (
                "frankengit_transaction_outcome",
                recovery("must-not-publish"),
            ),
        ] {
            let error = backend.call(name, &args).unwrap_err();
            assert_eq!(error.code, "agent_credential_unavailable");
            assert!(!format!("{error:?}").contains(&token(byte)));
        }
        backend.close().unwrap();
    }
}

#[test]
fn completed_request_guards_disclosure_but_never_becomes_another_calls_authority() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    backend
        .call("frankengit_issue_list", &Object::new())
        .unwrap();
    assert!(backend.agent.as_ref().unwrap().request.is_none());
    assert!(backend.response_checkpoint(OUTPUT_BYTES).is_ok());
    assert!(backend.response_checkpoint(OUTPUT_BYTES + 1).is_err());
    assert_eq!(
        session(&backend, key("not-a-live-request"))
            .unwrap_err()
            .code,
        "agent_request_required"
    );
    backend
        .agent
        .as_mut()
        .unwrap()
        .response
        .as_mut()
        .unwrap()
        .constrain_deadline(Instant::now() - Duration::from_secs(1));
    assert!(backend.response_checkpoint(0).is_err());
    backend.begin_message();
    assert!(backend.response_checkpoint(0).is_ok());
    backend
        .call("frankengit_issue_list", &Object::new())
        .unwrap();
    assert!(backend.response_checkpoint(0).is_ok());
    backend.finish_response();
    assert!(backend.agent.as_ref().unwrap().response.is_none());
    // Changing the token file cannot retarget this already launched process.
    std::fs::write(
        fixture.options.agent_token_file.as_ref().unwrap(),
        token(0xff),
    )
    .unwrap();
    backend
        .call("frankengit_issue_list", &Object::new())
        .unwrap();
    backend.close().unwrap();
}
