//! The MCP protocol reads real persisted native objects after node reopen.
//! Publication below seeds the fixture; no history tool has a write path.
use super::super::super::super::protocol::Server;
use super::*;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_node::LoopbackReceiveSession;
use fgit_pack::{EntryKind, object_type_from_base_entry};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-first-parent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn options(&self, format: GitHashAlgorithm) -> Options {
        Options {
            storage: self.0.join("node"),
            tenant: TenantId::from_bytes([0xe1; 16]),
            repository: RepositoryId::from_bytes([0xe2; 16]),
            format,
            incarnation: None,
            issues: false,
            discussions: false,
            pulls: false,
            source: true,
            writes: Default::default(),
            outcomes: false,
            principal: None,
            queues: Default::default(),
            agent_context: false,
            artifacts: false,
            artifact_root: None,
            agent_token_file: None,
            max_messages: 32,
            index_maintenance: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .basis()
        .id()
}

fn seed(options: &mut Options, reference: &RefName) -> Vec<GitOid> {
    let (mut node, _) = OneNode::init(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let tree = node
        .put_git_object(
            object_type_from_base_entry(EntryKind::Tree).unwrap(),
            vec![],
        )
        .unwrap()
        .identity();
    let mut objects = BTreeSet::from([tree]);
    let mut commits = Vec::new();
    for index in 0..4097 {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = commits.last() {
            writeln!(body, "parent {parent}").unwrap();
        }
        write!(body, "author A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\ncommit {index}").unwrap();
        let id = node
            .put_git_object(
                object_type_from_base_entry(EntryKind::Commit).unwrap(),
                body.into_bytes(),
            )
            .unwrap()
            .identity();
        objects.insert(id);
        commits.push(id);
    }
    let imported = validate_source_import(
        &[SourceRefUpdate {
            old: oid(options.format, 0),
            new: *commits.last().unwrap(),
            ref_name: reference.as_bytes().to_vec(),
        }],
        &SourceImportReceipt {
            object_format: options.format,
            object_count: u32::try_from(objects.len()).unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                objects.clone(),
            ))
            .unwrap(),
            objects,
        },
    )
    .unwrap();
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &node.request_context(),
            &AdmissionContext {
                head_key: node.authority_head_key().clone(),
                tenant_id: options.tenant,
                repository_id: options.repository,
                principal_id: PrincipalId::from_bytes([0xe3; 16]),
                idempotency_key: IdempotencyKey::new(b"mcp-long-history".to_vec()).unwrap(),
                object_format: options.format,
            },
            &imported,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    options.incarnation = Some(node.repository_incarnation_id());
    node.shutdown().unwrap();
    commits
}

fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"first-parent-test","version":"1"}}}"#).unwrap();
    assert!(
        server
            .receive(
                backend,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    server
}

fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, arguments: Object) -> Value {
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(LOG)), ("arguments", Value::Object(arguments))]),
        ),
    ]);
    server
        .receive(backend, request.encode(8192).unwrap().as_bytes())
        .unwrap()
}

fn result(response: &Value) -> &Object {
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].object().unwrap()
}

fn record_ids(result: &Object) -> Vec<String> {
    let Value::Array(commits) = &result["commits"] else {
        panic!("commits")
    };
    commits
        .iter()
        .map(|commit| commit.object().unwrap()["id"].text().unwrap().to_owned())
        .collect()
}

#[test]
fn mcp_recent_history_pages_large_reopened_native_nodes_and_rejects_stale_cursors() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new();
        let mut options = fixture.options(format);
        let reference = RefName::try_new(b"refs/heads/long-\xff").unwrap();
        let commits = seed(&mut options, &reference);
        assert!(commits.len() > HistoryLimits::default().max_commits);
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let before = authority(&backend.node);
        let mut protocol = server(&mut backend);
        let mut arguments = args();
        arguments.remove("reference");
        arguments.insert("reference_hex".into(), text(hex(reference.as_bytes())));
        arguments.insert("expected_commit".into(), text(commits[4096].to_string()));
        arguments.insert("max_commits".into(), json::number(2));
        let first = invoke(&mut protocol, &mut backend, 2, arguments.clone());
        let first = result(&first);
        assert_eq!(
            record_ids(first),
            [commits[4096].to_string(), commits[4095].to_string()]
        );
        assert_eq!(first["profile"].text(), Some("first-parent-prefix-v1"));
        assert_eq!(first["visited_commits"].text(), Some("2"));
        assert_eq!(first["root_reached"], Value::Bool(false));
        assert_eq!(first["complete"], Value::Bool(true));
        assert!(!first.contains_key("total_commits"));
        let cursor = first["next_cursor"].clone();
        // The same small bound still refuses the complete-DAG profile.
        let mut whole = arguments.clone();
        whole.remove("first_parent");
        assert_eq!(
            backend.call(LOG, &whole).unwrap_err().code,
            "resource_limit"
        );
        assert_eq!(authority(&backend.node), before);
        backend.close().unwrap();

        let mut backend = NodeTools::open(options.clone()).unwrap();
        let mut protocol = server(&mut backend);
        arguments.insert("cursor".into(), cursor.clone());
        arguments.insert("max_commits".into(), json::number(4));
        let next = invoke(&mut protocol, &mut backend, 2, arguments.clone());
        let next = result(&next);
        assert_eq!(
            record_ids(next),
            [commits[4094].to_string(), commits[4093].to_string()]
        );
        assert_eq!(next["after"].text(), Some("2"));
        assert_eq!(next["visited_commits"].text(), Some("4"));
        assert_eq!(
            next["snapshot_token"].text(),
            Some(head_token(before).as_str())
        );
        assert_eq!(
            backend.call(LOG, &arguments).unwrap().object().unwrap(),
            next
        );
        let mut too_small = arguments.clone();
        too_small.insert("max_commits".into(), json::number(2));
        assert_eq!(
            backend.call(LOG, &too_small).unwrap_err().code,
            "resource_limit"
        );
        let mut wrong_pin = arguments.clone();
        wrong_pin.insert("expected_commit".into(), text(commits[0].to_string()));
        assert_eq!(
            backend.call(LOG, &wrong_pin).unwrap_err().code,
            "cursor_commit_mismatch"
        );
        wrong_pin.remove("cursor");
        assert_eq!(
            backend.call(LOG, &wrong_pin).unwrap_err().code,
            "source_commit_moved"
        );
        let mut wrong_tip = FirstParentCursor::decode(cursor.text().unwrap()).unwrap();
        wrong_tip.tip = commits[0];
        let mut substituted = arguments.clone();
        substituted.insert("cursor".into(), text(wrong_tip.encode()));
        substituted.remove("expected_commit");
        assert_eq!(
            backend.call(LOG, &substituted).unwrap_err().code,
            "invalid_history_options"
        );
        let mut missing = args();
        missing.insert("reference".into(), text("refs/heads/missing"));
        assert_eq!(
            backend.call(LOG, &missing).unwrap_err().code,
            "reference_unavailable"
        );
        assert_eq!(authority(&backend.node), before);

        // A forge-only publication changes authority even though the native
        // reference and all first-parent objects remain exactly unchanged.
        let command = IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "advance authority".into(),
                body: String::new(),
                labels: vec![],
            },
        };
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xe3; 16]),
            IdempotencyKey::new(b"move-first-parent-snapshot".to_vec()).unwrap(),
        );
        let (_, outcome) = backend
            .node
            .runtime()
            .block_on(backend.node.admit_issue_durable_in(
                &backend.node.request_context(),
                &session,
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        let advanced = authority(&backend.node);
        assert_ne!(advanced, before);
        assert_eq!(
            backend.call(LOG, &arguments).unwrap_err().code,
            "snapshot_moved"
        );
        arguments.remove("cursor");
        assert_eq!(
            backend.call(LOG, &arguments).unwrap().object().unwrap()["snapshot_token"].text(),
            Some(head_token(advanced).as_str())
        );
        backend.options.source = false;
        backend.options.pulls = true;
        assert!(!backend.tools().iter().any(|tool| tool.name == LOG));
        assert_eq!(
            backend.call(LOG, &arguments).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(authority(&backend.node), advanced);
        backend.close().unwrap();
    }
}

#[test]
fn first_parent_history_keeps_operator_source_and_sponsored_grants_separate() {
    let fixture = Fixture::new();
    let mut options = fixture.options(GitHashAlgorithm::Sha1);
    assert!(
        super::super::super::tools_for_options(&options)
            .iter()
            .any(|tool| tool.name == LOG)
    );
    options.source = false;
    options.pulls = true;
    assert!(
        !super::super::super::tools_for_options(&options)
            .iter()
            .any(|tool| tool.name == LOG)
    );
    options.source = true;
    options.agent_token_file = Some(fixture.0.join("not-opened-agent.token"));
    assert!(
        !super::super::super::tools_for_options(&options)
            .iter()
            .any(|tool| tool.name == LOG)
    );
    assert_eq!(super::super::super::agent::operation(&options, LOG), None);
}
