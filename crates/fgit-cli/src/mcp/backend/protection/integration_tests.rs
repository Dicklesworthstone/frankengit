//! Persisted node and MCP protocol tests for the operator policy profile.
use super::*;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ADMIN: PrincipalId = PrincipalId::from_bytes([0x61; 16]);
const NEXT_ADMIN: PrincipalId = PrincipalId::from_bytes([0x62; 16]);
const REVIEWER: PrincipalId = PrincipalId::from_bytes([0x63; 16]);

struct Fixture {
    root: PathBuf,
    arguments: Vec<String>,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-policy-write-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0x64; 16]);
        let repository = RepositoryId::from_bytes([0x65; 16]);
        let (mut node, _) = OneNode::init(
            NodeConfig::new(root.join("node"), tenant, repository)
                .with_object_format(format)
                .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let arguments = vec![
            root.join("node").to_str().unwrap().into(),
            tenant.to_string(),
            repository.to_string(),
            "--trusted-local".into(),
            "--expected-incarnation".into(),
            node.repository_incarnation_id().to_string(),
            "--object-format".into(),
            format.as_str().into(),
        ];
        node.shutdown().unwrap();
        Self { root, arguments }
    }
    fn launch(&self, mask: u8, principal: PrincipalId) -> Launch {
        let mut arguments = self.arguments.clone();
        for (bit, flag) in [
            (1, "--allow-read"),
            (2, "--allow-write"),
            (4, "--allow-outcomes"),
        ] {
            if mask & bit != 0 {
                arguments.push(flag.into());
            }
        }
        if mask & 6 != 0 {
            arguments.extend(["--principal".into(), principal.to_string()]);
        }
        parse(&arguments).unwrap()
    }
    fn open(&self, mask: u8, principal: PrincipalId) -> ProtectionTools {
        ProtectionTools::open(self.launch(mask, principal)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn command(
    key: &str,
    version: &str,
    epoch: &str,
    administrator: PrincipalId,
    enabled: bool,
) -> Object {
    let branches = if enabled {
        vec![object([
            ("reference_hex", text(hex(b"refs/heads/main-\xff"))),
            (
                "required_reviewers",
                Value::Array(vec![text(REVIEWER.to_string())]),
            ),
        ])]
    } else {
        Vec::new()
    };
    let Value::Object(args) = object([
        ("idempotency_key", text(key)),
        ("expected_version", text(version)),
        ("expected_epoch", text(epoch)),
        (
            "administrators",
            Value::Array(vec![text(administrator.to_string())]),
        ),
        ("branches", Value::Array(branches)),
    ]) else {
        unreachable!()
    };
    args
}
fn key(value: &str) -> Object {
    let Value::Object(args) = object([("idempotency_key", text(value))]) else {
        unreachable!()
    };
    args
}
fn head(tools: &ProtectionTools) -> RepositoryAuthorityHeadId {
    let node = &tools.backend.node;
    let request = fgit_cli::command_request_context(node);
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
        .basis()
        .id()
}
fn assert_committed(value: &Value) {
    let fields = value.object().unwrap();
    assert_eq!(fields["outcome"].text(), Some("committed"));
    assert_eq!(fields["outcome_unknown"], Value::Bool(false));
    assert_eq!(fields["terminal"], Value::Bool(true));
    assert_eq!(fields["historical_outcome"], Value::Bool(true));
    assert_eq!(fields["refs_changed"], Value::Bool(false));
    assert_eq!(
        fields["principal_source"].text(),
        Some("operator_asserted_at_launch")
    );
}
fn assert_refused(value: &Value, code: &str) {
    let fields = value.object().unwrap();
    assert_eq!(fields["outcome"].text(), Some("refused"));
    assert_eq!(fields["refusal_code"].text(), Some(code));
    assert_eq!(fields["outcome_unknown"], Value::Bool(false));
    assert_eq!(fields["resulting_policy_epoch"], Value::Null);
}

#[test]
fn launch_grants_require_principal_for_write_or_recovery_and_never_imply_read() {
    let base = vec![
        "/unused".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
        "--expected-incarnation".into(),
        "33".repeat(16),
    ];
    for mask in 0..8 {
        let mut args = base.clone();
        for (bit, flag) in [
            (1, "--allow-read"),
            (2, "--allow-write"),
            (4, "--allow-outcomes"),
        ] {
            if mask & bit != 0 {
                args.push(flag.into());
            }
        }
        if mask & 6 != 0 {
            assert!(parse(&args).is_err());
            args.extend(["--principal".into(), ADMIN.to_string()]);
        }
        if mask == 0 {
            assert!(parse(&args).is_err());
            continue;
        }
        let launch = parse(&args).unwrap();
        assert_eq!(launch.read, mask & 1 != 0);
        assert_eq!(launch.write, mask & 2 != 0);
        assert_eq!(launch.options.outcomes, mask & 4 != 0);
        assert_eq!(launch.options.principal.is_some(), mask & 6 != 0);
        assert!(!launch.options.issues && !launch.options.pulls && !launch.options.source);
        assert!(!launch.options.writes.any());
        let mut missing_incarnation = args.clone();
        missing_incarnation.drain(4..6);
        assert!(parse(&missing_incarnation).is_err());
    }
    let mut args = base.clone();
    args.extend([
        "--allow-read".into(),
        "--principal".into(),
        ADMIN.to_string(),
    ]);
    assert!(parse(&args).is_err());
    for extra in [
        vec!["--allow-write", "--allow-write"],
        vec!["--allow-source-writes"],
        vec!["--allow-protection-bootstrap"],
        vec!["--principal", "AA"],
    ] {
        let mut args = base.clone();
        args.extend(extra.into_iter().map(str::to_owned));
        assert!(parse(&args).is_err());
    }
}

#[test]
fn canonical_install_rotation_disable_and_historical_recovery_survive_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut tools = fixture.open(6, ADMIN);
        assert_eq!(
            tools
                .tools()
                .iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            vec![write::NAME, outcomes::NAME]
        );
        for denied in [
            SHOW,
            "frankengit_issue_open",
            "frankengit_pull_merge",
            "shell",
        ] {
            assert_eq!(
                tools.call(denied, &Object::new()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        let refused = tools
            .call(
                write::NAME,
                &command("bootstrap-wrong-admin", "0", "1", NEXT_ADMIN, true),
            )
            .unwrap();
        assert_refused(&refused, "ProtectedRefTransitionDenied");
        assert!(tools.result_is_error(write::NAME, &refused));
        let original = command("install-policy", "0", "1", ADMIN, true);
        let installed = tools.call(write::NAME, &original).unwrap();
        assert_committed(&installed);
        assert!(!tools.result_is_error(write::NAME, &installed));
        let saved_head = head(&tools);
        assert_eq!(tools.call(write::NAME, &original).unwrap(), installed);
        assert_eq!(head(&tools), saved_head);
        let changed_key = command("install-policy", "0", "1", ADMIN, false);
        assert_eq!(
            tools.call(write::NAME, &changed_key).unwrap_err().code,
            "mutation_outcome_unknown"
        );
        assert_eq!(head(&tools), saved_head);
        let rotation = tools
            .call(
                write::NAME,
                &command("rotate-policy", "1", "2", NEXT_ADMIN, true),
            )
            .unwrap();
        assert_committed(&rotation);
        tools.close().unwrap();

        let mut former = fixture.open(2, ADMIN);
        // An exact terminal retry is historical, even after this principal lost administration.
        assert_eq!(former.call(write::NAME, &original).unwrap(), installed);
        let self_authorized = former
            .call(
                write::NAME,
                &command("take-policy-back", "2", "3", ADMIN, true),
            )
            .unwrap();
        assert_refused(&self_authorized, "ProtectedRefTransitionDenied");
        assert_eq!(
            former
                .call(outcomes::NAME, &key("install-policy"))
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        former.close().unwrap();

        let mut current = fixture.open(2, NEXT_ADMIN);
        let stale = current
            .call(
                write::NAME,
                &command("stale-policy", "1", "2", NEXT_ADMIN, false),
            )
            .unwrap();
        assert_refused(&stale, "EvidenceStale");
        let disabled = current
            .call(
                write::NAME,
                &command("disable-policy", "2", "3", NEXT_ADMIN, false),
            )
            .unwrap();
        assert_committed(&disabled);
        assert_eq!(
            disabled.object().unwrap()["resulting_version"].text(),
            Some("3")
        );
        assert_eq!(
            disabled.object().unwrap()["resulting_policy_epoch"].text(),
            Some("4")
        );
        current.close().unwrap();

        let mut reader = fixture.open(1, ADMIN);
        let selected = reader.call(SHOW, &Object::new()).unwrap();
        let fields = selected.object().unwrap();
        assert_eq!(fields["installed"], Value::Bool(true));
        assert_eq!(fields["enabled"], Value::Bool(false));
        assert_eq!(fields["version"].text(), Some("3"));
        assert_eq!(fields["policy_epoch"].text(), Some("4"));
        assert_eq!(
            fields["policy"].object().unwrap()["administrators"],
            Value::Array(vec![text(NEXT_ADMIN.to_string())])
        );
        assert!(reader.call(write::NAME, &original).unwrap_err().invalid);
        reader.close().unwrap();

        let mut recovery = fixture.open(4, ADMIN);
        assert_eq!(
            recovery
                .tools()
                .iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            vec![outcomes::NAME]
        );
        let recovered = recovery
            .call(outcomes::NAME, &key("install-policy"))
            .unwrap();
        assert_eq!(
            recovered.object().unwrap()["tx_id"],
            installed.object().unwrap()["tx_id"]
        );
        assert_eq!(recovered.object().unwrap()["read_only"], Value::Bool(true));
        assert_eq!(
            recovered.object().unwrap()["repository_changed"],
            Value::Bool(false)
        );
        assert!(recovery.call(write::NAME, &original).unwrap_err().invalid);
        assert!(recovery.call(SHOW, &Object::new()).unwrap_err().invalid);
        recovery.close().unwrap();
        let mut wrong_principal = fixture.open(4, NEXT_ADMIN);
        let unknown = wrong_principal
            .call(outcomes::NAME, &key("install-policy"))
            .unwrap();
        assert_eq!(
            unknown.object().unwrap()["observation"].text(),
            Some("key_not_observed")
        );
        assert_eq!(
            unknown.object().unwrap()["outcome_unknown"],
            Value::Bool(true)
        );
        assert_eq!(unknown.object().unwrap()["tx_id"], Value::Null);
        wrong_principal.close().unwrap();
    }
}

fn start(tools: &mut ProtectionTools) -> protocol::Server {
    let mut server = protocol::Server::new(tools).unwrap();
    server.receive(tools, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"protection-tests","version":"1"}}}"#).unwrap();
    assert!(
        server
            .receive(
                tools,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    server
}
fn invoke(
    server: &mut protocol::Server,
    tools: &mut ProtectionTools,
    id: u64,
    name: &str,
    args: Object,
) -> Value {
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(name)), ("arguments", Value::Object(args))]),
        ),
    ]);
    server
        .receive(tools, request.encode(json::MAX_INPUT).unwrap().as_bytes())
        .unwrap()
}
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"]
        .object()
        .unwrap()
}

#[test]
fn mcp_mutation_annotations_notifications_and_stopped_intake_preserve_outcome_semantics() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut tools = fixture.open(6, ADMIN);
    let mut server = start(&mut tools);
    let list = server
        .receive(
            &mut tools,
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        )
        .unwrap();
    let Value::Array(descriptors) = &list.object().unwrap()["result"].object().unwrap()["tools"]
    else {
        panic!("tools")
    };
    for descriptor in descriptors {
        let fields = descriptor.object().unwrap();
        assert_eq!(
            fields["annotations"].object().unwrap()["readOnlyHint"],
            Value::Bool(fields["name"].text() != Some(write::NAME))
        );
    }
    let before = head(&tools);
    let args = command("protocol-install", "0", "1", ADMIN, true);
    let notification = object([
        ("jsonrpc", text("2.0")),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text(write::NAME)),
                ("arguments", Value::Object(args.clone())),
            ]),
        ),
    ]);
    assert!(
        server
            .receive(
                &mut tools,
                notification.encode(json::MAX_INPUT).unwrap().as_bytes()
            )
            .is_none()
    );
    assert_eq!(head(&tools), before);
    let mut injected = args.clone();
    injected.insert("principal".into(), text(NEXT_ADMIN.to_string()));
    assert!(
        invoke(&mut server, &mut tools, 3, write::NAME, injected)
            .object()
            .unwrap()
            .contains_key("error")
    );
    assert_eq!(head(&tools), before);
    for (offset, value) in [
        None,
        Some(text("")),
        Some(text("not a key")),
        Some(text("x".repeat(257))),
    ]
    .into_iter()
    .enumerate()
    {
        let mut invalid = args.clone();
        if let Some(value) = value {
            invalid.insert("idempotency_key".into(), value);
        } else {
            invalid.remove("idempotency_key");
        }
        assert!(
            invoke(
                &mut server,
                &mut tools,
                20 + offset as u64,
                write::NAME,
                invalid
            )
            .object()
            .unwrap()
            .contains_key("error")
        );
        assert_eq!(head(&tools), before);
    }
    let installed = invoke(&mut server, &mut tools, 4, write::NAME, args.clone());
    assert_eq!(result(&installed)["outcome"].text(), Some("committed"));
    assert_eq!(
        installed.object().unwrap()["result"].object().unwrap()["isError"],
        Value::Bool(false)
    );
    assert!(
        server
            .receive(
                &mut tools,
                br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}"#
            )
            .is_none()
    );
    let retry = invoke(&mut server, &mut tools, 5, write::NAME, args.clone());
    assert_eq!(result(&retry), result(&installed));
    let committed_head = head(&tools);
    let options = tools.backend.options.clone();
    tools.close().unwrap();
    // Deliberately leave the reopened node out of service. Existing terminal
    // retries and read-only recovery precede the native new-publication gate.
    let node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_worker_threads(2),
    )
    .unwrap();
    let mut stopped = ProtectionTools {
        backend: NodeTools { node, options },
        read: false,
        write: true,
    };
    let mut server = start(&mut stopped);
    let retry = invoke(&mut server, &mut stopped, 2, write::NAME, args);
    assert_eq!(result(&retry), result(&installed));
    let uncertain = invoke(
        &mut server,
        &mut stopped,
        3,
        write::NAME,
        command("stopped-new", "1", "2", ADMIN, false),
    );
    assert_eq!(result(&uncertain)["outcome_unknown"], Value::Bool(true));
    assert_eq!(result(&uncertain)["terminal"], Value::Bool(false));
    assert_eq!(
        uncertain.object().unwrap()["result"].object().unwrap()["isError"],
        Value::Bool(true)
    );
    let recovered = invoke(
        &mut server,
        &mut stopped,
        4,
        outcomes::NAME,
        key("protocol-install"),
    );
    assert_eq!(result(&recovered)["tx_id"], result(&installed)["tx_id"]);
    stopped
        .backend
        .node
        .bring_into_service(HeadGeneration::FIRST)
        .unwrap();
    assert_eq!(head(&stopped), committed_head);
    stopped.close().unwrap();
}
