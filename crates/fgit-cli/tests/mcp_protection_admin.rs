#![forbid(unsafe_code)]

use fgit_authority::{IdempotencyKey, OutcomeLookup, key_recovery::RequestRecovery};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: TenantId = TenantId::from_bytes([0xb1; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0xb2; 16]);
const ADMIN: PrincipalId = PrincipalId::from_bytes([0xb3; 16]);
const REVIEWER: PrincipalId = PrincipalId::from_bytes([0xb4; 16]);
const KEY: &str = "protection-stdio-install";
const HANDSHAKE: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"protection-stdio\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

struct Fixture {
    root: PathBuf,
    incarnation: RepositoryIncarnationId,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-policy-stdio-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let (node, _) = OneNode::init(config(root.join("node"))).unwrap();
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        Self { root, incarnation }
    }
    fn run(&self, grant: &str, principal: bool, input: &str) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_fg"));
        process
            .args(["mcp", "--protection-admin"])
            .arg(self.root.join("node"))
            .args([TENANT.to_string(), REPOSITORY.to_string()])
            .args(["--trusted-local", "--expected-incarnation"])
            .arg(self.incarnation.to_string())
            .arg(grant)
            .args(["--max-messages", "16"]);
        if principal {
            process.arg("--principal").arg(ADMIN.to_string());
        }
        let mut child = process
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start fg mcp protection profile");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
    fn open(&self) -> OneNode {
        let mut node = OneNode::open_existing(config(self.root.join("node"))).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        node
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(root, TENANT, REPOSITORY).with_worker_threads(2)
}
fn call(id: u64, name: &str, args: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{args}}}}}\n"
    )
}
fn line(output: &str, id: u64) -> &str {
    output
        .lines()
        .find(|line| line.contains(&format!("\"id\":{id},")))
        .unwrap_or_else(|| panic!("missing response {id}: {output}"))
}
fn stdout(output: &Output) -> &str {
    assert!(
        output.status.success(),
        "process failed: {:?}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    std::str::from_utf8(&output.stdout).unwrap()
}

#[test]
fn real_stdio_policy_write_and_independent_recovery_use_one_persisted_decision() {
    let fixture = Fixture::new();
    let args = format!(
        "{{\"idempotency_key\":\"{KEY}\",\"expected_version\":\"0\",\"expected_epoch\":\"1\",\"administrators\":[\"{ADMIN}\"],\"branches\":[{{\"reference_hex\":\"726566732f68656164732f6d61696e\",\"required_reviewers\":[\"{REVIEWER}\"]}}]}}",
    );
    let input = format!(
        "{HANDSHAKE}{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{}{}{}",
        call(3, "frankengit_protection_set", &args),
        call(4, "frankengit_protection_set", &args),
        call(5, "frankengit_protection_show", "{}"),
    );
    let written = fixture.run("--allow-write", true, &input);
    let output = stdout(&written);
    assert_eq!(output.lines().count(), 5);
    let listed = line(output, 2);
    assert!(listed.contains("frankengit_protection_set"));
    assert!(listed.contains("\"readOnlyHint\":false"));
    assert!(!listed.contains("frankengit_protection_show"));
    assert!(!listed.contains("frankengit_transaction_outcome"));
    assert!(line(output, 3).contains("\"outcome\":\"committed\""));
    assert!(line(output, 3).contains("\"principal_source\":\"operator_asserted_at_launch\""));
    assert!(line(output, 4).contains("\"outcome\":\"committed\""));
    assert!(line(output, 5).contains("\"code\":-32602"));

    let node = fixture.open();
    let request = fgit_cli::command_request_context(&node);
    let state = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    assert_eq!(state.version().unwrap().get(), 1);
    assert_eq!(state.policy_epoch.get(), 2);
    assert_eq!(state.protection().unwrap().administrators, vec![ADMIN]);
    assert_eq!(
        state.protection().unwrap().branches[0].reviewers,
        vec![REVIEWER]
    );
    let selected_head = state.source_head;
    let session = LoopbackReceiveSession::authenticated(
        ADMIN,
        IdempotencyKey::new(KEY.as_bytes().to_vec()).unwrap(),
    );
    let RequestRecovery::Recovered(recovered) = node
        .runtime()
        .block_on(node.recover_transaction_in(&request, &session))
        .unwrap()
    else {
        panic!("expected original key recovery")
    };
    assert!(matches!(recovered.outcome(), OutcomeLookup::Decided(_)));
    let tx = recovered.tx_id().to_string();
    assert!(line(output, 3).contains(&tx));
    assert!(line(output, 4).contains(&tx));
    node.shutdown().unwrap();

    let input = format!(
        "{HANDSHAKE}{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{}{}{}",
        call(
            3,
            "frankengit_transaction_outcome",
            &format!("{{\"idempotency_key\":\"{KEY}\"}}")
        ),
        call(4, "frankengit_protection_set", &args),
        call(5, "frankengit_protection_show", "{}"),
    );
    let recovered = fixture.run("--allow-outcomes", true, &input);
    let output = stdout(&recovered);
    assert!(line(output, 2).contains("frankengit_transaction_outcome"));
    assert!(!line(output, 2).contains("frankengit_protection_set"));
    assert!(line(output, 3).contains(&tx));
    assert!(line(output, 3).contains("\"repository_changed\":false"));
    assert!(line(output, 4).contains("\"code\":-32602"));
    assert!(line(output, 5).contains("\"code\":-32602"));
    let node = fixture.open();
    let request = fgit_cli::command_request_context(&node);
    let after = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    assert_eq!(after.source_head, selected_head);
    assert_eq!(after.version().unwrap().get(), 1);
    node.shutdown().unwrap();
}
