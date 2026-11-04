//! Actual canonical agent reads and native durable maintenance share one MCP
//! process lifetime. Explicit operator launch config never becomes a tool grant.
#![cfg(unix)]
use super::*;
use crate::mcp::protocol;
use fgit_node::index_maintenance::{IndexKind, MaintenanceConfig, MaintenanceGroup};
use std::io::{self, Cursor, Write};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"maintained-source","version":"1"}}}"#;

fn group(fixture: &SourceFixture, initialize: bool) -> MaintenanceGroup {
    MaintenanceGroup::try_new(
        [
            ("lexical", IndexKind::Lexical),
            ("symbols", IndexKind::Symbols),
        ]
        .into_iter()
        .map(|(name, kind)| {
            let path = fixture.fixture.root.join(name);
            if initialize {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            MaintenanceConfig::try_new(
                kind,
                fixture.options.format,
                path,
                initialize,
                Duration::from_secs(1),
                vec![RefName::try_new(REFERENCE.as_bytes()).unwrap()],
            )
            .unwrap()
        })
        .collect(),
    )
    .unwrap()
}
fn start(backend: &mut NodeTools) {
    let mut output = Vec::new();
    protocol::serve(
        &mut Cursor::new(format!("{INIT}\n")),
        &mut output,
        backend,
        1,
    )
    .unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("protocolVersion")
    );
}
fn head(backend: &NodeTools) -> Vec<u8> {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .body()
        .to_vec()
}
fn required_context() -> Object {
    let mut args = query(CONTEXT);
    args.insert("symbol_name_hex".into(), text(hex(b"Thing")));
    args.insert("symbol_policy".into(), text("required"));
    args
}
fn wait_context(backend: &mut NodeTools, request: &Object, credential: AgentCredentialId) -> Value {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        match backend.call(CONTEXT, request) {
            Ok(value) => {
                assert_sponsorship(&value, credential);
                return value;
            }
            Err(error) => {
                assert!(
                    !error.invalid
                        && matches!(
                            error.code,
                            "source_index_uninitialized"
                                | "source_index_stale"
                                | "symbol_index_uninitialized"
                                | "symbol_index_stale"
                                | "index_checkpoint_unavailable"
                                | "index_generation_mismatch"
                                | "unavailable"
                                | "source_snapshot_mismatch"
                        ),
                    "{}",
                    error.code
                );
                assert!(
                    Instant::now() < until,
                    "maintained source did not become readable: {}",
                    error.code
                );
                backend.node.runtime().wait_for(Duration::from_millis(25));
            }
        }
    }
}
fn checkpoints(fixture: &SourceFixture) -> Vec<Vec<u8>> {
    ["lexical", "symbols"]
        .iter()
        .map(|name| fs::read(fixture.fixture.root.join(name).join("checkpoint")).unwrap())
        .collect()
}
fn assert_released(fixture: &SourceFixture) {
    for name in ["lexical", "symbols"] {
        assert!(!fixture.fixture.root.join(name).join("run.lock").exists());
    }
}
fn add_source(backend: &NodeTools, base: GitOid) -> GitOid {
    let reference = RefName::try_new(REFERENCE.as_bytes()).unwrap();
    let patch = b"diff --git a/src/maintained.rs b/src/maintained.rs\nnew file mode 100644\n--- /dev/null\n+++ b/src/maintained.rs\n@@ -0,0 +1 @@\n+pub fn ThingMaintained() { Thing(); }\n";
    let request = backend.node.command_request_context(None);
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 5,
        message: b"native maintained source\n".to_vec(),
    };
    let prepared = backend
        .node
        .runtime()
        .block_on(backend.node.prepare_trusted_patch_in(
            &request,
            &reference,
            base,
            [0xe1; 16],
            patch,
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let result = backend
        .node
        .runtime()
        .block_on(backend.node.apply_workspace_bundle_durable_in(
            &request,
            SPONSOR,
            b"maintained-source-publish",
            &reference,
            base,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    prepared.candidate_commit
}

#[test]
fn sponsored_mcp_maintains_both_indexes_across_native_code_changes_and_clean_resume() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = SourceFixture::new(format, false);
        let mut options = fixture.options.clone();
        options.index_maintenance = Some(group(&fixture, true));
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let before = head(&backend);
        // Owning progress alone does not authorize the first build.
        assert_eq!(
            backend.call(CONTEXT, &required_context()).unwrap_err().code,
            "source_index_uninitialized"
        );
        start(&mut backend);
        let original = wait_context(&mut backend, &required_context(), fixture.credential_id);
        assert_eq!(
            head(&backend),
            before,
            "derived maintenance changed repository authority"
        );
        let original_generations: Vec<_> = ["lexical_generation", "symbol_generation"]
            .iter()
            .map(|name| field(&original, &["retrieval_evidence", name]).clone())
            .collect();
        let next = add_source(&backend, fixture.tip);
        let published = head(&backend);
        assert_ne!(published, before);
        let mut pinned_old = required_context();
        pinned_old.insert(
            "expected_head".into(),
            field(&original, &["retrieval_evidence", "source", "head"]).clone(),
        );
        assert_eq!(
            backend.call(CONTEXT, &pinned_old).unwrap_err().code,
            "source_snapshot_moved"
        );
        let request = required_context();
        let current = wait_context(&mut backend, &request, fixture.credential_id);
        for (index, name) in ["lexical_generation", "symbol_generation"]
            .iter()
            .enumerate()
        {
            assert_ne!(
                field(&current, &["retrieval_evidence", name]),
                &original_generations[index]
            );
        }
        assert_eq!(
            field(&current, &["retrieval_evidence", "source", "commit"]),
            &text(next.to_string())
        );
        assert_eq!(head(&backend), published);
        // Real EOF follows the same cleanup composition as the production run.
        protocol::serve(
            &mut Cursor::new(Vec::<u8>::new()),
            &mut Vec::new(),
            &mut backend,
            1,
        )
        .unwrap();
        backend.close().unwrap();
        assert_released(&fixture);
        let before_resume = checkpoints(&fixture);
        options.index_maintenance = Some(group(&fixture, false));
        let mut resumed = NodeTools::open(options).unwrap();
        assert_eq!(checkpoints(&fixture), before_resume);
        start(&mut resumed);
        let restored = wait_context(&mut resumed, &request, fixture.credential_id);
        assert_eq!(
            field(&restored, &["retrieval_evidence", "source", "commit"]),
            &text(next.to_string())
        );
        assert_eq!(head(&resumed), published);
        resumed.close().unwrap();
        assert_released(&fixture);
    }
}

struct BrokenOutput {
    flush_only: bool,
}
impl Write for BrokenOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.flush_only {
            Ok(bytes.len())
        } else {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}
#[test]
fn initial_eof_and_output_faults_drain_both_owners_without_building_indexes() {
    for failure in ["eof", "write", "flush", "framing"] {
        let fixture = SourceFixture::new(GitHashAlgorithm::Sha256, false);
        let mut options = fixture.options.clone();
        options.index_maintenance = Some(group(&fixture, true));
        let mut backend = NodeTools::open(options).unwrap();
        let original = checkpoints(&fixture);
        let before = head(&backend);
        match failure {
            "eof" => protocol::serve(
                &mut Cursor::new(Vec::<u8>::new()),
                &mut Vec::new(),
                &mut backend,
                2,
            )
            .unwrap(),
            "framing" => assert!(
                protocol::serve(&mut Cursor::new(INIT), &mut Vec::new(), &mut backend, 2)
                    .unwrap_err()
                    .contains("framing bound")
            ),
            _ => assert!(
                protocol::serve(
                    &mut Cursor::new(format!("{INIT}\n")),
                    &mut BrokenOutput {
                        flush_only: failure == "flush"
                    },
                    &mut backend,
                    2
                )
                .unwrap_err()
                .contains("output failed")
            ),
        }
        assert_eq!(head(&backend), before);
        backend.close().unwrap();
        assert_released(&fixture);
        assert_eq!(checkpoints(&fixture), original);
        let mut reader = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(
            reader.call(CONTEXT, &required_context()).unwrap_err().code,
            "source_index_uninitialized"
        );
        reader.close().unwrap();
    }
}

#[test]
fn owner_failure_retires_agent_dispatch_and_maintenance_does_not_grant_source_scope() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha1, false);
    let mut options = fixture.options.clone();
    options.agent_token_file = fixture.fixture.replacement(0x42).agent_token_file;
    options.index_maintenance = Some(group(&fixture, true));
    let mut backend = NodeTools::open(options).unwrap();
    start(&mut backend);
    assert_eq!(
        backend.call(CONTEXT, &required_context()).unwrap_err().code,
        "agent_operation_not_granted"
    );
    fs::write(fixture.fixture.root.join("lexical/stop"), b"").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    while ["lexical", "symbols"]
        .iter()
        .any(|name| fixture.fixture.root.join(name).join("run.lock").exists())
    {
        assert!(Instant::now() < until, "group failed to stop");
        backend.node.runtime().wait_for(Duration::from_millis(10));
    }
    while !backend.maintenance.as_ref().unwrap().finished() {
        assert!(
            Instant::now() < until,
            "group release did not reach terminal observation"
        );
        backend.node.runtime().wait_for(Duration::from_millis(1));
    }
    assert_eq!(
        backend.call(CONTEXT, &required_context()).unwrap_err().code,
        "index_maintenance_stopped"
    );
    assert!(
        protocol::serve(
            &mut Cursor::new(format!("{INIT}\n")),
            &mut Vec::new(),
            &mut backend,
            2
        )
        .unwrap_err()
        .contains("background service stopped")
    );
    backend.close().unwrap();
    assert_released(&fixture);
}

struct BreakAfterInitialization {
    flushed: bool,
}
impl Write for BreakAfterInitialization {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.flushed {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushed = true;
        Ok(())
    }
}

#[test]
fn an_output_failure_after_activation_drains_original_attempts_and_allows_clean_resume() {
    let fixture = SourceFixture::new(GitHashAlgorithm::Sha1, false);
    let mut options = fixture.options.clone();
    options.index_maintenance = Some(group(&fixture, true));
    let mut backend = NodeTools::open(options.clone()).unwrap();
    let before = head(&backend);
    let input = format!(
        "{INIT}\n{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n"
    );
    let mut output = BreakAfterInitialization { flushed: false };
    let error = protocol::serve(&mut Cursor::new(input), &mut output, &mut backend, 3).unwrap_err();
    assert!(error.contains("output failed"));
    assert!(output.flushed);
    backend.close().unwrap();
    assert_released(&fixture);
    options.index_maintenance = Some(group(&fixture, false));
    let mut resumed = NodeTools::open(options).unwrap();
    assert_eq!(head(&resumed), before);
    start(&mut resumed);
    wait_context(&mut resumed, &required_context(), fixture.credential_id);
    assert_eq!(head(&resumed), before);
    resumed.close().unwrap();
    assert_released(&fixture);
}
