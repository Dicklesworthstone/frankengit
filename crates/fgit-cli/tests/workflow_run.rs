#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Exercise the actual fg binary, not just the argument parser or a fake runner.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: TenantId = TenantId::from_bytes([0x51; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x52; 16]);
struct Fixture {
    root: PathBuf,
    config: NodeConfig,
    tip: GitOid,
    format: GitHashAlgorithm,
    generation: u64,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, fail: bool) -> Self {
        let root = loop {
            let path = std::env::temp_dir().join(format!(
                "fg-workflow-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create fixture: {e}"),
            }
        };
        fs::create_dir(root.join("runs")).unwrap();
        fs::set_permissions(root.join("runs"), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let run = if fail {
            "printf workflow-failed; exit 7"
        } else {
            "printf workflow-ok"
        };
        let workflow = format!(
            "name: cli\non: push\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {run}\n"
        );
        let workflow = loose(
            &source,
            format,
            GitObjectKind::Blob,
            "blob",
            workflow.as_bytes(),
        );
        let tree = loose(
            &source,
            format,
            GitObjectKind::Tree,
            "tree",
            &[b"100644 workflow.yml\0".as_slice(), workflow.as_bytes()].concat(),
        );
        let body = format!(
            "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nworkflow\n"
        );
        let tip = loose(
            &source,
            format,
            GitObjectKind::Commit,
            "commit",
            body.as_bytes(),
        );
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(root.join("node"), TENANT, REPOSITORY)
            .with_object_format(format)
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(head.receipt().generation())
            .unwrap();
        let result = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &source,
                PrincipalId::from_bytes([0x53; 16]),
                b"cli-workflow-source",
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let generation = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation()
            .get();
        node.shutdown().unwrap();
        Self {
            root,
            config,
            tip,
            format,
            generation,
        }
    }
    fn command(&self, trusted: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fg"));
        command
            .args(["workflow", "run"])
            .arg(self.root.join("node"))
            .arg(TENANT.to_string())
            .arg(REPOSITORY.to_string())
            .arg("refs/heads/main")
            .args([
                "--workflow",
                "workflow.yml",
                "--input",
                "workflow.yml",
                "--run-id",
            ])
            .arg("61".repeat(16))
            .arg("--run-parent")
            .arg(self.root.join("runs"))
            .args(["--object-format", self.format.as_str(), "--expected-commit"])
            .arg(self.tip.to_string());
        if trusted {
            command.arg("--trusted-local");
        }
        command
    }
    fn assert_unchanged(&self) {
        let node = OneNode::open_existing(self.config.clone()).unwrap();
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head())
                .unwrap()
                .receipt()
                .generation()
                .get(),
            self.generation
        );
        node.shutdown().unwrap();
    }
    fn report(&self) -> PathBuf {
        self.root
            .join("runs")
            .join(format!("workflow-{}", "61".repeat(16)))
            .join("report.json")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    name: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let len = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(len.to_le_bytes());
    encoded.extend((!len).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    fs::create_dir_all(root.join("objects").join(&hex[..2])).unwrap();
    fs::write(
        root.join("objects").join(&hex[..2]).join(&hex[2..]),
        encoded,
    )
    .unwrap();
    id
}
fn exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn binary_executes_exact_source_persists_receipt_and_refuses_replay_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, false);
        let output = fixture.command(true).output().unwrap();
        exit(&output, 0);
        let response = String::from_utf8(output.stdout).unwrap();
        assert!(response.starts_with("{\"type\":\"workflow_result\""));
        assert_eq!(response.lines().count(), 1);
        assert!(response.contains("\"node_closed\":true"));
        assert!(response.contains("\"stdout_hex\":\"776f726b666c6f772d6f6b\""));
        assert!(response.contains(&format!("\"source_commit\":\"{}\"", fixture.tip)));
        let saved = fs::read_to_string(fixture.report()).unwrap();
        assert!(saved.contains("\"succeeded\":true"));
        assert!(saved.contains("\"authoritative_check\":false"));
        assert!(response.contains(&format!("\"run\":{saved}")));
        fixture.assert_unchanged();
        let retry = fixture.command(true).output().unwrap();
        exit(&retry, 2);
        assert!(retry.stdout.is_empty());
        assert_eq!(fs::read_to_string(fixture.report()).unwrap(), saved);
        fixture.assert_unchanged();
    }
}

#[test]
fn binary_requires_trust_and_reports_failed_commands_without_publication() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, true);
    let refused = fixture.command(false).output().unwrap();
    exit(&refused, 2);
    assert_eq!(fs::read_dir(fixture.root.join("runs")).unwrap().count(), 0);
    let output = fixture.command(true).output().unwrap();
    exit(&output, 1);
    let response = String::from_utf8(output.stdout).unwrap();
    assert!(response.contains("\"node_closed\":true"));
    assert!(response.contains("\"succeeded\":false"));
    assert!(response.contains("\"exit_code\":7"));
    assert!(response.contains("\"published\":false"));
    assert!(fixture.report().is_file());
    fixture.assert_unchanged();
}
