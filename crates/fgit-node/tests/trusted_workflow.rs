#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Actual source import, native workflow compiler, trusted child processes,
//! descriptor-relative workspaces, durable local reports and reopened authority.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{NodeConfig, OneNode};
use fgit_runner::workflow::{JobOutcome, WorkflowLimits};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName,
    RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, node: Option<OneNode>, config: NodeConfig, tip: GitOid, workflow: GitOid }
impl Fixture {
    fn new(format: GitHashAlgorithm, workflow: &str) -> Self {
        // Create-new ownership, including stale directories from a reused PID.
        let root = loop {
            let path = std::env::temp_dir().join(format!("fg-workflow-node-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("fixture directory: {error}"),
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
        let workflow = if workflow.starts_with("name:") { workflow.to_owned() }
            else { format!("name: integration\n{workflow}") };
        let workflow = loose(&source, format, GitObjectKind::Blob, "blob", workflow.as_bytes());
        let input = loose(&source, format, GitObjectKind::Blob, "blob", b"original\n");
        let mut tree = Vec::new();
        for (name, oid) in [(b"input.txt".as_slice(), input), (b"workflow.yml".as_slice(), workflow)] {
            tree.extend_from_slice(b"100644 "); tree.extend_from_slice(name); tree.push(0); tree.extend_from_slice(oid.as_bytes());
        }
        let tree = loose(&source, format, GitObjectKind::Tree, "tree", &tree);
        let body = format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nworkflow input\n");
        let tip = loose(&source, format, GitObjectKind::Commit, "commit", body.as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(root.join("node"), TenantId::from_bytes([0x41; 16]), RepositoryId::from_bytes([0x42; 16]))
            .with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap(); serve(&mut node);
        let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(&node.request_context(),
            &source, PrincipalId::from_bytes([0x43; 16]), b"workflow-fixture")).unwrap();
        assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        Self { root, node: Some(node), config, tip, workflow }
    }
    fn node(&self) -> &OneNode { self.node.as_ref().unwrap() }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(self.config.clone()).unwrap(); serve(&mut node); self.node = Some(node);
    }
    fn parent(&self) -> PathBuf { self.root.join("runs") }
}
impl Drop for Fixture {
    fn drop(&mut self) { if let Some(node) = self.node.take() { let _ = node.shutdown(); } let _ = fs::remove_dir_all(&self.root); }
}
fn serve(node: &mut OneNode) {
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
}
fn generation(node: &OneNode) -> u64 { node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get() }
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn inputs() -> Vec<Vec<u8>> { vec![b"workflow.yml".to_vec(), b"input.txt".to_vec()] }
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, name: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string(); fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(root.join("objects").join(&text[..2]).join(&text[2..]), encoded).unwrap(); id
}

#[test]
fn one_source_snapshot_fresh_job_copies_and_persistent_report_in_both_formats() {
    let workflow = "name: isolated\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat input.txt)\" = original; printf changed > generated; printf first\n      - run: test \"$(cat generated)\" = changed; printf second\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: test ! -e generated; test \"$(cat input.txt)\" = original; printf dependent\n  c:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test ! -e generated; printf independent\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, workflow); let before = generation(f.node());
        let result = f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
            &reference(), b"workflow.yml", [1; 16], &f.parent(), &inputs(), (None, Some(f.tip)), Default::default())).unwrap();
        assert!(result.succeeded()); assert!(result.workspaces_closed);
        assert_eq!(result.source_commit, f.tip); assert_eq!(result.workflow_blob, f.workflow);
        assert_eq!(result.source_reference, reference().as_bytes());
        assert_eq!(result.read_prefixes, vec![b"input.txt".to_vec(), b"workflow.yml".to_vec()]);
        assert_eq!(result.execution.jobs.iter().map(|j| j.id.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(result.execution.jobs[0].steps[0].observation.stdout, b"first");
        assert_eq!(result.execution.jobs[0].steps[1].observation.stdout, b"second");
        assert_eq!(result.execution.jobs[1].steps[0].observation.stdout, b"dependent");
        assert_eq!(result.execution.jobs[2].steps[0].observation.stdout, b"independent");
        let json = result.to_json();
        assert_eq!(fs::read_to_string(result.run_directory.join("report.json")).unwrap(), json);
        assert!(json.contains("\"published\":false") && json.contains("\"authoritative_check\":false"));
        let mut names = fs::read_dir(&result.run_directory).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>(); names.sort();
        assert_eq!(names, [std::ffi::OsString::from("attempt.json"), std::ffi::OsString::from("report.json")]);
        assert_eq!(generation(f.node()), before);
        f.reopen(); assert_eq!(generation(f.node()), before);
        assert!(f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
            &reference(), b"workflow.yml", [1; 16], &f.parent(), &inputs(), (None, None), Default::default())).is_err());
        assert_eq!(fs::read_to_string(result.run_directory.join("report.json")).unwrap(), json);
    }
}

#[test]
fn failed_dependency_skips_only_dependents_and_closes_all_started_jobs() {
    let workflow = "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf failure; exit 7\n      - run: printf forbidden\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: printf forbidden\n  c:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf independent\n";
    let f = Fixture::new(GitHashAlgorithm::Sha1, workflow);
    let result = f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
        &reference(), b"workflow.yml", [2; 16], &f.parent(), &inputs(), (None, None), Default::default())).unwrap();
    assert!(!result.succeeded()); assert!(result.workspaces_closed);
    assert_eq!(result.execution.jobs.iter().map(|j| j.outcome).collect::<Vec<_>>(), [JobOutcome::Failed, JobOutcome::Skipped, JobOutcome::Succeeded]);
    assert_eq!(result.execution.jobs[0].steps.len(), 1); assert!(result.execution.jobs[1].steps.is_empty());
    assert_eq!(result.execution.jobs[2].steps[0].observation.stdout, b"independent");
    assert!(result.run_directory.join("report.json").is_file());
}

#[test]
fn entire_graph_scope_and_source_pins_are_preflighted_before_host_creation() {
    let invalid = "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf must-not-run\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: printf unsupported\n";
    let f = Fixture::new(GitHashAlgorithm::Sha1, invalid);
    assert!(f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
        &reference(), b"workflow.yml", [3; 16], &f.parent(), &inputs(), (None, None), Default::default())).is_err());
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    let valid = "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf allowed\n";
    let f = Fixture::new(GitHashAlgorithm::Sha256, valid);
    for (path, prefixes, expected) in [
        (b"workflow.yml".as_slice(), vec![b"input.txt".to_vec()], None),
        (b"../workflow.yml".as_slice(), inputs(), None),
        (b"workflow.yml".as_slice(), inputs(), Some(f.workflow)),
    ] {
        assert!(f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
            &reference(), path, [4; 16], &f.parent(), &prefixes, (None, expected), Default::default())).is_err());
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    }
}

#[test]
fn interrupted_attempt_is_never_adopted_or_overwritten() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf must-not-replay\n");
    let directory = f.parent().join(format!("workflow-{}", "05".repeat(16)));
    fs::create_dir(&directory).unwrap(); fs::write(directory.join("attempt.json"), b"interrupted responsibility").unwrap();
    assert!(f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
        &reference(), b"workflow.yml", [5; 16], &f.parent(), &inputs(), (None, None), Default::default())).is_err());
    assert_eq!(fs::read(directory.join("attempt.json")).unwrap(), b"interrupted responsibility");
    assert!(!directory.join("report.json").exists());
}

#[test]
fn timeout_retains_workspace_and_does_not_start_other_jobs() {
    // Shell builtins only: no escaped child remains after the direct shell is
    // killed. Production still conservatively records unproved containment.
    let f = Fixture::new(GitHashAlgorithm::Sha1, "on: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: while true; do true; done\n  b:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf must-not-run\n");
    let limits = WorkflowLimits { step_timeout: Duration::from_millis(50), run_timeout: Duration::from_secs(30), ..Default::default() };
    let before = generation(f.node());
    let result = f.node().runtime().block_on(f.node().run_trusted_workflow_in(&f.node().request_context(),
        &reference(), b"workflow.yml", [6; 16], &f.parent(), &inputs(), (None, None), limits)).unwrap();
    assert!(!result.succeeded()); assert!(!result.workspaces_closed);
    assert!(result.run_directory.join("job-000").is_dir());
    assert!(!result.run_directory.join("job-001").exists());
    assert!(result.execution.jobs[1].steps.is_empty());
    assert!(fs::read_to_string(result.run_directory.join("report.json")).unwrap().contains("\"workspaces_closed\":false"));
    assert_eq!(generation(f.node()), before);
}


#[test]
fn failure_and_always_diagnostics_execute_in_real_workspaces_and_persist_without_greenwashing() {
    let workflow = "on: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf primary; exit 9\n      - run: printf forbidden-success\n      - if: failure()\n        run: printf same-job-diagnostic\n      - if: always()\n        run: printf same-job-cleanup\n  postmortem:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: failure()\n    steps:\n      - run: printf dependent-diagnostic\n  cleanup:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: always()\n    steps:\n      - run: printf dependent-cleanup\n  success-only:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: printf forbidden-dependent\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format, workflow);
        let before = generation(f.node());
        let run = f.node().runtime().block_on(f.node().run_trusted_workflow_in(
            &f.node().request_context(), &reference(), b"workflow.yml", [7; 16],
            &f.parent(), &inputs(), (None, Some(f.tip)), Default::default()
        )).unwrap();
        assert!(!run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.execution.jobs.iter().map(|job| job.outcome).collect::<Vec<_>>(),
            [JobOutcome::Failed, JobOutcome::Succeeded, JobOutcome::Succeeded, JobOutcome::Skipped]);
        assert_eq!(run.execution.jobs[0].steps.len(), 3);
        assert_eq!(run.execution.jobs[0].steps[0].observation.stdout, b"primary");
        assert_eq!(run.execution.jobs[0].steps[1].observation.stdout, b"same-job-diagnostic");
        assert_eq!(run.execution.jobs[0].steps[2].observation.stdout, b"same-job-cleanup");
        assert_eq!(run.execution.jobs[1].steps[0].observation.stdout, b"dependent-cleanup");
        assert_eq!(run.execution.jobs[2].steps[0].observation.stdout, b"dependent-diagnostic");
        assert!(run.execution.jobs[3].steps.is_empty());
        let saved = fs::read_to_string(run.run_directory.join("report.json")).unwrap();
        assert_eq!(saved, run.to_json());
        assert!(saved.contains("\"succeeded\":false"));
        assert!(saved.contains("\"authoritative_check\":false"));
        assert_eq!(generation(f.node()), before);
    }
}

#[test]
fn always_condition_cannot_escape_timeout_containment_in_real_process_execution() {
    let workflow = "on: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: while true; do true; done\n      - if: always()\n        run: printf forbidden-after-timeout\n  cleanup:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: always()\n    steps:\n      - run: printf forbidden-dependent-cleanup\n";
    let f = Fixture::new(GitHashAlgorithm::Sha1, workflow);
    let limits = WorkflowLimits {
        step_timeout: Duration::from_millis(50),
        run_timeout: Duration::from_secs(30),
        ..Default::default()
    };
    let run = f.node().runtime().block_on(f.node().run_trusted_workflow_in(
        &f.node().request_context(), &reference(), b"workflow.yml", [8; 16],
        &f.parent(), &inputs(), (None, None), limits
    )).unwrap();
    assert!(!run.succeeded());
    assert!(!run.workspaces_closed);
    assert_eq!(run.execution.jobs[0].steps.len(), 1);
    assert!(run.execution.jobs[1].steps.is_empty());
    assert!(!run.run_directory.join("job-001").exists());
    assert_eq!(fs::read_to_string(run.run_directory.join("report.json")).unwrap(), run.to_json());
}
