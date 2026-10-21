#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Native canonical ref changes -> real compiler/processes -> durable event custody.
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    config: NodeConfig,
    node: Option<OneNode>,
    tip: GitOid,
    tree: GitOid,
}
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn loose(root: &Path, fmt: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(fmt, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let n = u16::try_from(raw.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes());
    bytes.extend((!n).to_le_bytes());
    bytes.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), x| {
        let a = (a + u32::from(*x)) % 65521;
        (a, (b + a) % 65521)
    });
    bytes.extend(((b << 16) | a).to_be_bytes());
    let text = oid.to_string();
    fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(
        root.join("objects").join(&text[..2]).join(&text[2..]),
        bytes,
    )
    .unwrap();
    oid
}
impl Fixture {
    fn new(fmt: GitHashAlgorithm, event: &str, tail: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-ref-watch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("runs")).unwrap();
        fs::set_permissions(root.join("runs"), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"),match fmt { GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion=0\nbare=true\n",GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion=1\nbare=true\n[extensions]\nobjectformat=sha256\n" }).unwrap();
        let workflow = format!(
            "name: native-watch\non: {event}\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x >> '{}'; {tail}\n",
            root.join("effects").display()
        );
        let blob = loose(&source, fmt, GitObjectKind::Blob, workflow.as_bytes());
        let directory = loose(
            &source,
            fmt,
            GitObjectKind::Tree,
            &[b"100644 build.yml\0".as_slice(), blob.as_bytes()].concat(),
        );
        let tree = loose(
            &source,
            fmt,
            GitObjectKind::Tree,
            &[b"40000 ci\0".as_slice(), directory.as_bytes()].concat(),
        );
        let tip=loose(&source,fmt,GitObjectKind::Commit,format!("tree {tree}\nauthor Fixture <x@example.invalid> 1 +0000\ncommitter Fixture <x@example.invalid> 1 +0000\n\nbase\n").as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        )
        .with_object_format(fmt)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        serve(&mut node);
        let fixture = Self {
            root,
            config,
            node: Some(node),
            tip,
            tree,
        };
        fixture.import(b"initial");
        fixture
    }
    fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    fn parent(&self) -> PathBuf {
        self.root.join("runs")
    }
    fn count(&self) -> String {
        fs::read_to_string(self.root.join("effects")).unwrap_or_default()
    }
    fn import(&self, key: &[u8]) {
        let n = self.node();
        let request = n.command_request_context(None);
        let result = n
            .runtime()
            .block_on(n.import_loose_git_directory_durable_in(
                &request,
                &self.root.join("source"),
                PrincipalId::from_bytes([0xb3; 16]),
                key,
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })),
            "{result:?}"
        );
    }
    fn update_ref(&self, name: RefName, old: ExpectedOld, new: GitOid, key: &[u8]) {
        let n = self.node();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xb3; 16]),
            IdempotencyKey::new(key.to_vec()).unwrap(),
        );
        let command = RefCommand {
            name,
            expected_old: old,
            proposed_new: ProposedNew::Update(new),
            force: false,
        };
        let result = n
            .runtime()
            .block_on(n.admit_branch_updates_durable_in(
                &n.command_request_context(None),
                &session,
                &[command],
                Default::default(),
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })),
            "{result:?}"
        );
    }
    fn advance(&mut self) {
        let old = self.tip;
        self.tip=loose(&self.root.join("source"),old.algorithm(),GitObjectKind::Commit,
            format!("tree {}\nparent {old}\nauthor Fixture <x@example.invalid> 2 +0000\ncommitter Fixture <x@example.invalid> 2 +0000\n\nnext\n",self.tree).as_bytes());
        for entry in fs::read_dir(self.root.join("source/refs/heads")).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let branch = format!("future-{}", self.tip);
        fs::write(
            self.root.join("source/HEAD"),
            format!("ref: refs/heads/{branch}\n"),
        )
        .unwrap();
        fs::write(
            self.root.join("source/refs/heads").join(&branch),
            format!("{}\n", self.tip),
        )
        .unwrap();
        self.import(self.tip.as_bytes());
        self.update_ref(
            reference(),
            ExpectedOld::Exactly(old),
            self.tip,
            format!("advance-{}", self.tip).as_bytes(),
        );
    }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut n = OneNode::open_existing(self.config.clone()).unwrap();
        serve(&mut n);
        self.node = Some(n);
    }
    fn watch_root(&self) -> PathBuf {
        fs::read_dir(self.parent())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(n) = self.node.take() {
            n.shutdown().unwrap();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn serve(n: &mut OneNode) {
    let h = n
        .runtime()
        .block_on(n.authenticate_authority_head())
        .unwrap();
    n.bring_into_service(h.receipt().generation()).unwrap();
}
macro_rules! poll {
    ($f:expr) => {{
        let n = $f.node();
        n.runtime().block_on(n.poll_trusted_ref_workflows_in(
            &n.command_request_context(None),
            &reference(),
            b"ci",
            &$f.parent(),
            &[b"ci".to_vec()],
            WorkflowLimits::default(),
            None,
        ))
    }};
}

#[test]
fn canonical_ref_updates_execute_once_and_unrelated_head_changes_do_not_retrigger() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(fmt, "push", "true");
        let first = poll!(f).unwrap();
        assert_eq!(first.state(), "dispatched");
        assert!(first.dispatch().unwrap().succeeded());
        assert_eq!(f.count(), "x");
        let event = first.to_json();
        assert!(event.contains(&f.tip.to_string()));
        f.reopen();
        assert_eq!(poll!(f).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "x");
        f.update_ref(
            RefName::try_new(b"refs/heads/other").unwrap(),
            ExpectedOld::Absent,
            f.tip,
            b"unrelated-ref",
        );
        assert_eq!(poll!(f).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "x");
        f.advance();
        let second = poll!(f).unwrap();
        assert_eq!(second.state(), "dispatched");
        assert_eq!(second.dispatch().unwrap().runs()[0].source_commit, f.tip);
        assert_eq!(f.count(), "xx");
        f.reopen();
        assert_eq!(poll!(f).unwrap().state(), "previously_settled");
        assert_eq!(f.count(), "xx");
    }
}
#[test]
fn interrupted_execution_blocks_new_ref_events_even_after_restart() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256, "push", "sleep 30");
    let n = f.node();
    let limits = WorkflowLimits {
        step_timeout: Duration::from_millis(100),
        run_timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let result = n
        .runtime()
        .block_on(n.poll_trusted_ref_workflows_in(
            &n.command_request_context(None),
            &reference(),
            b"ci",
            &f.parent(),
            &[b"ci".to_vec()],
            limits,
            None,
        ))
        .unwrap();
    assert!(result.requires_reconciliation());
    assert_eq!(f.count(), "x");
    f.advance();
    f.reopen();
    let stopped = poll!(f).unwrap();
    assert_eq!(stopped.state(), "blocked_unresolved");
    assert!(stopped.requires_reconciliation());
    assert_eq!(f.count(), "x");
}
#[test]
fn no_matching_definitions_is_a_zero_run_not_a_passing_check() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "workflow_dispatch", "true");
    let p = poll!(f).unwrap();
    assert!(p.dispatch().unwrap().runs().is_empty());
    assert_eq!(f.count(), "");
    assert_eq!(poll!(f).unwrap().state(), "previously_settled");
}
#[test]
fn owner_contention_and_corrupt_settlement_refuse_beside_valid_recovery() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    poll!(f).unwrap();
    let root = f.watch_root();
    let owner = fs::OpenOptions::new()
        .write(true)
        .open(root.join("owner.lock"))
        .unwrap();
    owner.try_lock().unwrap();
    assert!(
        poll!(f)
            .unwrap_err()
            .to_string()
            .contains("another workflow watcher")
    );
    owner.unlock().unwrap();
    assert_eq!(poll!(f).unwrap().state(), "previously_settled");
    let dir = fs::read_dir(&root)
        .unwrap()
        .map(|x| x.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    let marker = dir.join("settled");
    let original = fs::read(&marker).unwrap();
    fs::write(&marker, [b'f'; 64]).unwrap();
    assert!(
        poll!(f)
            .unwrap_err()
            .to_string()
            .contains("identity mismatch")
    );
    fs::write(&marker, original).unwrap();
    assert_eq!(poll!(f).unwrap().state(), "previously_settled");
    assert_eq!(f.count(), "x");
}
#[test]
fn cancellation_and_invalid_names_do_not_create_execution_custody() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let n = f.node();
    let request = n.command_request_context(None);
    request.cancel();
    assert!(
        n.runtime()
            .block_on(n.poll_trusted_ref_workflows_in(
                &request,
                &reference(),
                b"ci",
                &f.parent(),
                &[b"ci".to_vec()],
                Default::default(),
                None
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
    assert!(
        n.runtime()
            .block_on(n.poll_trusted_ref_workflows_in(
                &n.command_request_context(None),
                &RefName::try_new(b"refs/tags/v1").unwrap(),
                b"ci",
                &f.parent(),
                &[b"ci".to_vec()],
                Default::default(),
                None
            ))
            .is_err()
    );
    assert_eq!(f.count(), "");
    assert_eq!(poll!(f).unwrap().state(), "dispatched");
}

#[path = "trusted_ref_workflow/check_reporting.rs"]
mod check_reporting;

#[path = "trusted_ref_workflow/pull_requests.rs"]
mod pull_requests;

#[test]
fn branch_filters_execute_matching_pushes_once_and_retain_exact_selection() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (on, execute) in [
            ("\n  push:\n    branches:\n      - 'ma*'", true),
            ("\n  push:\n    branches:\n      - 'topic/**'", false),
            (
                "\n  push:\n    branches:\n      - '**'\n      - '!main'",
                false,
            ),
            (
                "\n  push:\n    branches:\n      - '**'\n      - '!main'\n      - main",
                true,
            ),
            ("\n  push:\n    branches-ignore:\n      - main", false),
            (
                "\n  push:\n    branches-ignore:\n      - 'archive/**'",
                true,
            ),
        ] {
            let mut f = Fixture::new(fmt, on, "true");
            let first = poll!(f).unwrap();
            assert_eq!(first.dispatch().unwrap().runs().len(), usize::from(execute));
            assert_eq!(f.count(), if execute { "x" } else { "" });
            assert!(
                first
                    .dispatch()
                    .unwrap()
                    .to_json()
                    .contains("\"trigger_ref_hex\":\"726566732f68656164732f6d61696e\"")
            );
            f.reopen();
            assert_eq!(poll!(f).unwrap().state(), "previously_settled");
            assert_eq!(f.count(), if execute { "x" } else { "" });
        }
    }
}
#[test]
fn filtered_pr_dispatch_without_canonical_target_refuses_before_batch_or_script() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(
            fmt,
            "\n  pull_request:\n    branches:\n      - main",
            "true",
        );
        let n = f.node();
        let request = n.command_request_context(None);
        let state = n
            .runtime()
            .block_on(n.materialize_admission_in(&request))
            .unwrap();
        let result = n.runtime().block_on(n.dispatch_trusted_workflows_in(
            &request,
            &reference(),
            b"ci",
            "pull_request",
            [0x72; 16],
            &f.parent(),
            &[b"ci".to_vec()],
            (state.basis().id(), f.tip),
            WorkflowLimits::default(),
        ));
        assert!(result.unwrap_err().to_string().contains("canonical target"));
        assert_eq!(f.count(), "");
        assert_eq!(fs::read_dir(f.parent()).unwrap().count(), 0);
        // Near-identical unfiltered PR declarations retain explicit dispatch.
        let g = Fixture::new(fmt, "pull_request", "true");
        let n = g.node();
        let request = n.command_request_context(None);
        let state = n
            .runtime()
            .block_on(n.materialize_admission_in(&request))
            .unwrap();
        let report = n
            .runtime()
            .block_on(n.dispatch_trusted_workflows_in(
                &request,
                &reference(),
                b"ci",
                "pull_request",
                [0x73; 16],
                &g.parent(),
                &[b"ci".to_vec()],
                (state.basis().id(), g.tip),
                WorkflowLimits::default(),
            ))
            .unwrap();
        assert!(report.succeeded());
        assert_eq!(g.count(), "x");
    }
}
