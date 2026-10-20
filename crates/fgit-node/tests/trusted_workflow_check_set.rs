#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real saved jobs -> snapshot preflight -> canonical checks -> restart recovery.
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{Digest, GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode, RepositoryId,
    TenantId,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn branch() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn publisher() -> PrincipalId {
    PrincipalId::from_bytes([0xc3; 16])
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
    let hex = oid.to_string();
    fs::create_dir_all(root.join("objects").join(&hex[..2])).unwrap();
    fs::write(root.join("objects").join(&hex[..2]).join(&hex[2..]), bytes).unwrap();
    oid
}
struct Fixture {
    root: PathBuf,
    config: NodeConfig,
    node: Option<OneNode>,
    directory: PathBuf,
    journal: Digest,
    pin: (u64, Digest),
    tip: GitOid,
    tree: GitOid,
}
impl Fixture {
    fn new(fmt: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-check-set-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            source.join("config"),
            if fmt == GitHashAlgorithm::Sha1 {
                "[core]\nrepositoryformatversion=0\nbare=true\n"
            } else {
                "[core]\nrepositoryformatversion=1\nbare=true\n[extensions]\nobjectformat=sha256\n"
            },
        )
        .unwrap();
        let workflow = format!(
            "name: check-set\non: push\njobs:\n  a_success:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x >> '{}'; printf ok\n  b_failure:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exit 7\n  c_skipped:\n    needs: b_failure\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exit 99\n",
            root.join("effect").display()
        );
        let blob = loose(&source, fmt, GitObjectKind::Blob, workflow.as_bytes());
        let tree = loose(
            &source,
            fmt,
            GitObjectKind::Tree,
            &[b"100644 workflow.yml\0".as_slice(), blob.as_bytes()].concat(),
        );
        let tip=loose(&source,fmt,GitObjectKind::Commit,format!("tree {tree}\nauthor Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\nbase\n").as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
        )
        .with_object_format(fmt)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        serve(&mut node);
        let request = node.command_request_context(None);
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                publisher(),
                b"source",
            ))
            .unwrap();
        assert!(
            imported
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let run = node
            .runtime()
            .block_on(node.run_trusted_workflow_in(
                &request,
                &branch(),
                b"workflow.yml",
                [0xc4; 16],
                &root,
                &[b"workflow.yml".to_vec()],
                (None, Some(tip)),
                Default::default(),
            ))
            .unwrap();
        assert!(!run.succeeded());
        assert!(run.workspaces_closed);
        assert_eq!(run.execution.jobs.len(), 3);
        let journal = run.check_journal_scope().journal_id.digest();
        let saved = run.open_check_journal(None, &|| true).unwrap();
        let pin = (saved.pin().byte_len(), saved.pin().tail().digest());
        drop(saved);
        Self {
            root,
            config,
            node: Some(node),
            directory: run.run_directory,
            journal,
            pin,
            tip,
            tree,
        }
    }
    fn n(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut n = OneNode::open_existing(self.config.clone()).unwrap();
        serve(&mut n);
        self.node = Some(n);
    }
    fn head(&self) -> fgit_types::RepositoryAuthorityHeadId {
        self.n()
            .runtime()
            .block_on(
                self.n()
                    .materialize_admission_in(&self.n().command_request_context(None)),
            )
            .unwrap()
            .basis()
            .id()
    }
    fn advance(&self) {
        let source = self.root.join("source");
        let fmt = self.tip.algorithm();
        let tip=loose(&source,fmt,GitObjectKind::Commit,format!("tree {}\nparent {}\nauthor Fixture <test@example.invalid> 2 +0000\ncommitter Fixture <test@example.invalid> 2 +0000\n\nnext\n",self.tree,self.tip).as_bytes());
        fs::remove_file(source.join("refs/heads/main")).unwrap();
        fs::write(source.join("refs/heads/next"), format!("{tip}\n")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/next\n").unwrap();
        let n = self.n();
        let request = n.command_request_context(None);
        let imported = n
            .runtime()
            .block_on(n.import_loose_git_directory_durable_in(
                &request,
                &source,
                publisher(),
                b"advance-import",
            ))
            .unwrap();
        assert!(
            imported
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let session = LoopbackReceiveSession::authenticated(
            publisher(),
            IdempotencyKey::new(b"advance-main".to_vec()).unwrap(),
        );
        let update = n
            .runtime()
            .block_on(n.admit_branch_updates_durable_in(
                &request,
                &session,
                &[RefCommand {
                    name: branch(),
                    expected_old: ExpectedOld::Exactly(self.tip),
                    proposed_new: ProposedNew::Update(tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(
            update
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
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
macro_rules! prepare {
    ($f:expr) => {
        $f.n().prepare_trusted_workflow_check_set(
            &$f.n().command_request_context(None),
            &$f.directory,
            $f.journal,
            $f.pin,
            publisher(),
            branch(),
            (128, 16 * 1024 * 1024),
        )
    };
}

#[test]
fn all_jobs_preflight_and_partial_publication_restarts_with_original_decisions() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(fmt);
        let head = f.head();
        let bytes = fs::read(f.directory.join("check-proposals.journal")).unwrap();
        let plan = prepare!(f).unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(f.head(), head);
        assert!(plan.to_json().contains("\"conclusion\":\"success\""));
        assert!(plan.to_json().contains("\"conclusion\":\"failure\""));
        assert!(
            plan.to_json()
                .contains("\"conclusion\":\"action_required\"")
        );
        let partial = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &plan,
                |_| Err("lost receipt".into()),
            ));
        assert_eq!(partial.decisions.len(), 1);
        assert!(partial.error.as_ref().unwrap().contains("lost receipt"));
        assert!(!partial.all_committed());
        assert!(matches!(
            partial.decisions[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        f.reopen();
        fs::remove_file(f.directory.join("report.json")).unwrap();
        let recovered = prepare!(f).unwrap();
        assert_eq!(recovered.identity(), plan.identity());
        assert_eq!(recovered.to_json(), plan.to_json());
        let result = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &recovered,
                |_| Ok(()),
            ));
        assert_eq!(result.decisions.len(), 3);
        assert!(result.all_committed(), "{result:?}");
        assert_eq!(result.decisions[0].tx_id, partial.decisions[0].tx_id);
        assert_eq!(result.decisions[0].terminal, partial.decisions[0].terminal);
        let final_head = f.head();
        let again = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &recovered,
                |_| Ok(()),
            ));
        assert!(again.all_committed());
        assert_eq!(f.head(), final_head);
        for (old, new) in result.decisions.iter().zip(&again.decisions) {
            assert_eq!(old.tx_id, new.tx_id);
            assert_eq!(old.terminal, new.terminal);
        }
        assert_eq!(
            fs::read(f.directory.join("check-proposals.journal")).unwrap(),
            bytes
        );
        assert_eq!(fs::read_to_string(f.root.join("effect")).unwrap(), "x");
    }
}

#[test]
fn preflight_rejects_bad_scope_pin_limits_and_corruption_without_publishing() {
    let f = Fixture::new(GitHashAlgorithm::Sha256);
    let n = f.n();
    let head = f.head();
    for limits in [
        (0, 1024),
        (129, 1024),
        (128, 0),
        (2, 16 * 1024 * 1024),
        (128, 1),
        (128, 16 * 1024 * 1024 + 1),
    ] {
        assert!(
            n.prepare_trusted_workflow_check_set(
                &n.command_request_context(None),
                &f.directory,
                f.journal,
                f.pin,
                publisher(),
                branch(),
                limits
            )
            .is_err(),
            "{limits:?}"
        );
        assert_eq!(f.head(), head);
    }
    let wrong = fgit_runner::Commitment::of_bytes(b"wrong").digest();
    for (journal, pin) in [
        (wrong, f.pin),
        (f.journal, (f.pin.0, wrong)),
        (f.journal, (71, f.pin.1)),
    ] {
        assert!(
            n.prepare_trusted_workflow_check_set(
                &n.command_request_context(None),
                &f.directory,
                journal,
                pin,
                publisher(),
                branch(),
                (128, 16 * 1024 * 1024)
            )
            .is_err()
        );
    }
    let request = n.command_request_context(None);
    request.cancel();
    assert!(
        n.prepare_trusted_workflow_check_set(
            &request,
            &f.directory,
            f.journal,
            f.pin,
            publisher(),
            branch(),
            (128, 16 * 1024 * 1024)
        )
        .is_err()
    );
    let path = f.directory.join("check-proposals.journal");
    let original = fs::read(&path).unwrap();
    let mut bad = original.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    fs::write(&path, bad).unwrap();
    assert!(prepare!(f).is_err());
    assert_eq!(f.head(), head);
    fs::write(&path, original).unwrap();
    assert_eq!(prepare!(f).unwrap().len(), 3);
}

#[test]
fn cancellation_preserves_first_decision_and_does_not_submit_later_jobs() {
    let f = Fixture::new(GitHashAlgorithm::Sha1);
    let plan = prepare!(f).unwrap();
    let request = f.n().command_request_context(None);
    let result = f
        .n()
        .runtime()
        .block_on(
            f.n()
                .publish_trusted_workflow_check_set_in(&request, &plan, |_| {
                    request.cancel();
                    Ok(())
                }),
        );
    assert_eq!(result.decisions.len(), 1);
    assert!(result.error.is_some());
    assert!(!result.all_committed());
    let resumed = f
        .n()
        .runtime()
        .block_on(f.n().publish_trusted_workflow_check_set_in(
            &f.n().command_request_context(None),
            &plan,
            |_| Ok(()),
        ));
    assert!(resumed.all_committed());
    assert_eq!(result.decisions[0].terminal, resumed.decisions[0].terminal);
}

#[test]
fn historical_commit_survives_source_movement_while_new_checks_refuse() {
    for fmt in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(fmt);
        let plan = prepare!(f).unwrap();
        let first = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &plan,
                |_| Err("stop".into()),
            ));
        assert_eq!(first.decisions.len(), 1);
        f.advance();
        f.reopen();
        let plan = prepare!(f).unwrap();
        let result = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &plan,
                |_| Ok(()),
            ));
        assert!(result.error.is_none());
        assert_eq!(result.decisions.len(), 3);
        assert!(!result.all_committed());
        assert_eq!(result.decisions[0].terminal, first.decisions[0].terminal);
        for d in &result.decisions[1..] {
            assert!(
                matches!(
                    d.terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::TargetRefMoved,
                        ..
                    }
                ),
                "{d:?}"
            );
        }
        let head = f.head();
        let repeated = f
            .n()
            .runtime()
            .block_on(f.n().publish_trusted_workflow_check_set_in(
                &f.n().command_request_context(None),
                &plan,
                |_| Ok(()),
            ));
        assert_eq!(f.head(), head);
        for (a, b) in result.decisions.iter().zip(repeated.decisions) {
            assert_eq!(a.terminal, b.terminal);
        }
    }
}

#[test]
fn journal_append_requires_new_explicit_snapshot_and_never_changes_child_keys() {
    let f = Fixture::new(GitHashAlgorithm::Sha1);
    let old = prepare!(f).unwrap();
    let scope = fgit_runner::coordinator::delivery::journal::CheckJournalScope {
        tenant: f.n().tenant_id(),
        repository: f.n().repository_id(),
        journal_id: fgit_runner::Commitment::try_from_digest(f.journal).unwrap(),
    };
    let mut journal =
        OneNode::open_trusted_workflow_journal(&f.directory, scope, None, &|| true).unwrap();
    assert!(prepare!(f).is_err());
    journal
        .store_evidence(fgit_runner::Commitment::of_bytes(b"append"), b"append")
        .unwrap();
    let pin = (journal.pin().byte_len(), journal.pin().tail().digest());
    drop(journal);
    assert!(prepare!(f).is_err());
    let new = f
        .n()
        .prepare_trusted_workflow_check_set(
            &f.n().command_request_context(None),
            &f.directory,
            f.journal,
            pin,
            publisher(),
            branch(),
            (128, 16 * 1024 * 1024),
        )
        .unwrap();
    assert_ne!(old.identity(), new.identity());
    let a = f
        .n()
        .runtime()
        .block_on(f.n().publish_trusted_workflow_check_set_in(
            &f.n().command_request_context(None),
            &old,
            |_| Ok(()),
        ));
    assert!(a.all_committed());
    let head = f.head();
    let b = f
        .n()
        .runtime()
        .block_on(f.n().publish_trusted_workflow_check_set_in(
            &f.n().command_request_context(None),
            &new,
            |_| Ok(()),
        ));
    assert!(b.all_committed());
    assert_eq!(f.head(), head);
    for (a, b) in a.decisions.iter().zip(b.decisions) {
        assert_eq!(a.tx_id, b.tx_id);
        assert_eq!(a.terminal, b.terminal);
    }
}
