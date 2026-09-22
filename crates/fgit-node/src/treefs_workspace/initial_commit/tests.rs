use super::*;
use crate::{MaterializedAdmission, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_forge::aggregate::ExpectedVersion;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RepositoryId,
    TenantId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    format: GitHashAlgorithm,
    node: Option<OneNode>,
}
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-initial-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let mut result = Self {
            root,
            format,
            node: None,
        };
        let (mut node, _) = OneNode::init(result.config()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        result.node = Some(node);
        result
    }
    fn config(&self) -> NodeConfig {
        NodeConfig::new(
            self.root.join("node"),
            TenantId::from_bytes([0xe1; 16]),
            RepositoryId::from_bytes([0xe2; 16]),
        )
        .with_object_format(self.format)
        .with_worker_threads(2)
    }
    fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    fn state(&self) -> MaterializedAdmission {
        let request = self.node().request_context();
        self.node()
            .runtime()
            .block_on(self.node().materialize_admission_in(&request))
            .unwrap()
    }
    fn prepare(
        &self,
        name: &str,
        patch: &[u8],
    ) -> (RepositoryAuthorityHeadId, InitialCommitPlan, FullBundle) {
        let node = self.node();
        let request = node.request_context();
        node.runtime()
            .block_on(node.prepare_trusted_initial_patch_in(
                &request,
                &reference(name),
                patch,
                &metadata(),
                PatchLimits::default(),
                None,
            ))
            .unwrap()
    }
    fn apply(
        &self,
        name: &str,
        id: GitOid,
        bytes: &[u8],
        key: &[u8],
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let node = self.node();
        let request = node.request_context();
        node.runtime()
            .block_on(node.apply_initial_patch_bundle_durable_in(
                &request,
                &session(key),
                &reference(name),
                id,
                bytes,
                AdmissionLimits::default(),
            ))
    }
    fn reopen_stopped(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        self.node = Some(OneNode::open_existing(self.config()).unwrap());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn actor(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(1), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn reference(name: &str) -> RefName {
    RefName::try_new(name.as_bytes()).unwrap()
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Author <a@example.invalid>".into(),
        committer: "Committer <c@example.invalid>".into(),
        timestamp: 1,
        message: b"initial\n".to_vec(),
    }
}
fn patch() -> &'static [u8] {
    b"diff --git a/src/main.rs b/src/main.rs\nnew file mode 100755\n--- /dev/null\n+++ b/src/main.rs\n@@ -0,0 +1 @@\n+fn main() {}\ndiff --git a/empty b/empty\nnew file mode 100644\n--- /dev/null\n+++ b/empty\n"
}
fn committed(result: Result<AdmissionResult, NodeWorkspaceRefusal>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    assert_eq!(result.session.tx_ids, vec![result.commands[0].tx_id]);
    assert!(
        matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "{result:?}"
    );
    result
}
fn assert_unchanged(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.basis(), after.basis());
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().outbox, after.snapshot().outbox);
    assert_eq!(
        before.selected_closure().closure(),
        after.selected_closure().closure()
    );
}

#[test]
fn new_node_builds_complete_root_history_and_replays_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let before = f.state();
        assert!(before.snapshot().refs.is_empty());
        let (head, plan, bundle) = f.prepare("refs/heads/main", patch());
        assert_eq!(head, before.basis().id());
        assert_unchanged(&before, &f.state());
        assert_eq!(
            bundle.bytes(),
            f.prepare("refs/heads/main", patch()).2.bytes()
        );
        let published =
            committed(f.apply("refs/heads/main", plan.commit, bundle.bytes(), b"initial"));
        let after = f.state();
        assert_eq!(after.snapshot().refs.len(), 1);
        assert_eq!(
            after.snapshot().refs[&reference("refs/heads/main")],
            plan.commit
        );
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        for object in &plan.objects {
            assert_eq!(
                f.node().read_git_object(object.id).unwrap().payload(),
                object.body
            );
        }
        let commit = f.node().read_git_object(plan.commit).unwrap();
        assert!(!commit.payload().windows(8).any(|w| w == b"\nparent "));
        f.reopen_stopped();
        assert_eq!(
            f.apply("refs/heads/main", plan.commit, bundle.bytes(), b"initial")
                .unwrap(),
            published
        );
        assert!(
            f.apply(
                "refs/heads/main",
                plan.commit,
                bundle.bytes(),
                b"fresh-stopped"
            )
            .is_err()
        );
        f.node
            .as_mut()
            .unwrap()
            .bring_into_service(HeadGeneration::FIRST)
            .unwrap();
        assert_unchanged(&after, &f.state());
    }
}

#[test]
fn competing_preparations_use_absent_compare_and_swap_without_overwriting() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let (_, a, first) = f.prepare("refs/heads/main", patch());
        let different = String::from_utf8(patch().to_vec())
            .unwrap()
            .replace("fn main() {}", "fn main() { println!(\"hello\"); }");
        let (_, b, second) = f.prepare("refs/heads/main", different.as_bytes());
        assert_ne!(a.commit, b.commit);
        let winner = committed(f.apply("refs/heads/main", a.commit, first.bytes(), b"winner"));
        let lost = f
            .apply("refs/heads/main", b.commit, second.bytes(), b"loser")
            .unwrap();
        assert!(matches!(
            lost.commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        let after = f.state();
        assert_eq!(
            after.snapshot().refs[&reference("refs/heads/main")],
            a.commit
        );
        assert_eq!(
            f.apply("refs/heads/main", b.commit, second.bytes(), b"loser")
                .unwrap(),
            lost
        );
        assert_eq!(
            f.apply("refs/heads/main", a.commit, first.bytes(), b"winner")
                .unwrap(),
            winner
        );
        assert!(
            f.apply("refs/heads/main", b.commit, second.bytes(), b"winner")
                .is_err()
        );
        assert_unchanged(&after, &f.state());
        let request = f.node().request_context();
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().prepare_trusted_initial_patch_in(
                    &request,
                    &reference("refs/heads/main"),
                    patch(),
                    &metadata(),
                    PatchLimits::default(),
                    None
                ))
                .is_err()
        );
    }
}

#[test]
fn root_publication_recovery_survives_deleted_branch_and_exhausted_quota() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    let (_, plan, bundle) = f.prepare("refs/heads/topic", patch());
    let published = committed(f.apply("refs/heads/topic", plan.commit, bundle.bytes(), b""));
    let request = f.node().request_context();
    let deletion = RefCommand {
        name: reference("refs/heads/topic"),
        expected_old: ExpectedOld::Exactly(plan.commit),
        proposed_new: ProposedNew::Delete,
        force: false,
    };
    committed(
        f.node()
            .runtime()
            .block_on(f.node().admit_branch_updates_durable_in(
                &request,
                &session(b"delete"),
                &[deletion],
                AdmissionLimits::default(),
            )),
    );
    let before = f.state();
    assert!(
        !before
            .snapshot()
            .refs
            .contains_key(&reference("refs/heads/topic"))
    );
    f.node.as_mut().unwrap().push_quota.limit.max_events = 0;
    assert_eq!(
        f.apply("refs/heads/topic", plan.commit, bundle.bytes(), b"")
            .unwrap(),
        published
    );
    assert!(
        f.apply("refs/heads/topic", plan.commit, bundle.bytes(), b"fresh")
            .is_err()
    );
    assert_unchanged(&before, &f.state());
}

#[test]
fn independent_expectations_and_corrupt_or_cancelled_inputs_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let before = f.state();
        let (_, plan, bundle) = f.prepare("refs/heads/main", patch());
        assert!(
            f.apply(
                "refs/heads/other",
                plan.commit,
                bundle.bytes(),
                b"wrong-ref"
            )
            .is_err()
        );
        assert!(
            f.apply("refs/heads/main", plan.tree, bundle.bytes(), b"wrong-id")
                .is_err()
        );
        let mut corrupt = bundle.bytes().to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            f.apply("refs/heads/main", plan.commit, &corrupt, b"corrupt")
                .is_err()
        );
        assert!(
            f.apply(
                "refs/heads/main",
                plan.commit,
                &bundle.bytes()[..bundle.bytes().len() - 3],
                b"short"
            )
            .is_err()
        );
        let request = f.node().request_context();
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().apply_initial_patch_bundle_durable_in(
                    &request,
                    &LoopbackReceiveSession::anonymous(),
                    &reference("refs/heads/main"),
                    plan.commit,
                    bundle.bytes(),
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        request.authority().cancel();
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().apply_initial_patch_bundle_durable_in(
                    &request,
                    &session(b"cancel"),
                    &reference("refs/heads/main"),
                    plan.commit,
                    bundle.bytes(),
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().prepare_trusted_initial_patch_in(
                    &request,
                    &reference("refs/heads/main"),
                    patch(),
                    &metadata(),
                    PatchLimits::default(),
                    None
                ))
                .is_err()
        );
        assert_unchanged(&before, &f.state());
        committed(f.apply("refs/heads/main", plan.commit, bundle.bytes(), b"permitted"));
    }
}

#[test]
fn current_review_protection_blocks_root_creation_without_weakening_other_branches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let (basis, protected, bundle) = f.prepare("refs/heads/main", patch());
        let request = f.node().request_context();
        let command = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![actor(1)],
                branches: vec![ProtectedBranch {
                    name: reference("refs/heads/main"),
                    reviewers: vec![actor(3)],
                }],
            },
        };
        let policy = f
            .node()
            .runtime()
            .block_on(f.node().admit_review_protection_durable_in(
                &request,
                &session(b"protect"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            policy.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let blocked = f
            .apply(
                "refs/heads/main",
                protected.commit,
                bundle.bytes(),
                b"blocked",
            )
            .unwrap();
        assert!(matches!(
            blocked.commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        assert!(f.state().snapshot().refs.is_empty());
        assert!(
            f.node()
                .runtime()
                .block_on(f.node().prepare_trusted_initial_patch_in(
                    &request,
                    &reference("refs/heads/topic"),
                    patch(),
                    &metadata(),
                    PatchLimits::default(),
                    Some(basis)
                ))
                .is_err()
        );
        let (_, plan, allowed) = f.prepare("refs/heads/topic", patch());
        committed(f.apply("refs/heads/topic", plan.commit, allowed.bytes(), b"allowed"));
        let after = f.state();
        assert_eq!(after.snapshot().refs.len(), 1);
        assert_eq!(
            f.apply(
                "refs/heads/main",
                protected.commit,
                bundle.bytes(),
                b"blocked"
            )
            .unwrap(),
            blocked
        );
        assert_unchanged(&after, &f.state());
    }
}

// These are deliberately handwritten untrusted bundles, not builder-produced
// proof. The native pack writer commits real bytes; admission must rediscover
// their reference graph independently instead of trusting this test's metadata.
fn adversarial_bundle(
    format: GitHashAlgorithm,
    tip: GitOid,
    objects: &[(GitObjectKind, Vec<u8>)],
) -> Vec<u8> {
    let source = Objects(
        objects
            .iter()
            .map(|(kind, body)| {
                let id = git_object_id(format, *kind, body);
                (
                    id,
                    CanonicalPackObject::new(id, *kind, body.clone(), vec![], 0, 0),
                )
            })
            .collect(),
    );
    let ids = source.0.keys().copied().collect::<Vec<_>>();
    let limits = PackLimits::default();
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
        .plan_selected(&source, &ids, &mut || true)
        .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(format!("{tip} refs/heads/main\n\n").as_bytes());
    bundle.extend(pack);
    bundle
}

#[test]
fn complete_reviewed_root_is_required_even_when_advertisement_and_checksum_are_valid() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format);
        let (_, plan, _) = f.prepare("refs/heads/topic", patch());
        let complete = plan
            .objects
            .iter()
            .map(|o| (o.kind, o.body.clone()))
            .collect::<Vec<_>>();
        let valid = adversarial_bundle(format, plan.commit, &complete);
        let before = f.state();
        // An unreachable extra blob must not hitchhike into the object fabric.
        let mut extra = complete.clone();
        extra.push((GitObjectKind::Blob, b"unreviewed unrelated object".to_vec()));
        let extra_id = git_object_id(format, GitObjectKind::Blob, b"unreviewed unrelated object");
        assert!(
            f.apply(
                "refs/heads/main",
                plan.commit,
                &adversarial_bundle(format, plan.commit, &extra),
                b"extra"
            )
            .is_err()
        );
        assert!(f.node().read_git_object(extra_id).is_err());
        assert_unchanged(&before, &f.state());
        // A valid native commit with a parent is not an initial commit, even
        // with its correct independently supplied ID and complete ancestry.
        let body = format!("tree {}\nparent {}\nauthor Author <a@example.invalid> 2 +0000\ncommitter Committer <c@example.invalid> 2 +0000\n\nnot a root\n", plan.tree, plan.commit).into_bytes();
        let descendant = git_object_id(format, GitObjectKind::Commit, &body);
        let mut history = complete.clone();
        history.push((GitObjectKind::Commit, body));
        assert!(
            f.apply(
                "refs/heads/main",
                descendant,
                &adversarial_bundle(format, descendant, &history),
                b"parent"
            )
            .is_err()
        );
        assert!(f.node().read_git_object(descendant).is_err());
        assert_unchanged(&before, &f.state());
        // Store the exact dependencies under another branch first. A truncated
        // initial bundle still cannot borrow those admitted objects secretly.
        let (_, seed, bundle) = f.prepare("refs/heads/topic", patch());
        committed(f.apply("refs/heads/topic", seed.commit, bundle.bytes(), b"seed"));
        let seeded = f.state();
        let missing = complete
            .iter()
            .filter(|(kind, _)| *kind != GitObjectKind::Blob)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            f.apply(
                "refs/heads/main",
                plan.commit,
                &adversarial_bundle(format, plan.commit, &missing),
                b"missing"
            )
            .is_err()
        );
        assert_unchanged(&seeded, &f.state());
        committed(f.apply("refs/heads/main", plan.commit, &valid, b"complete"));
        assert_eq!(
            f.state().snapshot().refs[&reference("refs/heads/main")],
            plan.commit
        );
    }
}
