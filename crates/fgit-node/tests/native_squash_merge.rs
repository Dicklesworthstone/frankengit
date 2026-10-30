#![forbid(unsafe_code)]
//! Squash preparation, review and atomic publication through a real file-backed node.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{
    LoopbackReceiveSession, MaterializedAdmission, NodeConfig, NodeReceiveTransportRefusal,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RefusalCode, RepositoryId, TenantId, TxId,
};
use fgit_wire::visibility::RefVisibility;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-native-squash-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}

fn session(who: u8, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(who), IdempotencyKey::new(key.to_vec()).unwrap())
}

fn target_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}

fn source_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}

fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0xd1; 16]),
        RepositoryId::from_bytes([0xd2; 16]),
    )
    .with_object_format(format)
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let name = id.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), zlib).unwrap();
    id
}

fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}

fn tree_body(blob: GitOid, mode: u32) -> Vec<u8> {
    [format!("{mode:o} file\0").as_bytes(), blob.as_bytes()].concat()
}

struct Fixture {
    node: OneNode,
    target: GitOid,
    source: GitOid,
    next_target: GitOid,
    next_source: GitOid,
    expected_tree: GitOid,
    expected_blob: GitOid,
    data: PullRequestData,
}

fn fixture(root: &Path, format: GitHashAlgorithm) -> Fixture {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let path = root.join("source");
    fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        path.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => {
                "[core]\nrepositoryformatversion = 0\nbare = true\n"
            }
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let native_tree = |bytes: &[u8], mode| {
        let blob = loose(&path, format, GitObjectKind::Blob, bytes);
        loose(&path, format, GitObjectKind::Tree, &tree_body(blob, mode))
    };
    let base_tree = native_tree(b"one\ntwo\nthree\nfour\nfive\n", 0o100644);
    let target_tree = native_tree(b"ONE\ntwo\nthree\nfour\nfive\n", 0o100755);
    let source_tree = native_tree(b"one\ntwo\nthree\nfour\nFIVE\n", 0o100644);
    let base = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(base_tree, &[], "base\n"),
    );
    let target = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(target_tree, &[base], "target\n"),
    );
    let source = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(source_tree, &[base], "source\n"),
    );
    let next_target = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(target_tree, &[target], "future target\n"),
    );
    let next_source = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(source_tree, &[source], "future source\n"),
    );
    for (name, tip) in [
        ("main", target),
        ("topic", source),
        ("future-target", next_target),
        ("future-source", next_source),
    ] {
        fs::write(path.join("refs/heads").join(name), format!("{tip}\n")).unwrap();
    }
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &path,
            actor(1),
            b"squash-fixture-import",
        ))
        .unwrap();
    assert_eq!(imported.commands.len(), 4);
    for command in &imported.commands {
        committed(&command.terminal);
    }
    let data = PullRequestData {
        source_ref: source_ref(),
        target_ref: target_ref(),
        source_tip: source,
        target_tip: target,
        title: "Squash PR".into(),
        body: "Combine both branches into one new target commit.".into(),
    };
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: data.clone(),
    };
    let request = node.request_context();
    let (_, opened) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &request,
            &session(1, b"open-squash-pr"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&opened);
    let expected_blob = git_object_id(
        format,
        GitObjectKind::Blob,
        b"ONE\ntwo\nthree\nfour\nFIVE\n",
    );
    let expected_tree = git_object_id(
        format,
        GitObjectKind::Tree,
        &tree_body(expected_blob, 0o100755),
    );
    Fixture {
        node,
        target,
        source,
        next_target,
        next_source,
        expected_tree,
        expected_blob,
        data,
    }
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn committed(outcome: &TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}

fn refused(outcome: &TerminalOutcome, expected: RefusalCode) {
    assert!(
        matches!(
            outcome.outcome,
            DecisionOutcome::Refused { code, .. } if code == expected
        ),
        "{outcome:?}"
    );
}

fn unchanged_effects(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
}

struct Candidate {
    merge: NativeMerge,
    bundle: Vec<u8>,
    commit_body: Vec<u8>,
}

fn assert_discarded(fixture: &Fixture, candidate: &Candidate) {
    for id in [
        candidate.merge.merge_commit,
        fixture.expected_tree,
        fixture.expected_blob,
    ] {
        assert!(
            matches!(fixture.node.read_git_object(id),
            Err(fgit_node::NodeRefusal::Fabric(error))
                if matches!(*error, fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent)),
            "refused squash object {id} must remain unplaced"
        );
    }
    assert_eq!(
        fs::read_dir(fixture.node.storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
}

fn prepare(node: &OneNode, style: MergeCommitStyle, message: &[u8]) -> Candidate {
    let before = snapshot(node);
    let metadata = MergeMetadata {
        author: "Author <author@example.test>".into(),
        committer: "Committer <committer@example.test>".into(),
        timestamp: 1_700_000_000,
        message: message.to_vec(),
    };
    let request = node.request_context();
    let prepared = node
        .runtime()
        .block_on(node.prepare_merge_bundle_with_options_in(
            &request,
            &target_ref(),
            &source_ref(),
            &RefVisibility::new(),
            &metadata,
            Default::default(),
            MergeProfile::PathMergeV1,
            style,
        ))
        .unwrap();
    assert_eq!(prepared.source_head, before.basis().id());
    assert_eq!(snapshot(node).basis(), before.basis());
    let MergePreparation::Clean(plan) = prepared.outcome else {
        panic!("the fixture's disjoint text edits must merge");
    };
    assert_eq!(plan.style, style);
    assert!(node.read_git_object(plan.commit).is_err());
    let commit_body = plan
        .objects
        .iter()
        .find(|object| object.id == plan.commit)
        .unwrap()
        .body
        .clone();
    Candidate {
        merge: NativeMerge {
            source_ref: source_ref(),
            source_tip: plan.source,
            base_tip: plan.base,
            target_ref: target_ref(),
            target_tip_before: plan.target,
            merge_commit: plan.commit,
        },
        bundle: prepared.bundle.unwrap(),
        commit_body,
    }
}

const fn version() -> ExpectedVersion {
    ExpectedVersion::Exactly(AggregateVersion::FIRST)
}

fn apply(
    node: &OneNode,
    candidate: &Candidate,
    key: &[u8],
    expected_version: ExpectedVersion,
    method: NativeMergeMethod,
) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.apply_merge_bundle_with_method_durable_in(
            &request,
            actor(2),
            key,
            PullRequestNumber::FIRST,
            expected_version,
            &candidate.merge,
            &candidate.bundle,
            method,
        ))
}

fn subject(fixture: &Fixture, epoch: PolicyEpoch) -> ReviewSubject {
    ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: source_ref(),
        target_ref: target_ref(),
        source_tip: fixture.source,
        target_tip: fixture.target,
        policy_epoch: epoch,
    }
}

fn review_command(
    fixture: &Fixture,
    candidate: &Candidate,
    epoch: PolicyEpoch,
) -> CandidateReviewCommand {
    CandidateReviewCommand {
        review: ReviewCommand {
            expected_version: ExpectedVersion::NewStream,
            subject: subject(fixture, epoch),
            decision: ReviewDecision::Approve,
            reason: "Reviewed this exact candidate and resulting content.".into(),
        },
        candidate: CandidateBinding {
            merge_base: candidate.merge.base_tip,
            commit: candidate.merge.merge_commit,
        },
    }
}

#[test]
fn native_squash_combines_content_and_atomically_publishes_pr_ref_outbox_then_replays_after_restart()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format);
        let candidate = prepare(&f.node, MergeCommitStyle::Squash, b"one squash\n");
        let expected_body = format!(
            "tree {}\nparent {}\nauthor Author <author@example.test> 1700000000 +0000\ncommitter Committer <committer@example.test> 1700000000 +0000\n\none squash\n",
            f.expected_tree, f.target
        )
        .into_bytes();
        assert_eq!(candidate.commit_body, expected_body);
        assert_eq!(
            candidate.merge.merge_commit,
            git_object_id(format, GitObjectKind::Commit, &expected_body)
        );
        let approval = review_command(&f, &candidate, PolicyEpoch::FIRST);
        let request = f.node.request_context();
        let inspected = f
            .node
            .runtime()
            .block_on(f.node.inspect_pull_request_bundle_in(
                &request,
                &approval.review.subject,
                approval.candidate,
                &candidate.bundle,
                &RefVisibility::new(),
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.parents, [f.target]);
        assert_eq!(inspected.candidate_commit_body, expected_body);
        assert_eq!(inspected.review.comparison.entries.len(), 1);
        let before = snapshot(&f.node);
        let accepted = apply(
            &f.node,
            &candidate,
            b"squash-one",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap();
        committed(&accepted.1);
        let after = snapshot(&f.node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1,
            "no ref-only intermediate publication is permitted"
        );
        assert_eq!(
            after.snapshot().refs[&target_ref()],
            candidate.merge.merge_commit
        );
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_ne!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_ne!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_ne!(
            after.basis().body().outbox_root,
            before.basis().body().outbox_root
        );
        assert_eq!(
            f.node.read_git_object(f.expected_blob).unwrap().payload(),
            b"ONE\ntwo\nthree\nfour\nFIVE\n"
        );
        assert_eq!(
            f.node.read_git_object(f.expected_tree).unwrap().payload(),
            tree_body(f.expected_blob, 0o100755)
        );
        assert_eq!(
            f.node
                .read_git_object(candidate.merge.merge_commit)
                .unwrap()
                .payload(),
            expected_body
        );
        let intent = NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            candidate.merge.clone(),
        )
        .unwrap();
        let request = f.node.request_context();
        let history = f
            .node
            .runtime()
            .block_on(f.node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.batch.committed_rcrs[0].tx_id, accepted.0);
        assert_eq!(last.forge_events, vec![intent.event().clone()]);
        assert_eq!(
            last.batch.committed_rcrs[0].resulting_ref_root,
            after.basis().body().ref_root
        );
        assert_eq!(
            last.batch.committed_rcrs[0].resulting_forge_position_root,
            after.basis().body().forge_position_root
        );
        let page = f
            .node
            .runtime()
            .block_on(
                f.node
                    .read_pull_requests_in(&request, &RefVisibility::new(), 0, 10, None),
            )
            .unwrap();
        assert_eq!(page.pull_requests[0].event, *intent.event());
        assert_eq!(page.pull_requests[0].data, Some(f.data.clone()));
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = reopened.request_context();
        let retry = reopened
            .runtime()
            .block_on(reopened.apply_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"squash-one",
                PullRequestNumber::FIRST,
                version(),
                &candidate.merge,
                &[],
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        assert_eq!(retry, accepted);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_squash_keeps_method_version_and_request_identity_disjoint() {
    let scratch = Scratch::new();
    let f = fixture(&scratch.0, GitHashAlgorithm::Sha256);
    let squash = prepare(&f.node, MergeCommitStyle::Squash, b"squash\n");
    let ordinary = prepare(&f.node, MergeCommitStyle::TwoParent, b"ordinary\n");
    let before = snapshot(&f.node);
    let rejected = apply(
        &f.node,
        &squash,
        b"wrong-method",
        version(),
        NativeMergeMethod::MergeCommit,
    )
    .unwrap();
    refused(&rejected.1, RefusalCode::EvidenceInvalid);
    unchanged_effects(&before, &snapshot(&f.node));
    assert_discarded(&f, &squash);
    assert!(
        apply(
            &f.node,
            &squash,
            b"wrong-method",
            version(),
            NativeMergeMethod::Squash,
        )
        .is_err()
    );
    let rejected = apply(
        &f.node,
        &ordinary,
        b"wrong-parent-count",
        version(),
        NativeMergeMethod::Squash,
    )
    .unwrap();
    refused(&rejected.1, RefusalCode::EvidenceInvalid);
    assert_discarded(&f, &ordinary);
    let stale_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
    let rejected = apply(
        &f.node,
        &squash,
        b"stale-version",
        stale_version,
        NativeMergeMethod::Squash,
    )
    .unwrap();
    refused(&rejected.1, RefusalCode::EvidenceStale);
    assert_discarded(&f, &squash);
    assert!(
        apply(
            &f.node,
            &squash,
            b"new-stream",
            ExpectedVersion::NewStream,
            NativeMergeMethod::Squash,
        )
        .is_err()
    );
    unchanged_effects(&before, &snapshot(&f.node));
    let accepted = apply(
        &f.node,
        &squash,
        b"winner",
        version(),
        NativeMergeMethod::Squash,
    )
    .unwrap();
    committed(&accepted.1);
    let after = snapshot(&f.node);
    assert!(
        apply(
            &f.node,
            &ordinary,
            b"winner",
            version(),
            NativeMergeMethod::MergeCommit,
        )
        .is_err()
    );
    assert!(
        apply(
            &f.node,
            &squash,
            b"winner",
            stale_version,
            NativeMergeMethod::Squash,
        )
        .is_err()
    );
    assert_eq!(
        apply(
            &f.node,
            &squash,
            b"winner",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap(),
        accepted
    );
    assert_eq!(snapshot(&f.node).basis(), after.basis());
    f.node.shutdown().unwrap();
}

#[test]
fn source_or_target_movement_refuses_stale_squash_without_ref_or_forge_effects() {
    for move_source in [false, true] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, GitHashAlgorithm::Sha1);
        let candidate = prepare(&f.node, MergeCommitStyle::Squash, b"prepared before move\n");
        let (name, old, new) = if move_source {
            (source_ref(), f.source, f.next_source)
        } else {
            (target_ref(), f.target, f.next_target)
        };
        let request = f.node.request_context();
        let moved = f
            .node
            .runtime()
            .block_on(f.node.admit_branch_updates_durable_in(
                &request,
                &session(1, b"move-branch"),
                &[RefCommand {
                    name,
                    expected_old: ExpectedOld::Exactly(old),
                    proposed_new: ProposedNew::Update(new),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert_eq!(moved.commands.len(), 1);
        committed(&moved.commands[0].terminal);
        let before = snapshot(&f.node);
        let rejected = apply(
            &f.node,
            &candidate,
            b"stale-squash",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap();
        refused(&rejected.1, RefusalCode::TargetRefMoved);
        let after = snapshot(&f.node);
        unchanged_effects(&before, &after);
        assert_eq!(
            apply(
                &f.node,
                &candidate,
                b"stale-squash",
                version(),
                NativeMergeMethod::Squash,
            )
            .unwrap(),
            rejected
        );
        assert_eq!(snapshot(&f.node).basis(), after.basis());
        assert_discarded(&f, &candidate);
        f.node.shutdown().unwrap();
    }
}

fn vote(
    node: &OneNode,
    command: &CandidateReviewCommand,
    bytes: Option<&[u8]>,
    key: &[u8],
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_candidate_review_durable_in(
            &request,
            &session(3, key),
            command,
            bytes,
            Default::default(),
        ))
}

fn protect(node: &OneNode) -> PolicyEpoch {
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            ref_policy: None,
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                required_approvals: 1,
                required_checks: Vec::new(),
                name: target_ref(),
                reviewers: vec![actor(3)],
            }],
        },
    };
    let request = node.request_context();
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session(1, b"protect-squash"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
    PolicyEpoch::FIRST.next().unwrap()
}

#[test]
fn protected_squash_requires_its_exact_candidate_vote_and_honors_withdrawal_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format);
        let epoch = protect(&f.node);
        let squash = prepare(&f.node, MergeCommitStyle::Squash, b"reviewed squash\n");
        let ordinary = prepare(&f.node, MergeCommitStyle::TwoParent, b"reviewed merge\n");
        let missing = apply(
            &f.node,
            &squash,
            b"missing-review",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap();
        refused(&missing.1, RefusalCode::EvidenceMissing);
        assert_discarded(&f, &squash);
        let mut approval = review_command(&f, &ordinary, epoch);
        committed(
            &vote(
                &f.node,
                &approval,
                Some(&ordinary.bundle),
                b"ordinary-review",
            )
            .unwrap()
            .1,
        );
        let rejected = apply(
            &f.node,
            &squash,
            b"wrong-candidate-review",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap();
        refused(&rejected.1, RefusalCode::EvidenceStale);
        assert_discarded(&f, &squash);
        approval = review_command(&f, &squash, epoch);
        approval.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        committed(
            &vote(&f.node, &approval, Some(&squash.bundle), b"squash-review")
                .unwrap()
                .1,
        );
        let mut withdrawal = approval.clone();
        withdrawal.review.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        withdrawal.review.decision = ReviewDecision::Withdraw;
        withdrawal.review.reason = "Withdraw approval of this exact squash.".into();
        committed(
            &vote(&f.node, &withdrawal, None, b"withdraw-squash")
                .unwrap()
                .1,
        );
        let rejected = apply(
            &f.node,
            &squash,
            b"withdrawn-squash",
            version(),
            NativeMergeMethod::Squash,
        )
        .unwrap();
        refused(&rejected.1, RefusalCode::ProtectedRefTransitionDenied);
        assert_discarded(&f, &squash);
        approval.review.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap());
        committed(
            &vote(
                &f.node,
                &approval,
                Some(&squash.bundle),
                b"reapprove-squash",
            )
            .unwrap()
            .1,
        );
        assert_eq!(snapshot(&f.node).snapshot().refs[&target_ref()], f.target);
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(
            apply(
                &reopened,
                &squash,
                b"missing-review",
                version(),
                NativeMergeMethod::Squash,
            )
            .unwrap(),
            missing
        );
        let before = snapshot(&reopened);
        let request = reopened.request_context();
        let (_, accepted) = reopened
            .runtime()
            .block_on(reopened.apply_reviewed_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"reviewed-squash",
                PullRequestNumber::FIRST,
                version(),
                &squash.merge,
                &squash.bundle,
                epoch,
                &[actor(3)],
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        committed(&accepted);
        let after = snapshot(&reopened);
        assert_eq!(
            after.snapshot().refs[&target_ref()],
            squash.merge.merge_commit
        );
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        for id in [squash.merge.merge_commit, f.expected_tree, f.expected_blob] {
            reopened.read_git_object(id).unwrap();
        }
        assert_eq!(
            fs::read_dir(reopened.storage_root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn cancellation_before_squash_admission_leaves_the_exact_request_retryable() {
    let scratch = Scratch::new();
    let f = fixture(&scratch.0, GitHashAlgorithm::Sha1);
    let candidate = prepare(
        &f.node,
        MergeCommitStyle::Squash,
        b"cancelled then retried\n",
    );
    let before = snapshot(&f.node);
    let request = f.node.request_context();
    request.cancel();
    assert!(
        f.node
            .runtime()
            .block_on(f.node.apply_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"cancelled-squash",
                PullRequestNumber::FIRST,
                version(),
                &candidate.merge,
                &candidate.bundle,
                NativeMergeMethod::Squash,
            ))
            .is_err()
    );
    unchanged_effects(&before, &snapshot(&f.node));
    assert_discarded(&f, &candidate);
    let accepted = apply(
        &f.node,
        &candidate,
        b"cancelled-squash",
        version(),
        NativeMergeMethod::Squash,
    )
    .unwrap();
    committed(&accepted.1);
    f.node.shutdown().unwrap();
}
