//! Embedded authority regressions for candidate reviews and review-gated merge.
//! Fixtures are native objects imported by the real node, not mocked authority.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::{AggregateVersion, ForgeEventPayload};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{ReviewFreshness, ReviewSubject};
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, RefName, RepositoryId, TenantId};
use crate::{MaterializedAdmission, NodeConfig};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-review-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xc1;16]), RepositoryId::from_bytes([0xc2;16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn actor(id: u8) -> PrincipalId { PrincipalId::from_bytes([id;16]) }
fn session(id: u8, key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(id), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn target() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn incoming() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn commit(tree: GitOid, parents: &[GitOid], label: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
    body.push_str(label); body.push('\n'); body.into_bytes()
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut frame = vec![0x78, 0x01, 0x01];
    frame.extend(length.to_le_bytes()); frame.extend((!length).to_le_bytes()); frame.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a,b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    frame.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string(); let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap(); fs::write(dir.join(&hex[2..]), frame).unwrap(); id
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context(); node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}
fn committed(value: (TxId, TerminalOutcome)) -> (TxId, TerminalOutcome) {
    assert!(matches!(value.1.outcome, DecisionOutcome::Committed { .. }), "{value:?}"); value
}
struct Fixture { node: OneNode, command: CandidateReviewCommand, bundle: Vec<u8>, data: PullRequestData }
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> Fixture {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap(); node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source"); fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = loose(&root, format, GitObjectKind::Blob, "blob", b"retained file\n");
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", &[b"100644 file\0".as_slice(), blob.as_bytes()].concat());
    let base = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[], "base"));
    let ours = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[base], "target"));
    let theirs = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[base], "source"));
    fs::write(root.join("refs/heads/main"), format!("{ours}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{theirs}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(&request, &root, actor(1), b"review-fixture")).unwrap();
    assert!(imported.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    let data = PullRequestData { source_ref: incoming(), target_ref: target(), source_tip: theirs, target_tip: ours,
        title: "Candidate review".into(), body: "Review the actual artifact".into() };
    let pr = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open, data: data.clone() };
    committed(node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session(1, "open"), &pr, AdmissionLimits::default())).unwrap());
    let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(), committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 1, message: b"actual reviewed candidate\n".to_vec() };
    let prepared = node.runtime().block_on(node.prepare_merge_bundle_in(&request, &target(), &incoming(),
        &RefVisibility::new(), &metadata, PreparationLimits::default())).unwrap();
    let MergePreparation::Clean(plan) = prepared.outcome else { panic!("clean fixture candidate"); };
    let command = CandidateReviewCommand { candidate: CandidateBinding { merge_base: plan.base, commit: plan.commit },
        review: ReviewCommand { expected_version: ExpectedVersion::NewStream,
            subject: ReviewSubject { pull_request: PullRequestNumber::FIRST, pull_request_version: AggregateVersion::FIRST,
                source_ref: incoming(), target_ref: target(), source_tip: theirs, target_tip: ours,
                policy_epoch: snapshot(&node).basis().body().policy_epoch },
            decision: ReviewDecision::Approve, reason: "Reviewed exact candidate bytes".into() } };
    Fixture { node, command, bundle: prepared.bundle.unwrap(), data }
}
fn vote(node: &OneNode, command: &CandidateReviewCommand, bundle: Option<&[u8]>, reviewer: u8, key: &str)
    -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context(); node.runtime().block_on(node.admit_candidate_review_durable_in(
        &request, &session(reviewer,key), command, bundle, AdmissionLimits::default()))
}
fn publish(node: &OneNode, command: &CandidateReviewCommand, bundle: &[u8], reviewers: &[PrincipalId], key: &str)
    -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.apply_reviewed_merge_bundle_durable_in(&request, actor(2), key.as_bytes(),
        command.review.subject.pull_request, ExpectedVersion::Exactly(command.review.subject.pull_request_version),
        &command.candidate.merge(&command.review.subject), bundle, command.review.subject.policy_epoch, reviewers))
}
fn page(node: &OneNode, after: Option<PrincipalId>, limit: u16, head: Option<RepositoryAuthorityHeadId>) -> Option<ReviewPage> {
    let request = node.request_context(); node.runtime().block_on(node.read_reviews_in(&request, &RefVisibility::new(),
        PullRequestNumber::FIRST, after, limit, head)).unwrap()
}
fn code_unchanged(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().retention_root, after.basis().body().retention_root);
}

#[test]
fn review_then_publish_both_formats_preserves_code_until_the_coupled_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let f = fixture(&scratch, format); let before = snapshot(&f.node);
        assert!(f.node.read_git_object(f.command.candidate.commit).is_err());
        let accepted = committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "approve").unwrap());
        let reviewed = snapshot(&f.node); code_unchanged(&before, &reviewed);
        assert_ne!(reviewed.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_ne!(reviewed.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(reviewed.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);
        assert!(f.node.read_git_object(f.command.candidate.commit).is_err(), "review never imports candidate objects");
        let rows = page(&f.node, None, 100, None).unwrap(); assert_eq!(rows.reviews.len(), 1);
        assert_eq!(rows.pull_request_version, AggregateVersion::FIRST);
        assert_eq!(rows.reviews[0].event.candidate, Some(f.command.candidate));
        assert_eq!(rows.reviews[0].freshness, ReviewFreshness::Current);
        assert_eq!(rows.reviews[0].reviewer_is_opener, Some(false));
        assert_eq!(vote(&f.node, &f.command, None, 3, "approve").unwrap(), accepted);
        assert_eq!(snapshot(&f.node).basis(), reviewed.basis());
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Recovery is allowed even before re-entering mutation-ready service.
        assert_eq!(vote(&reopened, &f.command, None, 3, "approve").unwrap(), accepted);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let terminal = committed(publish(&reopened, &f.command, &f.bundle, &[actor(3)], "publish").unwrap());
        let after = snapshot(&reopened);
        assert_eq!(after.snapshot().refs[&target()], f.command.candidate.commit);
        assert_ne!(after.basis().body().forge_position_root, reviewed.basis().body().forge_position_root);
        assert_ne!(after.basis().body().outbox_root, reviewed.basis().body().outbox_root);
        let request = reopened.request_context();
        let prs = reopened.runtime().block_on(reopened.read_pull_requests_in(&request, &RefVisibility::new(), 0, 100, None)).unwrap();
        assert!(matches!(prs.pull_requests[0].event.payload, ForgeEventPayload::MergeCommittedNative(_)));
        assert_eq!(prs.pull_requests[0].data, Some(f.data));
        assert_eq!(publish(&reopened, &f.command, &[], &[actor(3)], "publish").unwrap(), terminal);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn later_approval_cannot_rewrite_an_earlier_canonical_refusal() {
    let scratch = Scratch::new(); let f = fixture(&scratch, GitHashAlgorithm::Sha256);
    let before = snapshot(&f.node);
    let refused = publish(&f.node, &f.command, &f.bundle, &[actor(3)], "missing-vote").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceMissing, .. }));
    code_unchanged(&before, &snapshot(&f.node));
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "approve-later").unwrap());
    let after_vote = snapshot(&f.node);
    assert_eq!(publish(&f.node, &f.command, &[], &[actor(3)], "missing-vote").unwrap(), refused);
    assert_eq!(snapshot(&f.node).basis(), after_vote.basis());
    committed(publish(&f.node, &f.command, &f.bundle, &[actor(3)], "new-merge-attempt").unwrap());
    f.node.shutdown().unwrap();
}

#[test]
fn withdrawal_and_changed_candidate_cannot_satisfy_required_reviewers() {
    let scratch = Scratch::new(); let f = fixture(&scratch, GitHashAlgorithm::Sha1);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "approve").unwrap());
    let mut withdrawn = f.command.clone(); withdrawn.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    withdrawn.review.decision = ReviewDecision::Withdraw; withdrawn.review.reason = "Candidate needs another pass".into();
    committed(vote(&f.node, &withdrawn, None, 3, "withdraw").unwrap());
    assert_eq!(page(&f.node, None, 100, None).unwrap().reviews[0].freshness, ReviewFreshness::Withdrawn);
    let before = snapshot(&f.node);
    let refused = publish(&f.node, &f.command, &f.bundle, &[actor(3)], "withdrawn-merge").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    code_unchanged(&before, &snapshot(&f.node));
    let mut renewed = f.command.clone(); renewed.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
    committed(vote(&f.node, &renewed, Some(&f.bundle), 3, "renew").unwrap());
    let request = f.node.request_context();
    let other = f.node.runtime().block_on(f.node.prepare_merge_bundle_in(&request, &target(), &incoming(), &RefVisibility::new(),
        &MergeMetadata { author: "Fixture <fixture@example.invalid>".into(), committer: "Fixture <fixture@example.invalid>".into(),
            timestamp: 1, message: b"different actual commit\n".to_vec() }, PreparationLimits::default())).unwrap();
    let MergePreparation::Clean(plan) = other.outcome else { panic!("second candidate"); };
    let mut different = f.command.clone(); different.candidate.commit = plan.commit;
    let stale = publish(&f.node, &different, &other.bundle.unwrap(), &[actor(3)], "unreviewed-candidate").unwrap();
    assert!(matches!(stale.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    committed(publish(&f.node, &f.command, &f.bundle, &[actor(3)], "approved-again").unwrap());
    f.node.shutdown().unwrap();
}

#[test]
fn reviewer_keys_competing_versions_and_snapshot_pages_do_not_alias() {
    let scratch = Scratch::new(); let f = fixture(&scratch, GitHashAlgorithm::Sha1);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "first-reviewer").unwrap());
    committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "second-reviewer").unwrap());
    let first = page(&f.node, None, 1, None).unwrap(); assert_eq!(first.reviews.len(), 1);
    assert_eq!(first.next_after, Some(actor(3)));
    let second = page(&f.node, first.next_after, 1, Some(first.source_head)).unwrap();
    assert_eq!(second.reviews[0].event.reviewer, actor(4)); assert!(second.next_after.is_none());
    let request = f.node.request_context();
    assert!(matches!(f.node.runtime().block_on(f.node.read_reviews_in(&request, &RefVisibility::new(),
        PullRequestNumber::FIRST, first.next_after, 1, None)), Err(ReviewReadRefusal::UnpinnedContinuation)));
    let mut changed = f.command.clone(); changed.review.reason.push('!');
    assert!(vote(&f.node, &changed, Some(&f.bundle), 3, "first-reviewer").is_err());
    let mut update = f.command.clone(); update.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    update.review.decision = ReviewDecision::RequestChanges; update.review.reason = "Blocking problem".into();
    committed(vote(&f.node, &update, Some(&f.bundle), 3, "block").unwrap());
    let stale = vote(&f.node, &update, Some(&f.bundle), 3, "competing-review").unwrap();
    assert!(matches!(stale.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    assert!(matches!(f.node.runtime().block_on(f.node.read_reviews_in(&request, &RefVisibility::new(),
        PullRequestNumber::FIRST, first.next_after, 1, Some(first.source_head))), Err(ReviewReadRefusal::SnapshotMoved)));
    let mut hidden = RefVisibility::new(); hidden.push_rule(b"refs/heads/topic", &fgit_wire::WireLimits::default()).unwrap();
    assert!(f.node.runtime().block_on(f.node.read_reviews_in(&request, &hidden,
        PullRequestNumber::FIRST, None, 100, None)).unwrap().is_none());
    let refused = publish(&f.node, &f.command, &f.bundle, &[actor(3),actor(4)], "blocked").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    f.node.shutdown().unwrap();
}

#[test]
fn opener_votes_and_stale_pr_metadata_do_not_authorize_publication() {
    let scratch = Scratch::new(); let f = fixture(&scratch, GitHashAlgorithm::Sha256);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 1, "opener-vote").unwrap());
    let refused = publish(&f.node, &f.command, &f.bundle, &[actor(1)], "self-approved").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    assert!(publish(&f.node, &f.command, &f.bundle, &[actor(2)], "submitter-vote").is_err());
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "peer-vote").unwrap());
    let mut data = f.data.clone(); data.title = "New metadata version".into();
    let command = PullRequestCommand { number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST), action: PullRequestAction::Update, data };
    let request = f.node.request_context();
    committed(f.node.runtime().block_on(f.node.admit_pull_request_durable_in(&request, &session(1,"update"),
        &command, AdmissionLimits::default())).unwrap());
    assert!(page(&f.node, None, 100, None).unwrap().reviews.iter().all(|v| v.freshness == ReviewFreshness::PullRequestChanged));
    let mut new_version = f.command.clone(); new_version.review.subject.pull_request_version = AggregateVersion::try_new(2).unwrap();
    let refused = publish(&f.node, &new_version, &f.bundle, &[actor(3)], "stale-peer-vote").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    f.node.shutdown().unwrap();
}
