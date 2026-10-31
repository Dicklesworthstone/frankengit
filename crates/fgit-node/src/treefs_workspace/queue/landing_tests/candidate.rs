//! Actual divergent trees, read-only preparation and protected bundle admission.
//! Reuses the file-backed queue fixture's real native loose-object importer.

use super::*;
use crate::NodeWorkspaceRefusal;
use crate::treefs_workspace::queue::PreparedQueueHeadBundle;
use crate::treefs_workspace::queue::tests::loose;
use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request::PullRequestData;
use fgit_forge::preparation::{
    MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile, PreparationLimits,
};
use std::fs;

mod queue_required;

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Queue operator <queue@example.invalid>".into(),
        committer: "Queue operator <queue@example.invalid>".into(),
        timestamp: 3,
        message: b"Integrate the exact queue head\n".to_vec(),
    }
}

fn fixture(
    format: GitHashAlgorithm,
    conflict: bool,
) -> (Scratch, OneNode, [PullRequestCommand; 2], GitOid, GitOid) {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        root.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            }
        },
    )
    .unwrap();
    let blob = |body: &[u8]| loose(&root, format, GitObjectKind::Blob, "blob", body);
    let original = blob(b"common\n");
    let ours = blob(b"target addition\n");
    let theirs = blob(b"source addition\n");
    let tree = |entries: &[(&str, GitOid)]| {
        let mut body = Vec::new();
        for (name, oid) in entries {
            body.extend_from_slice(format!("100644 {name}\0").as_bytes());
            body.extend_from_slice(oid.as_bytes());
        }
        loose(&root, format, GitObjectKind::Tree, "tree", &body)
    };
    let base_tree = tree(&[("base.txt", original)]);
    let target_tree = if conflict {
        tree(&[("base.txt", ours)])
    } else {
        tree(&[("base.txt", original), ("target.txt", ours)])
    };
    let source_tree = if conflict {
        tree(&[("base.txt", theirs)])
    } else {
        tree(&[("base.txt", original), ("source.txt", theirs)])
    };
    let commit = |tree: GitOid, parent: Option<GitOid>, name: &str| {
        let parent = parent.map_or_else(String::new, |id| format!("parent {id}\n"));
        loose(
            &root,
            format,
            GitObjectKind::Commit,
            "commit",
            format!(
                "tree {tree}\n{parent}author Fixture <queue@example.invalid> 1 +0000\ncommitter Fixture <queue@example.invalid> 1 +0000\n\n{name}\n"
            )
            .as_bytes(),
        )
    };
    let base = commit(base_tree, None, "common ancestor");
    let target = commit(target_tree, Some(base), "independent target change");
    let source = commit(source_tree, Some(base), "independent source change");
    let advanced = commit(target_tree, Some(target), "later target change");
    for (name, oid) in [
        ("main", target),
        ("topic-7", source),
        ("topic-9", source),
        ("advance", advanced),
    ] {
        fs::write(root.join("refs/heads").join(name), format!("{oid}\n")).unwrap();
    }
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &root,
            actor(),
            b"queue-divergent-fixture",
        ))
        .unwrap();
    assert!(!imported.commands.is_empty());
    for result in imported.commands {
        committed((result.tx_id, result.terminal));
    }
    let pulls = [7, 9].map(|number| PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: source,
            target_tip: target,
            title: format!("Divergent queued PR {number}"),
            body: String::new(),
        },
    });
    for pull in &pulls {
        apply_pull(&node, pull, &format!("open-{}", pull.number.get()));
    }
    accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "queue-first"));
    (scratch, node, pulls, base, advanced)
}

fn subject(node: &OneNode, pull: &PullRequestCommand) -> ReviewSubject {
    ReviewSubject {
        pull_request: pull.number,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: pull.data.source_ref.clone(),
        target_ref: pull.data.target_ref.clone(),
        source_tip: pull.data.source_tip,
        target_tip: pull.data.target_tip,
        policy_epoch: snapshot(node).basis().body().policy_epoch,
    }
}

fn prepare(
    node: &OneNode,
    subject: &ReviewSubject,
    queue_version: u64,
    profile: MergeProfile,
) -> Result<PreparedQueueHeadBundle, NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.prepare_queue_head_bundle_with_profile_in(
            &node.request_context(),
            QueueNumber::FIRST,
            version(queue_version),
            subject,
            &RefVisibility::new(),
            &metadata(),
            PreparationLimits::default(),
            profile,
        ))
}

fn offer(prepared: &PreparedQueueHeadBundle) -> QueueCandidateLandingCommand {
    let MergePreparation::Clean(plan) = &prepared.outcome else {
        panic!("expected a clean native candidate");
    };
    assert_eq!(plan.style, MergeCommitStyle::TwoParent);
    QueueCandidateLandingCommand {
        number: prepared.number,
        expected_version: prepared.expected_version,
        expected_policy_epoch: prepared.subject.policy_epoch,
        pull_request: prepared.subject.pull_request,
        expected_pull_request_version: prepared.subject.pull_request_version,
        merge: CandidateBinding {
            merge_base: plan.base,
            commit: plan.commit,
        }
        .merge(&prepared.subject),
    }
}

fn publish(
    node: &OneNode,
    command: &QueueCandidateLandingCommand,
    bundle: &[u8],
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.land_queue_head_bundle_durable_in(
            &node.request_context(),
            &session(key),
            command,
            bundle,
            AdmissionLimits::default(),
        ))
}

fn committed(result: (TxId, TerminalOutcome)) -> (TxId, TerminalOutcome) {
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}

fn refused(
    node: &OneNode,
    command: &QueueCandidateLandingCommand,
    bundle: &[u8],
    key: &str,
    expected: RefusalCode,
) -> (TxId, TerminalOutcome) {
    let before = snapshot(node);
    let queued = read(node, 1, None).queue;
    let result = publish(node, command, bundle, key).unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "expected {expected:?}: {result:?}"
    );
    unchanged_publication(&before, &snapshot(node));
    assert_eq!(read(node, 1, None).queue, queued);
    result
}

#[test]
fn divergent_queue_head_prepares_real_objects_and_lands_as_one_recoverable_decision() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node, pulls, base, _) = fixture(format, false);
        accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "queue-second"));
        let before = snapshot(&node);
        let selected = subject(&node, &pulls[0]);
        let prepared = prepare(&node, &selected, 2, MergeProfile::PathMergeV1).unwrap();
        let repeated = prepare(&node, &selected, 2, MergeProfile::PathMergeV1).unwrap();
        assert_eq!(prepared.source_head, before.basis().id());
        assert_eq!(prepared.subject, selected);
        assert_eq!(prepared.outcome, repeated.outcome);
        assert_eq!(prepared.bundle, repeated.bundle);
        assert_eq!(snapshot(&node).basis(), before.basis());
        let offered = offer(&prepared);
        assert_eq!(offered.merge.base_tip, base);
        assert_ne!(offered.merge.merge_commit, offered.merge.source_tip);
        assert_ne!(offered.merge.merge_commit, offered.merge.target_tip_before);
        assert!(node.read_git_object(offered.merge.merge_commit).is_err());
        let pinned = read(&node, 1, None);
        let original = committed(
            publish(
                &node,
                &offered,
                prepared.bundle.as_deref().unwrap(),
                "land-divergent",
            )
            .unwrap(),
        );
        let after = snapshot(&node);
        let mut expected_refs = before.snapshot().refs.clone();
        expected_refs.insert(offered.merge.target_ref.clone(), offered.merge.merge_commit);
        assert_eq!(after.snapshot().refs, expected_refs);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        let MergePreparation::Clean(plan) = &prepared.outcome else {
            unreachable!();
        };
        for object in &plan.objects {
            assert_eq!(
                node.read_git_object(object.id).unwrap().payload(),
                object.body.as_slice()
            );
            assert!(
                after
                    .selected_closure()
                    .closure()
                    .objects()
                    .contains(&object.id)
            );
        }
        let commit = node.read_git_object(plan.commit).unwrap();
        let body = std::str::from_utf8(commit.payload()).unwrap();
        assert!(body.starts_with(&format!(
            "tree {}\nparent {}\nparent {}\n",
            plan.tree, offered.merge.target_tip_before, offered.merge.source_tip
        )));
        let tree = node.read_git_object(plan.tree).unwrap();
        for path in [b"base.txt\0".as_slice(), b"source.txt\0", b"target.txt\0"] {
            assert!(
                tree.payload()
                    .windows(path.len())
                    .any(|window| window == path)
            );
        }
        let queue = read(&node, 1, None).queue.unwrap();
        assert_eq!(queue.version, version(4));
        assert_eq!(queue.deterministic_order(), vec![pulls[1].number]);
        assert!(queue.active_batch.is_none());
        assert_eq!(read(&node, 1, Some(pinned.source_head)), pinned);
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let decision = history.last().unwrap();
        assert_eq!(decision.batch.decisions.len(), 1);
        assert_eq!(decision.batch.committed_rcrs.len(), 1);
        assert_eq!(decision.forge_events.len(), 3);
        assert_eq!(decision.forge_events[0].version, version(3));
        assert_eq!(decision.forge_events[1].version, version(2));
        assert_eq!(decision.forge_events[2].version, version(4));
        assert_eq!(
            decision.forge_events[1].payload,
            ForgeEventPayload::MergeCommittedNative(offered.merge.clone())
        );
        let head = after.basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // The original terminal result does not need service or candidate bytes.
        assert_eq!(
            publish(&reopened, &offered, b"lost bundle", "land-divergent").unwrap(),
            original
        );
        let mut changed = offered.clone();
        changed.expected_version = version(5);
        assert!(publish(&reopened, &changed, b"", "land-divergent").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), head);
        assert_eq!(read(&reopened, 1, Some(pinned.source_head)), pinned);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn preparation_refuses_wrong_queue_subject_hidden_entries_and_exhausted_construction() {
    let (_scratch, node, pulls, _, _) = fixture(GitHashAlgorithm::Sha256, false);
    let selected = subject(&node, &pulls[0]);
    let before = snapshot(&node);
    assert!(matches!(
        prepare(&node, &selected, 2, MergeProfile::PathMergeV1),
        Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
    ));
    assert!(matches!(
        prepare(
            &node,
            &subject(&node, &pulls[1]),
            1,
            MergeProfile::PathMergeV1
        ),
        Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
    ));
    let mut stale = selected.clone();
    stale.pull_request_version = version(2);
    assert!(matches!(
        prepare(&node, &stale, 1, MergeProfile::PathMergeV1),
        Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
    ));
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(selected.source_ref.as_bytes(), &Default::default())
        .unwrap();
    let request = node.request_context();
    assert!(matches!(
        node.runtime().block_on(node.prepare_queue_head_bundle_in(
            &request,
            QueueNumber::FIRST,
            version(1),
            &selected,
            &hidden,
            &metadata(),
            PreparationLimits::default(),
        )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    assert!(
        node.runtime()
            .block_on(node.prepare_queue_head_bundle_in(
                &request,
                QueueNumber::FIRST,
                version(1),
                &selected,
                &RefVisibility::new(),
                &metadata(),
                PreparationLimits {
                    max_output_bytes: 1,
                    ..Default::default()
                },
            ))
            .is_err()
    );
    request.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.prepare_queue_head_bundle_in(
                &request,
                QueueNumber::FIRST,
                version(1),
                &selected,
                &RefVisibility::new(),
                &metadata(),
                PreparationLimits::default(),
            ))
            .is_err()
    );
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert!(matches!(
        prepare(&node, &selected, 1, MergeProfile::ExactRenamesV1)
            .unwrap()
            .outcome,
        MergePreparation::Clean(_)
    ));
    accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "second-hidden"));
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(pulls[1].data.source_ref.as_bytes(), &Default::default())
        .unwrap();
    assert!(matches!(
        node.runtime().block_on(node.prepare_queue_head_bundle_in(
            &node.request_context(),
            QueueNumber::FIRST,
            version(2),
            &selected,
            &hidden,
            &metadata(),
            PreparationLimits::default(),
        )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    node.shutdown().unwrap();
}

#[test]
fn conflicted_queue_head_returns_no_publishable_candidate_or_canonical_side_effect() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, pulls, base, _) = fixture(format, true);
        let before = snapshot(&node);
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let MergePreparation::Conflicted {
            base: observed,
            conflicts,
        } = prepared.outcome
        else {
            panic!("conflicting edits must not manufacture a merge result");
        };
        assert_eq!(observed, base);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, b"base.txt");
        assert!(prepared.bundle.is_none());
        assert_eq!(snapshot(&node).basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn malformed_unauthenticated_and_cancelled_candidates_never_escape_private_quarantine() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, pulls, _, _) = fixture(format, false);
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let offered = offer(&prepared);
        let bytes = prepared.bundle.unwrap();
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let before = snapshot(&node);
        assert!(publish(&node, &offered, &corrupt, "malformed").is_err());
        assert!(
            node.runtime()
                .block_on(node.land_queue_head_bundle_durable_in(
                    &node.request_context(),
                    &LoopbackReceiveSession::anonymous(),
                    &offered,
                    &bytes,
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        let request = node.request_context();
        request.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.land_queue_head_bundle_durable_in(
                    &request,
                    &session("cancelled"),
                    &offered,
                    &bytes,
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        assert!(node.read_git_object(offered.merge.merge_commit).is_err());
        assert_eq!(
            fs::read_dir(node.storage_root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        committed(publish(&node, &offered, &bytes, "permitted-twin").unwrap());
        node.shutdown().unwrap();
    }
}

#[test]
fn candidate_landing_preserves_queue_pr_policy_and_live_target_guards() {
    let (_scratch, node, pulls, _, advanced) = fixture(GitHashAlgorithm::Sha256, false);
    let prepared = prepare(
        &node,
        &subject(&node, &pulls[0]),
        1,
        MergeProfile::PathMergeV1,
    )
    .unwrap();
    let mut offered = offer(&prepared);
    let original_command = offered.clone();
    let bytes = prepared.bundle.unwrap();
    accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "queue-second"));
    let stale_queue = refused(
        &node,
        &offered,
        &bytes,
        "stale-queue",
        RefusalCode::EvidenceStale,
    );
    offered.expected_version = version(2);
    let mut wrong_head = offered.clone();
    wrong_head.pull_request = pulls[1].number;
    wrong_head.merge.source_ref = pulls[1].data.source_ref.clone();
    refused(
        &node,
        &wrong_head,
        &bytes,
        "non-head",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let mut changed = pulls[0].clone();
    changed.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    changed.action = PullRequestAction::Update;
    changed.data.title = "Updated exact PR observation".into();
    apply_pull(&node, &changed, "update-pr");
    refused(
        &node,
        &offered,
        &bytes,
        "stale-pr",
        RefusalCode::EvidenceStale,
    );
    offered.expected_pull_request_version = version(2);
    let epoch = protect(&node, Vec::new(), "new-policy");
    refused(
        &node,
        &offered,
        &bytes,
        "stale-policy",
        RefusalCode::EvidenceStale,
    );
    offered.expected_policy_epoch = epoch;
    let changed = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session("move-target"),
            &[RefCommand {
                name: offered.merge.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(offered.merge.target_tip_before),
                proposed_new: ProposedNew::Update(advanced),
                force: false,
            }],
            AdmissionLimits::default(),
        ))
        .unwrap();
    for result in changed.commands {
        committed((result.tx_id, result.terminal));
    }
    refused(
        &node,
        &offered,
        &bytes,
        "target-moved",
        RefusalCode::TargetRefMoved,
    );
    assert_eq!(
        publish(&node, &original_command, b"", "stale-queue").unwrap(),
        stale_queue
    );
    node.shutdown().unwrap();
}

#[test]
fn candidate_landing_requires_an_approval_for_the_actual_prepared_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, pulls, _, _) = fixture(format, false);
        let reviewer = PrincipalId::from_bytes([0xa4; 16]);
        protect(
            &node,
            vec![ProtectedBranch {
                require_merge_queue: true,
                name: pulls[0].data.target_ref.clone(),
                required_approvals: 1,
                reviewers: vec![reviewer],
                required_checks: Vec::new(),
            }],
            "candidate-review-policy",
        );
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let offered = offer(&prepared);
        let bytes = prepared.bundle.unwrap();
        let missing = refused(
            &node,
            &offered,
            &bytes,
            "candidate-missing-review",
            RefusalCode::EvidenceMissing,
        );
        let approved = CandidateReviewCommand {
            review: ReviewCommand {
                expected_version: ExpectedVersion::NewStream,
                subject: prepared.subject,
                decision: ReviewDecision::Approve,
                reason: "Inspected the exact two-parent candidate bundle".into(),
            },
            candidate: CandidateBinding {
                merge_base: offered.merge.base_tip,
                commit: offered.merge.merge_commit,
            },
        };
        let reviewer_session = LoopbackReceiveSession::authenticated(
            reviewer,
            IdempotencyKey::new(b"approve-queue-candidate".to_vec()).unwrap(),
        );
        accepted(
            node.runtime()
                .block_on(node.admit_candidate_review_durable_in(
                    &node.request_context(),
                    &reviewer_session,
                    &approved,
                    Some(&bytes),
                    AdmissionLimits::default(),
                )),
        );
        assert_eq!(
            publish(&node, &offered, b"", "candidate-missing-review").unwrap(),
            missing,
            "later approval cannot rewrite the original terminal refusal"
        );
        committed(publish(&node, &offered, &bytes, "candidate-reviewed-land").unwrap());
        assert_eq!(
            snapshot(&node).snapshot().refs[&offered.merge.target_ref],
            offered.merge.merge_commit
        );
        assert!(read(&node, 1, None).queue.unwrap().is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn candidate_landing_preserves_authenticated_policy_evidence_and_exact_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (scratch, node, pulls, _, _) = fixture(format, false);
        let epoch = install_protection(&node, ReviewProtection {
            ref_policy: Some(compile_ref_policy(
                "policy queue_credential { rule verified { when actor.authentication >= single_factor then allow } default deny \"verified credential required\" }"
            ).unwrap()),
            administrators: vec![actor()],
            branches: vec![super::protection::queue_only(pulls[0].data.target_ref.clone())],
        }, "candidate-auth-policy");
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let offered = offer(&prepared);
        assert_eq!(offered.expected_policy_epoch, epoch);
        let bytes = prepared.bundle.unwrap();
        let original_refusal = refused(
            &node,
            &offered,
            &bytes,
            "unverified-candidate",
            RefusalCode::ProtectedRefTransitionDenied,
        );
        let verified = LoopbackReceiveSession::Authenticated(
            crate::AuthenticatedReceiveSession::new(
                actor(),
                IdempotencyKey::new(b"verified-candidate".to_vec()).unwrap(),
            )
            .with_authentication(AdmissionAuthentication::HttpToken),
        );
        let original = committed(
            node.runtime()
                .block_on(node.land_queue_head_bundle_durable_in(
                    &node.request_context(),
                    &verified,
                    &offered,
                    &bytes,
                    AdmissionLimits::default(),
                ))
                .unwrap(),
        );
        assert_authenticated_landing_evidence(&node, original.0);
        let head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            publish(&reopened, &offered, b"", "verified-candidate").unwrap(),
            original
        );
        assert_eq!(
            publish(&reopened, &offered, b"", "unverified-candidate").unwrap(),
            original_refusal
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), head);
        assert_authenticated_landing_evidence(&reopened, original.0);
        reopened.shutdown().unwrap();
    }
}
