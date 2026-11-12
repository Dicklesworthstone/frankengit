use super::tests::{empty, envelope, issue, page, pull};
use super::*;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionCommand};
use fgit_forge::event::milestone::{MilestoneAction, MilestoneCommand};
use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
use fgit_forge::event::review::{ReviewCommand, ReviewDecision, ReviewSubject};
use fgit_forge::{
    DiscussionNumber, ExpectedVersion, IssueNumber, MilestoneNumber, PullRequestNumber,
};
use fgit_types::PrincipalId;
use std::cell::Cell;
use std::collections::BTreeSet;

fn all() -> ForgeEventReadGrants {
    ForgeEventReadGrants {
        issues: true,
        pulls: true,
        discussions: true,
        reviews: true,
    }
}

fn discussion_command(body: &str) -> DiscussionCommand {
    DiscussionCommand {
        number: DiscussionNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: DiscussionAction::Open {
            title: "A discussion".into(),
            body: body.into(),
        },
    }
}

fn discussion(body: &str) -> ForgeEvent {
    discussion_command(body)
        .proposed_event(PrincipalId::from_bytes([0x37; 16]))
        .unwrap()
}

fn milestone_command() -> MilestoneCommand {
    MilestoneCommand {
        number: MilestoneNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: MilestoneAction::Open {
            title: "Release".into(),
            body: "Milestone body".into(),
            due_at: Some(1),
        },
    }
}

fn milestone() -> ForgeEvent {
    milestone_command()
        .proposed_event(PrincipalId::from_bytes([0x38; 16]))
        .unwrap()
}

fn review() -> ForgeEvent {
    let ForgeEventPayload::PullRequestChangedNative(pull) = pull().payload else {
        unreachable!()
    };
    ReviewCommand {
        expected_version: ExpectedVersion::NewStream,
        subject: ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: pull.data.source_ref,
            target_ref: pull.data.target_ref,
            source_tip: pull.data.source_tip,
            target_tip: pull.data.target_tip,
            policy_epoch: PolicyEpoch::FIRST,
        },
        decision: ReviewDecision::Approve,
        reason: "Reviewed".into(),
    }
    .proposed_event(PrincipalId::from_bytes([0x39; 16]), GitHashAlgorithm::Sha1)
    .unwrap()
}

fn comment(body: &str) -> ForgeEvent {
    PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        body: body.into(),
        anchor: None,
    }
    .proposed_event(PrincipalId::from_bytes([0x3a; 16]))
    .unwrap()
}

fn visible() -> collaboration::Visibility {
    collaboration::Visibility {
        reviews: BTreeSet::from([PullRequestNumber::FIRST]),
        conversations: BTreeSet::from([PullRequestNumber::FIRST]),
    }
}

fn result(grants: ForgeEventReadGrants, after: Option<(u64, u32)>) -> ScopedForgeEventPage {
    let mut result = empty(grants.issues, grants.pulls, after);
    result.profile = ForgeEventDisclosureProfile::CollaborationV2;
    result.discussions_read = grants.discussions;
    result.reviews_read = grants.reviews;
    result
}

fn select(
    raw: ForgeEventPage,
    grants: ForgeEventReadGrants,
    visibility: &collaboration::Visibility,
    after: Option<(u64, u32)>,
) -> ScopedForgeEventPage {
    let mut result = result(grants, after);
    project_authorized(
        &mut result,
        raw,
        after,
        100,
        &|event| collaboration::permitted(event, grants, visibility, &|_| false),
        &|| false,
    )
    .unwrap();
    result
}

#[test]
fn collaboration_profile_is_explicit_and_each_family_needs_its_own_read_grant() {
    let events = vec![
        envelope(1, issue("Issue")),
        envelope(2, pull()),
        envelope(3, milestone()),
        envelope(4, discussion("Discussion")),
        envelope(5, review()),
        envelope(6, comment("Comment")),
    ];
    for mask in 0..16 {
        let grants = ForgeEventReadGrants {
            issues: mask & 1 != 0,
            pulls: mask & 2 != 0,
            discussions: mask & 4 != 0,
            reviews: mask & 8 != 0,
        };
        let selected = select(page(events.clone(), false), grants, &visible(), None);
        let expected: Vec<_> = [
            (1, 8, grants.issues),
            (2, 6, grants.pulls),
            (3, 22, grants.issues),
            (4, 24, grants.discussions),
            (5, 7, grants.reviews),
            (6, 12, grants.pulls),
        ]
        .into_iter()
        .filter_map(|(sequence, kind, granted)| granted.then_some(((sequence, 0), kind)))
        .collect();
        assert_eq!(
            selected
                .events()
                .iter()
                .map(|e| (e.cursor(), e.kind()))
                .collect::<Vec<_>>(),
            expected,
            "grant mask {mask}"
        );
        for item in selected.events() {
            let original = events
                .iter()
                .find(|e| position(e.cursor) == item.cursor())
                .unwrap();
            assert_eq!(
                item.frame_hex(),
                hex(&encode_body(&original.event).unwrap()).unwrap()
            );
        }
        assert_eq!(selected.resume_after(), Some((6, 0)));
        let json = selected.to_json().unwrap();
        assert!(json.contains("\"disclosure_profile\":\"collaboration-v2\""));
        assert!(json.contains(&format!("\"discussions_read\":{}", grants.discussions)));
        assert!(json.contains(&format!("\"reviews_read\":{}", grants.reviews)));
    }

    let mut legacy = empty(true, true, None);
    project(
        &mut legacy,
        page(events.clone(), false),
        None,
        100,
        &|_| false,
        &|| false,
    )
    .unwrap();
    let mut old_families = empty(true, true, None);
    project(
        &mut old_families,
        page(events[..2].to_vec(), false),
        None,
        100,
        &|_| false,
        &|| false,
    )
    .unwrap();
    old_families.resume_after = Some((6, 0));
    assert_eq!(legacy.to_json().unwrap(), old_families.to_json().unwrap());
    assert!(!legacy.to_json().unwrap().contains("discussions_read"));
    assert!(!legacy.to_json().unwrap().contains("reviews_read"));
    assert_eq!(
        all().for_profile(ForgeEventDisclosureProfile::IssuesPullsV1),
        ForgeEventReadGrants {
            issues: true,
            pulls: true,
            discussions: false,
            reviews: false,
        }
    );
}

#[test]
fn reviews_and_comments_require_canonical_visibility_and_matching_aggregate_identities() {
    let allowed = |event: &ForgeEvent, visibility: &collaboration::Visibility| {
        collaboration::permitted(event, all(), visibility, &|_| false)
    };
    for event in [review(), comment("Comment")] {
        assert!(!allowed(&event, &collaboration::Visibility::default()));
        assert!(allowed(&event, &visible()));
    }
    for hidden in [
        b"refs/heads/topic".as_slice(),
        b"refs/heads/main".as_slice(),
    ] {
        assert!(!collaboration::permitted(
            &review(),
            all(),
            &visible(),
            &|name| name == hidden
        ));
    }
    for mut event in [
        milestone(),
        discussion("Body"),
        review(),
        comment("Comment"),
    ] {
        event.aggregate = AggregateId::Issue(IssueNumber::FIRST);
        assert!(!allowed(&event, &visible()));
    }
    let mut mismatched_number = review();
    let ForgeEventPayload::PullRequestReviewedNative(event) = &mut mismatched_number.payload else {
        unreachable!()
    };
    event.subject.pull_request = PullRequestNumber::try_new(2).unwrap();
    assert!(!allowed(&mismatched_number, &visible()));
    let mut mismatched_reviewer = review();
    let ForgeEventPayload::PullRequestReviewedNative(event) = &mut mismatched_reviewer.payload
    else {
        unreachable!()
    };
    event.reviewer = PrincipalId::from_bytes([0xff; 16]);
    assert!(!allowed(&mismatched_reviewer, &visible()));
}

#[test]
fn private_recipient_preferences_and_ungranted_invalid_frames_are_never_encoded() {
    use fgit_forge::event::notification::{
        NotificationAction, NotificationCommand, NotificationMode, NotificationTarget,
    };
    for target in [
        NotificationTarget::Issue(IssueNumber::FIRST),
        NotificationTarget::Discussion(DiscussionNumber::FIRST),
        NotificationTarget::PullRequest(PullRequestNumber::FIRST),
    ] {
        let private = NotificationCommand {
            target,
            expected_version: ExpectedVersion::NewStream,
            action: NotificationAction::SetMode(NotificationMode::Muted),
        }
        .proposed_event(PrincipalId::from_bytes([0x42; 16]))
        .unwrap();
        let private_frame = hex(&encode_body(&private).unwrap()).unwrap();
        let selected = select(
            page(
                vec![envelope(1, private), envelope(2, discussion("Public"))],
                false,
            ),
            all(),
            &visible(),
            None,
        );
        assert_eq!(selected.events().len(), 1);
        assert_eq!(selected.events()[0].kind(), 24);
        assert!(!selected.to_json().unwrap().contains(&private_frame));
        assert_eq!(selected.resume_after(), Some((2, 0)));
    }

    let mut invalid = discussion("Body");
    let ForgeEventPayload::DiscussionChangedNative(change) = &mut invalid.payload else {
        unreachable!()
    };
    change.action = DiscussionAction::Comment {
        body: "invalid\0private".into(),
    };
    assert!(encode_body(&invalid).is_err());
    let grants = ForgeEventReadGrants {
        issues: true,
        ..Default::default()
    };
    let filtered = select(
        page(vec![envelope(1, invalid.clone())], true),
        grants,
        &visible(),
        None,
    );
    assert!(filtered.events().is_empty());
    assert_eq!(filtered.next_after(), Some((1, 0)));
    assert_eq!(filtered.resume_after(), Some((1, 0)));
    let mut disclosed = result(all(), None);
    assert!(matches!(
        project_authorized(
            &mut disclosed,
            page(vec![envelope(1, invalid)], false),
            None,
            100,
            &|event| collaboration::permitted(event, all(), &visible(), &|_| false),
            &|| false,
        ),
        Err(ForgeEventReadRefusal::InvalidPage)
    ));
}

#[test]
fn collaboration_frame_splits_keep_exact_source_positions_and_resume_every_event() {
    let events: Vec<_> = (1..=12)
        .map(|sequence| envelope(sequence, discussion(&"d".repeat(65_536))))
        .collect();
    let grants = ForgeEventReadGrants {
        discussions: true,
        ..Default::default()
    };
    let first = select(page(events.clone(), false), grants, &visible(), None);
    let cursor = first
        .next_after()
        .expect("bounded frame page splits before EOF");
    assert_eq!(Some(cursor), first.resume_after());
    assert!(first.events().len() < events.len());
    let second = select(
        page(
            events
                .into_iter()
                .filter(|e| position(e.cursor) > cursor)
                .collect(),
            false,
        ),
        grants,
        &visible(),
        Some(cursor),
    );
    let positions: Vec<_> = first
        .events()
        .iter()
        .chain(second.events())
        .map(|e| e.cursor())
        .collect();
    assert_eq!(
        positions,
        (1..=12).map(|sequence| (sequence, 0)).collect::<Vec<_>>()
    );
    assert_eq!(second.next_after(), None);
    assert_eq!(second.resume_after(), Some((12, 0)));
    assert!(first.to_json().unwrap().len() <= MAX_JSON_BYTES);
    assert!(second.to_json().unwrap().len() <= MAX_JSON_BYTES);
}

#[test]
fn collaboration_projection_checks_cancellation_before_output_and_between_events() {
    let grants = ForgeEventReadGrants {
        discussions: true,
        ..Default::default()
    };
    for stop_at in 0..4 {
        let calls = Cell::new(0);
        let cancelled = || {
            let position = calls.get();
            calls.set(position + 1);
            position == stop_at
        };
        let mut selected = result(grants, None);
        assert!(matches!(
            project_authorized(
                &mut selected,
                page(
                    vec![
                        envelope(1, discussion("One")),
                        envelope(2, discussion("Two"))
                    ],
                    false
                ),
                None,
                100,
                &|event| collaboration::permitted(event, grants, &visible(), &|_| false),
                &cancelled,
            ),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
    }
}

// Exercise the production admission and persistence boundaries, without a
// worktree, external Git, a substitute repository or fabricated event history.
mod native {
    use super::*;
    use crate::{LoopbackReceiveSession, NodeConfig};
    use fgit_admission::AdmissionLimits;
    use fgit_authority::{IdempotencyKey, TerminalOutcome};
    use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
    use fgit_forge::event::pull_request_comment::{
        SourceCommentAnchor, SourceCommentComparison, SourceCommentSide,
    };
    use fgit_forge::initial_commit::InitialCommitPlan;
    use fgit_forge::preparation::MergeMetadata;
    use fgit_types::{DecisionOutcome, HeadGeneration, RefName};
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
                "fg-collaboration-feed-{}-{}",
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
                TenantId::from_bytes([0xda; 16]),
                RepositoryId::from_bytes([0xdb; 16]),
            )
            .with_object_format(self.format)
            .with_worker_threads(2)
        }
        fn node(&self) -> &OneNode {
            self.node.as_ref().unwrap()
        }
        fn reopen(&mut self) {
            self.node.take().unwrap().shutdown().unwrap();
            let mut node = OneNode::open_existing(self.config()).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            self.node = Some(node);
        }
        fn initial(&self, name: &[u8], content: &str, key: &str) -> InitialCommitPlan {
            let node = self.node();
            let request = node.request_context();
            let reference = RefName::try_new(name).unwrap();
            let patch = format!(
                "diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+{content}\n"
            );
            let (_, plan, bundle) = node
                .runtime()
                .block_on(node.prepare_trusted_initial_patch_in(
                    &request,
                    &reference,
                    patch.as_bytes(),
                    &MergeMetadata {
                        author: "Fixture <fixture@example.invalid>".into(),
                        committer: "Fixture <fixture@example.invalid>".into(),
                        timestamp: 1,
                        message: b"event-feed fixture\n".to_vec(),
                    },
                    Default::default(),
                    None,
                ))
                .unwrap();
            let applied = node
                .runtime()
                .block_on(node.apply_initial_patch_bundle_durable_in(
                    &request,
                    &session(key),
                    &reference,
                    plan.commit,
                    bundle.bytes(),
                    AdmissionLimits::default(),
                ))
                .unwrap();
            assert!(applied.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            )));
            plan
        }
        fn pull(&self) -> PullRequestData {
            let base = self.initial(b"refs/heads/main", "before", "initial-main");
            let source = self.initial(b"refs/heads/topic", "after", "initial-topic");
            let data = PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: source.commit,
                target_tip: base.commit,
                title: "Native pull request".into(),
                body: "Canonical conversation".into(),
            };
            let node = self.node();
            let request = node.request_context();
            committed(
                node.runtime()
                    .block_on(node.admit_pull_request_durable_in(
                        &request,
                        &session("open-pull"),
                        &PullRequestCommand {
                            number: PullRequestNumber::FIRST,
                            expected_version: ExpectedVersion::NewStream,
                            action: PullRequestAction::Open,
                            data: data.clone(),
                        },
                        AdmissionLimits::default(),
                    ))
                    .unwrap(),
            );
            self.comment(
                ExpectedVersion::NewStream,
                "First plain comment",
                None,
                "comment-one",
            );
            self.comment(
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                "Anchored comment",
                Some(SourceCommentAnchor {
                    pull_request_version: AggregateVersion::FIRST,
                    source_ref: data.source_ref.clone(),
                    target_ref: data.target_ref.clone(),
                    source_tip: source.commit,
                    target_tip: base.commit,
                    compared_base: base.commit,
                    comparison: SourceCommentComparison::Direct,
                    path: b"file".to_vec(),
                    side: SourceCommentSide::After,
                    blob: source.files[0].blob,
                    mode: 0o100644,
                    byte_start: 0,
                    byte_end: 6,
                    line_start: 0,
                    line_count: 1,
                }),
                "comment-two",
            );
            data
        }
        fn comment(
            &self,
            expected_version: ExpectedVersion,
            body: &str,
            anchor: Option<SourceCommentAnchor>,
            key: &str,
        ) {
            let node = self.node();
            let request = node.request_context();
            committed(
                node.runtime()
                    .block_on(node.admit_pull_request_comment_durable_in(
                        &request,
                        &session(key),
                        &PullRequestCommentCommand {
                            number: PullRequestNumber::FIRST,
                            expected_version,
                            body: body.into(),
                            anchor,
                        },
                        AdmissionLimits::default(),
                    ))
                    .unwrap(),
            );
        }
        fn discussion(&self, command: &DiscussionCommand, key: &str) {
            let node = self.node();
            let request = node.request_context();
            committed(
                node.runtime()
                    .block_on(node.admit_discussion_durable_in(
                        &request,
                        &session(key),
                        command,
                        AdmissionLimits::default(),
                    ))
                    .unwrap(),
            );
        }
        fn milestone(&self) {
            let node = self.node();
            let request = node.request_context();
            committed(
                node.runtime()
                    .block_on(node.admit_milestone_durable_in(
                        &request,
                        &session("milestone"),
                        &milestone_command(),
                        AdmissionLimits::default(),
                    ))
                    .unwrap(),
            );
        }
        fn read(
            &self,
            after: Option<(u64, u32)>,
            limit: u16,
            head: Option<RepositoryAuthorityHeadId>,
            grants: ForgeEventReadGrants,
        ) -> Result<ScopedForgeEventPage, ForgeEventReadRefusal> {
            let node = self.node();
            let request = node.request_context();
            node.runtime().block_on(node.read_profiled_forge_events_in(
                &request,
                after,
                limit,
                head,
                ForgeEventDisclosureProfile::CollaborationV2,
                grants,
            ))
        }
        fn raw(&self) -> ForgeEventPage {
            let node = self.node();
            let request = node.request_context();
            node.runtime()
                .block_on(node.read_forge_events_in(&request, None, 100, None))
                .unwrap()
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
    fn session(key: &str) -> LoopbackReceiveSession {
        LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xdc; 16]),
            IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
        )
    }
    fn committed(result: (TxId, TerminalOutcome)) {
        assert!(
            matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
            "{result:?}"
        );
    }

    #[test]
    fn native_collaboration_feed_preserves_frames_pagination_and_reopen_in_both_git_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut fixture = Fixture::new(format);
            fixture.milestone();
            fixture.discussion(
                &discussion_command("A durable discussion"),
                "open-discussion",
            );
            fixture.pull();
            let raw = fixture.raw();
            assert_eq!(
                raw.events
                    .iter()
                    .map(|e| e.event.payload.kind())
                    .collect::<Vec<_>>(),
                vec![22, 24, 6, 12, 15]
            );
            let full = fixture.read(None, 100, None, all()).unwrap();
            assert_eq!(full.events().len(), raw.events.len());
            assert_eq!(full.source_head(), raw.source_head);
            for (disclosed, canonical) in full.events().iter().zip(&raw.events) {
                assert_eq!(disclosed.cursor(), position(canonical.cursor));
                assert_eq!(disclosed.tx_id(), canonical.tx_id);
                assert_eq!(disclosed.policy_epoch(), canonical.policy_epoch);
                assert_eq!(
                    disclosed.frame_hex(),
                    hex(&encode_body(&canonical.event).unwrap()).unwrap()
                );
            }
            let grants = ForgeEventReadGrants {
                discussions: true,
                ..Default::default()
            };
            let mut after = None;
            let mut emitted = Vec::new();
            let mut filtered_pages = 0;
            loop {
                let next = fixture
                    .read(after, 1, Some(full.source_head()), grants)
                    .unwrap();
                filtered_pages += usize::from(next.events().is_empty());
                emitted.extend(next.events().iter().map(|e| (e.cursor(), e.kind())));
                assert!(next.resume_after() > after);
                after = next.resume_after();
                if next.next_after().is_none() {
                    break;
                }
            }
            assert_eq!(emitted, vec![(position(raw.events[1].cursor), 24)]);
            assert_eq!(filtered_pages, 4);
            assert_eq!(after, full.resume_after());
            let before = full.to_json().unwrap();
            fixture.reopen();
            assert_eq!(
                fixture
                    .read(None, 100, Some(full.source_head()), all())
                    .unwrap()
                    .to_json()
                    .unwrap(),
                before
            );
            fixture.discussion(
                &DiscussionCommand {
                    number: DiscussionNumber::FIRST,
                    expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    action: DiscussionAction::Comment {
                        body: "After reopen".into(),
                    },
                },
                "later-discussion",
            );
            assert!(matches!(
                fixture.read(after, 1, Some(full.source_head()), all()),
                Err(ForgeEventReadRefusal::SnapshotMoved)
            ));
            let continued = fixture.read(after, 1, None, grants).unwrap();
            assert_eq!(continued.events().len(), 1);
            assert_eq!(continued.events()[0].kind(), 24);
            assert!(continued.events()[0].cursor() > after.unwrap());
            assert_eq!(continued.next_after(), None);
        }
    }

    #[test]
    fn canonical_visibility_is_bound_to_the_selected_head_and_current_pr_refs() {
        let fixture = Fixture::new(GitHashAlgorithm::Sha1);
        let data = fixture.pull();
        let node = fixture.node();
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.event_read_basis_in(&request, None))
            .unwrap();
        let raw = fixture.raw();
        let plain = raw
            .events
            .iter()
            .find(|e| e.event.payload.kind() == 12)
            .unwrap()
            .clone();
        // Only the first plain comment is in the event page. Canonical
        // conversation validation still includes the later anchored comment.
        let plain_page = ForgeEventPage {
            source_head: raw.source_head,
            events: vec![plain],
            next_after: None,
        };
        let visible = node
            .runtime()
            .block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &selected.basis,
                &plain_page,
                all(),
                &|_| false,
                &|| false,
            ))
            .unwrap();
        assert!(visible.conversations.contains(&PullRequestNumber::FIRST));
        for reference in [data.source_ref.as_bytes(), data.target_ref.as_bytes()] {
            let hidden = node
                .runtime()
                .block_on(collaboration::read_visibility_at(
                    &node.authority,
                    request.authority(),
                    &selected.basis,
                    &plain_page,
                    all(),
                    &|name| name == reference,
                    &|| false,
                ))
                .unwrap();
            assert!(hidden.conversations.is_empty());
            assert!(!collaboration::permitted(
                &plain_page.events[0].event,
                all(),
                &hidden,
                &|name| name == reference
            ));
        }

        // These deliberately constructed review inputs test the metadata
        // resolver, not durable review admission. Event refs alone cannot
        // authorize a review when its current canonical PR is undisclosed.
        let mut review = super::review();
        let ForgeEventPayload::PullRequestReviewedNative(event) = &mut review.payload else {
            unreachable!()
        };
        event.subject.source_ref = RefName::try_new(b"refs/heads/old-public-source").unwrap();
        event.subject.target_ref = RefName::try_new(b"refs/heads/old-public-target").unwrap();
        let review_page = ForgeEventPage {
            source_head: raw.source_head,
            events: vec![envelope(1, review.clone())],
            next_after: None,
        };
        let public_review = node
            .runtime()
            .block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &selected.basis,
                &review_page,
                all(),
                &|_| false,
                &|| false,
            ))
            .unwrap();
        assert!(public_review.reviews.contains(&PullRequestNumber::FIRST));
        let hidden_review = node
            .runtime()
            .block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &selected.basis,
                &review_page,
                all(),
                &|name| name == data.source_ref.as_bytes(),
                &|| false,
            ))
            .unwrap();
        assert!(hidden_review.reviews.is_empty());

        committed(
            node.runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &request,
                    &session("update-pull"),
                    &PullRequestCommand {
                        number: PullRequestNumber::FIRST,
                        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                        action: PullRequestAction::Update,
                        data: PullRequestData {
                            title: "New PR version".into(),
                            ..data
                        },
                    },
                    AdmissionLimits::default(),
                ))
                .unwrap(),
        );
        let advanced = node
            .runtime()
            .block_on(node.event_read_basis_in(&request, None))
            .unwrap();
        assert_ne!(selected.basis.id(), advanced.basis.id());
        let ForgeEventPayload::PullRequestReviewedNative(event) = &mut review.payload else {
            unreachable!()
        };
        event.subject.pull_request_version = AggregateVersion::try_new(2).unwrap();
        let mut future_review = ForgeEventPage {
            source_head: selected.basis.id(),
            events: vec![envelope(1, review)],
            next_after: None,
        };
        assert!(matches!(
            node.runtime().block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &selected.basis,
                &future_review,
                all(),
                &|_| false,
                &|| false,
            )),
            Err(ForgeEventReadRefusal::InvalidPage)
        ));
        future_review.source_head = advanced.basis.id();
        let fresh = node
            .runtime()
            .block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &advanced.basis,
                &future_review,
                all(),
                &|_| false,
                &|| false,
            ))
            .unwrap();
        assert!(fresh.reviews.contains(&PullRequestNumber::FIRST));
        assert!(matches!(
            node.runtime().block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &selected.basis,
                &future_review,
                all(),
                &|_| false,
                &|| false,
            )),
            Err(ForgeEventReadRefusal::InvalidPage)
        ));
        assert!(matches!(
            node.runtime().block_on(collaboration::read_visibility_at(
                &node.authority,
                request.authority(),
                &advanced.basis,
                &future_review,
                all(),
                &|_| false,
                &|| true,
            )),
            Err(ForgeEventReadRefusal::Cancelled)
        ));
        assert!(matches!(
            node.runtime().block_on(node.read_profiled_forge_events_in(
                &request,
                None,
                0,
                None,
                ForgeEventDisclosureProfile::CollaborationV2,
                ForgeEventReadGrants::default(),
            )),
            Err(ForgeEventReadRefusal::NoReadScope)
        ));
        assert!(matches!(
            node.runtime().block_on(node.read_profiled_forge_events_in(
                &request,
                None,
                100,
                None,
                ForgeEventDisclosureProfile::IssuesPullsV1,
                ForgeEventReadGrants {
                    discussions: true,
                    reviews: true,
                    ..Default::default()
                },
            )),
            Err(ForgeEventReadRefusal::NoReadScope)
        ));
    }
}
