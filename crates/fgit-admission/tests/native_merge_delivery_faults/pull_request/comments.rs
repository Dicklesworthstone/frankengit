//! The real discussion admission driver over the existing faultable model.
//! This is canonical publication/retry evidence, not filesystem crash evidence.
use super::*;
use fgit_admission::merge::native::pull_request::comments as conversation;
use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
use fgit_forge::{AggregateVersion, ForgeEventPayload};

fn opened(format: GitHashAlgorithm) -> PrFixture {
    PrFixture::new(format, PullRequestAction::Update).with_key(b"comment-first")
}

fn command(previous: u64, body: &str) -> PullRequestCommentCommand {
    PullRequestCommentCommand {
        number: PullRequestNumber::FIRST,
        expected_version: AggregateVersion::try_new(previous)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        body: body.into(),
    }
}

fn submit(
    case: &PrFixture,
    command: &PullRequestCommentCommand,
) -> Result<TerminalOutcome, AdmissionError> {
    poll_ready(conversation::admit_async(
        case.fixture.store.as_ref(),
        &(),
        &case.fixture.context,
        command,
        AdmissionLimits::default(),
        &case.projection,
    ))
}

fn tx(case: &PrFixture, command: &PullRequestCommentCommand) -> TxId {
    conversation::proposal(&case.fixture.context, command)
        .unwrap()
        .1
        .derive()
        .unwrap()
        .0
}

fn basis(case: &PrFixture) -> PublicationBasis {
    let head = case.fixture.head();
    PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    )
}

fn read(
    case: &PrFixture,
    basis: &PublicationBasis,
    after: u64,
    limit: u16,
) -> conversation::PullRequestCommentsPage {
    poll_ready(conversation::read_page_at(
        case.fixture.store.as_ref(),
        &(),
        basis,
        PullRequestNumber::FIRST,
        after,
        limit,
        &|_, _| true,
        &|| false,
    ))
    .unwrap()
    .unwrap()
}

fn assert_one_comment(
    case: &PrFixture,
    command: &PullRequestCommentCommand,
    before: &RepositoryAuthorityHeadBody,
) {
    let after = case.fixture.head();
    assert_eq!(after.ref_root, before.ref_root);
    assert_eq!(after.retention_root, before.retention_root);
    assert_eq!(after.policy_epoch, before.policy_epoch);
    assert_ne!(after.forge_position_root, before.forge_position_root);
    assert_ne!(after.outbox_root, before.outbox_root);
    let (_, state) = selected_state(&case.fixture);
    let pr = AsciiSlug::from_static("pull-request/1");
    let before_forge: CanonicalForgePositionState = case
        .fixture
        .store
        .read(
            case.fixture.context.repository_id,
            POSITION_NAMESPACE,
            before.forge_position_root,
        )
        .unwrap();
    assert_eq!(state.forge.entry(pr), before_forge.entry(pr));
    assert_eq!(
        state
            .forge
            .entry(AsciiSlug::from_static("conversation/1"))
            .unwrap()
            .successor_position(),
        1
    );
    assert_eq!(
        state
            .outbox
            .entries()
            .iter()
            .filter(|entry| entry.tx_id() == tx(case, command))
            .count(),
        1
    );
    let page = read(case, &basis(case), 0, 10);
    assert_eq!(page.discussion_version.unwrap().get(), 1);
    assert_eq!(page.comments.len(), 1);
    assert_eq!(page.comments[0].body, command.body);
    assert_eq!(page.comments[0].actor, case.fixture.context.principal_id);
    assert_eq!(page.next_after, None);
    let batch =
        read_decision_batch_body(&case.fixture.store.backend, after.decision_tail_id.unwrap())
            .unwrap();
    assert_eq!(batch.committed_rcrs.len(), 1);
    let event = conversation::proposal(&case.fixture.context, command)
        .unwrap()
        .0;
    assert_eq!(
        batch.committed_rcrs[0].forge_event_batch_root,
        evidence_root(&ForgeEventBatch::of_one(event)).unwrap()
    );
}

#[test]
fn native_comment_publication_retries_and_independent_metadata_versions_survive_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let case = opened(format);
        let initial = basis(&case);
        let empty = read(&case, &initial, 0, 10);
        assert!(empty.discussion_version.is_none() && empty.comments.is_empty());
        let first = command(0, "Original <script>inert</script> discussion é");
        let terminal = submit(&case, &first).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_one_comment(&case, &first, initial.body());
        let first_basis = basis(&case);
        assert_eq!(submit(&case, &first).unwrap(), terminal);
        assert_eq!(basis(&case).id(), first_basis.id());
        assert!(submit(&case, &command(0, "Changed meaning under original key")).is_err());
        assert_eq!(basis(&case).id(), first_basis.id());

        let update = case.with_key(b"metadata-after-comment");
        assert!(matches!(
            update.run().unwrap().outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(submit(&case, &first).unwrap(), terminal);
        let second = case.with_key(b"comment-second");
        assert!(matches!(
            submit(&second, &command(1, "Second author message"))
                .unwrap()
                .outcome,
            DecisionOutcome::Committed { .. }
        ));
        let final_basis = basis(&case);
        let first_page = read(&case, &final_basis, 0, 1);
        assert_eq!(first_page.discussion_version.unwrap().get(), 2);
        assert_eq!(first_page.next_after, Some(1));
        let second_page = read(&case, &final_basis, 1, 1);
        assert_eq!(second_page.comments[0].body, "Second author message");
        assert_eq!(second_page.next_after, None);
        assert_eq!(read(&case, &final_basis, 0, 1), first_page);
        assert_eq!(
            read(&case, &first_basis, 0, 1)
                .discussion_version
                .unwrap()
                .get(),
            1
        );
        assert!(read(&case, &initial, 0, 1).comments.is_empty());
        assert_eq!(
            selected_state(&case.fixture)
                .1
                .forge
                .entry(AsciiSlug::from_static("pull-request/1"))
                .unwrap()
                .successor_position(),
            2
        );
    }
}

#[test]
fn native_comment_cancellation_or_ambiguous_cas_never_duplicates_the_conversation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for cancellation in [CANCEL_BEFORE_SEAL, CANCEL_BEFORE_PUBLICATION] {
            let case = opened(format);
            let before = case.fixture.head();
            let command = command(0, "Retry this exact comment");
            case.projection
                .cancellation
                .store(cancellation, Ordering::SeqCst);
            assert!(matches!(
                submit(&case, &command),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
            assert_eq!(case.fixture.head(), before);
            assert_eq!(
                case.fixture.outcome(tx(&case, &command)),
                OutcomeLookup::Undecided
            );
            case.projection.cancellation.store(LIVE, Ordering::SeqCst);
            let terminal = submit(&case, &command).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_one_comment(&case, &command, &before);
            let after = case.fixture.head();
            assert_eq!(submit(&case, &command).unwrap(), terminal);
            assert_eq!(case.fixture.head(), after);
        }
        for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let case = opened(format);
            let before = case.fixture.head();
            let command = command(0, "Ambiguous response is not rollback");
            case.fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    fault,
                )]));
            assert!(matches!(
                submit(&case, &command),
                Err(AdmissionError::Outcome(_))
            ));
            let observed = case.fixture.outcome(tx(&case, &command));
            assert_eq!(
                matches!(observed, OutcomeLookup::Decided(_)),
                fault == FaultKind::LoseResponse
            );
            case.fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::none());
            let terminal = submit(&case, &command).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_one_comment(&case, &command, &before);
            let after = case.fixture.head();
            assert_eq!(submit(&case, &command).unwrap(), terminal);
            assert_eq!(case.fixture.head(), after);
        }
    }
}

#[test]
fn competing_first_comments_cannot_merge_or_relabel_the_losing_command() {
    let case = opened(GitHashAlgorithm::Sha256);
    let competitor = Arc::new(case.with_key(b"competing-comment"));
    let before = case.fixture.head();
    let winner_command = command(0, "Winning discussion");
    let losing_command = command(0, "Losing discussion");
    let winner = Arc::new(Mutex::new(None));
    let captured = winner.clone();
    let competing = competitor.clone();
    *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        *captured.lock().unwrap() = Some(submit(&competing, &winner_command).unwrap());
    }));
    let losing = submit(&case, &losing_command).unwrap();
    assert!(matches!(
        losing.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            ..
        }
    ));
    assert!(matches!(
        winner.lock().unwrap().unwrap().outcome,
        DecisionOutcome::Committed { .. }
    ));
    let after = case.fixture.head();
    assert_eq!(after.ref_root, before.ref_root);
    let page = read(&case, &basis(&case), 0, 10);
    assert_eq!(page.comments.len(), 1);
    assert_eq!(page.comments[0].body, "Winning discussion");
    assert_eq!(submit(&case, &losing_command).unwrap(), losing);
    assert_eq!(case.fixture.head(), after);
}

#[test]
fn missing_pr_refuses_and_visibility_or_cancellation_never_becomes_partial_history() {
    let missing = PrFixture::new(GitHashAlgorithm::Sha1, PullRequestAction::Open)
        .with_key(b"comment-missing-pr");
    let before = missing.fixture.head();
    let terminal = submit(&missing, &command(0, "Cannot create a PR by commenting")).unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceMissing,
            ..
        }
    ));
    assert_eq!(
        missing.fixture.head().forge_position_root,
        before.forge_position_root
    );
    let case = opened(GitHashAlgorithm::Sha1);
    submit(
        &case,
        &command(0, "Visible only through both PR references"),
    )
    .unwrap();
    let selected = basis(&case);
    for source_hidden in [true, false] {
        let visible = |source: &RefName, target: &RefName| {
            if source_hidden {
                source != &case.command.data.source_ref
            } else {
                target != &case.command.data.target_ref
            }
        };
        assert!(
            poll_ready(conversation::read_page_at(
                case.fixture.store.as_ref(),
                &(),
                &selected,
                PullRequestNumber::FIRST,
                0,
                10,
                &visible,
                &|| false
            ))
            .unwrap()
            .is_none()
        );
    }
    assert!(matches!(
        poll_ready(conversation::read_page_at(
            case.fixture.store.as_ref(),
            &(),
            &selected,
            PullRequestNumber::FIRST,
            0,
            10,
            &|_, _| true,
            &|| true
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert_eq!(read(&case, &selected, 0, 10).comments.len(), 1);
    let stored = conversation::proposal(
        &case.fixture.context,
        &command(0, "Visible only through both PR references"),
    )
    .unwrap()
    .0;
    assert!(matches!(
        stored.payload,
        ForgeEventPayload::PullRequestCommentedNative(_)
    ));
}
