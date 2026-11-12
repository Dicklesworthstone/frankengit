//! Cancellation checkpoints and model-store crashes on the ordinary metadata path.
//! The reference store models lost effects; it is not filesystem crash evidence.
use super::*;

struct CancelProjection {
    inner: Projection,
    at_publication: bool,
}

impl AsyncAdmissionProjection<Model> for CancelProjection {
    fn snapshot_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, authenticated)
    }

    fn materialize_commit_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_commit_async(store, cx, basis, request, fold, closure)
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(store, cx, basis, tx_id, code)
    }
}

impl NativeMergeProjection<Model> for CancelProjection {
    fn merge_checkpoint(&self, (): &()) -> Result<(), RefusalCode> {
        if self.at_publication {
            Ok(())
        } else {
            Err(RefusalCode::CancellationInProgress)
        }
    }

    fn merge_publication_checkpoint(&self, (): &()) -> Result<(), RefusalCode> {
        Err(RefusalCode::CancellationInProgress)
    }

    fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner
            .resolve_merge_basis_async(store, cx, basis, authenticated)
    }

    fn validate_merge_async<'a>(
        &'a self,
        store: &'a Model,
        cx: &'a (),
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.inner
            .validate_merge_async(store, cx, basis, authenticated, intent)
    }
}

#[test]
fn cancellation_before_seal_or_publication_remains_undecided_and_retries_once() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for at_publication in [false, true] {
            let fixture = opened(format);
            let before = fixture.head();
            let context = context(&fixture, b"cancelled-append");
            let mutation = append("Original comment survives cancellation");
            let original = seal(&context, &mutation);
            let tx = original.derive().unwrap().0;
            let Mutation::Append(intent) = &mutation else {
                unreachable!()
            };
            let projection = CancelProjection {
                inner: fixture.projection(&context),
                at_publication,
            };
            let result = poll_ready(discussions::admit_discussion_comment_async(
                fixture.store.as_ref(),
                &(),
                &context,
                intent,
                AdmissionLimits::default(),
                &projection,
            ));
            assert!(matches!(
                result,
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
            assert_eq!(fixture.head(), before);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_eq!(seal(&context, &mutation), original);
            assert_once(&fixture, tx, 1, 2);
            let after = fixture.head();
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn model_crashes_before_or_after_the_head_cas_preserve_one_original_outcome() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for position in [FaultPosition::BeforeEffect, FaultPosition::AfterEffect] {
            let fixture = opened(format);
            let before = fixture.head();
            let context = context(&fixture, b"crashed-append");
            let mutation = append("An acknowledged comment cannot disappear");
            let tx = seal(&context, &mutation).derive().unwrap().0;
            fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    FaultKind::Crash { position },
                )]));
            assert!(submit(&fixture, &context, &mutation, AdmissionLimits::default()).is_err());
            assert!(fixture.store.backend.is_crashed());
            let faults = fixture.store.backend.fault_log();
            assert_eq!(faults.records().len(), 1);
            assert_eq!(
                faults.records()[0].effect_reached,
                position == FaultPosition::AfterEffect
            );
            fixture.store.backend.restart();
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            let original = fixture.outcome(tx);
            if position == FaultPosition::BeforeEffect {
                assert_eq!(original, OutcomeLookup::Undecided);
                assert_eq!(fixture.head(), before);
            } else {
                assert!(matches!(original, OutcomeLookup::Decided(_)));
                assert_once(&fixture, tx, 1, 2);
            }
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            if let OutcomeLookup::Decided(original) = original {
                assert_eq!(terminal, original);
            }
            assert_once(&fixture, tx, 1, 2);
            let after = fixture.head();
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn closing_a_discussion_preserves_a_losing_append_and_identical_text_has_distinct_identity() {
    use fgit_forge::event::discussion::DiscussionState;

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = opened(format);
        let submitted_context = context(&fixture, b"comment-while-closing");
        let mutation = append("Same exact text é\r\n");
        let original = seal(&submitted_context, &mutation);
        let tx = original.derive().unwrap().0;
        interleave(
            &fixture,
            context(&fixture, b"concurrent-close"),
            Mutation::Strict(DiscussionCommand {
                number: DiscussionNumber::FIRST,
                expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                action: DiscussionAction::Close,
            }),
        );
        let terminal = submit(
            &fixture,
            &submitted_context,
            &mutation,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(seal(&submitted_context, &mutation), original);
        assert_once(&fixture, tx, 1, 3);
        assert_eq!(
            history(&fixture).discussion.unwrap().state,
            DiscussionState::Closed
        );
        let second_context = context(&fixture, b"separate-contribution-same-text");
        let second_tx = seal(&second_context, &mutation).derive().unwrap().0;
        assert_ne!(second_tx, tx);
        let second = submit(
            &fixture,
            &second_context,
            &mutation,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(matches!(second.outcome, DecisionOutcome::Committed { .. }));
        assert_once(&fixture, second_tx, 2, 4);
        assert_eq!(
            history(&fixture).discussion.unwrap().state,
            DiscussionState::Closed
        );
        let after = fixture.head();
        assert_eq!(
            submit(
                &fixture,
                &submitted_context,
                &mutation,
                AdmissionLimits::default()
            )
            .unwrap(),
            terminal
        );
        assert_eq!(
            submit(
                &fixture,
                &second_context,
                &mutation,
                AdmissionLimits::default()
            )
            .unwrap(),
            second
        );
        assert_eq!(fixture.head(), after);
    }
}

#[test]
fn absent_discussion_refuses_once_and_later_creation_requires_a_new_comment_key() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new_for_format(format);
        let submitted_context = context(&fixture, b"comment-before-open");
        let mutation = append("Reply requires an existing conversation");
        let tx = seal(&submitted_context, &mutation).derive().unwrap().0;
        let refused = submit(
            &fixture,
            &submitted_context,
            &mutation,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(refused));
        assert!(history(&fixture).discussion.is_none());
        let open = Mutation::Strict(DiscussionCommand {
            number: DiscussionNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: DiscussionAction::Open {
                title: "Opened later".into(),
                body: String::new(),
            },
        });
        let opened = submit(
            &fixture,
            &context(&fixture, b"open-later"),
            &open,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(matches!(opened.outcome, DecisionOutcome::Committed { .. }));
        let before = fixture.head();
        assert_eq!(
            submit(
                &fixture,
                &submitted_context,
                &mutation,
                AdmissionLimits::default()
            )
            .unwrap(),
            refused
        );
        assert_eq!(fixture.head(), before);
        let permitted_context = context(&fixture, b"comment-after-open");
        let permitted_tx = seal(&permitted_context, &mutation).derive().unwrap().0;
        let permitted = submit(
            &fixture,
            &permitted_context,
            &mutation,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            permitted.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_once(&fixture, permitted_tx, 1, 2);
    }
}
