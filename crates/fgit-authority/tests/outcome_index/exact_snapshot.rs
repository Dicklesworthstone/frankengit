//! Exact-receipt collectors preserve historical selection across both walks.

use super::*;
use fgit_authority::{
    AuthorityRefusal, SealFailure, collect_cumulative_outcomes_at_authenticated_head_async,
    collect_cumulative_outcomes_from_checkpoint_at_authenticated_head_async,
};

fn append(view: &AsyncView, identity: u8) -> (AuthenticatedHead, RepositoryDecisionBatchBody) {
    let cumulative = collect(view, false).unwrap();
    let (receipt, head) = current(view);
    let (batch, candidate) = candidate(&head, &cumulative, identity);
    let receipt = published(
        publish_retained(
            view,
            false,
            receipt.token(),
            &batch,
            &candidate,
            &cumulative,
        )
        .unwrap(),
    );
    (view.0.authenticate_head_receipt(&receipt).unwrap(), batch)
}

fn forbid_current_head_reads(view: &AsyncView) {
    view.0
        .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
            0,
            AuthorityOpKind::ReadHead,
            FaultKind::LoseResponse,
        )]));
}

fn assert_current_head_was_not_read(view: &AsyncView) {
    assert!(view.0.fault_log().records().is_empty());
    assert!(
        view.0.read_head(&head_slot()).is_err(),
        "the armed current-head read refusal remains unconsumed"
    );
}

#[test]
fn authentic_superseded_receipts_collect_genesis_and_prefix_without_current_head_reads() {
    let view = fixture(0x941, false);
    let genesis = view.0.authenticate_head_receipt(&current(&view).0).unwrap();
    let (first, _) = append(&view, 1);
    let expected = collect(&view, false)
        .unwrap()
        .checkpoint_decisions_against(first.receipt().token())
        .unwrap();
    let (latest, _) = append(&view, 2);
    assert_ne!(first.receipt().token(), latest.receipt().token());

    forbid_current_head_reads(&view);
    let empty = poll_ready(collect_cumulative_outcomes_at_authenticated_head_async(
        &view,
        &(),
        &genesis,
    ))
    .unwrap();
    assert_eq!(empty.observed(), genesis.receipt().token());
    assert!(empty.is_empty());
    let prefix = poll_ready(collect_cumulative_outcomes_at_authenticated_head_async(
        &view,
        &(),
        &first,
    ))
    .unwrap();
    assert_eq!(
        prefix
            .checkpoint_decisions_against(first.receipt().token())
            .unwrap(),
        expected
    );
    assert!(prefix.decision_for(tx(2)).is_none());
    assert!(
        prefix
            .checkpoint_decisions_against(latest.receipt().token())
            .is_err(),
        "historical evidence cannot be relabeled with a newer publication token"
    );
    assert_current_head_was_not_read(&view);
}

#[test]
fn retained_prefix_and_tail_equal_exact_genesis_oracle_and_reject_wrong_positions() {
    let view = fixture(0x942, false);
    let (checkpoint_head, first_batch) = append(&view, 1);
    let checkpoint_body = checkpoint_head.body().unwrap();
    let (selected, _) = append(&view, 2);
    let oracle = collect(&view, false)
        .unwrap()
        .checkpoint_decisions_against(selected.receipt().token())
        .unwrap();
    let (future, _) = append(&view, 3);
    let future_body = future.body().unwrap();
    forbid_current_head_reads(&view);

    let collect_checkpoint = |decisions: &[RepositoryDecision], tail, sequence| {
        poll_ready(
            collect_cumulative_outcomes_from_checkpoint_at_authenticated_head_async(
                &view,
                &(),
                &selected,
                decisions,
                tail,
                sequence,
            ),
        )
    };
    let retained = collect_checkpoint(
        &first_batch.decisions,
        checkpoint_body.decision_tail_id,
        checkpoint_body.latest_decision_sequence,
    )
    .unwrap();
    let decisions = retained
        .checkpoint_decisions_against(selected.receipt().token())
        .unwrap();
    assert_eq!(decisions, oracle);
    assert_eq!(
        retained
            .fold_against(selected.receipt().token(), &[])
            .unwrap(),
        selected.body().unwrap().outcome_index_root
    );
    assert!(retained.decision_for(tx(3)).is_none());
    assert!(matches!(
        collect_checkpoint(
            &first_batch.decisions,
            checkpoint_body.decision_tail_id,
            Some(DecisionSequence::try_new(7).unwrap()),
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
    assert!(matches!(
        collect_checkpoint(
            &first_batch.decisions,
            future_body.decision_tail_id,
            future_body.latest_decision_sequence,
        ),
        Err(OutcomeFailure::CheckpointPositionMismatch)
    ));
    assert!(matches!(
        collect_checkpoint(
            &[],
            checkpoint_body.decision_tail_id,
            checkpoint_body.latest_decision_sequence,
        ),
        Err(OutcomeFailure::CheckpointRootMismatch)
    ));
    let from_empty = collect_checkpoint(&[], None, None).unwrap();
    assert_eq!(
        from_empty
            .checkpoint_decisions_against(selected.receipt().token())
            .unwrap(),
        oracle,
        "an empty retained prefix is checked against the real genesis root"
    );
    assert_current_head_was_not_read(&view);
}

#[test]
fn exact_checkpoint_needs_no_old_batch_but_both_apis_reauthenticate_foreign_receipts() {
    let view = fixture(0x943, false);
    let (selected, batch) = append(&view, 1);
    let selected_body = selected.body().unwrap();
    view.0
        .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
            0,
            AuthorityOpKind::ReadImmutable,
            FaultKind::LoseResponse,
        )]));
    let checkpointed = poll_ready(
        collect_cumulative_outcomes_from_checkpoint_at_authenticated_head_async(
            &view,
            &(),
            &selected,
            &batch.decisions,
            selected_body.decision_tail_id,
            selected_body.latest_decision_sequence,
        ),
    )
    .unwrap();
    assert_eq!(checkpointed.len(), 1);
    assert!(view.0.fault_log().records().is_empty());
    assert!(
        poll_ready(collect_cumulative_outcomes_at_authenticated_head_async(
            &view,
            &(),
            &selected,
        ))
        .is_err(),
        "the full-history control encounters the unavailable prefix batch"
    );

    let foreign = fixture(0x944, false);
    // AuthenticatedHead is publicly constructible. Its marker cannot substitute
    // for the target store authenticating the receipt's original issuance.
    let forged = AuthenticatedHead::new(selected.receipt().clone(), foreign.0.instance_id());
    for result in [
        poll_ready(collect_cumulative_outcomes_at_authenticated_head_async(
            &foreign,
            &(),
            &forged,
        )),
        poll_ready(
            collect_cumulative_outcomes_from_checkpoint_at_authenticated_head_async(
                &foreign,
                &(),
                &forged,
                &batch.decisions,
                selected_body.decision_tail_id,
                selected_body.latest_decision_sequence,
            ),
        ),
    ] {
        assert!(matches!(
            result,
            Err(OutcomeFailure::Seal(error))
                if matches!(error.as_ref(), SealFailure::Store(AuthorityFailure::Refused(
                    AuthorityRefusal::UnknownVersionToken
                )))
        ));
    }
}
