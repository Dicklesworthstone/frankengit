//! A long session must not reread its original history for every physical
//! chunk or publication's duplicate check. Count historical batch-body reads,
//! independently of the terminal/ref oracle and without wall-clock assertions.

use super::*;
use fgit_admission::policy_bridge::receive_session;

fn seed_history(authority: &Authority, context: &AdmissionContext, projection: &Projection) {
    let seed_context = AdmissionContext {
        idempotency_key: IdempotencyKey::new(b"seed-existing-batch-history".to_vec()).unwrap(),
        ..context.clone()
    };
    let seed = receive(
        context.object_format,
        (0..24)
            .map(|index| {
                command(
                    context.object_format,
                    &format!("refs/heads/seed-absent-{index:04}"),
                    0,
                    0,
                )
            })
            .collect(),
        false,
    );
    let seeded = admit_validated_receive(
        &authority.inner,
        &seed_context,
        &seed,
        AdmissionLimits::default(),
        &Sequential(projection),
    )
    .unwrap();
    assert_eq!(codes(&seeded), vec![None; 24]);
    assert_eq!(
        head(&authority.inner, context).generation.get(),
        HeadGeneration::FIRST.get() + 24
    );
}

fn watch_history(authority: &Authority, context: &AdmissionContext) {
    let mut current = head(&authority.inner, context);
    let mut keys = BTreeMap::new();
    while let Some(id) = current.decision_tail_id {
        keys.insert(body_key_for_id(id.as_internal_object_id()).unwrap(), 0);
        let batch = read_decision_batch_body(&authority.inner, id).unwrap();
        current = read_authority_head_body(&authority.inner, batch.predecessor_head_id).unwrap();
    }
    assert!(!keys.is_empty(), "the read bound requires existing history");
    *authority.watched_reads.lock().unwrap() = keys;
}

fn assert_history_reads(authority: &Authority, expected: usize, operation: &str) {
    let reads = authority.watched_reads.lock().unwrap();
    assert!(
        reads.values().all(|count| *count == expected),
        "{operation} must collect each preexisting batch {expected} times, not once per chunk or CAS: {reads:?}"
    );
}

fn reset_watched_reads(authority: &Authority) {
    for count in authority.watched_reads.lock().unwrap().values_mut() {
        *count = 0;
    }
}

#[test]
fn a_three_chunk_session_and_its_retry_read_old_history_once_with_mixed_outcomes() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context(format, b"shared-old-history");
        let mut commands = (0..129)
            .map(|index| command(format, &format!("refs/heads/history-work-{index:04}"), 0, 1))
            .collect::<Vec<_>>();
        commands[63] = command(format, "refs/heads/hidden", 0, 1);
        commands[64] = command(format, "refs/heads/stale-absent", 9, 0);
        commands[127] = command(format, "refs/heads/non-ff", 0, 1);
        commands[128] = command(format, "refs/heads/absent-noop", 0, 0);
        let input = receive(format, commands, false);
        let (authority, staging, projection) = setup(&context, &[], None);
        seed_history(&authority, &context, &projection);
        watch_history(&authority, &context);

        let result = run(&authority, &context, &input, &projection);
        assert_history_reads(&authority, 1, "new session");
        let mut expected = vec![None; 129];
        expected[63] = Some(RefusalCode::HiddenRefUnauthorized);
        expected[64] = Some(RefusalCode::ExpectedOldRefMismatch);
        expected[127] = Some(RefusalCode::NonFastForwardRefused);
        assert_eq!(codes(&result), expected);
        assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
        let current = head(&authority.inner, &context);
        assert_eq!(current.generation.get(), HeadGeneration::FIRST.get() + 27);
        assert_eq!(current.latest_decision_sequence.unwrap().get(), 24 + 129);
        assert_eq!(refs(&authority.inner, &staging, &context).refs().len(), 125);
        verify_outcomes(&authority.inner, &context, &result);

        // The blocking driver must preserve exact terminal records, including
        // refusals stamped at their actual positions within each chunk.
        let (blocking, blocking_staging, blocking_projection) = setup(&context, &[], None);
        seed_history(&blocking, &context, &blocking_projection);
        let blocking_result = admit_validated_receive(
            &blocking.inner,
            &context,
            &input,
            AdmissionLimits::default(),
            &blocking_projection,
        )
        .unwrap();
        assert_eq!(blocking_result, result);
        assert_eq!(
            refs(&blocking.inner, &blocking_staging, &context),
            refs(&authority.inner, &staging, &context)
        );

        reset_watched_reads(&authority);
        let before = authority.inner.read_head(&context.head_key).unwrap();
        assert_eq!(run(&authority, &context, &input, &projection), result);
        assert_history_reads(&authority, 1, "whole-session retry");
        assert_eq!(
            authority.inner.read_head(&context.head_key).unwrap(),
            before
        );
        assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn a_foreign_index_publication_invalidates_the_carried_prefix_before_chunk_two() {
    let format = GitObjectFormat::Sha256;
    let context = context(format, b"carried-history-index-race");
    let input = receive(
        format,
        (0..129)
            .map(|index| command(format, &format!("refs/heads/index-{index:04}"), 0, 1))
            .collect(),
        false,
    );
    let (reference, _, reference_projection) = setup(&context, &[], None);
    seed_history(&reference, &context, &reference_projection);
    let expected = admit_validated_receive(
        &reference.inner,
        &context,
        &input,
        AdmissionLimits::default(),
        &Sequential(&reference_projection),
    )
    .unwrap();

    let (authority, staging, projection) = setup(&context, &[], None);
    seed_history(&authority, &context, &projection);
    watch_history(&authority, &context);
    let target = fgit_authority::outcome_key(
        context.tenant_id,
        context.repository_id,
        expected.session.tx_ids[64],
    )
    .unwrap();
    *authority.index_rival.lock().unwrap() = Some((
        target,
        Rival {
            context: context.clone(),
            receive: input.clone(),
            projection: projection.clone(),
            staging: staging.clone(),
            interrupt_after_first: true,
        },
    ));

    // The first chunk supplies a carried cumulative set. While chunk two
    // probes its accelerator, a real competing admission recovers that first
    // chunk and commits only command 64. The old set must be discarded before
    // reconciling the newer index, then the remaining children can continue.
    let result = run(&authority, &context, &input, &projection);
    assert!(authority.index_rival.lock().unwrap().is_none());
    assert_eq!(result.session, expected.session);
    assert_eq!(codes(&result), vec![None; 129]);
    assert_history_reads(&authority, 2, "one foreign head change");
    assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
    let current = head(&authority.inner, &context);
    assert_eq!(current.generation.get(), HeadGeneration::FIRST.get() + 28);
    assert_eq!(current.latest_decision_sequence.unwrap().get(), 24 + 129);
    assert_eq!(refs(&authority.inner, &staging, &context).refs().len(), 129);
    verify_outcomes(&authority.inner, &context, &result);

    reset_watched_reads(&authority);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    assert_eq!(run(&authority, &context, &input, &projection), result);
    assert_history_reads(&authority, 1, "retry after the foreign head change");
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
}

#[test]
fn failure_while_extending_a_prefix_retains_every_known_terminal_and_its_error_class() {
    for failure in [
        AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled),
        AuthorityFailure::Refused(fgit_authority::AuthorityRefusal::TokenBodyMismatch),
    ] {
        let format = GitObjectFormat::Sha1;
        let context = context(format, b"cache-extension-interrupted");
        let input = receive(
            format,
            (0..65)
                .map(|index| command(format, &format!("refs/heads/extension-{index:04}"), 0, 0))
                .collect(),
            false,
        );
        let (authority, _, projection) = setup(&context, &[], None);
        let initial = head(&authority.inner, &context);
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&initial).unwrap(),
            initial,
        );
        let validated = validate_receive_at_basis(
            input.request(),
            None,
            input.receipt(),
            &basis,
            &DeclaredClosure,
            &mut || true,
        )
        .unwrap();
        // Authentication 1 proves the just-published chunk. Authentication 2
        // is the cache extension's predecessor recheck, after known terminals
        // have passed index reconciliation. A failure there cannot erase them.
        *authority.post_publication_auth_failure.lock().unwrap() = Some((2, failure));
        let interrupted = ready(receive_session::admit(
            &authority,
            &(),
            &context,
            &validated,
            AdmissionLimits::default(),
            &projection,
        ))
        .unwrap_err();
        assert!(
            authority
                .post_publication_auth_failure
                .lock()
                .unwrap()
                .is_none()
        );
        assert_eq!(interrupted.completed_commands().len(), 64);
        assert!(interrupted.completed_commands().iter().all(|command| {
            matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })
        }));
        assert!(matches!(
            interrupted.admission_error(),
            fgit_admission::AdmissionError::Outcome(error)
                if matches!(error.as_ref(), fgit_authority::OutcomeFailure::Seal(error)
                    if matches!(error.as_ref(), fgit_authority::SealFailure::Store(actual)
                        if *actual == failure))
        ));
        let mapping = interrupted.session().unwrap().clone();
        assert_eq!(mapping.tx_ids.len(), 65);
        assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolve_outcome(
                &authority.inner,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                mapping.tx_ids[64],
            )
            .unwrap(),
            OutcomeLookup::Undecided
        );
        let result = ready(receive_session::admit(
            &authority,
            &(),
            &context,
            &validated,
            AdmissionLimits::default(),
            &projection,
        ))
        .unwrap();
        assert_eq!(result.session, mapping);
        assert_eq!(&result.commands[..64], interrupted.completed_commands());
        assert_eq!(codes(&result), vec![None; 65]);
        assert_eq!(authority.publications.load(Ordering::SeqCst), 2);
        verify_outcomes(&authority.inner, &context, &result);
    }
}

#[test]
fn the_final_chunk_does_not_reauthenticate_an_unused_cache_extension() {
    let format = GitObjectFormat::Sha256;
    let context = context(format, b"no-final-cache-extension");
    let input = receive(
        format,
        (0..64)
            .map(|index| command(format, &format!("refs/heads/final-{index:04}"), 0, 0))
            .collect(),
        false,
    );
    let (authority, _, projection) = setup(&context, &[], None);
    *authority.post_publication_auth_failure.lock().unwrap() =
        Some((2, AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled)));
    let result = run(&authority, &context, &input, &projection);
    assert_eq!(codes(&result), vec![None; 64]);
    assert_eq!(
        authority
            .post_publication_authentications
            .load(Ordering::SeqCst),
        1
    );
    assert!(
        authority
            .post_publication_auth_failure
            .lock()
            .unwrap()
            .is_some()
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
    verify_outcomes(&authority.inner, &context, &result);
}
