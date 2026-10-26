//! Sessions above the physical publication bound keep independent outcomes.

use super::*;
use fgit_admission::policy_bridge::receive_session::{self, InterruptedSession};
use fgit_admission::{BasisBoundValidatedReceive, MAX_ADMISSION_COMMANDS};

fn history(authority: &Authority, context: &AdmissionContext) -> Vec<RepositoryDecisionBatchBody> {
    let mut current = head(&authority.inner, context);
    let mut batches = Vec::new();
    while let Some(predecessor) = current.predecessor_head_id {
        let previous = read_authority_head_body(&authority.inner, predecessor).unwrap();
        let publication =
            read_decision_batch_body(&authority.inner, current.decision_tail_id.unwrap()).unwrap();
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor, previous.clone()),
            &publication,
            &current,
        )
        .unwrap();
        batches.push(publication);
        current = previous;
    }
    batches.reverse();
    batches
}

fn assert_chunk_sizes(authority: &Authority, context: &AdmissionContext, expected: &[usize]) {
    let batches = history(authority, context);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.decisions.len())
            .collect::<Vec<_>>(),
        expected
    );
    let mut identities = BTreeSet::new();
    for batch in batches {
        for decision in batch.decisions {
            assert!(
                identities.insert(decision.tx_id),
                "a transaction was decided twice"
            );
        }
    }
}

struct DeleteSession {
    context: AdmissionContext,
    authority: Authority,
    staging: StagingStore,
    projection: Projection,
    validated: BasisBoundValidatedReceive,
}

impl DeleteSession {
    fn new(format: GitObjectFormat, key: &[u8], count: usize) -> Self {
        let context = context(format, key);
        let names = (0..count)
            .map(|index| format!("refs/heads/remove-{index:04}"))
            .collect::<Vec<_>>();
        let initial = names
            .iter()
            .map(|name| (name.as_str(), 1))
            .collect::<Vec<_>>();
        let (authority, staging, projection) = setup(&context, &initial, None);
        let input = receive(
            format,
            names
                .iter()
                .map(|name| command(format, name, 1, 0))
                .collect(),
            false,
        );
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
        Self {
            context,
            authority,
            staging,
            projection,
            validated,
        }
    }

    fn admit(&self) -> Result<AdmissionResult, InterruptedSession> {
        ready(receive_session::admit(
            &self.authority,
            &(),
            &self.context,
            &self.validated,
            AdmissionLimits::default(),
            &self.projection,
        ))
    }
}

#[test]
fn conflicts_and_refusals_at_chunk_boundaries_preserve_later_siblings() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"chunk-boundary-effects");
    let mut commands = (0..130)
        .map(|index| command(format, &format!("refs/heads/bulk-{index:04}"), 0, 1))
        .collect::<Vec<_>>();
    commands[63] = command(format, "refs/heads/boundary", 0, 1);
    commands[64] = command(format, "refs/heads/boundary/child", 0, 1);
    commands[127] = command(format, "refs/heads/absent-stale", 9, 0);
    let input = receive(format, commands, false);
    let (authority, staging, projection) = setup(&context, &[], None);
    let result = run(&authority, &context, &input, &projection);
    let mut expected = vec![None; 130];
    expected[64] = Some(RefusalCode::RefNameConflict);
    expected[127] = Some(RefusalCode::ExpectedOldRefMismatch);
    assert_eq!(codes(&result), expected);
    assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
    assert_chunk_sizes(&authority, &context, &[64, 64, 2]);
    let current = refs(&authority.inner, &staging, &context);
    assert_eq!(current.refs().len(), 128);
    assert_eq!(
        current.refs()[&RefName::try_new(b"refs/heads/boundary").unwrap()],
        oid(format, 1)
    );
    assert!(
        current
            .refs()
            .contains_key(&RefName::try_new(b"refs/heads/bulk-0128").unwrap())
    );
    verify_outcomes(&authority.inner, &context, &result);

    let (blocking, blocking_staging, blocking_projection) = setup(&context, &[], None);
    let blocking_result = admit_validated_receive(
        &blocking.inner,
        &context,
        &input,
        AdmissionLimits::default(),
        &blocking_projection,
    )
    .unwrap();
    assert_eq!(
        blocking_result, result,
        "the two drivers must stamp the same chunk history"
    );
    assert_eq!(refs(&blocking.inner, &blocking_staging, &context), current);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    assert_eq!(run(&authority, &context, &input, &projection), result);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 3);
}

#[test]
fn basis_bound_session_continues_across_complete_own_chunks() {
    let session = DeleteSession::new(GitObjectFormat::Sha256, b"bound-multiple-chunks", 129);
    let result = session.admit().unwrap();
    assert_eq!(codes(&result), vec![None; 129]);
    assert_chunk_sizes(&session.authority, &session.context, &[64, 64, 1]);
    assert!(
        refs(&session.authority.inner, &session.staging, &session.context)
            .refs()
            .is_empty()
    );
    verify_outcomes(&session.authority.inner, &session.context, &result);
    let before = session
        .authority
        .inner
        .read_head(&session.context.head_key)
        .unwrap();
    assert_eq!(session.admit().unwrap(), result);
    assert_eq!(
        session
            .authority
            .inner
            .read_head(&session.context.head_key)
            .unwrap(),
        before
    );
    assert_eq!(session.authority.publications.load(Ordering::SeqCst), 3);
}

#[test]
fn cancellation_between_chunks_retains_the_authenticated_prefix_and_retries_the_rest() {
    let session = DeleteSession::new(GitObjectFormat::Sha1, b"cancel-between-chunks", 129);
    session
        .authority
        .interrupt_read_after_commit
        .store(1, Ordering::SeqCst);
    let interrupted = session.admit().unwrap_err();
    assert_eq!(interrupted.completed_commands().len(), 64);
    let mapping = interrupted.session().unwrap().clone();
    assert_eq!(mapping.tx_ids.len(), 129);
    assert_chunk_sizes(&session.authority, &session.context, &[64]);
    assert_eq!(
        refs(&session.authority.inner, &session.staging, &session.context)
            .refs()
            .len(),
        65
    );
    for index in [64, 128] {
        assert_eq!(
            resolve_outcome(
                &session.authority.inner,
                &session.context.head_key,
                session.context.tenant_id,
                session.context.repository_id,
                mapping.tx_ids[index],
            )
            .unwrap(),
            OutcomeLookup::Undecided
        );
    }
    let result = session.admit().unwrap();
    assert_eq!(result.session, mapping);
    assert_eq!(&result.commands[..64], interrupted.completed_commands());
    assert_eq!(codes(&result), vec![None; 129]);
    assert_chunk_sizes(&session.authority, &session.context, &[64, 64, 1]);
    assert!(
        refs(&session.authority.inner, &session.staging, &session.context)
            .refs()
            .is_empty()
    );
    assert_eq!(session.authority.publications.load(Ordering::SeqCst), 3);
    verify_outcomes(&session.authority.inner, &session.context, &result);
}

#[test]
fn a_dropped_second_chunk_reply_is_recovered_without_redeciding_any_child() {
    let session = DeleteSession::new(GitObjectFormat::Sha256, b"lost-second-chunk", 129);
    session
        .authority
        .drop_response_at
        .store(2, Ordering::SeqCst);
    let interrupted = session.admit().unwrap_err();
    assert_eq!(interrupted.completed_commands().len(), 64);
    let mapping = interrupted.session().unwrap().clone();
    assert_chunk_sizes(&session.authority, &session.context, &[64, 64]);
    assert_eq!(
        refs(&session.authority.inner, &session.staging, &session.context)
            .refs()
            .len(),
        1,
        "a lost response cannot erase the second chunk's publication"
    );
    assert!(matches!(
        resolve_outcome(
            &session.authority.inner,
            &session.context.head_key,
            session.context.tenant_id,
            session.context.repository_id,
            mapping.tx_ids[127],
        )
        .unwrap(),
        OutcomeLookup::Decided(_)
    ));
    assert_eq!(
        resolve_outcome(
            &session.authority.inner,
            &session.context.head_key,
            session.context.tenant_id,
            session.context.repository_id,
            mapping.tx_ids[128],
        )
        .unwrap(),
        OutcomeLookup::Undecided
    );
    let result = session.admit().unwrap();
    assert_eq!(result.session, mapping);
    assert_eq!(&result.commands[..64], interrupted.completed_commands());
    assert_eq!(codes(&result), vec![None; 129]);
    assert_chunk_sizes(&session.authority, &session.context, &[64, 64, 1]);
    assert_eq!(session.authority.publications.load(Ordering::SeqCst), 3);
    verify_outcomes(&session.authority.inner, &session.context, &result);
}

#[test]
fn a_foreign_winner_in_the_second_chunk_does_not_republish_the_first_chunk() {
    let session = DeleteSession::new(GitObjectFormat::Sha1, b"second-chunk-cas-loss", 129);
    session.authority.rival_at.store(2, Ordering::SeqCst);
    *session.authority.rival.lock().unwrap() = Some(Rival {
        context: AdmissionContext {
            idempotency_key: IdempotencyKey::new(b"foreign-between-chunks".to_vec()).unwrap(),
            ..session.context.clone()
        },
        receive: receive(
            session.context.object_format,
            vec![command(
                session.context.object_format,
                "refs/heads/remove-0064",
                1,
                0,
            )],
            false,
        ),
        projection: session.projection.clone(),
        staging: session.staging.clone(),
        interrupt_after_first: false,
    });
    let result = session.admit().unwrap();
    let mut expected = vec![None; 64];
    expected.extend(vec![Some(RefusalCode::AuthorityReceiptStale); 65]);
    assert_eq!(codes(&result), expected);
    assert_eq!(session.authority.publications.load(Ordering::SeqCst), 4);
    assert_chunk_sizes(&session.authority, &session.context, &[64, 1, 64, 1]);
    assert_eq!(
        refs(&session.authority.inner, &session.staging, &session.context)
            .refs()
            .len(),
        64
    );
    verify_outcomes(&session.authority.inner, &session.context, &result);
    let before = session
        .authority
        .inner
        .read_head(&session.context.head_key)
        .unwrap();
    assert_eq!(session.admit().unwrap(), result);
    assert_eq!(
        session
            .authority
            .inner
            .read_head(&session.context.head_key)
            .unwrap(),
        before
    );
}

#[test]
fn maximum_atomic_request_is_one_transaction_and_excess_is_rejected_before_sealing() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context(format, b"atomic-command-ceiling");
        let commands = (0..MAX_ADMISSION_COMMANDS)
            .map(|index| command(format, &format!("refs/heads/absent-{index:04}"), 0, 0))
            .collect::<Vec<_>>();
        let permitted = receive(format, commands.clone(), true);
        let mut commands = commands;
        commands.push(command(format, "refs/heads/overflow", 0, 0));
        let excessive = receive(format, commands, true);
        let (authority, staging, projection) = setup(&context, &[], None);
        let before = authority.inner.read_head(&context.head_key).unwrap();
        assert!(matches!(
            ready(admit_validated_receive_async(
                &authority, &(), &context, &excessive, AdmissionLimits::default(), &projection,
            )),
            Err(fgit_admission::AdmissionError::CommandLimitExceeded { limit })
                if limit == MAX_ADMISSION_COMMANDS
        ));
        assert_eq!(
            authority.inner.read_head(&context.head_key).unwrap(),
            before
        );
        assert_eq!(authority.publications.load(Ordering::SeqCst), 0);
        assert_eq!(authority.immutable_writes.load(Ordering::SeqCst), 0);
        assert_eq!(staging.0.ref_stages.load(Ordering::SeqCst), 1);

        let result = run(&authority, &context, &permitted, &projection);
        assert!(result.session.atomic);
        assert_eq!(result.session.tx_ids.len(), 1);
        assert_eq!(result.commands.len(), MAX_ADMISSION_COMMANDS);
        assert_eq!(codes(&result), vec![None; MAX_ADMISSION_COMMANDS]);
        assert!(
            result
                .commands
                .iter()
                .all(|value| value == &result.commands[0])
        );
        assert_chunk_sizes(&authority, &context, &[1]);
        assert_eq!(authority.publications.load(Ordering::SeqCst), 1);
        assert_eq!(batch(&authority.inner, &context).committed_rcrs.len(), 1);
        assert_eq!(
            resolve_outcome(
                &authority.inner,
                &context.head_key,
                context.tenant_id,
                context.repository_id,
                result.session.tx_ids[0],
            )
            .unwrap(),
            OutcomeLookup::Decided(result.commands[0].terminal)
        );
    }
}
