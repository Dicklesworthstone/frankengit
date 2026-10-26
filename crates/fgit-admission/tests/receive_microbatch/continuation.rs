//! A basis-bound coordinator may continue only over its own canonical effects.

use super::*;

fn bind(
    authority: &Authority,
    context: &AdmissionContext,
    input: &ValidatedReceive,
) -> fgit_admission::BasisBoundValidatedReceive {
    let current = head(&authority.inner, context);
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&current).unwrap(),
        current,
    );
    validate_receive_at_basis(
        input.request(),
        None,
        input.receipt(),
        &basis,
        &DeclaredClosure,
        &mut || true,
    )
    .unwrap()
}

#[test]
fn bound_session_advances_over_an_authenticated_same_session_prefix() {
    let format = GitObjectFormat::Sha1;
    let context = context(format, b"bound-own-prefix");
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/first", 1, 0),
            command(format, "refs/heads/second", 2, 0),
            command(format, "refs/heads/third", 3, 0),
        ],
        false,
    );
    let (authority, staging, projection) = setup(
        &context,
        &[
            ("refs/heads/first", 1),
            ("refs/heads/second", 2),
            ("refs/heads/third", 3),
        ],
        None,
    );
    let bound = bind(&authority, &context, &input);
    *authority.rival.lock().unwrap() = Some(Rival {
        context: context.clone(),
        receive: input,
        projection: projection.clone(),
        staging: staging.clone(),
        interrupt_after_first: true,
    });

    let result = ready(fgit_admission::policy_bridge::receive_session::admit(
        &authority,
        &(),
        &context,
        &bound,
        AdmissionLimits::default(),
        &projection,
    ))
    .unwrap();
    assert_eq!(codes(&result), vec![None; 3]);
    assert!(refs(&authority.inner, &staging, &context).refs().is_empty());
    assert_eq!(authority.publications.load(Ordering::SeqCst), 2);
    assert_eq!(
        head(&authority.inner, &context)
            .latest_decision_sequence
            .unwrap()
            .get(),
        3,
        "recovering the prefix must not publish a second terminal decision"
    );
    let publication = batch(&authority.inner, &context);
    assert_eq!(
        publication
            .decisions
            .iter()
            .map(|decision| decision.tx_id)
            .collect::<Vec<_>>(),
        result.session.tx_ids[1..],
        "the remainder continues from the authenticated own prefix"
    );
    verify_outcomes(&authority.inner, &context, &result);
    let before = authority.inner.read_head(&context.head_key).unwrap();
    let recovered = ready(fgit_admission::policy_bridge::receive_session::admit(
        &authority,
        &(),
        &context,
        &bound,
        AdmissionLimits::default(),
        &projection,
    ))
    .unwrap();
    assert_eq!(recovered, result);
    assert_eq!(
        authority.inner.read_head(&context.head_key).unwrap(),
        before
    );
}

#[test]
fn bound_session_does_not_advance_its_witness_over_a_foreign_publication() {
    let format = GitObjectFormat::Sha256;
    let context = context(format, b"bound-foreign-winner");
    let input = receive(
        format,
        vec![
            command(format, "refs/heads/first", 1, 0),
            command(format, "refs/heads/second", 2, 0),
        ],
        false,
    );
    let (authority, staging, projection) = setup(
        &context,
        &[
            ("refs/heads/first", 1),
            ("refs/heads/second", 2),
            ("refs/heads/unrelated", 3),
        ],
        None,
    );
    let bound = bind(&authority, &context, &input);
    *authority.rival.lock().unwrap() = Some(Rival {
        context: AdmissionContext {
            idempotency_key: IdempotencyKey::new(b"foreign-session".to_vec()).unwrap(),
            ..context.clone()
        },
        receive: receive(
            format,
            vec![command(format, "refs/heads/unrelated", 3, 0)],
            false,
        ),
        projection: projection.clone(),
        staging: staging.clone(),
        interrupt_after_first: false,
    });

    let result = ready(fgit_admission::policy_bridge::receive_session::admit(
        &authority,
        &(),
        &context,
        &bound,
        AdmissionLimits::default(),
        &projection,
    ))
    .unwrap();
    assert_eq!(
        codes(&result),
        vec![Some(RefusalCode::AuthorityReceiptStale); 2],
        "an uncommitted validation authority cannot authorize a foreign head"
    );
    assert_eq!(authority.publications.load(Ordering::SeqCst), 2);
    let current = refs(&authority.inner, &staging, &context);
    assert_eq!(current.refs().len(), 2);
    for (name, seed) in [("refs/heads/first", 1), ("refs/heads/second", 2)] {
        assert_eq!(
            current.refs()[&RefName::try_new(name.as_bytes()).unwrap()],
            oid(format, seed)
        );
    }
    let publication = batch(&authority.inner, &context);
    assert_eq!(publication.decisions.len(), 2);
    assert!(publication.committed_rcrs.is_empty());
    verify_outcomes(&authority.inner, &context, &result);
}
