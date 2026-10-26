use super::*;
use fgit_authority::{
    ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, RequestRejection, SealAttempt,
    SealFailure, SemanticRequest, bind_idempotency_keys_async, idempotency_binding_key, read_seal,
    seal_key, seal_request, seal_requests, seal_requests_async,
};
use fgit_codec::encode_body;
use fgit_types::{
    GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, PrincipalId, RefName, RepositoryId,
    TenantId,
};

fn attempt(index: usize, format: GitHashAlgorithm) -> SealAttempt {
    let oid = match format {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([7; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([7; 32])),
    };
    SealAttempt {
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        authenticated_principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(format!("key-{index}").into_bytes()).unwrap(),
        request: SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            format,
            true,
            vec![RefCommand {
                name: RefName::try_new(format!("refs/heads/ref-{index}").as_bytes()).unwrap(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(oid),
                force: false,
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap(),
    }
}

fn binding_key(attempt: &SealAttempt) -> ImmutableKey {
    idempotency_binding_key(
        attempt.tenant_id,
        attempt.repository_id,
        attempt.authenticated_principal_id,
        &attempt.idempotency_key,
    )
    .unwrap()
}

fn seal_slot(attempt: &SealAttempt) -> ImmutableKey {
    seal_key(
        attempt.tenant_id,
        attempt.repository_id,
        attempt.derive().unwrap().0,
    )
    .unwrap()
}

#[test]
fn batch_seals_equal_individual_seals_and_exact_bytes_for_both_object_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let attempts = (0..MAX_IMMUTABLE_BATCH_ITEMS)
            .map(|index| attempt(index, format))
            .collect::<Vec<_>>();
        let serial = memory(AuthorityLimits::default());
        let expected = attempts
            .iter()
            .map(|attempt| seal_request(&serial, attempt).unwrap())
            .collect::<Vec<_>>();
        let grouped = memory(AuthorityLimits::default());
        assert_eq!(seal_requests(&grouped, &attempts).unwrap(), expected);
        let asynchronous = AsyncStore::new(AuthorityLimits::default());
        assert_eq!(
            ready(seal_requests_async(
                &asynchronous,
                &Context::live(),
                &attempts
            ))
            .unwrap(),
            expected
        );
        for attempt in &attempts {
            for key in [binding_key(attempt), seal_slot(attempt)] {
                let bytes = serial.read_immutable(&key).unwrap();
                assert_eq!(grouped.read_immutable(&key).unwrap(), bytes);
                assert_eq!(asynchronous.inner.read_immutable(&key).unwrap(), bytes);
            }
        }
        let repeated = ready(seal_requests_async(
            &asynchronous,
            &Context::live(),
            &attempts,
        ))
        .unwrap();
        assert!(repeated.iter().all(|seal| !seal.is_created()));
        assert_eq!(
            repeated
                .iter()
                .map(|seal| seal.seal_id())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|seal| seal.seal_id())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn binding_only_does_not_create_seals_and_a_changed_key_rejects_before_all_seals() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let original = attempt(1, GitHashAlgorithm::Sha1);
    let created = ready(bind_idempotency_keys_async(
        &store,
        &Context::live(),
        std::slice::from_ref(&original),
    ))
    .unwrap();
    assert_eq!(created[0].tx_id(), original.derive().unwrap().0);
    assert_absent(&store.inner, &seal_slot(&original));
    let changed = SealAttempt {
        request: attempt(5, GitHashAlgorithm::Sha1).request,
        ..original.clone()
    };
    let attempts = vec![attempt(0, GitHashAlgorithm::Sha1), changed.clone()];
    let failure = ready(seal_requests_async(&store, &Context::live(), &attempts)).unwrap_err();
    assert_eq!(
        failure,
        SealFailure::Rejected(Box::new(RequestRejection::IdempotencyKeyReuse {
            bound: original.derive().unwrap().0,
            attempted: changed.derive().unwrap().0,
        }))
    );
    for attempt in &attempts {
        assert_absent(&store.inner, &seal_slot(attempt));
    }
    // An independent binding can exist even when another key conflicts. The
    // helper promises pre-seal rejection, never rollback of other bindings.
    assert!(matches!(
        store
            .inner
            .read_immutable(&binding_key(&attempts[0]))
            .unwrap(),
        ImmutableRead::Present(_)
    ));
    assert_eq!(
        ready(seal_requests_async(
            &store,
            &Context::live(),
            &[attempts[0].clone(), original]
        ))
        .unwrap()
        .len(),
        2
    );
}

#[test]
fn oversized_seal_is_preflighted_before_any_key_binding() {
    let attempt = attempt(0, GitHashAlgorithm::Sha1);
    let seal_bytes = encode_body(&attempt.derive().unwrap().1).unwrap();
    let store = AsyncStore::new(AuthorityLimits {
        body_bytes: seal_bytes.len() - 1,
        ..AuthorityLimits::default()
    });
    let failure = ready(seal_requests_async(
        &store,
        &Context::live(),
        std::slice::from_ref(&attempt),
    ))
    .unwrap_err();
    assert!(matches!(failure, SealFailure::Batch(ref error)
        if matches!(error.as_ref(), ImmutableBatchFailure::Bounds(
            ImmutableBatchRefusal::BodyTooLarge { observed, .. }
        ) if *observed == seal_bytes.len())));
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_absent(&store.inner, &binding_key(&attempt));
    let permitted = AsyncStore::new(AuthorityLimits {
        body_bytes: seal_bytes.len(),
        ..AuthorityLimits::default()
    });
    assert_eq!(
        ready(seal_requests_async(
            &permitted,
            &Context::live(),
            &[attempt]
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn interrupted_binding_and_lost_seal_response_retry_with_unchanged_identities() {
    for lost_at in [2, 5] {
        let store = AsyncStore::new(AuthorityLimits::default());
        store.lose_after.store(lost_at, Ordering::SeqCst);
        let attempts = (0..3)
            .map(|index| attempt(index, GitHashAlgorithm::Sha256))
            .collect::<Vec<_>>();
        let failure = ready(seal_requests_async(&store, &Context::live(), &attempts)).unwrap_err();
        assert!(matches!(failure, SealFailure::Batch(ref failure)
        if matches!(failure.as_ref(), ImmutableBatchFailure::Interrupted {
            completed: 1,
            source: AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
        })));
        if lost_at == 2 {
            for attempt in &attempts {
                assert_absent(&store.inner, &seal_slot(attempt));
            }
        } else {
            assert!(matches!(
                store
                    .inner
                    .read_immutable(&seal_slot(&attempts[1]))
                    .unwrap(),
                ImmutableRead::Present(_)
            ));
            assert_absent(&store.inner, &seal_slot(&attempts[2]));
        }
        let recovered = ready(seal_requests_async(&store, &Context::live(), &attempts)).unwrap();
        for (attempt, observed) in attempts.iter().zip(recovered) {
            let (tx_id, expected) = attempt.derive().unwrap();
            assert_eq!(observed.tx_id(), tx_id);
            assert_eq!(
                read_seal(
                    &store.inner,
                    attempt.tenant_id,
                    attempt.repository_id,
                    tx_id
                )
                .unwrap(),
                Some(expected)
            );
        }
    }
}

#[test]
fn corrupt_existing_seal_never_becomes_a_successful_group() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let attempts = vec![
        attempt(0, GitHashAlgorithm::Sha1),
        attempt(1, GitHashAlgorithm::Sha1),
    ];
    let corrupted_key = seal_slot(&attempts[0]);
    store
        .inner
        .put_if_absent(&corrupted_key, b"wrong seal bytes")
        .unwrap();
    assert_eq!(
        ready(seal_requests_async(&store, &Context::live(), &attempts)).unwrap_err(),
        SealFailure::SlotContentUnexpected { slot: "seal" }
    );
    assert_eq!(
        store.inner.read_immutable(&corrupted_key).unwrap(),
        ImmutableRead::Present(b"wrong seal bytes".to_vec())
    );
}

#[test]
fn seal_group_count_refuses_before_derivation_or_storage() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let attempts = (0..=MAX_IMMUTABLE_BATCH_ITEMS)
        .map(|index| attempt(index, GitHashAlgorithm::Sha1))
        .collect::<Vec<_>>();
    assert!(matches!(
        ready(seal_requests_async(&store, &Context::live(), &attempts)).unwrap_err(),
        SealFailure::Batch(error) if matches!(error.as_ref(),
            ImmutableBatchFailure::Bounds(ImmutableBatchRefusal::TooManyItems { .. }))
    ));
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
}
