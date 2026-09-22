use super::*;
use crate::generation::activation::tests::{AsyncStore, candidate, key, ready};
use fgit_authority::{AmbiguityReason, AuthorityFailure};

fn view() -> GraphViewId {
    GraphViewId::try_new(b"commit-ancestry").unwrap()
}
fn chain(store: &AsyncStore, count: usize) -> Vec<(GraphGenerationBody, GenerationActivation)> {
    let authority = GenerationAuthority::new(store, key());
    let mut out = Vec::new();
    let mut parent = None;
    for n in 0..count {
        let body = candidate(format!("generation-{n}").as_bytes(), parent);
        let activated = ready(authority.stage_and_activate_async(&1, &body)).unwrap();
        parent = Some(activated.generation_id);
        out.push((body, activated));
    }
    out
}
fn recovered(store: &AsyncStore, id: GraphGenerationId) -> GenerationRecovery {
    ready(
        GenerationAuthority::new(store, key()).recover_activation_async(
            &2,
            view(),
            id,
            None,
            GenerationReadLimits::default(),
            &mut || true,
        ),
    )
    .unwrap()
}
fn install(store: &AsyncStore, body: &GraphGenerationBody, position: u64, backing: bool) {
    let bytes = encode_body(body).unwrap();
    if backing {
        store
            .inner
            .put_if_absent(
                &immutable_generation_key(body.generation_id().unwrap()).unwrap(),
                &bytes,
            )
            .unwrap();
    }
    store
        .inner
        .initialize_head(&key(), HeadGeneration::try_new(position).unwrap(), &bytes)
        .unwrap();
}

#[test]
fn uninitialized_selection_never_discards_a_higher_checkpoint() {
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let body = candidate(b"candidate", None);
    let checkpoint = GenerationActivation {
        generation_id: body.generation_id().unwrap(),
        authority_generation: HeadGeneration::FIRST,
    };
    assert_eq!(
        ready(authority.read_active_async(&7, view(), None, Default::default(), &mut || true))
            .unwrap(),
        None
    );
    assert_eq!(
        recovered(&store, checkpoint.generation_id),
        GenerationRecovery::Uninitialized
    );
    assert!(matches!(
        ready(authority.read_active_async(
            &7,
            view(),
            Some(&checkpoint),
            Default::default(),
            &mut || true
        )),
        Err(GenerationAuthorityError::CheckpointUnresolved)
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), HeadRead::Absent);
    assert!(
        store
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(op, _)| *op == "head")
    );
}

#[test]
fn lost_reply_recovers_without_reexecution_and_survives_a_later_activation() {
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let first = candidate(b"first", None);
    store.lose_next_reply();
    assert!(matches!(
        ready(authority.stage_and_activate_async(&1, &first)),
        Err(GenerationAuthorityError::Authority(
            AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse)
        ))
    ));
    let GenerationRecovery::Active { selected } = recovered(&store, first.generation_id().unwrap())
    else {
        panic!("active candidate not recovered")
    };
    assert_eq!(selected.body(), &first);
    let first_activation = selected.activation().clone();
    let later = candidate(b"later", Some(first_activation.generation_id));
    let later_activation = ready(authority.stage_and_activate_async(&1, &later)).unwrap();
    let before = store.inner.read_head(&key()).unwrap();
    store.calls.lock().unwrap().clear();
    let actual = recovered(&store, first_activation.generation_id);
    let expected = GenerationAuthority::new(&store.inner, key())
        .recover_activation(
            view(),
            first_activation.generation_id,
            None,
            Default::default(),
            &mut || true,
        )
        .unwrap();
    assert_eq!(actual, expected);
    let GenerationRecovery::Superseded {
        activation,
        selected,
    } = actual
    else {
        panic!("ancestor not recovered")
    };
    assert_eq!(activation, first_activation);
    assert_eq!(selected.activation(), &later_activation);
    assert_eq!(selected.body(), &later);
    assert_eq!(selected.generations_read(), 2);
    assert_eq!(store.inner.read_head(&key()).unwrap(), before);
    assert!(
        store
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(op, cx)| ["head", "authenticate", "immutable"].contains(op) && *cx == 2)
    );
}

#[test]
fn staged_orphans_are_not_active_and_absence_requires_a_complete_chain() {
    let store = AsyncStore::new();
    let chain = chain(&store, 3);
    let orphan = candidate(b"orphan", Some(chain[1].1.generation_id));
    let immutable_key = immutable_generation_key(orphan.generation_id().unwrap()).unwrap();
    store
        .inner
        .put_if_absent(&immutable_key, &encode_body(&orphan).unwrap())
        .unwrap();
    let before = store.inner.read_head(&key()).unwrap();
    let result = recovered(&store, orphan.generation_id().unwrap());
    let GenerationRecovery::NotInSelectedHistory { selected } = result else {
        panic!("staging was promoted")
    };
    assert_eq!(selected.generations_read(), 3);
    assert_eq!(selected.activation(), &chain[2].1);
    assert!(matches!(
        store.inner.read_immutable(&immutable_key).unwrap(),
        ImmutableRead::Present(_)
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), before);
}

#[test]
fn missing_or_substituted_ancestors_never_produce_a_negative_answer() {
    for substituted in [false, true] {
        let store = AsyncStore::new();
        let first = candidate(b"first", None);
        let next = candidate(b"next", Some(first.generation_id().unwrap()));
        install(&store, &next, 2, true);
        if substituted {
            let wrong = candidate(b"wrong", None);
            store
                .inner
                .put_if_absent(
                    &immutable_generation_key(first.generation_id().unwrap()).unwrap(),
                    &encode_body(&wrong).unwrap(),
                )
                .unwrap();
        }
        let result = ready(
            GenerationAuthority::new(&store, key()).recover_activation_async(
                &5,
                view(),
                first.generation_id().unwrap(),
                None,
                Default::default(),
                &mut || true,
            ),
        );
        match result {
            Err(GenerationAuthorityError::MissingGeneration { generation_id }) if !substituted => {
                assert_eq!(*generation_id, first.generation_id().unwrap())
            }
            Err(GenerationAuthorityError::GenerationIdentityMismatch { expected, observed })
                if substituted =>
            {
                assert_eq!(*expected, first.generation_id().unwrap());
                assert_ne!(expected, observed);
            }
            other => panic!("incomplete history misclassified: {other:?}"),
        }
    }
}

#[test]
fn current_selection_requires_the_immutable_backing_and_consistent_generation_shape() {
    for (position, backing) in [(1, false), (2, true), (1, true)] {
        let store = AsyncStore::new();
        let first = candidate(b"first", None);
        install(&store, &first, position, backing);
        let result = ready(GenerationAuthority::new(&store, key()).read_active_async(
            &3,
            view(),
            None,
            Default::default(),
            &mut || true,
        ));
        match (position, backing, result) {
            (1, false, Err(GenerationAuthorityError::MissingGeneration { .. }))
            | (2, true, Err(GenerationAuthorityError::HistoryInconsistent)) => {}
            (1, true, Ok(Some(selected))) => assert_eq!(selected.body(), &first),
            other => panic!("root-last/sequence check failed: {other:?}"),
        }
    }
}

#[test]
fn checkpoints_require_exact_identity_at_their_original_position() {
    let store = AsyncStore::new();
    let chain = chain(&store, 3);
    let authority = GenerationAuthority::new(&store, key());
    for floor in [&chain[0].1, &chain[1].1, &chain[2].1] {
        let selected = ready(authority.read_active_async(
            &2,
            view(),
            Some(floor),
            Default::default(),
            &mut || true,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(selected.activation(), &chain[2].1);
        assert_eq!(
            selected.generations_read() as u64,
            4 - floor.authority_generation.get()
        );
    }
    for floor in [
        GenerationActivation {
            generation_id: chain[2].1.generation_id,
            authority_generation: HeadGeneration::try_new(4).unwrap(),
        },
        GenerationActivation {
            generation_id: chain[0].1.generation_id,
            authority_generation: chain[2].1.authority_generation,
        },
        GenerationActivation {
            generation_id: chain[2].1.generation_id,
            authority_generation: HeadGeneration::FIRST,
        },
    ] {
        assert!(matches!(
            ready(authority.read_active_async(
                &2,
                view(),
                Some(&floor),
                Default::default(),
                &mut || true
            )),
            Err(GenerationAuthorityError::CheckpointUnresolved)
        ));
        // Finding the candidate at the active root must not skip a lower
        // caller-retained checkpoint whose fork is unresolved.
        assert!(matches!(
            ready(authority.recover_activation_async(
                &2,
                view(),
                chain[2].1.generation_id,
                Some(&floor),
                Default::default(),
                &mut || true
            )),
            Err(GenerationAuthorityError::CheckpointUnresolved)
        ));
    }
}

#[test]
fn ancestry_and_byte_bounds_have_exact_permitted_twins() {
    let store = AsyncStore::new();
    let chain = chain(&store, 2);
    let authority = GenerationAuthority::new(&store, key());
    let first = chain[0].1.generation_id;
    let too_few = GenerationReadLimits {
        max_generations: 1,
        ..Default::default()
    };
    assert!(matches!(
        ready(authority.recover_activation_async(&1, view(), first, None, too_few, &mut || true)),
        Err(GenerationAuthorityError::ReadBudgetExceeded(
            "generation ancestry"
        ))
    ));
    let exact_bytes =
        encode_body(&chain[1].0).unwrap().len() * 2 + encode_body(&chain[0].0).unwrap().len();
    let exact = GenerationReadLimits {
        max_generations: 2,
        max_total_bytes: exact_bytes,
        ..Default::default()
    };
    let GenerationRecovery::Superseded { selected, .. } =
        ready(authority.recover_activation_async(&1, view(), first, None, exact, &mut || true))
            .unwrap()
    else {
        panic!("exact bound refused")
    };
    assert_eq!(selected.bytes_read(), exact_bytes);
    let short = GenerationReadLimits {
        max_total_bytes: exact_bytes - 1,
        ..exact
    };
    assert!(matches!(
        ready(authority.recover_activation_async(&1, view(), first, None, short, &mut || true)),
        Err(GenerationAuthorityError::ReadBudgetExceeded(
            "generation read bytes"
        ))
    ));
    let before = store.calls.lock().unwrap().len();
    for limits in [
        GenerationReadLimits {
            max_generations: 0,
            ..exact
        },
        GenerationReadLimits {
            max_body_bytes: usize::MAX,
            ..exact
        },
    ] {
        assert!(matches!(
            ready(authority.read_active_async(&1, view(), None, limits, &mut || true)),
            Err(GenerationAuthorityError::InvalidReadLimits)
        ));
    }
    assert_eq!(store.calls.lock().unwrap().len(), before);
}

#[test]
fn cancellation_before_and_during_reads_discloses_no_provisional_selection() {
    let store = AsyncStore::new();
    chain(&store, 2);
    store.calls.lock().unwrap().clear();
    let authority = GenerationAuthority::new(&store, key());
    assert!(matches!(
        ready(authority.read_active_async(&1, view(), None, Default::default(), &mut || false)),
        Err(GenerationAuthorityError::ReadCancelled)
    ));
    assert!(store.calls.lock().unwrap().is_empty());
    let mut live = || {
        !store
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(op, _)| *op == "immutable")
    };
    assert!(matches!(
        ready(authority.read_active_async(&2, view(), None, Default::default(), &mut live)),
        Err(GenerationAuthorityError::ReadCancelled)
    ));
    assert!(
        store
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(op, _)| *op == "immutable"),
        "mid-read stop must fire"
    );
    assert!(
        ready(authority.read_active_async(&3, view(), None, Default::default(), &mut || true))
            .unwrap()
            .is_some()
    );
}

#[test]
fn an_intervening_writer_cannot_change_the_selected_recovery_lineage() {
    let store = AsyncStore::new();
    let chain = chain(&store, 2);
    store.calls.lock().unwrap().clear();
    let later = candidate(b"concurrent", Some(chain[1].1.generation_id));
    let mut fired = false;
    let mut live = || {
        let immutable_seen = store
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(op, _)| *op == "immutable");
        if immutable_seen && !fired {
            GenerationAuthority::new(&store.inner, key())
                .stage_and_activate(&later)
                .unwrap();
            fired = true;
        }
        true
    };
    let result = ready(
        GenerationAuthority::new(&store, key()).recover_activation_async(
            &2,
            view(),
            chain[0].1.generation_id,
            None,
            Default::default(),
            &mut live,
        ),
    )
    .unwrap();
    let GenerationRecovery::Superseded { selected, .. } = result else {
        panic!("wrong recovery class")
    };
    assert!(fired);
    assert_eq!(selected.activation(), &chain[1].1);
    assert_eq!(
        store
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, _)| *op == "head")
            .count(),
        1
    );
    let HeadRead::Present(current) = store.inner.read_head(&key()).unwrap() else {
        panic!("head missing")
    };
    assert_eq!(current.body(), encode_body(&later).unwrap());
}

#[test]
fn a_foreign_view_in_the_selected_ancestry_fails_closed() {
    let store = AsyncStore::new();
    let mut first = candidate(b"foreign", None);
    first.graph_view_id = GraphViewId::try_new(b"foreign-view").unwrap();
    let next = candidate(b"local", Some(first.generation_id().unwrap()));
    store
        .inner
        .put_if_absent(
            &immutable_generation_key(first.generation_id().unwrap()).unwrap(),
            &encode_body(&first).unwrap(),
        )
        .unwrap();
    install(&store, &next, 2, true);
    let authority = GenerationAuthority::new(&store, key());
    assert!(matches!(
        ready(authority.recover_activation_async(
            &1,
            view(),
            first.generation_id().unwrap(),
            None,
            Default::default(),
            &mut || true
        )),
        Err(GenerationAuthorityError::HistoryInconsistent)
    ));
    assert!(matches!(
        ready(authority.read_active_async(
            &1,
            first.graph_view_id(),
            None,
            Default::default(),
            &mut || true
        )),
        Err(GenerationAuthorityError::ViewMismatch { .. })
    ));
}
