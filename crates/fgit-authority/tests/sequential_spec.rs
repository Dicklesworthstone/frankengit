//! Sequential-specification conformance of the in-memory reference profile.

use fgit_authority::{
    AuthorityOp, AuthorityResponse, AuthorityStore, CasOutcome, HeadGeneration, HeadInit, HeadKey,
    HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    run_authority_conformance, run_fault_conformance,
};

fn head_generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive head generation")
}

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn head_key(name: &str) -> HeadKey {
    HeadKey::new(name.as_bytes().to_vec()).expect("admissible head key")
}

fn immutable_key(name: &str) -> ImmutableKey {
    ImmutableKey::new(name.as_bytes().to_vec()).expect("admissible immutable key")
}

#[test]
fn reference_profile_passes_every_backend_agnostic_check() {
    let report = run_authority_conformance(MemoryAuthorityStore::new);
    assert!(
        report.is_pass(),
        "reference profile failed {:?}: {:#?}",
        report.failed_ids(),
        report.failures().collect::<Vec<_>>()
    );
    assert_eq!(report.checks().len(), 20, "the suite lost or gained checks");
}

#[test]
fn reference_profile_passes_every_fault_check() {
    let report = run_fault_conformance(MemoryAuthorityStore::new);
    assert!(
        report.is_pass(),
        "reference profile failed {:?}: {:#?}",
        report.failed_ids(),
        report.failures().collect::<Vec<_>>()
    );
    assert_eq!(
        report.checks().len(),
        8,
        "the fault suite lost or gained checks"
    );
}

#[test]
fn head_read_after_commit_observes_the_commit() {
    let store = store();
    let key = head_key("repo/head");
    let HeadInit::Created(first) = store
        .initialize_head(&key, HeadGeneration::FIRST, b"head-1")
        .expect("head creation")
    else {
        panic!("a fresh head slot must be created");
    };

    let CasOutcome::Committed(published) = store
        .compare_exchange_head(&key, first.token(), head_generation(2), b"head-2")
        .expect("conditional replacement")
    else {
        panic!("a conditional write on the exact predecessor token must publish");
    };

    let HeadRead::Present(observed) = store.read_head(&key).expect("head read") else {
        panic!("a published head must be readable");
    };
    assert_eq!(observed.generation(), head_generation(2));
    assert_eq!(observed.body(), b"head-2");
    assert_eq!(
        observed, published,
        "the read must return exactly what the conditional write published"
    );
}

#[test]
fn absent_slots_read_as_absent() {
    let store = store();
    assert_eq!(
        store.read_head(&head_key("repo/never")).expect("head read"),
        HeadRead::Absent
    );
    assert_eq!(
        store
            .read_immutable(&immutable_key("body/never"))
            .expect("immutable read"),
        ImmutableRead::Absent
    );
}

#[test]
fn uniform_execute_agrees_with_the_typed_methods() {
    let typed = store();
    let uniform = store();
    let key = immutable_key("body/seal");

    let typed_first = typed.put_if_absent(&key, b"seal").expect("typed put");
    let uniform_first = uniform.execute(&AuthorityOp::PutIfAbsent {
        key: key.clone(),
        body: b"seal".to_vec(),
    });
    assert_eq!(uniform_first, AuthorityResponse::PutIfAbsent(typed_first));
    assert_eq!(typed_first, PutOutcome::Created);

    let typed_second = typed.put_if_absent(&key, b"seal").expect("typed retry");
    let uniform_second = uniform.execute(&AuthorityOp::PutIfAbsent {
        key,
        body: b"seal".to_vec(),
    });
    assert_eq!(uniform_second, AuthorityResponse::PutIfAbsent(typed_second));
    assert_eq!(typed_second, PutOutcome::IdenticalRetry);
}

#[test]
fn operation_kinds_and_mutation_classification_are_stable() {
    let key = head_key("repo/head");
    let read = AuthorityOp::ReadHead { key: key.clone() };
    assert!(!read.is_mutating());
    let write = AuthorityOp::InitializeHead {
        key,
        generation: HeadGeneration::FIRST,
        body: b"head-1".to_vec(),
    };
    assert!(write.is_mutating());
    assert_ne!(read.kind(), write.kind());
}
