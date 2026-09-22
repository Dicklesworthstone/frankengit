use super::*;
use fgit_authority::{CasOutcome, HeadInit, HeadRead, ImmutableRead};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;

fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Request));
    cx
}
fn sample() -> ExportBundle {
    let key = b"repository/head".to_vec();
    let issuance: Vec<_> = (1..=2).map(|sequence| ExportedIssuance {
        token: mint_token(StoreInstanceId::from_raw(51), IssuanceSequence::new(sequence).unwrap())
            .to_opaque_bytes().to_vec(),
        sequence, head_key: key.clone(), generation: sequence,
        body: format!("head-{sequence}").into_bytes(),
    }).collect();
    let last = &issuance[1];
    ExportBundle { schema_version: SCHEMA_VERSION, instance: 51,
        bodies: vec![ExportedBody { key: b"body".to_vec(), body: b"payload".to_vec() }],
        head: Some(ExportedHead { key, token: last.token.clone(),
            generation: last.generation, body: last.body.clone() }), issuance }
}
fn valid(bundle: &ExportBundle) -> Result<(), PortableStoreError> {
    validate_bundle(bundle, Default::default(), AuthorityLimits::default(), || Ok(()))
}
fn bytes(bundle: &ExportBundle) -> u64 {
    let body: usize = bundle.bodies.iter().map(|row| row.key.len() + row.body.len()).sum();
    let issued: usize = bundle.issuance.iter().map(|row| row.token.len() + row.head_key.len() + row.body.len()).sum();
    let head = bundle.head.as_ref().map_or(0, |row| row.key.len() + row.token.len() + row.body.len());
    (body + issued + head) as u64
}

#[test]
fn valid_and_empty_bundles_are_admitted_without_inventing_a_head() {
    assert!(valid(&sample()).is_ok());
    assert!(valid(&ExportBundle { schema_version: SCHEMA_VERSION, instance: 1,
        bodies: Vec::new(), issuance: Vec::new(), head: None }).is_ok());
}

#[test]
fn source_tokens_must_match_both_instance_and_sequence() {
    let mut bundle = sample();
    bundle.instance += 1;
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidSourceToken)));
    let mut bundle = sample();
    bundle.issuance[0].token[15] ^= 4;
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidSourceToken)));
}

#[test]
fn old_valid_head_missing_history_and_cross_key_issuance_are_refused() {
    let mut bundle = sample();
    let old = &bundle.issuance[0];
    bundle.head = Some(ExportedHead { key: old.head_key.clone(), token: old.token.clone(),
        generation: old.generation, body: old.body.clone() });
    assert!(bundle.validate().is_ok(), "the wire-level check alone accepts the old genuine head");
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidLineage)));
    let mut bundle = sample();
    bundle.issuance.remove(0);
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidLineage)));
    let mut bundle = sample();
    bundle.issuance[0].head_key = b"other-head".to_vec();
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidLineage)));
    let mut bundle = sample();
    bundle.head = None;
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidLineage)));
}

#[test]
fn limits_apply_to_payload_history_and_destination_capacity() {
    let bundle = sample();
    let check = |limits, store| validate_bundle(&bundle, limits, store, || Ok(()));
    assert!(check(PortableStoreLimits { max_field_bytes: bytes(&bundle), ..Default::default() },
        AuthorityLimits::default()).is_ok());
    assert!(matches!(check(PortableStoreLimits { max_field_bytes: bytes(&bundle) - 1, ..Default::default() },
        AuthorityLimits::default()), Err(PortableStoreError::Limit("retained field bytes"))));
    assert!(check(PortableStoreLimits { max_bodies: 0, ..Default::default() }, AuthorityLimits::default()).is_err());
    assert!(check(PortableStoreLimits { max_issuance: 1, ..Default::default() }, AuthorityLimits::default()).is_err());
    assert!(check(Default::default(), AuthorityLimits { immutable_slots: 0, ..Default::default() }).is_err());
    assert!(check(Default::default(), AuthorityLimits { version_tokens: 1, ..Default::default() }).is_err());
    assert!(check(Default::default(), AuthorityLimits { body_bytes: 1, ..Default::default() }).is_err());
}

#[test]
fn malformed_keys_noncanonical_order_and_cancelled_work_do_not_validate() {
    let mut bundle = sample();
    bundle.bodies[0].key.clear();
    assert!(matches!(valid(&bundle), Err(PortableStoreError::InvalidKey)));
    let mut bundle = sample();
    bundle.bodies.push(bundle.bodies[0].clone());
    assert!(matches!(valid(&bundle), Err(PortableStoreError::Bundle(_))));
    let mut calls = 0;
    let result = validate_bundle(&sample(), Default::default(), AuthorityLimits::default(), || {
        calls += 1;
        if calls == 3 { Err(PortableStoreError::Limit("cancel probe")) } else { Ok(()) }
    });
    assert!(matches!(result, Err(PortableStoreError::Limit("cancel probe"))));
    assert_eq!(calls, 3);
}

#[test]
fn real_engine_export_import_remints_tokens_and_continues_cas() {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    let mut source = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
        StoreInstanceId::from_raw(51), AuthorityLimits::default())).unwrap();
    let mut target = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
        StoreInstanceId::from_raw(52), AuthorityLimits::default())).unwrap();
    let key = HeadKey::new(b"repository/head".to_vec()).unwrap();
    runtime.block_on(async {
        for name in [b"z".as_slice(), b"a"] {
            source.put_if_absent(&cx, &ImmutableKey::new(name.to_vec()).unwrap(), name).await.unwrap();
        }
        let HeadInit::Created(first) = source.initialize_head(&cx, &key, HeadGeneration::FIRST, b"old").await.unwrap()
            else { panic!("fresh source") };
        let CasOutcome::Committed(current) = source.compare_exchange_head(&cx, &key, first.token(),
            HeadGeneration::try_new(2).unwrap(), b"current").await.unwrap() else { panic!("source CAS") };
        let bundle = source.export_portable(&cx, Default::default()).await.unwrap();
        assert_eq!(bundle.bodies.iter().map(|item| item.key.as_slice()).collect::<Vec<_>>(), vec![b"a".as_slice(), b"z".as_slice()]);
        assert_eq!(bundle.issuance.len(), 2);
        assert_eq!(source.export_portable(&cx, Default::default()).await.unwrap(), bundle);
        let wire = crate::export_bundle(&bundle).unwrap();
        let decoded = crate::import_bundle(&wire).unwrap();
        let receipt = target.import_portable(&cx, &decoded, Default::default()).await.unwrap().unwrap();
        assert_eq!(receipt.body(), current.body());
        assert_eq!(receipt.generation(), current.generation());
        assert_ne!(receipt.token(), current.token());
        target.authenticate_head_receipt(&cx, &receipt).await.unwrap();
        assert!(target.authenticate_head_receipt(&cx, &first).await.is_err());
        assert!(target.authenticate_head_receipt(&cx, &current).await.is_err());
        assert_eq!(target.read_immutable(&cx, &ImmutableKey::new(b"a".to_vec()).unwrap()).await.unwrap(),
            ImmutableRead::Present(b"a".to_vec()));
        assert!(matches!(target.import_portable(&cx, &decoded, Default::default()).await,
            Err(PortableStoreError::DestinationNotEmpty)));
        let CasOutcome::Committed(next) = target.compare_exchange_head(&cx, &key, receipt.token(),
            HeadGeneration::try_new(3).unwrap(), b"next").await.unwrap() else { panic!("target CAS") };
        assert_eq!(next.token(), mint_token(StoreInstanceId::from_raw(52), IssuanceSequence::new(3).unwrap()));
        assert_eq!(target.read_head(&cx, &key).await.unwrap(), HeadRead::Present(next));
        assert_eq!(source.read_head(&cx, &key).await.unwrap(), HeadRead::Present(current));
    });
    runtime.block_on(source.close(&cx)).unwrap();
    runtime.block_on(target.close(&cx)).unwrap();
    drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}

#[test]
fn dropped_import_lease_cannot_leak_staged_bodies_head_or_tokens_into_an_export() {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    let mut target = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
        StoreInstanceId::from_raw(52), AuthorityLimits::default())).unwrap();
    let bundle = sample();
    runtime.block_on(async {
        // Exercise the production staging function and operation lease at the
        // exact pre-COMMIT interruption boundary, not a synthetic in-memory map.
        let mut lease = target.operation(&cx).await.unwrap();
        target.begin(&cx, &mut lease).await.unwrap();
        let staged = target.import_portable_snapshot(&cx, &bundle).await.unwrap().unwrap();
        assert!(target.connection.in_transaction());
        drop(lease);
        let exported = target.export_portable(&cx, Default::default()).await.unwrap();
        assert!(exported.bodies.is_empty());
        assert!(exported.issuance.is_empty());
        assert!(exported.head.is_none());
        assert!(!target.connection.in_transaction());
        assert!(target.authenticate_head_receipt(&cx, &staged).await.is_err(),
            "a staged but uncommitted receipt is not authentic");
        let committed = target.import_portable(&cx, &bundle, Default::default()).await.unwrap().unwrap();
        target.authenticate_head_receipt(&cx, &committed).await.unwrap();
        assert_eq!(target.export_portable(&cx, Default::default()).await.unwrap().bodies, bundle.bodies);
    });
    runtime.block_on(target.close(&cx)).unwrap();
    drop(target); drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}

#[test]
fn any_occupied_destination_table_refuses_the_whole_import_without_appending_rows() {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    for occupied in 0..3 {
        let cx = context(&runtime);
        let mut target = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
            StoreInstanceId::from_raw(60 + occupied), AuthorityLimits::default())).unwrap();
        runtime.block_on(async {
            let key = HeadKey::new(b"preexisting/head".to_vec()).unwrap();
            match occupied {
                0 => { target.put_if_absent(&cx, &ImmutableKey::new(b"preexisting/body".to_vec()).unwrap(), b"keep").await.unwrap(); }
                1 => { target.initialize_head(&cx, &key, HeadGeneration::FIRST, b"keep").await.unwrap(); }
                _ => {
                    // Deliberately damaged fixture: an issuance row with no
                    // head is still occupied, never permission to restore over it.
                    let sequence = IssuanceSequence::FIRST;
                    target.record_issuance(&cx, mint_token(target.instance_id(), sequence),
                        sequence, &key, HeadGeneration::FIRST, b"keep").await.unwrap();
                }
            }
            let mut before = Vec::new();
            for table in ["body.count", "head.count", "issuance.count"] {
                before.push(target.occupancy(&cx, table).await.unwrap());
            }
            assert!(matches!(target.import_portable(&cx, &sample(), Default::default()).await,
                Err(PortableStoreError::DestinationNotEmpty)));
            for (table, count) in ["body.count", "head.count", "issuance.count"].into_iter().zip(before) {
                assert_eq!(target.occupancy(&cx, table).await.unwrap(), count);
            }
            assert_eq!(target.read_immutable(&cx, &ImmutableKey::new(b"body".to_vec()).unwrap()).await.unwrap(), ImmutableRead::Absent);
            assert!(!target.connection.in_transaction());
        });
        runtime.block_on(target.close(&cx)).unwrap();
    }
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}

#[test]
fn export_limits_and_multi_head_refusal_finalize_the_snapshot_without_changing_state() {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    let mut target = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
        StoreInstanceId::from_raw(52), AuthorityLimits::default())).unwrap();
    runtime.block_on(async {
        target.import_portable(&cx, &sample(), Default::default()).await.unwrap();
        let original = target.export_portable(&cx, Default::default()).await.unwrap();
        for limits in [PortableStoreLimits { max_bodies: 0, ..Default::default() },
            PortableStoreLimits { max_issuance: 1, ..Default::default() },
            PortableStoreLimits { max_field_bytes: bytes(&original) - 1, ..Default::default() }]
        {
            assert!(matches!(target.export_portable(&cx, limits).await, Err(PortableStoreError::Limit(_))));
            assert!(!target.connection.in_transaction());
            assert_eq!(target.export_portable(&cx, Default::default()).await.unwrap(), original);
        }
        let key = HeadKey::new(b"second/head".to_vec()).unwrap();
        let HeadInit::Created(second) = target.initialize_head(&cx, &key, HeadGeneration::FIRST, b"other").await.unwrap()
            else { panic!("new second slot") };
        assert!(matches!(target.export_portable(&cx, Default::default()).await, Err(PortableStoreError::MultipleHeads)));
        assert!(!target.connection.in_transaction());
        assert_eq!(target.read_head(&cx, &key).await.unwrap(), HeadRead::Present(second));
    });
    runtime.block_on(target.close(&cx)).unwrap();
    drop(target); drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}

#[test]
fn portable_source_open_does_not_initialize_an_unrelated_database() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!("fg-portable-unrelated-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&path).unwrap();
    let database = path.join("unrelated.fsqlite");
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    runtime.block_on(async {
        let mut unrelated = fsqlite::AsyncConnection::open(&cx, database.to_string_lossy().to_string()).await.unwrap();
        unrelated.execute(&cx, "CREATE TABLE unrelated (value INTEGER NOT NULL) STRICT").await.unwrap();
        unrelated.execute(&cx, "INSERT INTO unrelated VALUES (42)").await.unwrap();
        unrelated.close(&cx).await.unwrap();
        assert!(FsqliteAuthorityStore::open_portable_source(&cx, database.to_string_lossy().to_string(), AuthorityLimits::default()).await.is_err());
        let mut check = fsqlite::AsyncConnection::open(&cx, database.to_string_lossy().to_string()).await.unwrap();
        let names = check.query_with_params(&cx, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name", &[]).await.unwrap();
        assert_eq!(names.len(), 1, "source opener must not add authority tables");
        let values = check.query_with_params(&cx, "SELECT value FROM unrelated", &[]).await.unwrap();
        assert_eq!(read_unsigned(&values[0], 0).unwrap(), 42);
        check.close(&cx).await.unwrap();
    });
    drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
    std::fs::remove_dir_all(path).unwrap();
}
