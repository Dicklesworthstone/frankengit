use super::*;
use super::super::tests::sample;
use fgit_authority::{AuthorityLimits, AuthorityVersionToken, CasOutcome, HeadRead, ImmutableKey, ImmutableRead};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;

fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new(); cx.set_native_cx(runtime.request_cx(BudgetClass::Database)); cx
}
fn fixture() -> (NodeRuntime, Cx, FsqliteAuthorityStore) {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    let target = runtime.block_on(FsqliteAuthorityStore::open(&cx, ":memory:",
        StoreInstanceId::from_raw(42), AuthorityLimits::default())).unwrap();
    (runtime, cx, target)
}
fn close(runtime: NodeRuntime, cx: Cx, mut store: FsqliteAuthorityStore) {
    runtime.block_on(store.close(&cx)).unwrap(); drop(store); drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}
fn generation(raw: u64) -> HeadGeneration { HeadGeneration::try_new(raw).unwrap() }
fn issued(row: &ExportedIssuance, instance: StoreInstanceId) -> HeadReadReceipt {
    HeadReadReceipt::new(HeadKey::new(row.head_key.clone()).unwrap(),
        mint_token(instance, IssuanceSequence::new(row.sequence).unwrap()),
        generation(row.generation), row.body.clone())
}

#[test]
fn whole_store_round_trip_authenticates_each_head_and_continues_the_global_ledger() {
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let receipts = store.import_multi_head_portable(&cx, &source, Default::default()).await.unwrap();
        assert_eq!(receipts.len(), 2);
        for receipt in &receipts {
            assert_eq!(store.read_head(&cx, receipt.key()).await.unwrap(), HeadRead::Present(receipt.clone()));
            store.authenticate_head_receipt(&cx, receipt).await.unwrap();
        }
        for row in &source.issuance {
            store.authenticate_head_receipt(&cx, &issued(row, store.instance_id())).await.unwrap();
            assert!(store.authenticate_head_receipt(&cx, &issued(row, StoreInstanceId::from_raw(source.instance))).await.is_err());
        }
        let before = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert_eq!(before.bodies, source.bodies); assert_eq!(before.heads.len(), 2);
        for (offset, old) in receipts.iter().enumerate() {
            let outcome = store.compare_exchange_head(&cx, old.key(), old.token(),
                old.generation().next().unwrap(), b"after restore").await.unwrap();
            let CasOutcome::Committed(receipt) = outcome else { panic!("next CAS must commit"); };
            assert_eq!(receipt.token(), mint_token(store.instance_id(), IssuanceSequence::new(5 + offset as u64).unwrap()));
        }
        let after = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert_eq!(after.issuance.len(), 6); assert_eq!(after.heads.len(), 2);
    });
    close(runtime, cx, store);
}

#[test]
fn exact_resumes_do_not_write_but_changed_or_extra_state_cannot_be_adopted() {
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let first = store.resume_multi_head_import(&cx, &source, Default::default()).await.unwrap();
        let original = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert!(matches!(store.import_multi_head_portable(&cx, &source, Default::default()).await,
            Err(PortableStoreError::DestinationNotEmpty)));
        for _ in 0..3 {
            assert_eq!(store.resume_multi_head_import(&cx, &source, Default::default()).await.unwrap(), first);
            assert_eq!(store.verify_multi_head_import(&cx, &source, Default::default()).await.unwrap(), first);
            assert_eq!(store.export_multi_head_portable(&cx, Default::default()).await.unwrap(), original);
        }
        store.put_if_absent(&cx, &ImmutableKey::new(b"extra".to_vec()).unwrap(), b"preserve").await.unwrap();
        let changed = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert!(matches!(store.resume_multi_head_import(&cx, &source, Default::default()).await,
            Err(PortableStoreError::DestinationSnapshotMismatch)));
        assert!(store.verify_multi_head_import(&cx, &source, Default::default()).await.is_err());
        assert_eq!(store.export_multi_head_portable(&cx, Default::default()).await.unwrap(), changed);
    });
    close(runtime, cx, store);
}

#[test]
fn an_advanced_nonfirst_head_refuses_resume_without_rewinding_either_slot() {
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let receipts = store.import_multi_head_portable(&cx, &source, Default::default()).await.unwrap();
        let other = &receipts[1];
        assert!(matches!(store.compare_exchange_head(&cx, other.key(), other.token(),
            other.generation().next().unwrap(), b"new accepted work").await.unwrap(), CasOutcome::Committed(_)));
        let advanced = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert!(store.resume_multi_head_import(&cx, &source, Default::default()).await.is_err());
        assert_eq!(store.export_multi_head_portable(&cx, Default::default()).await.unwrap(), advanced);
        assert_eq!(store.read_head(&cx, receipts[0].key()).await.unwrap(), HeadRead::Present(receipts[0].clone()));
    });
    close(runtime, cx, store);
}

#[test]
fn abandoned_import_transaction_does_not_publish_any_head_body_or_token() {
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let mut lease = store.operation(&cx).await.unwrap(); store.begin(&cx, &mut lease).await.unwrap();
        let staged = store.import_multi_head_snapshot(&cx, &source).await.unwrap();
        assert_eq!(store.occupancy(&cx, "head.count").await.unwrap(), 2);
        assert_eq!(store.occupancy(&cx, "issuance.count").await.unwrap(), 4);
        drop(lease); // the next operation must finalize, not expose these rows
        let empty = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert!(empty.bodies.is_empty() && empty.heads.is_empty() && empty.issuance.is_empty());
        for receipt in &staged { assert!(store.authenticate_head_receipt(&cx, receipt).await.is_err()); }
        assert!(store.verify_multi_head_import(&cx, &source, Default::default()).await.is_err());
        assert_eq!(store.read_immutable(&cx, &ImmutableKey::new(vec![0]).unwrap()).await.unwrap(), ImmutableRead::Absent);
        assert_eq!(store.resume_multi_head_import(&cx, &source, Default::default()).await.unwrap(), staged);
    });
    close(runtime, cx, store);
}

#[test]
fn canceled_or_over_limit_calls_leave_the_connection_and_snapshot_usable() {
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let cancelled = context(&runtime); cancelled.cancel();
        assert!(store.import_multi_head_portable(&cancelled, &source, Default::default()).await.is_err());
        assert!(store.export_multi_head_portable(&cancelled, Default::default()).await.is_err());
        assert!(store.export_multi_head_portable(&cx, Default::default()).await.unwrap().heads.is_empty());
        let too_small = MultiHeadLimits { max_heads: 1, ..Default::default() };
        assert!(store.import_multi_head_portable(&cx, &source, too_small).await.is_err());
        store.import_multi_head_portable(&cx, &source, Default::default()).await.unwrap();
        let expected = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert!(store.export_multi_head_portable(&cx, too_small).await.is_err());
        assert!(!store.connection.in_transaction());
        assert_eq!(store.export_multi_head_portable(&cx, Default::default()).await.unwrap(), expected);
        assert!(matches!(store.export_portable(&cx, Default::default()).await, Err(PortableStoreError::MultipleHeads)));
    });
    close(runtime, cx, store);
}

#[test]
fn head_writes_cannot_interleave_with_the_multi_head_snapshot_transaction() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let (runtime, cx, store) = fixture(); let source = sample();
    runtime.block_on(async {
        let receipts = store.import_multi_head_portable(&cx, &source, Default::default()).await.unwrap();
        let mut lease = store.operation(&cx).await.unwrap(); store.begin(&cx, &mut lease).await.unwrap();
        let snapshot = store.export_multi_head_snapshot(&cx, Default::default()).await.unwrap();
        let old = &receipts[1];
        let mut writer = Box::pin(store.compare_exchange_head(&cx, old.key(), old.token(), generation(3), b"queued"));
        poll_fn(|task| { assert!(writer.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        assert_eq!(store.export_multi_head_snapshot(&cx, Default::default()).await.unwrap(), snapshot);
        store.connection.rollback_transaction(&cx).await.unwrap(); lease.finalized(); drop(lease);
        assert!(matches!(writer.await.unwrap(), CasOutcome::Committed(_)));
        let after = store.export_multi_head_portable(&cx, Default::default()).await.unwrap();
        assert_eq!(after.issuance.len(), snapshot.issuance.len() + 1);
        assert_eq!(after.heads[0], snapshot.heads[0]); assert_ne!(after.heads[1], snapshot.heads[1]);
    });
    close(runtime, cx, store);
}

#[test]
fn an_occupied_ledger_without_any_head_is_not_an_empty_restore_target() {
    let (runtime, cx, store) = fixture();
    runtime.block_on(async {
        let key = HeadKey::new(b"damaged".to_vec()).unwrap();
        store.record_issuance(&cx, AuthorityVersionToken::from_opaque_bytes([9; 16]),
            IssuanceSequence::FIRST, &key, HeadGeneration::FIRST, b"retain evidence").await.unwrap();
        assert!(matches!(store.import_multi_head_portable(&cx, &sample(), Default::default()).await,
            Err(PortableStoreError::DestinationNotEmpty)));
        assert!(store.resume_multi_head_import(&cx, &sample(), Default::default()).await.is_err());
        assert_eq!(store.occupancy(&cx, "body.count").await.unwrap(), 0);
        assert_eq!(store.occupancy(&cx, "head.count").await.unwrap(), 0);
        assert_eq!(store.occupancy(&cx, "issuance.count").await.unwrap(), 1);
    });
    close(runtime, cx, store);
}
