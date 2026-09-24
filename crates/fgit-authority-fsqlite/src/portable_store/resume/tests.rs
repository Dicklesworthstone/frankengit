use super::*;
use crate::{ExportedBody, ExportedHead, ExportedIssuance, SCHEMA_VERSION};
use fgit_authority::{AuthorityLimits, CasOutcome, HeadRead, ImmutableKey, ImmutableRead};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;

fn source() -> ExportBundle {
    let instance = StoreInstanceId::from_raw(41);
    let issuance: Vec<_> = [(1, b"old".as_slice()), (2, b"current".as_slice())]
        .into_iter()
        .map(|(sequence, body)| ExportedIssuance {
            token: mint_token(instance, IssuanceSequence::new(sequence).unwrap())
                .to_opaque_bytes()
                .to_vec(),
            sequence,
            head_key: b"head".to_vec(),
            generation: sequence,
            body: body.to_vec(),
        })
        .collect();
    let head = &issuance[1];
    ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: instance.raw(),
        bodies: vec![
            ExportedBody {
                key: b"a".to_vec(),
                body: b"A".to_vec(),
            },
            ExportedBody {
                key: b"b".to_vec(),
                body: b"B".to_vec(),
            },
        ],
        head: Some(ExportedHead {
            key: head.head_key.clone(),
            token: head.token.clone(),
            generation: head.generation,
            body: head.body.clone(),
        }),
        issuance,
    }
}
fn context(runtime: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    cx
}
fn fixture() -> (NodeRuntime, FsqliteAuthorityStore, Cx) {
    let runtime = RuntimeProfile::deterministic().build().unwrap();
    let cx = context(&runtime);
    let store = runtime
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            ":memory:",
            StoreInstanceId::from_raw(52),
            AuthorityLimits::default(),
        ))
        .unwrap();
    (runtime, store, cx)
}
fn close(runtime: NodeRuntime, mut store: FsqliteAuthorityStore, cx: Cx) {
    runtime.block_on(store.close(&cx)).unwrap();
    drop(store);
    drop(cx);
    assert!(runtime.join_root(std::time::Duration::from_secs(5)));
}
fn image(source: &ExportBundle, instance: StoreInstanceId) -> ExportBundle {
    let mut image = source.clone();
    image.instance = instance.raw();
    for row in &mut image.issuance {
        row.token = mint_token(instance, IssuanceSequence::new(row.sequence).unwrap())
            .to_opaque_bytes()
            .to_vec();
    }
    image.head.as_mut().unwrap().token = image.issuance.last().unwrap().token.clone();
    image
}

#[test]
fn exact_retry_preserves_receipt_every_body_and_every_issued_token() {
    let (runtime, store, cx) = fixture();
    let source = source();
    runtime.block_on(async {
        let first = store
            .resume_portable_import(&cx, &source, Default::default())
            .await
            .unwrap()
            .unwrap();
        let before = store
            .export_portable(&cx, Default::default())
            .await
            .unwrap();
        assert_eq!(before, image(&source, store.instance_id()));
        for _ in 0..3 {
            assert_eq!(
                store
                    .resume_portable_import(&cx, &source, Default::default())
                    .await
                    .unwrap(),
                Some(first.clone())
            );
            assert_eq!(
                store
                    .verify_portable_import(&cx, &source, Default::default())
                    .await
                    .unwrap(),
                Some(first.clone())
            );
            assert_eq!(
                store
                    .export_portable(&cx, Default::default())
                    .await
                    .unwrap(),
                before
            );
            assert!(!store.connection.in_transaction());
        }
        store.authenticate_head_receipt(&cx, &first).await.unwrap();
        let foreign = HeadReadReceipt::new(
            first.key().clone(),
            AuthorityVersionToken::from_opaque_bytes(
                source
                    .head
                    .as_ref()
                    .unwrap()
                    .token
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            first.generation(),
            first.body().to_vec(),
        );
        assert!(
            store
                .authenticate_head_receipt(&cx, &foreign)
                .await
                .is_err()
        );
        assert!(
            matches!(
                store
                    .import_portable(&cx, &source, Default::default())
                    .await,
                Err(PortableStoreError::DestinationNotEmpty)
            ),
            "strict import remains strict"
        );
    });
    close(runtime, store, cx);
}

#[test]
fn interrupted_prefix_and_fully_staged_import_recover_through_the_real_operation_gate() {
    for complete_staging in [false, true] {
        let (runtime, store, cx) = fixture();
        let source = source();
        runtime.block_on(async {
            let mut lease = store.operation(&cx).await.unwrap();
            store.begin(&cx, &mut lease).await.unwrap();
            if complete_staging {
                store.import_portable_snapshot(&cx, &source).await.unwrap();
            } else {
                store
                    .put_body(
                        &cx,
                        &ImmutableKey::new(b"partial-only".to_vec()).unwrap(),
                        b"discard",
                    )
                    .await
                    .unwrap();
            }
            assert!(store.connection.in_transaction());
            drop(lease);
            let receipt = store
                .resume_portable_import(&cx, &source, Default::default())
                .await
                .unwrap()
                .unwrap();
            store
                .authenticate_head_receipt(&cx, &receipt)
                .await
                .unwrap();
            assert_eq!(
                store
                    .export_portable(&cx, Default::default())
                    .await
                    .unwrap(),
                image(&source, store.instance_id())
            );
            assert_eq!(
                store
                    .read_immutable(&cx, &ImmutableKey::new(b"partial-only".to_vec()).unwrap())
                    .await
                    .unwrap(),
                ImmutableRead::Absent
            );
            assert!(!store.connection.in_transaction());
        });
        close(runtime, store, cx);
    }
}

#[test]
fn an_identical_head_does_not_hide_changed_bodies_or_historical_issuance() {
    let (runtime, store, cx) = fixture();
    let original = source();
    runtime.block_on(async {
        store
            .import_portable(&cx, &original, Default::default())
            .await
            .unwrap();
        let before = store
            .export_portable(&cx, Default::default())
            .await
            .unwrap();
        for field in 0..3 {
            let mut different = original.clone();
            match field {
                0 => different.bodies[0].body.push(0),
                1 => {
                    different.bodies.pop();
                }
                _ => different.issuance[0].body.push(0),
            }
            assert_eq!(different.head, original.head);
            validate_bundle(
                &different,
                Default::default(),
                AuthorityLimits::default(),
                || Ok(()),
            )
            .unwrap();
            assert!(
                matches!(
                    store
                        .resume_portable_import(&cx, &different, Default::default())
                        .await,
                    Err(PortableStoreError::DestinationSnapshotMismatch)
                ),
                "field {field}"
            );
            assert_eq!(
                store
                    .export_portable(&cx, Default::default())
                    .await
                    .unwrap(),
                before
            );
        }
        store
            .put_if_absent(&cx, &ImmutableKey::new(b"extra".to_vec()).unwrap(), b"keep")
            .await
            .unwrap();
        let extra = store
            .export_portable(&cx, Default::default())
            .await
            .unwrap();
        assert!(matches!(
            store
                .resume_portable_import(&cx, &original, Default::default())
                .await,
            Err(PortableStoreError::DestinationSnapshotMismatch)
        ));
        assert_eq!(
            store
                .export_portable(&cx, Default::default())
                .await
                .unwrap(),
            extra
        );
    });
    close(runtime, store, cx);
}

#[test]
fn a_newer_destination_cannot_be_rewound_by_resume_or_verification() {
    let (runtime, store, cx) = fixture();
    let source = source();
    runtime.block_on(async {
        let original = store
            .import_portable(&cx, &source, Default::default())
            .await
            .unwrap()
            .unwrap();
        let CasOutcome::Committed(newer) = store
            .compare_exchange_head(
                &cx,
                original.key(),
                original.token(),
                HeadGeneration::try_new(3).unwrap(),
                b"new canonical work",
            )
            .await
            .unwrap()
        else {
            panic!("permitted successor")
        };
        let before = store
            .export_portable(&cx, Default::default())
            .await
            .unwrap();
        assert!(matches!(
            store
                .resume_portable_import(&cx, &source, Default::default())
                .await,
            Err(PortableStoreError::DestinationSnapshotMismatch)
        ));
        assert!(matches!(
            store
                .verify_portable_import(&cx, &source, Default::default())
                .await,
            Err(PortableStoreError::DestinationSnapshotMismatch)
        ));
        assert_eq!(
            store.read_head(&cx, original.key()).await.unwrap(),
            HeadRead::Present(newer)
        );
        assert_eq!(
            store
                .export_portable(&cx, Default::default())
                .await
                .unwrap(),
            before
        );
    });
    close(runtime, store, cx);
}

#[test]
fn read_only_verification_and_cancelled_or_over_budget_resume_never_initialize() {
    let (runtime, store, cx) = fixture();
    let source = source();
    runtime.block_on(async {
        let before = store
            .export_portable(&cx, Default::default())
            .await
            .unwrap();
        assert!(matches!(
            store
                .verify_portable_import(&cx, &source, Default::default())
                .await,
            Err(PortableStoreError::DestinationSnapshotMismatch)
        ));
        let cancelled = context(&runtime);
        cancelled.cancel();
        assert!(
            store
                .resume_portable_import(&cancelled, &source, Default::default())
                .await
                .is_err()
        );
        let limits = PortableStoreLimits {
            max_bodies: 1,
            ..Default::default()
        };
        assert!(matches!(
            store.resume_portable_import(&cx, &source, limits).await,
            Err(PortableStoreError::Limit(_))
        ));
        assert_eq!(
            store
                .export_portable(&cx, Default::default())
                .await
                .unwrap(),
            before
        );
        assert!(!store.connection.in_transaction());
    });
    close(runtime, store, cx);
}

#[test]
fn exact_image_comparison_checks_every_coordinate_and_all_checkpoints() {
    let source = source();
    let instance = StoreInstanceId::from_raw(52);
    let good = image(&source, instance);
    let mut checkpoints = 0;
    assert!(
        match_image(&source, &good, instance, || {
            checkpoints += 1;
            Ok(())
        })
        .unwrap()
        .is_some()
    );
    for field in 0..12 {
        let mut changed = good.clone();
        match field {
            0 => changed.instance += 1,
            1 => changed.schema_version += 1,
            2 => changed.bodies[0].key.push(0),
            3 => changed.bodies[0].body.push(0),
            4 => changed.issuance[0].sequence += 1,
            5 => changed.issuance[0].head_key.push(0),
            6 => changed.issuance[0].generation += 1,
            7 => changed.issuance[0].body.push(0),
            8 => changed.issuance[0].token[0] ^= 1,
            9 => changed.head.as_mut().unwrap().token[0] ^= 1,
            10 => changed.head.as_mut().unwrap().body.push(0),
            _ => changed.head = None,
        }
        assert!(
            matches!(
                match_image(&source, &changed, instance, || Ok(())),
                Err(PortableStoreError::DestinationSnapshotMismatch)
            ),
            "field {field}"
        );
    }
    for stop in 1..=checkpoints {
        let mut count = 0;
        let result = match_image(&source, &good, instance, || {
            count += 1;
            if count == stop {
                Err(PortableStoreError::Limit("test checkpoint"))
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(PortableStoreError::Limit("test checkpoint"))
        ));
    }
}
