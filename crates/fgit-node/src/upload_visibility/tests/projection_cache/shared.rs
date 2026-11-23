//! Sharing a verified index must save history-sized copies without sharing
//! session authority, cancellation, or mutable adapter replacement state.
use super::*;

#[test]
fn cloned_adapters_share_membership_but_replacing_it_drops_all_session_proofs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            ancestor,
            ..
        } = fixture(format);
        let selected = prepare(&node).unwrap();
        let original = selected.repository();
        let cloned = original.clone();
        assert!(Arc::ptr_eq(&selected.closure, &cloned.closure_objects));
        assert_eq!(cloned.advertised_refs(), original.advertised_refs());
        assert_eq!(
            cloned.object_info_size(public).unwrap(),
            original.object_info_size(public).unwrap()
        );
        assert!(cloned.supports_shallow());
        cloned.ref_in_want_checkpoint().unwrap();

        let replaced = cloned.with_closure_objects(BTreeSet::from([private]));
        assert!(!Arc::ptr_eq(
            &original.closure_objects,
            &replaced.closure_objects
        ));
        assert_eq!(
            replaced.closure_objects.objects(),
            &BTreeSet::from([private])
        );
        assert!(!replaced.supports_shallow());
        assert!(!replaced.supports_object_info());
        assert!(!replaced.supports_ref_in_want());
        assert!(replaced.object_info_size(private).is_err());
        assert!(replaced.ref_in_want_checkpoint().is_err());
        // Replacement cannot change another adapter's membership or proof.
        assert!(original.contains_want(ancestor));
        assert!(original.supports_shallow());
        assert!(original.object_info_size(public).unwrap().is_some());
        original.ref_in_want_checkpoint().unwrap();
        node.shutdown().unwrap();
    }
}

#[test]
fn cancelled_preparation_cannot_publish_or_displace_a_shared_projection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            ..
        } = fixture(format);
        let request = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let mut expired = session_deadline();
        expired.started -= Duration::from_secs(3600);

        assert!(
            node.prepare_visible_upload_pack(
                &request,
                &materialized,
                &WireLimits::default(),
                &expired,
            )
            .is_err()
        );
        assert_eq!(node.upload_visibility_cache_stats(), (0, 0));
        let first = prepare(&node).unwrap();
        assert_eq!(node.upload_visibility_cache_stats(), (0, 1));

        assert!(
            node.prepare_visible_upload_pack(
                &request,
                &materialized,
                &WireLimits::default(),
                &expired,
            )
            .is_err()
        );
        assert_eq!(node.upload_visibility_cache_stats(), (0, 1));
        let next = prepare(&node).unwrap();
        assert_shared_projection(&first, &next);
        assert_eq!(node.upload_visibility_cache_stats(), (1, 1));

        // Independent connections share only immutable object facts. Their
        // deadline/byte counters are distinct even at the same selected head.
        let first_clock = first.repository().ref_in_want_deadline.as_ref().unwrap();
        let next_clock = next.repository().ref_in_want_deadline.as_ref().unwrap();
        assert!(!Arc::ptr_eq(&first_clock.shared, &next_clock.shared));
        first_clock.note_admitted(4096);
        assert_eq!(next_clock.shared.admitted_bytes.load(Ordering::Relaxed), 0);
        let mut exhausted = first.repository().clone();
        exhausted.ref_in_want_deadline = Some(expired.clone());
        exhausted.object_info_proof =
            Some(crate::upload_visibility::object_info::ObjectInfoProof::new(
                Arc::clone(&first.objects),
                expired,
            ));
        assert!(exhausted.ref_in_want_checkpoint().is_err());
        assert!(exhausted.object_info_size(public).is_err());
        next.repository().ref_in_want_checkpoint().unwrap();
        assert!(
            next.repository()
                .object_info_size(public)
                .unwrap()
                .is_some()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn long_native_history_adapter_clones_pin_one_membership_allocation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let mut parent = None;
        for revision in 0..4096 {
            let blob = source.put(
                ObjectType::Blob,
                format!("revision {revision}\n").into_bytes(),
            );
            let tree = source.tree(&[(b"100644", b"tracked", blob)]);
            parent = Some(source.commit(tree, parent.as_slice()));
        }
        let tip = parent.unwrap();
        let graph =
            project_visible_graph(&source, &source.admitted(), [tip], &PackLimits::default())
                .unwrap();
        assert_eq!(graph.closure.objects().len(), 3 * 4096);
        assert_eq!(graph.path_hashes.len(), 4096);
        let expected = graph.closure.objects().clone();
        let projection = VisibleProjection::new(None, graph);
        let repository = AdmissionUploadPackRepository::from_snapshot(
            &AdmissionSnapshot::default(),
            format,
            &WireLimits::default(),
        )
        .unwrap()
        .with_shared_closure_objects(Arc::clone(&projection.closure));
        let body_reads = source.reads.borrow().len();
        let header_reads = source.header_reads.borrow().len();
        let mut adapters = Vec::new();
        for _ in 0..64 {
            let cloned = repository.clone();
            assert!(Arc::ptr_eq(&projection.closure, &cloned.closure_objects));
            assert!(cloned.contains_want(tip));
            assert_eq!(cloned.closure_objects.objects(), &expected);
            adapters.push(cloned);
        }
        assert_eq!(Arc::strong_count(&projection.closure), 66);
        assert_eq!(source.reads.borrow().len(), body_reads);
        assert_eq!(source.header_reads.borrow().len(), header_reads);
        drop(repository);
        drop(projection);
        assert!(adapters.iter().all(|adapter| adapter.contains_want(tip)));
        assert_eq!(Arc::strong_count(&adapters[0].closure_objects), 64);
    }
}
