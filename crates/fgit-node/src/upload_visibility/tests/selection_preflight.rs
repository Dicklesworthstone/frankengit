//! Selected-work admission uses the verified graph before opening pack bodies.
use super::*;
use fgit_wire::{ObjectFilter, PackOptions};

fn fetch(want: GitOid) -> PackRequest {
    PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![want],
        haves: Vec::new(),
        shallows: Vec::new(),
        deepen: None,
        deepen_since: None,
        deepen_not: Vec::new(),
        filter: None,
        options: PackOptions::NONE,
    }
}

fn selected_ids(keys: &[PackOrderKey]) -> BTreeSet<GitOid> {
    keys.iter().map(|key| key.id).collect()
}

#[test]
fn preflight_reports_the_complete_selected_total_before_any_body_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            mut node,
            public,
            private,
            ..
        } = fixture_with_public_body(format, vec![b'x'; 4096]);
        let context = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::DEFAULT,
        );
        let scope = node
            .prepare_visible_upload_pack(&context, &materialized, &WireLimits::default(), &deadline)
            .unwrap();
        let request = fetch(public);
        let (keys, _, exact) = scope
            .prepare_selection(
                &request,
                &node.selected_pack_limits,
                usize::MAX,
                &mut || true,
            )
            .unwrap();
        assert!(exact > 4096);
        // Losing the body store after the proof makes any accidental fabric
        // read observable. Metadata preparation must still complete/refuse.
        let objects = node.storage_root().join("objects");
        let parked = node.storage_root().join("objects-preflight-test");
        std::fs::rename(&objects, &parked).unwrap();
        let pack_context = node.session_pack_materialization_context(&deadline);
        node.selected_pack_limits.max_total_expanded_bytes = exact - 1;
        let refusal = node
            .prepare_upload_pack_selection(
                &materialized,
                &scope,
                &request,
                &deadline,
                &pack_context,
                &mut || true,
            )
            .unwrap_err();
        assert!(
            matches!(
                &refusal,
                NodePackMaterializationRefusal::Pack(error)
                    if matches!(error.as_ref(), PackWriteError::Pack(PackError::TotalExpandedLimit {
                        actual, limit,
                    }) if *actual == exact && *limit == exact - 1)
            ),
            "{refusal:?}"
        );
        assert!(refusal.to_string().contains("--pack-max-expanded-mib"));
        assert_eq!(
            deadline
                .shared
                .selected_upload_bytes
                .load(Ordering::Relaxed),
            0
        );

        node.selected_pack_limits.max_total_expanded_bytes = exact;
        node.selected_pack_limits.max_object_bytes = 4095;
        assert!(matches!(
            node.prepare_upload_pack_selection(
                &materialized, &scope, &request, &deadline, &pack_context, &mut || true,
            ),
            Err(NodePackMaterializationRefusal::Pack(error))
                if matches!(error.as_ref(), PackWriteError::Pack(PackError::ObjectSizeLimit {
                    actual: 4096, limit: 4095,
                }))
        ));
        assert_eq!(
            deadline
                .shared
                .selected_upload_bytes
                .load(Ordering::Relaxed),
            0
        );

        node.selected_pack_limits.max_object_bytes = 4096;
        let prepared = node
            .prepare_upload_pack_selection(
                &materialized,
                &scope,
                &request,
                &deadline,
                &pack_context,
                &mut || true,
            )
            .unwrap();
        assert_eq!(selected_ids(&prepared.keys), selected_ids(&keys));
        assert_eq!(
            deadline
                .shared
                .selected_upload_bytes
                .load(Ordering::Relaxed),
            exact as u64
        );
        assert!(
            node.materialize_prepared_upload_pack(
                &materialized,
                &prepared,
                context.authority(),
                &Cell::new(None),
                None,
                &mut || true,
            )
            .is_err(),
            "body verification is still required before publication"
        );
        std::fs::rename(&parked, &objects).unwrap();
        let actual = node
            .materialize_prepared_upload_pack(
                &materialized,
                &prepared,
                context.authority(),
                &Cell::new(None),
                None,
                &mut || true,
            )
            .unwrap()
            .into_bytes()
            .unwrap();
        let prior = node
            .materialize_selected_pack_in_scope(
                &materialized,
                scope.closure_for(&materialized).unwrap(),
                Some((&scope, &request)),
                Some(&request.wants),
                &request.haves,
                crate::selected_fetch_write_profile(&request),
                context.authority(),
                &Cell::new(None),
                None,
                &mut || true,
            )
            .unwrap()
            .into_bytes()
            .unwrap();
        assert_eq!(
            actual, prior,
            "preflight preserves deterministic pack bytes"
        );
        delete_private(&node, private);
        let changed = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        expect_code(
            node.materialize_prepared_upload_pack(
                &changed,
                &prepared,
                context.authority(),
                &Cell::new(None),
                None,
                &mut || true,
            ),
            RefusalCode::AuthorityReceiptStale,
        );
        let fresh_deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::DEFAULT,
        );
        expect_code(
            node.prepare_upload_pack_selection(
                &changed,
                &scope,
                &request,
                &fresh_deadline,
                &pack_context,
                &mut || true,
            ),
            RefusalCode::AuthorityReceiptStale,
        );
        assert_eq!(
            fresh_deadline
                .shared
                .selected_upload_bytes
                .load(Ordering::Relaxed),
            0
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn selected_work_follows_have_subtraction_filters_shallow_and_explicit_lazy_wants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch: _scratch,
            node,
            public,
            private,
            private_blob,
            ancestor,
            visible,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let (inner_tag, outer_tag, deleted_tag) = publish_tag_fixture(&node, public);
        let context = node.request_context();
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission_in(&context))
            .unwrap();
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::DEFAULT,
        );
        let scope = node
            .prepare_visible_upload_pack(&context, &materialized, &WireLimits::default(), &deadline)
            .unwrap();
        let base = fetch(public);
        let mut requests = vec![base.clone()];
        for filter in [
            ObjectFilter::BlobNone,
            ObjectFilter::TreeDepth(0),
            ObjectFilter::Combine(vec![
                ObjectFilter::BlobLimit(22),
                ObjectFilter::TreeDepth(1),
            ]),
        ] {
            let mut filtered = base.clone();
            filtered.filter = Some(filter);
            requests.push(filtered);
        }
        let mut incremental = base.clone();
        incremental.haves = vec![ancestor];
        requests.push(incremental);
        let mut shallow = base.clone();
        shallow.deepen = Some(1);
        requests.push(shallow);
        let blob = visible
            .iter()
            .find(|id| scope.kind_of(id) == Some(ObjectType::Blob))
            .copied()
            .unwrap();
        let mut lazy = fetch(blob);
        lazy.filter = Some(ObjectFilter::BlobNone);
        lazy.haves = vec![public];
        requests.push(lazy);
        let mut noop = base.clone();
        noop.haves = vec![public];
        requests.push(noop);
        // Obtain the actual negotiated include-tag option from the v2 machine;
        // PackOptions deliberately exposes no arbitrary bit constructor.
        let capabilities = Capabilities::parse_v1(
            format!("fetch object-format={}", format.as_str()).as_bytes(),
            &WireLimits::default(),
        )
        .unwrap();
        let mut machine = V2UploadPack::new(capabilities, WireLimits::default()).unwrap();
        let transition = machine
            .push_bytes(
                &encode_packets(
                    &[
                        Packet::Data(b"command=fetch\n".to_vec()),
                        Packet::Delimiter,
                        Packet::Data(format!("want {public}\n").into_bytes()),
                        Packet::Data(b"include-tag\n".to_vec()),
                        Packet::Data(b"done\n".to_vec()),
                        Packet::Flush,
                    ],
                    &WireLimits::default(),
                )
                .unwrap(),
                scope.repository(),
            )
            .unwrap();
        let tagged = transition
            .events
            .into_iter()
            .find_map(|event| match event {
                crate::WireEvent::PackRequested(request) => Some(request),
                _ => None,
            })
            .unwrap();
        requests.push(tagged);
        for request in requests {
            let pack_context = node.session_pack_materialization_context(&deadline);
            let prepared = node
                .prepare_upload_pack_selection(
                    &materialized,
                    &scope,
                    &request,
                    &deadline,
                    &pack_context,
                    &mut || true,
                )
                .unwrap();
            let ids = selected_ids(&prepared.keys);
            assert!(!ids.contains(&private_blob) && !ids.contains(&deleted_tag));
            let exact: usize = ids.iter().map(|id| scope.objects[id].size).sum();
            let (_, _, admitted) = scope
                .prepare_selection(
                    &request,
                    &node.selected_pack_limits,
                    usize::MAX,
                    &mut || true,
                )
                .unwrap();
            assert_eq!(admitted, exact);
            if request.wants == [blob] {
                assert_eq!(ids, BTreeSet::from([blob]));
            }
            if request.haves == [public] && request.wants == [public] {
                assert!(ids.is_empty());
            }
            if request.deepen == Some(1) {
                assert!(!ids.contains(&ancestor));
            }
            if request.filter == Some(ObjectFilter::BlobNone) && request.wants == [public] {
                assert!(
                    prepared
                        .keys
                        .iter()
                        .all(|key| key.object_type != ObjectType::Blob)
                );
            }
            if request.options.include_tag() {
                assert!(ids.contains(&inner_tag) && ids.contains(&outer_tag));
            }
            let actual = node
                .materialize_prepared_upload_pack(
                    &materialized,
                    &prepared,
                    context.authority(),
                    &Cell::new(None),
                    None,
                    &mut || true,
                )
                .unwrap()
                .into_bytes()
                .unwrap();
            let prior = node
                .materialize_selected_pack_in_scope(
                    &materialized,
                    scope.closure_for(&materialized).unwrap(),
                    Some((&scope, &request)),
                    Some(&request.wants),
                    &request.haves,
                    crate::selected_fetch_write_profile(&request),
                    context.authority(),
                    &Cell::new(None),
                    None,
                    &mut || true,
                )
                .unwrap()
                .into_bytes()
                .unwrap();
            assert_eq!(actual, prior);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn preflight_allows_streamed_blob_metadata_above_the_buffered_body_cap() {
    let Fixture {
        scratch: _scratch,
        node,
        public,
        ..
    } = fixture(GitHashAlgorithm::Sha256);
    let context = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&context))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    let mut scope = node
        .prepare_visible_upload_pack(&context, &materialized, &WireLimits::default(), &deadline)
        .unwrap();
    let large = 64 * 1024 * 1024;
    let blob = scope
        .objects
        .iter()
        .find(|(_, object)| object.kind == ObjectType::Blob)
        .map(|(id, _)| *id)
        .unwrap();
    // Header-only fixture: no allocation or body read is needed for admission.
    scope.repository.shallow_proof = None;
    Arc::get_mut(&mut scope.objects)
        .unwrap()
        .get_mut(&blob)
        .unwrap()
        .size = large;
    let limits = PackLimits {
        max_object_bytes: large,
        max_total_expanded_bytes: large,
        ..PackLimits::default()
    };
    let (keys, _, bytes) = scope
        .prepare_selection(&fetch(blob), &limits, 32 * 1024 * 1024, &mut || true)
        .unwrap();
    assert_eq!(selected_ids(&keys), BTreeSet::from([blob]));
    assert_eq!(bytes, large);
    Arc::get_mut(&mut scope.objects)
        .unwrap()
        .get_mut(&public)
        .unwrap()
        .size = large;
    assert!(
        matches!(scope.prepare_selection(&fetch(public), &limits, 32 * 1024 * 1024, &mut || true),
            Err(NodePackMaterializationRefusal::Pack(error)) if matches!(error.as_ref(),
                PackWriteError::Pack(PackError::ObjectSizeLimit { actual, limit })
                    if *actual == large && *limit == 32 * 1024 * 1024)
        )
    );
    node.shutdown().unwrap();
}
