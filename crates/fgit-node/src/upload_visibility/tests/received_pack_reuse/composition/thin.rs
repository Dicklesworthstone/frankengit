//! Incremental fetches may reuse a received REF delta only against native
//! objects proved held by this client in the same current disclosure basis.

use super::*;

fn prepare_fetch(
    node: &OneNode,
    want: GitOid,
    have: GitOid,
    thin: bool,
    ofs_delta: bool,
    edit: impl FnOnce(&mut PackRequest),
) -> (MaterializedAdmission, PreparedUploadPack) {
    let request = node.request_context();
    let head = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    let scope = node
        .prepare_visible_upload_pack(&request, &head, &WireLimits::default(), &deadline)
        .unwrap();
    let capabilities = Capabilities::parse_v1(
        format!("fetch object-format={}", node.object_format.as_str()).as_bytes(),
        &WireLimits::default(),
    )
    .unwrap();
    let mut machine = V2UploadPack::new(capabilities, WireLimits::default()).unwrap();
    let mut packets = vec![
        Packet::Data(b"command=fetch\n".to_vec()),
        Packet::Delimiter,
        Packet::Data(format!("want {want}\n").into_bytes()),
        Packet::Data(format!("have {have}\n").into_bytes()),
    ];
    if thin {
        packets.push(Packet::Data(b"thin-pack\n".to_vec()));
    }
    if ofs_delta {
        packets.push(Packet::Data(b"ofs-delta\n".to_vec()));
    }
    packets.extend([Packet::Data(b"done\n".to_vec()), Packet::Flush]);
    let transition = machine
        .push_bytes(
            &encode_packets(&packets, &WireLimits::default()).unwrap(),
            scope.repository(),
        )
        .unwrap();
    let mut fetch = transition
        .events
        .into_iter()
        .find_map(|event| match event {
            crate::WireEvent::PackRequested(request) => Some(request),
            _ => None,
        })
        .unwrap();
    assert_eq!(fetch.options.thin_pack(), thin);
    assert_eq!(fetch.options.ofs_delta(), ofs_delta);
    edit(&mut fetch);
    let context = node.session_pack_materialization_context(&deadline);
    let prepared = node
        .prepare_upload_pack_selection(
            &head,
            &scope,
            &fetch,
            &deadline,
            &context,
            node.request_context().authority(),
            &Cell::new(None),
            &mut || true,
        )
        .unwrap();
    (head, prepared)
}

fn without_fabric_objects(
    node: &OneNode,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
) -> AuthoritySelectedPackPayload {
    let objects = node.storage_root().join("objects");
    let parked = node.storage_root().join("objects-thin-reuse-test");
    std::fs::rename(&objects, &parked).unwrap();
    let payload = node.materialize_prepared_upload_pack(
        head,
        selection,
        node.request_context().authority(),
        &Cell::new(None),
        None,
        &mut || true,
    );
    std::fs::rename(&parked, &objects).unwrap();
    payload.unwrap()
}

fn assert_thin_increment(
    payload: AuthoritySelectedPackPayload,
    head: &MaterializedAdmission,
    increment: &Increment,
) -> Vec<u8> {
    assert_eq!(payload.basis(), head.basis());
    assert!(payload.receipt().writer().is_none());
    let receipt = payload.receipt().received().unwrap();
    assert_eq!(receipt.profile(), "received-pack-thin-v1");
    assert_eq!(receipt.source_pack_count(), 1);
    assert_eq!(receipt.external_base_count(), 1);
    assert_eq!(receipt.object_count(), 3);
    assert_eq!(receipt.ref_delta_count(), 1);
    assert_eq!(receipt.output_bytes(), increment.pack.len());
    let bytes = payload.into_bytes().unwrap();
    assert_eq!(bytes, increment.pack);
    bytes
}

#[test]
fn an_incremental_fetch_reuses_exact_thin_ingress_without_expanded_object_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let mut increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        let (head, selection) = prepare_fetch(
            &fixture.node,
            increment.tip,
            fixture.tip,
            true,
            true,
            |_| {},
        );
        assert!(selection.write_profile.thin);
        assert_eq!(selected_ids(&selection), increment.objects);
        let payload = without_fabric_objects(&fixture.node, &head, &selection);
        increment.pack = assert_thin_increment(payload, &head, &increment);

        // The receiving peer really holds A. Native receive must resolve B's
        // external REF base from that peer's durable selected closure and then
        // verify its commit, tree, blob, pack trailer and exact ref predecessor.
        let (_scratch, peer) = empty_node(format);
        let admitted = receive(
            &peer,
            &[(fixture.tip, b"refs/heads/main")],
            &fixture.pack,
            b"thin-reuse-seed-peer",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        receive_increment(&peer, fixture.tip, &increment);
        let selected = peer
            .runtime()
            .block_on(peer.materialize_admission())
            .unwrap();
        let expected: BTreeSet<_> = fixture
            .public_objects
            .union(&increment.objects)
            .copied()
            .collect();
        assert_eq!(selected.selected_closure().closure().objects(), &expected);
        assert_eq!(
            peer.read_git_object(increment.blob).unwrap().payload(),
            increment.body
        );
    }
}

#[test]
fn thin_reuse_preserves_capability_filter_and_shallow_gates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        for case in 0..5 {
            let (head, selection) = prepare_fetch(
                &fixture.node,
                increment.tip,
                fixture.tip,
                case != 0,
                case != 1,
                |request| match case {
                    2 => request.filter = Some(ObjectFilter::BlobNone),
                    3 => request.deepen = Some(1),
                    4 => request.shallows.push(fixture.tip),
                    _ => {}
                },
            );
            assert!(!selection.write_profile.thin, "gate {case}");
            assert!(!selected_ids(&selection).contains(&fixture.ancestor));
            if case == 2 {
                // Blob filtering removes the external REF delta entirely;
                // the remaining native commit/tree entries are self-contained.
                let payload = super::super::selective::without_fabric_objects(
                    &fixture.node,
                    &head,
                    &selection,
                );
                let receipt = payload.receipt().received().unwrap();
                assert_eq!(receipt.profile(), "received-pack-select-v1");
                assert_eq!(receipt.source_pack_count(), 1);
                assert_eq!(receipt.external_base_count(), 0);
                super::super::selective::assert_exact_selected_bytes(
                    &payload.into_bytes().unwrap(),
                    format,
                    &selection,
                    &BTreeMap::new(),
                );
            } else {
                assert_written_subset(&fixture.node, &head, &selection);
            }
        }
        // A preceding refused reuse must not poison custody for a subsequent
        // fully negotiated request at the same canonical basis.
        let (head, selection) = prepare_fetch(
            &fixture.node,
            increment.tip,
            fixture.tip,
            true,
            true,
            |_| {},
        );
        assert_thin_increment(
            materialize(&fixture.node, &head, &selection),
            &head,
            &increment,
        );
    }
}

#[test]
fn an_older_have_requires_the_newer_cached_ref_delta_base_in_the_emitted_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        let mut held = MemorySource::new(format);
        let blob = held.put(ObjectType::Blob, vec![b'x'; 8192]);
        let tree = held.tree(&[(b"100644", b"file", blob)]);
        assert_eq!(held.commit(tree, &[]), fixture.ancestor);

        let (head, selection) = prepare_fetch(
            &fixture.node,
            increment.tip,
            fixture.ancestor,
            true,
            true,
            |_| {},
        );
        assert!(selection.write_profile.thin);
        assert_eq!(selection.keys.len(), 6);
        let payload =
            super::super::selective::without_fabric_objects(&fixture.node, &head, &selection);
        let receipt = payload.receipt().received().unwrap();
        assert_eq!(
            receipt.profile(),
            if receipt.external_base_count() == 0 {
                "received-pack-select-v1"
            } else {
                "received-pack-select-thin-v1"
            }
        );
        assert_eq!(receipt.source_pack_count(), 2);
        assert_eq!(receipt.object_count(), 6);
        assert_eq!(receipt.ofs_delta_count(), 0);
        let bytes = payload.into_bytes().unwrap();
        // Only the old ancestor's closure is supplied externally. The newer
        // base must be emitted and independently reconstructed from this pack.
        super::super::selective::assert_exact_selected_bytes(
            &bytes,
            format,
            &selection,
            &held.objects,
        );
        let mut newer_base = vec![b'x'; 8192];
        newer_base[4096] = b'y';
        let newer_id = git_object_id(format, GitObjectKind::Blob, &newer_base);
        assert!(!held.objects.contains_key(&newer_id));
        assert!(selected_ids(&selection).contains(&newer_id));
    }
}

#[test]
fn an_unknown_have_does_not_authorize_any_external_delta_base() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        let unknown = git_object_id(format, GitObjectKind::Commit, b"not a stored object");
        let (head, selection) =
            prepare_fetch(&fixture.node, increment.tip, unknown, true, true, |_| {});
        assert_eq!(selection.keys.len(), 9);
        let payload = without_fabric_objects(&fixture.node, &head, &selection);
        let receipt = payload.receipt().received().unwrap();
        assert_eq!(receipt.profile(), "received-pack-concat-v1");
        assert_eq!(receipt.external_base_count(), 0);
        assert_eq!(receipt.source_pack_count(), 2);
        assert_eq!(receipt.object_count(), 9);
    }
}

#[test]
fn thin_reuse_survives_loss_of_the_base_packs_process_local_custody() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch, node, tip, ..
        } = received_fixture(format, ExtraObject::None);
        node.shutdown().unwrap();
        let config = NodeConfig::new(
            scratch.0.clone(),
            TenantId::from_bytes([0x62; 16]),
            RepositoryId::from_bytes([0x63; 16]),
        )
        .with_object_format(format)
        .with_received_pack_cache_bytes(2 * 1024 * 1024);
        let mut reopened = OneNode::open_existing(config).unwrap();
        let selected = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        reopened
            .bring_into_service(selected.receipt().generation())
            .unwrap();
        assert_eq!(reopened.received_pack_cache().retained_entries(), 0);
        let increment = increment(format, tip);
        receive_increment(&reopened, tip, &increment);
        assert_eq!(reopened.received_pack_cache().retained_entries(), 1);
        let (head, selection) = prepare_fetch(&reopened, increment.tip, tip, true, true, |_| {});
        assert_eq!(selected_ids(&selection), increment.objects);
        let payload = without_fabric_objects(&reopened, &head, &selection);
        assert_thin_increment(payload, &head, &increment);
    }
}

#[test]
fn deleted_refs_and_changed_bases_cannot_reuse_an_old_thin_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        let (before, selection) = prepare_fetch(
            &fixture.node,
            increment.tip,
            fixture.tip,
            true,
            true,
            |_| {},
        );
        assert_thin_increment(
            materialize(&fixture.node, &before, &selection),
            &before,
            &increment,
        );
        delete_named_ref(
            &fixture.node,
            increment.tip,
            b"refs/heads/main",
            b"delete-main-thin-reuse-test",
        );
        let request = fixture.node.request_context();
        let after = fixture
            .node
            .runtime()
            .block_on(fixture.node.materialize_admission_in(&request))
            .unwrap();
        assert_ne!(before.basis(), after.basis());
        assert!(
            after
                .selected_closure()
                .closure()
                .objects()
                .contains(&increment.tip)
        );
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 2);
        expect_code(
            fixture.node.materialize_prepared_upload_pack(
                &after,
                &selection,
                request.authority(),
                &Cell::new(None),
                None,
                &mut || true,
            ),
            RefusalCode::AuthorityReceiptStale,
        );
        let deadline = GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::DEFAULT,
            GitDaemonSessionWorkScaling::DEFAULT,
        );
        let scope = fixture
            .node
            .prepare_visible_upload_pack(&request, &after, &WireLimits::default(), &deadline)
            .unwrap();
        assert!(!scope.repository().contains_want(increment.tip));
        let context = fixture.node.session_pack_materialization_context(&deadline);
        assert!(matches!(
            fixture.node.prepare_upload_pack_selection(
                &after,
                &scope,
                &selection.request,
                &deadline,
                &context, fixture.node.request_context().authority(), &Cell::new(None),
                &mut || true,
            ),
            Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(id))
                if id == increment.tip
        ));
    }
}
