//! A complete live cover precedes optional cold reconstruction, even when
//! another process has retained an alternative encoding of the same objects.
use super::*;

fn persist_alternative(fixture: &ReceivedFixture) {
    let format = fixture.node.object_format;
    let objects = selective::decoded_objects(&fixture.pack, format, &BTreeMap::new());
    let mut alternate = b"PACK\0\0\0\x02".to_vec();
    alternate.extend_from_slice(&u32::try_from(objects.len()).unwrap().to_be_bytes());
    for (kind, body) in objects.values() {
        let code = match kind {
            ObjectType::Commit => 1,
            ObjectType::Tree => 2,
            ObjectType::Blob => 3,
            ObjectType::Tag => 4,
        };
        composition::object_header(&mut alternate, code, body.len());
        alternate.extend(composition::zlib_stored(body));
    }
    match format {
        GitHashAlgorithm::Sha1 => alternate.extend(fgit_crypto::sha1_digest(&alternate)),
        GitHashAlgorithm::Sha256 => alternate.extend(fgit_crypto::sha256_digest(&alternate)),
    }
    assert_ne!(alternate, fixture.pack);
    assert_eq!(
        selective::decoded_objects(&alternate, format, &BTreeMap::new()),
        objects
    );

    // This new configuration has its own empty memory cache. A separately
    // admitted receive persists the alternative without warming the first one.
    let other = reopen(&fixture.scratch, format, CACHE_BYTES);
    let admitted = receive(
        &other,
        &[(fixture.tip, b"refs/tags/alternate-encoding")],
        &alternate,
        b"warm-reuse-alternative-encoding",
    )
    .unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
    assert_eq!(other.received_pack_cache().retained_entries(), 1);
    other.shutdown().unwrap();
    assert_eq!(durable_slots(&fixture.scratch).len(), 2);
    assert_eq!(fixture.node.received_pack_cache().retained_entries(), 1);
}

#[test]
fn a_complete_warm_cover_skips_alternative_cold_reconstruction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        persist_alternative(&fixture);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert!(selection.reused.is_some());
        // Before the warm-first ordering, preparation restored the redundant
        // second encoding and expanded every canonical body a second time.
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 1);
        let payload = selective::without_fabric_objects(&fixture.node, &head, &selection);
        assert_eq!(payload.basis(), head.basis());
        assert!(payload.receipt().received().is_some());
        assert_eq!(payload.into_bytes().unwrap(), fixture.pack);
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 1);
    }
}

#[test]
fn a_cold_miss_still_restores_and_a_disabled_cache_still_writes_native_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        persist_alternative(&fixture);
        fixture.node.shutdown().unwrap();
        for capacity in [CACHE_BYTES, 0] {
            let node = reopen(&fixture.scratch, format, capacity);
            let (head, selection) = prepare(&node, fixture.tip, true, |_| {}).unwrap();
            assert!(selection.reused.is_none(), "the new service started cold");
            assert_eq!(
                node.received_pack_cache().retained_entries(),
                if capacity == 0 { 0 } else { 2 }
            );
            let payload = materialize(&node, &head, &selection);
            assert_eq!(payload.receipt().received().is_some(), capacity != 0);
            assert_eq!(payload.receipt().writer().is_some(), capacity == 0);
            selective::assert_exact_selected_bytes(
                &payload.into_bytes().unwrap(),
                format,
                &selection,
                &BTreeMap::new(),
            );
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn damaged_cold_custody_does_not_displace_a_live_cover_or_prevent_native_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        persist_alternative(&fixture);
        for slot in durable_slots(&fixture.scratch) {
            let mut bytes = std::fs::read(&slot).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(slot, bytes).unwrap();
        }
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert!(selection.reused.is_some());
        let payload = selective::without_fabric_objects(&fixture.node, &head, &selection);
        assert_eq!(payload.into_bytes().unwrap(), fixture.pack);
        fixture.node.shutdown().unwrap();

        let cold = reopen(&fixture.scratch, format, CACHE_BYTES);
        let (head, selection) = prepare(&cold, fixture.tip, true, |_| {}).unwrap();
        assert!(selection.reused.is_none());
        assert_eq!(cold.received_pack_cache().retained_entries(), 0);
        let payload = materialize(&cold, &head, &selection);
        assert!(payload.receipt().writer().is_some());
        assert!(payload.receipt().received().is_none());
        selective::assert_exact_selected_bytes(
            &payload.into_bytes().unwrap(),
            format,
            &selection,
            &BTreeMap::new(),
        );
        cold.shutdown().unwrap();
    }
}

#[test]
fn a_warm_thin_cover_keeps_the_held_base_gate_and_authoritative_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = composition::increment(format, fixture.tip);
        composition::receive_increment(&fixture.node, fixture.tip, &increment);
        let (_, full) = prepare_fetch_after_graph(
            &fixture.node,
            increment.tip,
            Some(fixture.tip),
            false,
            || {},
        )
        .unwrap();
        assert!(
            full.reused.is_none(),
            "a full pack cannot pin an external delta"
        );
        assert!(full.held_bases.is_empty());

        let (head, selection) =
            prepare_fetch_after_graph(&fixture.node, increment.tip, Some(fixture.tip), true, || {})
                .unwrap();
        assert!(selection.reused.is_some());
        assert_eq!(selection.held_bases.len(), 1);
        let mut checkpoints = 0;
        let refused = fixture.node.materialize_prepared_upload_pack(
            &head,
            &selection,
            fixture.node.request_context().authority(),
            &Cell::new(None),
            None,
            &mut || {
                checkpoints += 1;
                checkpoints < 3
            },
        );
        assert!(matches!(
            refused,
            Err(NodePackMaterializationRefusal::Pack(error))
                if matches!(error.as_ref(), PackWriteError::Pack(PackError::DeadlineExceeded))
        ));
        // A stopped reader cannot consume or mutate the pinned request. A new
        // reader still emits the exact thin pack against the same held proof.
        let payload = selective::without_fabric_objects(&fixture.node, &head, &selection);
        assert_eq!(
            payload.receipt().received().unwrap().external_base_count(),
            1
        );
        let output = payload.into_bytes().unwrap();
        assert_eq!(output, increment.pack);
        let held = selective::decoded_objects(&fixture.pack, format, &BTreeMap::new());
        selective::assert_exact_selected_bytes(&output, format, &selection, &held);
    }
}
