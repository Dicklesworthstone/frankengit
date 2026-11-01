//! A real push history can retain more than eight complete representations
//! without widening the byte budget or the exact clone disclosure.

use super::*;

const UPDATES: usize = 12;
const CACHE_BYTES: usize = 2 * 1024 * 1024;

struct History {
    fixture: ReceivedFixture,
    updates: Vec<Increment>,
    objects: BTreeSet<GitOid>,
    output_bytes: usize,
}

fn next_increment(
    format: GitHashAlgorithm,
    parent: GitOid,
    base: &[u8],
    ordinal: usize,
) -> Increment {
    let suffix = format!("history update {ordinal:02}\n");
    let mut body = base.to_vec();
    body.extend_from_slice(suffix.as_bytes());
    let mut source = MemorySource::new(format);
    let blob = source.put(ObjectType::Blob, body.clone());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let tip = source.commit(tree, &[parent]);
    let base_id = git_object_id(format, GitObjectKind::Blob, base);
    let program = copy_and_append_delta(base, suffix.as_bytes());
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x03".to_vec();
    object_header(&mut pack, 7, program.len());
    pack.extend_from_slice(base_id.as_bytes());
    pack.extend(zlib_stored(&program));
    for (kind, id) in [(2, tree), (1, tip)] {
        let (_, bytes) = source.objects.get(&id).unwrap();
        object_header(&mut pack, kind, bytes.len());
        pack.extend(zlib_stored(bytes));
    }
    match format {
        GitHashAlgorithm::Sha1 => pack.extend(sha1_digest(&pack)),
        GitHashAlgorithm::Sha256 => pack.extend(sha256_digest(&pack)),
    }
    let parsed = read_verified_pack(
        &pack,
        format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    assert_eq!(parsed.entries().len(), 3);
    assert!(matches!(
        parsed.entries()[0].delta_base.as_ref(),
        Some(fgit_pack::ParsedDeltaBase::Ref { base, .. }) if *base == base_id
    ));
    Increment {
        pack,
        tip,
        blob,
        body,
        objects: source.objects.keys().copied().collect(),
    }
}

fn receive_step(node: &OneNode, previous: GitOid, increment: &Increment, ordinal: usize) {
    let format = node.object_format;
    let limits = ReceiveLimits::default();
    let caps = format!("report-status object-format={}", format.as_str());
    let context = ReceiveContext::new(
        format,
        Capabilities::parse_v1(caps.as_bytes(), &limits.wire).unwrap(),
        limits.clone(),
        SignedPushProfile::Refuse,
    )
    .unwrap();
    let mut input = encode_packets(
        &[
            Packet::Data(
                format!("{previous} {} refs/heads/main\0{caps}\n", increment.tip).into_bytes(),
            ),
            Packet::Flush,
        ],
        &limits.wire,
    )
    .unwrap();
    input.extend_from_slice(&increment.pack);
    let request = node.request_context();
    let head = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let key = format!("received-pack-history-step-{ordinal}").into_bytes();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x64; 16]),
        IdempotencyKey::new(key).unwrap(),
    );
    let admitted = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &session,
            &head,
            context,
            &input,
            ParseLimits {
                tree_reference_bytes: format.digest_len(),
                ..ParseLimits::default()
            },
            AdmissionLimits::default(),
            &mut || true,
        ))
        .unwrap();
    assert_eq!(admitted.commands.len(), 1);
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
}

fn history(format: GitHashAlgorithm) -> History {
    let fixture = received_fixture(format, ExtraObject::None);
    assert_eq!(fixture.node.received_pack_cache().max_bytes(), CACHE_BYTES);
    let mut previous = fixture.tip;
    let mut base = vec![b'x'; 8192];
    base[4096] = b'y';
    let mut objects = fixture.public_objects.clone();
    let mut output_bytes = fixture.pack.len();
    let mut updates = Vec::new();
    for ordinal in 1..=UPDATES {
        let increment = next_increment(format, previous, &base, ordinal);
        receive_step(&fixture.node, previous, &increment, ordinal);
        assert_eq!(
            fixture.node.received_pack_cache().retained_entries(),
            ordinal + 1,
            "small pushes must not evict the original full pack at the ninth source"
        );
        for &id in &increment.objects {
            assert!(
                objects.insert(id),
                "every push contributes distinct native objects"
            );
        }
        output_bytes += increment.pack.len() - 12 - format.digest_len();
        previous = increment.tip;
        base.clone_from(&increment.body);
        updates.push(increment);
    }
    assert_eq!(objects.len(), 6 + 3 * UPDATES);
    History {
        fixture,
        updates,
        objects,
        output_bytes,
    }
}

#[test]
fn a_full_clone_after_twelve_thin_pushes_reuses_the_entire_native_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let history = history(format);
        let node = &history.fixture.node;
        let tip = history.updates.last().unwrap().tip;
        let (head, selection) = prepare(node, tip, true, |_| {}).unwrap();
        assert_eq!(selected_ids(&selection), history.objects);
        let objects = node.storage_root().join("objects");
        let parked = node.storage_root().join("objects-long-history-test");
        std::fs::rename(&objects, &parked).unwrap();
        let payload = node.materialize_prepared_upload_pack(
            &head,
            &selection,
            node.request_context().authority(),
            &Cell::new(None),
            None,
            &mut || true,
        );
        std::fs::rename(&parked, &objects).unwrap();
        let payload = payload.unwrap();
        let receipt = payload.receipt().received().unwrap();
        assert_eq!(receipt.profile(), "received-pack-concat-v1");
        assert_eq!(receipt.source_pack_count(), UPDATES + 1);
        assert_eq!(receipt.external_base_count(), 0);
        assert_eq!(receipt.object_count() as usize, history.objects.len());
        assert_eq!(receipt.ref_delta_count(), UPDATES);
        assert!(receipt.ofs_delta_count() > 0);
        assert!(receipt.maximum_delta_depth() >= UPDATES);
        assert!(receipt.maximum_delta_depth() <= PackLimits::default().max_delta_depth);
        assert_eq!(receipt.output_bytes(), history.output_bytes);
        assert_eq!(payload.basis(), head.basis());
        let bytes = payload.into_bytes().unwrap();
        assert_eq!(bytes.len(), history.output_bytes);

        // Empty-receiver native admission resolves the complete REF chain
        // through all thirteen source runs. No external base oracle is supplied.
        let (_scratch, peer) = empty_node(format);
        let admitted = receive(
            &peer,
            &[(tip, b"refs/heads/main")],
            &bytes,
            b"received-pack-long-history-clone",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let selected = peer
            .runtime()
            .block_on(peer.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.selected_closure().closure().objects(),
            &history.objects
        );
        for increment in &history.updates {
            assert_eq!(
                peer.read_git_object(increment.blob).unwrap().payload(),
                increment.body
            );
        }
    }
}

fn receive_cache_pressure(node: &OneNode, ordinal: u8) {
    let mut source = MemorySource::new(node.object_format);
    // Three stored packs of this size exceed the unchanged 2 MiB custody
    // limit even before metadata charges. Each stays well below 1 MiB, so a
    // geometrically grown ingress allocation still fits its capture ceiling.
    // Only sixteen sources are received throughout this test.
    let body = vec![ordinal; 768 * 1024];
    let blob = source.put(ObjectType::Blob, body);
    let tree = source.tree(&[(b"100644", b"pressure", blob)]);
    let tip = source.commit(tree, &[]);
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let source = ReceivedSource(source);
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        node.object_format,
        PackWriteProfile::STORED_V1,
        limits.clone(),
    )
    .plan_selected(&source, &ids, &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    assert!(pack.len() < node.received_pack_cache().capture_limit());
    let name = format!("refs/heads/cache-pressure-{ordinal}");
    let key = format!("received-pack-cache-pressure-{ordinal}");
    let admitted = receive(node, &[(tip, name.as_bytes())], &pack, key.as_bytes()).unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
    // Prove actual custody of the new allocation; successful publication
    // alone would also be possible if optional capture had refused its size.
    let (head, selection) = prepare(node, tip, true, |_| {}).unwrap();
    let payload = materialize(node, &head, &selection);
    assert_eq!(payload.receipt().received().unwrap().source_pack_count(), 1);
    assert_eq!(payload.into_bytes().unwrap(), pack);
}

#[test]
fn byte_budget_eviction_still_falls_back_for_the_same_long_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let history = history(format);
        let node = &history.fixture.node;
        let tip = history.updates.last().unwrap().tip;
        receive_cache_pressure(node, 0x71);
        receive_cache_pressure(node, 0x72);
        receive_cache_pressure(node, 0x73);
        assert_eq!(node.received_pack_cache().max_bytes(), CACHE_BYTES);
        assert!(node.received_pack_cache().retained_entries() < UPDATES + 1);
        let (head, selection) = prepare(node, tip, true, |_| {}).unwrap();
        assert_eq!(selected_ids(&selection), history.objects);
        // The pressure branches remain outside this wanted history. Losing
        // original custody changes only materialization work, never selection.
        assert_written_subset(node, &head, &selection);
    }
}
