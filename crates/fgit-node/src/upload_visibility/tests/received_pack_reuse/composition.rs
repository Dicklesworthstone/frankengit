//! A clone after an incremental push can reuse complete verified representations
//! only when their union is precisely the current authorized object selection.

use super::*;
use fgit_crypto::{sha1_digest, sha256_digest};

struct Increment {
    pack: Vec<u8>,
    tip: GitOid,
    blob: GitOid,
    body: Vec<u8>,
    objects: BTreeSet<GitOid>,
}

fn write_size(output: &mut Vec<u8>, mut size: usize) {
    loop {
        let byte = (size & 0x7f) as u8;
        size >>= 7;
        output.push(byte | if size == 0 { 0 } else { 0x80 });
        if size == 0 {
            return;
        }
    }
}

fn copy_and_append_delta(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    assert!(!base.is_empty() && base.len() < (1 << 24));
    let mut program = Vec::new();
    write_size(&mut program, base.len());
    write_size(&mut program, base.len() + suffix.len());
    let mut copy = 0x80;
    let mut operands = Vec::new();
    for index in 0..3 {
        let byte = ((base.len() >> (index * 8)) & 0xff) as u8;
        if byte != 0 {
            copy |= 0x10 << index;
            operands.push(byte);
        }
    }
    program.push(copy);
    program.extend(operands);
    for part in suffix.chunks(127) {
        program.push(u8::try_from(part.len()).unwrap());
        program.extend_from_slice(part);
    }
    program
}

fn object_header(output: &mut Vec<u8>, kind: u8, mut size: usize) {
    let mut byte = (kind << 4) | (size & 0xf) as u8;
    size >>= 4;
    while size != 0 {
        output.push(byte | 0x80);
        byte = (size & 0x7f) as u8;
        size >>= 7;
    }
    output.push(byte);
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("small native metadata and delta fixture");
    let mut output = vec![0x78, 0x01, 0x01];
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&(!length).to_le_bytes());
    output.extend_from_slice(bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    output.extend_from_slice(&((b << 16) | a).to_be_bytes());
    output
}

fn increment(format: GitHashAlgorithm, parent: GitOid) -> Increment {
    // This is the second blob in received_fixture's initial full pack. The
    // incremental pack transports only its REF-delta, tree and child commit.
    let mut base = vec![b'x'; 8192];
    base[4096] = b'y';
    let base_id = git_object_id(format, GitObjectKind::Blob, &base);
    let mut body = base.clone();
    body.extend_from_slice(b"incremental suffix\n");
    let mut source = MemorySource::new(format);
    let blob = source.put(ObjectType::Blob, body.clone());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let tip = source.commit(tree, &[parent]);
    let program = copy_and_append_delta(&base, &body[base.len()..]);

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

fn receive_increment(node: &OneNode, previous: GitOid, increment: &Increment) {
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
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x64; 16]),
        IdempotencyKey::new(b"received-pack-incremental-update".to_vec()).unwrap(),
    );
    let admitted = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &session,
            &materialized,
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

fn selected_ids(selection: &PreparedUploadPack) -> BTreeSet<GitOid> {
    selection.keys.iter().map(|key| key.id).collect()
}

fn assert_written_subset(
    node: &OneNode,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
) {
    let payload = materialize(node, head, selection);
    assert!(payload.receipt().received().is_none());
    assert_eq!(
        payload.receipt().writer().unwrap().object_count as usize,
        selection.keys.len()
    );
    let bytes = payload.into_bytes().unwrap();
    let parsed = read_verified_pack(
        &bytes,
        node.object_format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    assert_eq!(parsed.entries().len(), selection.keys.len());
    let offsets: Vec<_> = parsed.entries().iter().map(|entry| entry.offset).collect();
    let objects = parsed.into_scalar_objects(|_| None).unwrap();
    let limits = PackLimits::default();
    let resolver = fgit_pack::ScalarResolver::new(&objects, &(), &limits, &mut || true).unwrap();
    let reconstructed: BTreeSet<_> = offsets
        .into_iter()
        .map(|offset| {
            let (kind, body) = resolver.resolve_offset_typed(offset, &mut || true).unwrap();
            git_object_id(node.object_format, crypto_object_kind(kind), &body)
        })
        .collect();
    assert_eq!(reconstructed, selected_ids(selection));
}

#[test]
fn first_clone_after_a_thin_push_reuses_both_verified_packs_without_object_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        let (head, selection) = prepare(&fixture.node, increment.tip, true, |_| {}).unwrap();
        let expected: BTreeSet<_> = fixture
            .public_objects
            .union(&increment.objects)
            .copied()
            .collect();
        assert_eq!(selected_ids(&selection), expected);
        assert_eq!(expected.len(), 9);

        // The actual production disclosure and preflight are complete. A
        // materializer that reloads either metadata or expanded blob bytes now
        // fails: only the received representations remain accessible.
        let objects = fixture.node.storage_root().join("objects");
        let parked = fixture.node.storage_root().join("objects-composition-test");
        std::fs::rename(&objects, &parked).unwrap();
        let payload = materialize(&fixture.node, &head, &selection);
        std::fs::rename(&parked, &objects).unwrap();
        let receipt = payload.receipt().received().unwrap();
        assert_eq!(receipt.profile(), "received-pack-concat-v1");
        assert_eq!(receipt.source_pack_count(), 2);
        assert_eq!(receipt.object_count(), 9);
        assert!(receipt.ofs_delta_count() > 0);
        assert_eq!(receipt.ref_delta_count(), 1);
        assert_eq!(payload.basis(), head.basis());
        let expected_bytes = fixture.pack.len() + increment.pack.len() - 12 - format.digest_len();
        assert_eq!(receipt.output_bytes(), expected_bytes);
        let bytes = payload.into_bytes().unwrap();
        assert_eq!(bytes.len(), expected_bytes);

        // Receiving into an empty repository proves the resulting pack has a
        // real native trailer, valid relocated OFS distances, all REF bases and
        // precisely the commit/tree/blob history needed by an actual clone.
        let (_scratch, clone) = empty_node(format);
        let admitted = receive(
            &clone,
            &[(increment.tip, b"refs/heads/main")],
            &bytes,
            b"received-pack-composition-clone",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let cloned = clone
            .runtime()
            .block_on(clone.materialize_admission())
            .unwrap();
        assert_eq!(cloned.selected_closure().closure().objects(), &expected);
        assert_eq!(
            clone.read_git_object(increment.blob).unwrap().payload(),
            increment.body
        );
    }
}

#[test]
fn partial_fetches_do_not_import_unselected_bases_or_whole_pack_extras() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let increment = increment(format, fixture.tip);
        receive_increment(&fixture.node, fixture.tip, &increment);
        for case in 0..4 {
            let want = if case == 3 {
                fixture.ancestor
            } else {
                increment.tip
            };
            let (head, selection) = prepare(&fixture.node, want, true, |request| match case {
                0 => request.haves.push(fixture.tip),
                1 => request.filter = Some(ObjectFilter::BlobNone),
                2 => request.deepen = Some(1),
                _ => {}
            })
            .unwrap();
            assert!(selection.keys.len() < 9);
            if case == 0 || case == 2 {
                assert_eq!(selected_ids(&selection), increment.objects);
            }
            assert_written_subset(&fixture.node, &head, &selection);
        }
        // A historical request that exactly equals the original full pack
        // remains reusable; reduced history alone does not prohibit a hit.
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        let payload = materialize(&fixture.node, &head, &selection);
        let receipt = payload.receipt().received().unwrap();
        assert_eq!(receipt.profile(), "received-pack-v1");
        assert_eq!(receipt.source_pack_count(), 1);
        assert_eq!(payload.into_bytes().unwrap(), fixture.pack);
    }
}

#[test]
fn unreachable_and_deleted_branch_objects_prevent_composition_into_a_public_clone() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for extra in [ExtraObject::Unreachable, ExtraObject::PrivateBranch] {
            let fixture = received_fixture(format, extra);
            let increment = increment(format, fixture.tip);
            receive_increment(&fixture.node, fixture.tip, &increment);
            if let Some(private) = fixture.private {
                let (before, both) = prepare(&fixture.node, increment.tip, true, |request| {
                    request.wants.push(private);
                })
                .unwrap();
                let payload = materialize(&fixture.node, &before, &both);
                assert_eq!(payload.receipt().received().unwrap().source_pack_count(), 2);
                delete_private(&fixture.node, private);
            }
            let (head, selection) = prepare(&fixture.node, increment.tip, true, |_| {}).unwrap();
            let expected: BTreeSet<_> = fixture
                .public_objects
                .union(&increment.objects)
                .copied()
                .collect();
            assert_eq!(selected_ids(&selection), expected);
            assert_written_subset(&fixture.node, &head, &selection);
        }
    }
}

#[test]
fn a_thin_pack_without_retained_base_history_falls_back_to_native_materialization() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch,
            node,
            tip,
            public_objects,
            ..
        } = received_fixture(format, ExtraObject::None);
        node.shutdown().unwrap();
        // A new process configuration has the durable selected objects but no
        // custody of the original pack. Its subsequent thin push is real and
        // valid; the cache must not pretend that its external base is present.
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
        let increment = increment(format, tip);
        receive_increment(&reopened, tip, &increment);
        assert_eq!(reopened.received_pack_cache().retained_entries(), 1);
        let (head, selection) = prepare(&reopened, increment.tip, true, |_| {}).unwrap();
        assert_eq!(
            selected_ids(&selection),
            public_objects.union(&increment.objects).copied().collect()
        );
        assert_written_subset(&reopened, &head, &selection);
    }
}
