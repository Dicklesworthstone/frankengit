//! Received representations are reusable only for a fresh, exact disclosure.
use super::*;
use crate::{AuthoritySelectedPackPayload, NodeReceiveTransportRefusal, PreparedUploadPack};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, NativeChecksumVerifier, read_verified_pack,
};
use fgit_wire::ObjectFilter;

mod composition;

struct ReceivedSource(MemorySource);

impl CanonicalObjectSource for ReceivedSource {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            1,
        ))
    }
}

#[derive(Clone, Copy)]
enum ExtraObject {
    None,
    Unreachable,
    PrivateBranch,
}

struct ReceivedFixture {
    scratch: Scratch,
    node: OneNode,
    pack: Vec<u8>,
    tip: GitOid,
    ancestor: GitOid,
    private: Option<GitOid>,
    public_objects: BTreeSet<GitOid>,
}

fn receive_input(
    format: GitHashAlgorithm,
    tips: &[(GitOid, &[u8])],
    pack: &[u8],
) -> (ReceiveContext, Vec<u8>) {
    let limits = ReceiveLimits::default();
    let caps = format!("report-status object-format={}", format.as_str());
    let context = ReceiveContext::new(
        format,
        Capabilities::parse_v1(caps.as_bytes(), &limits.wire).unwrap(),
        limits.clone(),
        SignedPushProfile::Refuse,
    )
    .unwrap();
    let zero = "0".repeat(format.digest_len() * 2);
    let mut packets = Vec::new();
    for (position, (tip, name)) in tips.iter().enumerate() {
        let mut line = format!("{zero} {tip} ").into_bytes();
        line.extend_from_slice(name);
        if position == 0 {
            line.push(0);
            line.extend_from_slice(caps.as_bytes());
        }
        line.push(b'\n');
        packets.push(Packet::Data(line));
    }
    packets.push(Packet::Flush);
    let mut input = encode_packets(&packets, &limits.wire).unwrap();
    input.extend_from_slice(pack);
    (context, input)
}

fn receive(
    node: &OneNode,
    tips: &[(GitOid, &[u8])],
    pack: &[u8],
    key: &[u8],
) -> Result<fgit_admission::AdmissionResult, NodeReceiveTransportRefusal> {
    let format = node.object_format;
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let (context, input) = receive_input(format, tips, pack);
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x64; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    node.runtime()
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
}

fn empty_node(format: GitHashAlgorithm) -> (Scratch, OneNode) {
    let scratch = Scratch::new();
    let config = NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0x62; 16]),
        RepositoryId::from_bytes([0x63; 16]),
    )
    .with_object_format(format)
    .with_received_pack_cache_bytes(2 * 1024 * 1024);
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    (scratch, node)
}

fn received_fixture(format: GitHashAlgorithm, extra: ExtraObject) -> ReceivedFixture {
    let (scratch, node) = empty_node(format);
    let mut source = MemorySource::new(format);
    let old_body = vec![b'x'; 8192];
    let mut new_body = old_body.clone();
    new_body[4096] = b'y';
    let old = source.put(ObjectType::Blob, old_body);
    let old_tree = source.tree(&[(b"100644", b"file", old)]);
    let ancestor = source.commit(old_tree, &[]);
    let new = source.put(ObjectType::Blob, new_body);
    let new_tree = source.tree(&[(b"100644", b"file", new)]);
    let tip = source.commit(new_tree, &[ancestor]);
    let public_objects = source.objects.keys().copied().collect();
    let private = match extra {
        ExtraObject::None => None,
        ExtraObject::Unreachable => {
            source.put(
                ObjectType::Blob,
                b"unreachable secret uploaded alongside main".to_vec(),
            );
            None
        }
        ExtraObject::PrivateBranch => {
            let blob = source.put(ObjectType::Blob, b"private branch secret".to_vec());
            let tree = source.tree(&[(b"100644", b"secret", blob)]);
            Some(source.commit(tree, &[ancestor]))
        }
    };
    let ids: Vec<_> = source.objects.keys().copied().collect();
    let source = ReceivedSource(source);
    // Stored ingress deliberately differs from the compressed fallback, so
    // byte equality detects reuse independently of the materialization receipt.
    let limits = PackLimits::default();
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
        .plan_selected(&source, &ids, &mut || true)
        .unwrap();
    let (pack, receipt) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    assert!(
        receipt.delta_count > 0,
        "ingress fixture must contain OFS deltas"
    );
    let mut tips = vec![(tip, b"refs/heads/main".as_slice())];
    if let Some(private) = private {
        tips.push((private, b"refs/heads/private"));
    }
    let admitted = receive(&node, &tips, &pack, b"received-pack-reuse-fixture").unwrap();
    assert!(admitted.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
    ReceivedFixture {
        scratch,
        node,
        pack,
        tip,
        ancestor,
        private,
        public_objects,
    }
}

fn prepare(
    node: &OneNode,
    tip: GitOid,
    ofs_delta: bool,
    edit: impl FnOnce(&mut PackRequest),
) -> Result<(MaterializedAdmission, PreparedUploadPack), NodePackMaterializationRefusal> {
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    let scope = node
        .prepare_visible_upload_pack(&request, &materialized, &WireLimits::default(), &deadline)
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
        Packet::Data(format!("want {tip}\n").into_bytes()),
    ];
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
    edit(&mut fetch);
    let context = node.session_pack_materialization_context(&deadline);
    node.prepare_upload_pack_selection(
        &materialized,
        &scope,
        &fetch,
        &deadline,
        &context,
        &mut || true,
    )
    .map(|prepared| (materialized, prepared))
}

fn materialize(
    node: &OneNode,
    materialized: &MaterializedAdmission,
    prepared: &PreparedUploadPack,
) -> AuthoritySelectedPackPayload {
    node.materialize_prepared_upload_pack(
        materialized,
        prepared,
        node.request_context().authority(),
        &Cell::new(None),
        None,
        &mut || true,
    )
    .unwrap()
}

#[test]
fn first_clone_reuses_the_native_validated_ingress_bytes_for_both_object_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            fixture.public_objects
        );
        // The current disclosure proof is complete. Making every fabric body
        // unavailable exposes any accidental re-read during the first clone.
        let objects = fixture.node.storage_root().join("objects");
        let parked = fixture.node.storage_root().join("objects-reuse-test");
        std::fs::rename(&objects, &parked).unwrap();
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(payload.receipt().received().is_some());
        assert!(payload.receipt().writer().is_none());
        assert_eq!(payload.basis(), head.basis());
        assert_eq!(payload.into_bytes().unwrap(), fixture.pack);
        std::fs::rename(&parked, &objects).unwrap();
    }
}

#[test]
fn unreachable_ingress_entries_cannot_be_disclosed_by_a_cache_hit() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::Unreachable);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            fixture.public_objects
        );
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(payload.receipt().received().is_none());
        assert_eq!(payload.receipt().writer().unwrap().object_count, 6);
        assert_ne!(payload.into_bytes().unwrap(), fixture.pack);
    }
}

#[test]
fn a_deleted_ref_removes_reuse_permission_even_while_its_pack_is_cached() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::PrivateBranch);
    let private = fixture.private.unwrap();
    let (before, both) = prepare(&fixture.node, fixture.tip, true, |request| {
        request.wants.push(private);
    })
    .unwrap();
    assert!(
        materialize(&fixture.node, &before, &both)
            .receipt()
            .received()
            .is_some()
    );
    delete_private(&fixture.node, private);
    let (after, public) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    assert_ne!(before.basis(), after.basis());
    assert_eq!(
        public
            .keys
            .iter()
            .map(|key| key.id)
            .collect::<BTreeSet<_>>(),
        fixture.public_objects
    );
    assert!(
        materialize(&fixture.node, &after, &public)
            .receipt()
            .received()
            .is_none()
    );
    expect_code(
        fixture.node.materialize_prepared_upload_pack(
            &after,
            &both,
            fixture.node.request_context().authority(),
            &Cell::new(None),
            None,
            &mut || true,
        ),
        RefusalCode::AuthorityReceiptStale,
    );
}

#[test]
fn haves_filters_shallow_history_and_older_wants_use_the_exact_selected_subset() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    for case in 0..4 {
        let want = if case == 3 {
            fixture.ancestor
        } else {
            fixture.tip
        };
        let (head, selection) = prepare(&fixture.node, want, true, |request| match case {
            0 => request.haves.push(fixture.ancestor),
            1 => request.filter = Some(ObjectFilter::BlobNone),
            2 => request.deepen = Some(1),
            _ => {}
        })
        .unwrap();
        assert!(selection.keys.len() < fixture.public_objects.len());
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(
            payload.receipt().received().is_none(),
            "reduced fetch case {case}"
        );
        assert_eq!(
            payload.receipt().writer().unwrap().object_count as usize,
            selection.keys.len()
        );
    }
}

#[test]
fn an_ofs_pack_requires_the_clients_negotiated_capability() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    let (head, selection) = prepare(&fixture.node, fixture.tip, false, |_| {}).unwrap();
    let payload = materialize(&fixture.node, &head, &selection);
    assert!(payload.receipt().received().is_none());
    assert_eq!(payload.receipt().writer().unwrap().delta_count, 0);
    let bytes = payload.into_bytes().unwrap();
    let parsed = read_verified_pack(
        &bytes,
        fixture.node.object_format,
        &PackLimits::default(),
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    assert!(
        parsed
            .entries()
            .iter()
            .all(|entry| entry.delta_base.is_none())
    );
    let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    assert!(
        materialize(&fixture.node, &head, &selection)
            .receipt()
            .received()
            .is_some()
    );
}

#[test]
fn retained_payloads_have_independent_chunk_cursors() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    let mut first = materialize(&fixture.node, &head, &selection);
    let mut second = materialize(&fixture.node, &head, &selection);
    let mut left = Vec::new();
    let mut right = Vec::new();
    loop {
        let a = first.next_chunk(31).unwrap();
        let b = second.next_chunk(127).unwrap();
        if a.is_none() && b.is_none() {
            break;
        }
        left.extend(a.unwrap_or_default());
        right.extend(b.unwrap_or_default());
    }
    assert_eq!(left, fixture.pack);
    assert_eq!(right, fixture.pack);
}

#[test]
fn reuse_keeps_the_current_output_envelope_and_cancellation_boundary() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    let (head, mut selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    selection.limits.max_input_bytes = fixture.pack.len() - 1;
    let payload = materialize(&fixture.node, &head, &selection);
    assert!(payload.receipt().received().is_none());
    assert!(payload.receipt().writer().unwrap().output_bytes < fixture.pack.len());
    selection.limits.max_input_bytes = fixture.pack.len();
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
    assert!(
        materialize(&fixture.node, &head, &selection)
            .receipt()
            .received()
            .is_some()
    );
}

#[test]
fn structurally_valid_pack_with_an_invalid_native_object_is_never_retained() {
    let fixture = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    let (before, _) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    let retained = fixture.node.received_pack_cache().retained_entries();
    assert_eq!(retained, 1);
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let malformed = source.put(ObjectType::Commit, b"not a native commit body\n".to_vec());
    let source = ReceivedSource(source);
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        GitHashAlgorithm::Sha1,
        PackWriteProfile::STORED_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[malformed], &mut || true)
    .unwrap();
    let (bytes, _) = PackWriter::new(limits.clone())
        .write(&plan, &mut || true)
        .unwrap();
    read_verified_pack(
        &bytes,
        GitHashAlgorithm::Sha1,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .expect("framing, DEFLATE and trailer alone do not validate native commit structure");
    let refused = receive(
        &fixture.node,
        &[(malformed, b"refs/heads/malformed")],
        &bytes,
        b"received-pack-native-object-refusal",
    );
    assert!(matches!(
        refused,
        Err(NodeReceiveTransportRefusal::Admission(error))
            if matches!(error.as_ref(), fgit_admission::AdmissionError::Receive(
                fgit_wire::receive::ReceiveError::AuthoritativeRefusal(
                    RefusalCode::ObjectHeaderInvalid
                )
            ))
    ));
    assert_eq!(
        fixture.node.received_pack_cache().retained_entries(),
        retained
    );
    let (after, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
    assert_eq!(before.basis(), after.basis());
    let payload = materialize(&fixture.node, &after, &selection);
    assert!(payload.receipt().received().is_some());
    assert_eq!(payload.into_bytes().unwrap(), fixture.pack);
}

fn one_blob_pack(body: &[u8]) -> (GitOid, Vec<u8>) {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let id = source.put(ObjectType::Blob, body.to_vec());
    let source = ReceivedSource(source);
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        GitHashAlgorithm::Sha1,
        PackWriteProfile::STORED_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[id], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    (id, pack)
}

fn stored_object_path(node: &OneNode, id: GitOid) -> PathBuf {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    node.storage_root()
        .join("objects")
        .join(hex(&node.namespace))
        .join(hex(&id.algorithm().code_point().to_be_bytes()))
        .join(id.to_string())
}

#[test]
fn corrupt_existing_placement_cannot_install_received_pack_custody() {
    let (_scratch, node) = empty_node(GitHashAlgorithm::Sha1);
    let body = b"native bytes that must also pass immutable placement";
    let (id, pack) = one_blob_pack(body);
    assert_eq!(
        node.put_git_object(ObjectType::Blob, body.to_vec())
            .unwrap()
            .identity(),
        id
    );
    let path = stored_object_path(&node, id);
    let original = std::fs::read(&path).unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    assert!(node.read_git_object(id).is_err());
    let before = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let tips = [(id, b"refs/tags/placement-fence".as_slice())];
    let refused = receive(&node, &tips, &pack, b"corrupt-placement-receive");
    assert!(matches!(
        refused,
        Err(NodeReceiveTransportRefusal::Admission(error))
            if matches!(error.as_ref(), fgit_admission::AdmissionError::Receive(
                fgit_wire::receive::ReceiveError::AuthoritativeRefusal(RefusalCode::EvidenceInvalid)
            ))
    ));
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    let after = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(before.basis(), after.basis());

    std::fs::write(&path, original).unwrap();
    let admitted = receive(&node, &tips, &pack, b"corrupt-placement-receive").unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
    assert_eq!(node.received_pack_cache().retained_entries(), 1);
    let (head, selection) = prepare(&node, id, true, |_| {}).unwrap();
    let payload = materialize(&node, &head, &selection);
    assert!(payload.receipt().received().is_some());
    assert_eq!(payload.into_bytes().unwrap(), pack);
}

#[test]
fn a_conflict_after_native_validation_prevents_cache_publication_and_latches_failure() {
    let (_scratch, node) = empty_node(GitHashAlgorithm::Sha1);
    let (id, pack) = one_blob_pack(b"staged bytes still need the final immutable-name fence");
    let tips = [(id, b"refs/tags/final-placement-fence".as_slice())];
    let context = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&context))
        .unwrap();
    let staging = crate::receive_staging::ReceiveStaging::default();
    let (receive_context, input) = receive_input(node.object_format, &tips, &pack);
    {
        let validator = node
            .production_quarantine_validator(
                &materialized,
                receive_context.limits.pack.clone(),
                ParseLimits::default(),
            )
            .unwrap()
            .with_receive_staging(&staging);
        let mut handoff =
            crate::ProductionReceiveQuarantineHandoff::new(validator, materialized.basis().clone());
        let mut machine = fgit_wire::receive::ReceivePack::new(receive_context)
            .unwrap()
            .with_pack_retention(node.received_pack_cache().capture_limit());
        machine.push_bytes(&input).unwrap();
        machine
            .finish_with_handoff(&mut handoff, &mut || true)
            .unwrap();
        handoff.into_validated_receive().unwrap();
    }
    assert!(staging.contains(id));
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    let path = stored_object_path(&node, id);
    assert!(
        !path.exists(),
        "native verification only staged the immutable object"
    );
    std::fs::write(&path, b"conflicting concurrent immutable-name publication").unwrap();
    let refused = staging.publish(&node.fabric, &mut || true);
    assert!(matches!(
        refused,
        Err(crate::NodeRefusal::Fabric(error))
            if matches!(error.as_ref(), fgit_object_fabric::fabric::StoreRefusal::StoredObjectIdentityCollision)
    ));
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    std::fs::remove_file(path).unwrap();
    assert!(
        staging.publish(&node.fabric, &mut || true).is_err(),
        "a failed holder cannot turn a later retry into successful placement"
    );
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    drop(staging);

    let admitted = receive(&node, &tips, &pack, b"fresh-placement-after-conflict").unwrap();
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
    assert_eq!(node.received_pack_cache().retained_entries(), 1);
    let (head, selection) = prepare(&node, id, true, |_| {}).unwrap();
    let payload = materialize(&node, &head, &selection);
    assert!(payload.receipt().received().is_some());
    assert_eq!(payload.into_bytes().unwrap(), pack);
}

#[test]
fn a_fresh_process_configuration_rebuilds_instead_of_trusting_stale_cache_state() {
    let ReceivedFixture {
        scratch, node, tip, ..
    } = received_fixture(GitHashAlgorithm::Sha1, ExtraObject::None);
    node.shutdown().unwrap();
    let config = NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0x62; 16]),
        RepositoryId::from_bytes([0x63; 16]),
    )
    .with_object_format(GitHashAlgorithm::Sha1);
    let node = OneNode::open_existing(config).unwrap();
    let (head, selection) = prepare(&node, tip, true, |_| {}).unwrap();
    let payload = materialize(&node, &head, &selection);
    assert!(payload.receipt().received().is_none());
    assert_eq!(payload.receipt().writer().unwrap().object_count, 6);
}
