//! Selected received entries preserve disclosure without expanding their bodies.
use super::composition::{copy_and_append_delta, object_header, zlib_stored};
use super::*;
use fgit_crypto::{sha1_digest, sha256_digest};
use fgit_pack::{ExternalBaseLookup, PackObject, ScalarResolver};

type NativeObjects = BTreeMap<GitOid, (ObjectType, Vec<u8>)>;

struct Bases<'a>(&'a NativeObjects);

impl ExternalBaseLookup for Bases<'_> {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.0.get(id).map(|(_, body)| body.as_slice())
    }

    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.0.get(id).map(|(kind, body)| (*kind, body.as_slice()))
    }
}

fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

/// Discover identities from actual decoded bodies, never retained cache hints.
/// A REF parent may follow its child in the output, so learned IDs are installed
/// only after independent hashing and another bounded resolver pass follows.
pub(super) fn decoded_objects(
    bytes: &[u8],
    format: GitHashAlgorithm,
    held: &NativeObjects,
) -> NativeObjects {
    let limits = PackLimits::default();
    let parsed = read_verified_pack(
        bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    let mut objects = parsed.into_scalar_objects(|_| None).unwrap();
    let bases = Bases(held);
    let mut resolved = BTreeMap::new();
    for _ in 0..objects.len() {
        let resolver = ScalarResolver::new(&objects, &bases, &limits, &mut || true).unwrap();
        let mut learned = Vec::new();
        for object in &objects {
            let at = offset(object);
            if resolved.contains_key(&at) {
                continue;
            }
            match resolver.resolve_offset_typed(at, &mut || true) {
                Ok((kind, body)) => learned.push((
                    at,
                    git_object_id(format, crypto_object_kind(kind), &body),
                    kind,
                    body,
                )),
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("native selected-pack decoding failed: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "selected output has an unresolved delta graph"
        );
        for (at, id, kind, body) in learned {
            match objects
                .iter_mut()
                .find(|object| offset(object) == at)
                .unwrap()
            {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
                    *slot = Some(id);
                }
                PackObject::Delta(delta) => delta.id = Some(id),
            }
            assert!(resolved.insert(at, (id, kind, body)).is_none());
        }
        if resolved.len() == objects.len() {
            break;
        }
    }
    assert_eq!(resolved.len(), objects.len());
    let mut decoded = BTreeMap::new();
    for (id, kind, body) in resolved.into_values() {
        assert!(
            decoded.insert(id, (kind, body)).is_none(),
            "duplicate output identity"
        );
    }
    decoded
}

pub(super) fn assert_exact_selected_bytes(
    bytes: &[u8],
    format: GitHashAlgorithm,
    selection: &PreparedUploadPack,
    held: &NativeObjects,
) {
    let decoded = decoded_objects(bytes, format, held);
    let actual: BTreeMap<_, _> = decoded
        .into_iter()
        .map(|(id, (kind, _))| (id, kind))
        .collect();
    let expected: BTreeMap<_, _> = selection
        .keys
        .iter()
        .map(|key| (key.id, key.object_type))
        .collect();
    assert_eq!(actual, expected);
}

pub(super) fn assert_exact_selected_subset(
    node: &OneNode,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
) {
    let payload = materialize(node, head, selection);
    assert_eq!(payload.basis(), head.basis());
    let bytes = payload.into_bytes().unwrap();
    assert_exact_selected_bytes(&bytes, node.object_format, selection, &BTreeMap::new());
}

pub(super) fn without_fabric_objects(
    node: &OneNode,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
) -> AuthoritySelectedPackPayload {
    let objects = node.storage_root().join("objects");
    let parked = node.storage_root().join("objects-selective-reuse-test");
    std::fs::rename(&objects, &parked).unwrap();
    let result = node.materialize_prepared_upload_pack(
        head,
        selection,
        node.request_context().authority(),
        &Cell::new(None),
        None,
        &mut || true,
    );
    std::fs::rename(&parked, &objects).unwrap();
    result.unwrap()
}

struct SelectiveFixture {
    _scratch: Scratch,
    node: OneNode,
    source: MemorySource,
    pack: Vec<u8>,
    ancestor: GitOid,
    tip: GitOid,
    old_blob: GitOid,
    new_blob: GitOid,
    old_tree: GitOid,
    new_tree: GitOid,
    private: Option<GitOid>,
    public: BTreeSet<GitOid>,
}

fn append_whole(pack: &mut Vec<u8>, source: &MemorySource, id: GitOid) {
    let (kind, body) = source.objects.get(&id).unwrap();
    let code = match kind {
        ObjectType::Commit => 1,
        ObjectType::Tree => 2,
        ObjectType::Blob => 3,
        ObjectType::Tag => 4,
    };
    object_header(pack, code, body.len());
    pack.extend(zlib_stored(body));
}

fn ofs_distance(pack: &mut Vec<u8>, mut distance: usize) {
    assert!(distance > 0);
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        distance -= 1;
        bytes.push(0x80 | (distance & 0x7f) as u8);
        distance >>= 7;
    }
    bytes.reverse();
    pack.extend(bytes);
}

fn fixture(format: GitHashAlgorithm, extra: ExtraObject) -> SelectiveFixture {
    let (scratch, node) = empty_node(format);
    let mut source = MemorySource::new(format);
    let base = vec![b'x'; 8192];
    let suffix = b"selective delta suffix\n";
    let old_blob = source.put(ObjectType::Blob, base.clone());
    let old_tree = source.tree(&[(b"100644", b"base", old_blob)]);
    let ancestor = source.commit(old_tree, &[]);
    let mut body = base.clone();
    body.extend_from_slice(suffix);
    let new_blob = source.put(ObjectType::Blob, body);
    // A depth-one shallow selection still includes the delta's base blob;
    // ordinary have subtraction removes it and therefore needs thin proof.
    let new_tree = source.tree(&[
        (b"100644", b"base", old_blob),
        (b"100644", b"file", new_blob),
    ]);
    let tip = source.commit(new_tree, &[ancestor]);
    let public = source.objects.keys().copied().collect();
    let mut private_objects = Vec::new();
    let mut extra_blob = None;
    let private = match extra {
        ExtraObject::None => None,
        ExtraObject::Unreachable => {
            extra_blob =
                Some(source.put(ObjectType::Blob, b"unreachable sender-only secret".to_vec()));
            None
        }
        ExtraObject::PrivateBranch => {
            let blob = source.put(ObjectType::Blob, b"deleted branch secret".to_vec());
            let tree = source.tree(&[(b"100644", b"private", blob)]);
            let private = source.commit(tree, &[ancestor]);
            extra_blob = Some(blob);
            private_objects.extend([tree, private]);
            Some(private)
        }
    };
    let mut pack = b"PACK".to_vec();
    pack.extend(2u32.to_be_bytes());
    pack.extend(u32::try_from(source.objects.len()).unwrap().to_be_bytes());
    let base_offset = pack.len();
    append_whole(&mut pack, &source, old_blob);
    if let Some(extra) = extra_blob {
        // Removing this entry invalidates the original OFS distance, making
        // the permitted subset exercise real header rewriting.
        append_whole(&mut pack, &source, extra);
    }
    let distance = pack.len() - base_offset;
    let delta = copy_and_append_delta(&base, suffix);
    object_header(&mut pack, 6, delta.len());
    ofs_distance(&mut pack, distance);
    pack.extend(zlib_stored(&delta));
    for id in [old_tree, ancestor, new_tree, tip] {
        append_whole(&mut pack, &source, id);
    }
    for id in private_objects {
        append_whole(&mut pack, &source, id);
    }
    match format {
        GitHashAlgorithm::Sha1 => pack.extend(sha1_digest(&pack)),
        GitHashAlgorithm::Sha256 => pack.extend(sha256_digest(&pack)),
    }
    assert_eq!(
        decoded_objects(&pack, format, &BTreeMap::new()),
        source.objects
    );
    let mut tips = vec![(tip, b"refs/heads/main".as_slice())];
    if let Some(private) = private {
        tips.push((private, b"refs/heads/private"));
    }
    let admitted = receive(&node, &tips, &pack, b"selected-entry-native-fixture").unwrap();
    assert!(admitted.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
    assert_eq!(node.received_pack_cache().retained_entries(), 1);
    SelectiveFixture {
        _scratch: scratch,
        node,
        source,
        pack,
        ancestor,
        tip,
        old_blob,
        new_blob,
        old_tree,
        new_tree,
        private,
        public,
    }
}

fn expected(fixture: &SelectiveFixture, selected: &BTreeSet<GitOid>) -> NativeObjects {
    selected
        .iter()
        .map(|id| (*id, fixture.source.objects[id].clone()))
        .collect()
}

fn assert_selective(
    fixture: &SelectiveFixture,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
    selected: &BTreeSet<GitOid>,
    held: &NativeObjects,
    thin: bool,
) -> Vec<u8> {
    assert_eq!(
        selection
            .keys
            .iter()
            .map(|key| key.id)
            .collect::<BTreeSet<_>>(),
        *selected
    );
    let payload = without_fabric_objects(&fixture.node, head, selection);
    assert_eq!(payload.basis(), head.basis());
    assert!(payload.receipt().writer().is_none());
    let receipt = payload.receipt().received().unwrap();
    assert_eq!(
        receipt.profile(),
        if thin {
            "received-pack-select-thin-v1"
        } else {
            "received-pack-select-v1"
        }
    );
    assert_eq!(receipt.source_pack_count(), 1);
    assert_eq!(receipt.object_count() as usize, selected.len());
    assert_eq!(receipt.ofs_delta_count(), 0);
    assert_eq!(receipt.external_base_count(), usize::from(thin));
    assert_eq!(
        receipt.ref_delta_count(),
        usize::from(selected.contains(&fixture.new_blob))
    );
    let bytes = payload.into_bytes().unwrap();
    assert_ne!(bytes, fixture.pack);
    assert_eq!(
        decoded_objects(&bytes, fixture.node.object_format, held),
        expected(fixture, selected)
    );
    bytes
}

fn prepare_thin(fixture: &SelectiveFixture) -> (MaterializedAdmission, PreparedUploadPack) {
    let request = fixture.node.request_context();
    let head = fixture
        .node
        .runtime()
        .block_on(fixture.node.materialize_admission_in(&request))
        .unwrap();
    let deadline = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::DEFAULT,
    );
    let scope = fixture
        .node
        .prepare_visible_upload_pack(&request, &head, &WireLimits::default(), &deadline)
        .unwrap();
    let capabilities = Capabilities::parse_v1(
        format!(
            "fetch object-format={}",
            fixture.node.object_format.as_str()
        )
        .as_bytes(),
        &WireLimits::default(),
    )
    .unwrap();
    let mut machine = V2UploadPack::new(capabilities, WireLimits::default()).unwrap();
    let packets = [
        Packet::Data(b"command=fetch\n".to_vec()),
        Packet::Delimiter,
        Packet::Data(format!("want {}\n", fixture.tip).into_bytes()),
        Packet::Data(format!("have {}\n", fixture.ancestor).into_bytes()),
        Packet::Data(b"thin-pack\n".to_vec()),
        Packet::Data(b"ofs-delta\n".to_vec()),
        Packet::Data(b"done\n".to_vec()),
        Packet::Flush,
    ];
    let transition = machine
        .push_bytes(
            &encode_packets(&packets, &WireLimits::default()).unwrap(),
            scope.repository(),
        )
        .unwrap();
    let fetch = transition
        .events
        .into_iter()
        .find_map(|event| match event {
            crate::WireEvent::PackRequested(request) => Some(request),
            _ => None,
        })
        .unwrap();
    let context = fixture.node.session_pack_materialization_context(&deadline);
    let selection = fixture
        .node
        .prepare_upload_pack_selection(&head, &scope, &fetch, &deadline, &context, &mut || true)
        .unwrap();
    assert!(selection.write_profile.thin);
    (head, selection)
}

#[test]
fn selective_public_clone_omits_unreachable_and_deleted_branch_entries_without_object_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for extra in [ExtraObject::Unreachable, ExtraObject::PrivateBranch] {
            let fixture = fixture(format, extra);
            if let Some(private) = fixture.private {
                delete_private(&fixture.node, private);
            }
            let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
            let bytes = assert_selective(
                &fixture,
                &head,
                &selection,
                &fixture.public,
                &BTreeMap::new(),
                false,
            );
            let (_scratch, peer) = empty_node(format);
            let admitted = receive(
                &peer,
                &[(fixture.tip, b"refs/heads/main")],
                &bytes,
                b"selected-public-clone",
            )
            .unwrap();
            assert!(matches!(
                admitted.commands[0].terminal.outcome,
                fgit_types::DecisionOutcome::Committed { .. }
            ));
            let materialized = peer
                .runtime()
                .block_on(peer.materialize_admission())
                .unwrap();
            assert_eq!(
                materialized.selected_closure().closure().objects(),
                &fixture.public
            );
            for id in &fixture.public {
                assert_eq!(
                    peer.read_git_object(*id).unwrap().payload(),
                    fixture.source.objects[id].1
                );
            }
        }
    }
}

#[test]
fn filtered_shallow_and_older_wants_reuse_dependency_complete_selected_entries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::Unreachable);
        for case in 0..3 {
            let want = if case == 2 {
                fixture.ancestor
            } else {
                fixture.tip
            };
            let (head, selection) = prepare(&fixture.node, want, true, |request| match case {
                0 => request.filter = Some(ObjectFilter::BlobNone),
                1 => request.deepen = Some(1),
                _ => {}
            })
            .unwrap();
            let selected = match case {
                0 => BTreeSet::from([
                    fixture.old_tree,
                    fixture.ancestor,
                    fixture.new_tree,
                    fixture.tip,
                ]),
                1 => BTreeSet::from([
                    fixture.old_blob,
                    fixture.new_blob,
                    fixture.new_tree,
                    fixture.tip,
                ]),
                _ => BTreeSet::from([fixture.old_blob, fixture.old_tree, fixture.ancestor]),
            };
            assert_selective(
                &fixture,
                &head,
                &selection,
                &selected,
                &BTreeMap::new(),
                false,
            );
        }
    }
}

#[test]
fn a_client_without_ofs_capability_receives_ref_deltas_from_the_original_zlib_members() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::None);
        let (head, selection) = prepare(&fixture.node, fixture.tip, false, |_| {}).unwrap();
        assert!(!selection.request.options.ofs_delta());
        let bytes = assert_selective(
            &fixture,
            &head,
            &selection,
            &fixture.public,
            &BTreeMap::new(),
            false,
        );
        let (_scratch, peer) = empty_node(format);
        let admitted = receive(
            &peer,
            &[(fixture.tip, b"refs/heads/main")],
            &bytes,
            b"ref-only-selected-clone",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            peer.read_git_object(fixture.new_blob).unwrap().payload(),
            fixture.source.objects[&fixture.new_blob].1
        );
    }
}

#[test]
fn client_haves_authorize_an_omitted_internal_ofs_base_for_selective_thin_fetch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::Unreachable);
        let (head, selection) = prepare_thin(&fixture);
        assert!(
            selection
                .held_bases
                .contains(&(fixture.old_blob, ObjectType::Blob))
        );
        let selected = BTreeSet::from([fixture.new_blob, fixture.new_tree, fixture.tip]);
        let old = BTreeSet::from([fixture.old_blob, fixture.old_tree, fixture.ancestor]);
        let held = expected(&fixture, &old);
        let bytes = assert_selective(&fixture, &head, &selection, &selected, &held, true);

        let (seed_head, seed_selection) =
            prepare(&fixture.node, fixture.ancestor, true, |_| {}).unwrap();
        let seed_bytes = assert_selective(
            &fixture,
            &seed_head,
            &seed_selection,
            &old,
            &BTreeMap::new(),
            false,
        );
        let (_scratch, peer) = empty_node(format);
        receive(
            &peer,
            &[(fixture.ancestor, b"refs/heads/base")],
            &seed_bytes,
            b"selected-thin-peer-seed",
        )
        .unwrap();
        let admitted = receive(
            &peer,
            &[(fixture.tip, b"refs/heads/main")],
            &bytes,
            b"selected-thin-peer-fetch",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let materialized = peer
            .runtime()
            .block_on(peer.materialize_admission())
            .unwrap();
        assert_eq!(
            materialized.selected_closure().closure().objects(),
            &fixture.public
        );
        assert_eq!(
            peer.read_git_object(fixture.new_blob).unwrap().payload(),
            fixture.source.objects[&fixture.new_blob].1
        );
    }
}

#[test]
fn omitting_an_internal_base_without_thin_negotiation_keeps_the_native_writer_fallback() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::Unreachable);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |request| {
            request.haves.push(fixture.ancestor);
        })
        .unwrap();
        assert!(!selection.write_profile.thin);
        assert!(selection.held_bases.is_empty());
        let selected = BTreeSet::from([fixture.new_blob, fixture.new_tree, fixture.tip]);
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            selected
        );
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(payload.receipt().received().is_none());
        assert_eq!(payload.receipt().writer().unwrap().object_count, 3);
        let bytes = payload.into_bytes().unwrap();
        assert_eq!(
            decoded_objects(&bytes, format, &BTreeMap::new()),
            expected(&fixture, &selected)
        );
    }
}

#[test]
fn absent_or_wrong_kind_held_base_proofs_cannot_bless_cached_internal_deltas() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::Unreachable);
        let held = expected(
            &fixture,
            &BTreeSet::from([fixture.old_blob, fixture.old_tree, fixture.ancestor]),
        );
        for wrong_kind in [false, true] {
            let (head, mut selection) = prepare_thin(&fixture);
            selection.held_bases.clear();
            if wrong_kind {
                selection
                    .held_bases
                    .push((fixture.old_blob, ObjectType::Tree));
            }
            let payload = materialize(&fixture.node, &head, &selection);
            assert!(payload.receipt().received().is_none());
            assert_eq!(payload.receipt().writer().unwrap().object_count, 3);
            assert_exact_selected_bytes(&payload.into_bytes().unwrap(), format, &selection, &held);
        }
    }
}

#[test]
fn selective_reuse_rejects_a_stale_preparation_even_when_the_public_object_set_is_unchanged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, ExtraObject::PrivateBranch);
        let (before, old_selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_selective(
            &fixture,
            &before,
            &old_selection,
            &fixture.public,
            &BTreeMap::new(),
            false,
        );
        delete_private(&fixture.node, fixture.private.unwrap());
        let (after, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_ne!(before.basis(), after.basis());
        expect_code(
            fixture.node.materialize_prepared_upload_pack(
                &after,
                &old_selection,
                fixture.node.request_context().authority(),
                &Cell::new(None),
                None,
                &mut || true,
            ),
            RefusalCode::AuthorityReceiptStale,
        );
        assert_selective(
            &fixture,
            &after,
            &selection,
            &fixture.public,
            &BTreeMap::new(),
            false,
        );
    }
}
