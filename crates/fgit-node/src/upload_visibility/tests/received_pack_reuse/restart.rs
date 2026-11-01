//! Durable custody is only an input to native revalidation after a cold open.
//! Every reopened node uses a NEW configuration, not a shared in-memory cache.
use super::*;

const CACHE_BYTES: usize = 2 * 1024 * 1024;

fn reopen(scratch: &Scratch, format: GitHashAlgorithm, cache_bytes: usize) -> OneNode {
    reopen_at(scratch.0.clone(), format, cache_bytes)
}

fn reopen_at(storage_root: PathBuf, format: GitHashAlgorithm, cache_bytes: usize) -> OneNode {
    let config = NodeConfig::new(
        storage_root,
        TenantId::from_bytes([0x62; 16]),
        RepositoryId::from_bytes([0x63; 16]),
    )
    .with_object_format(format)
    .with_received_pack_cache_bytes(cache_bytes);
    let mut node = OneNode::open_existing(config).unwrap();
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(selected.receipt().generation())
        .unwrap();
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    node
}

fn durable_slots(scratch: &Scratch) -> Vec<PathBuf> {
    let root = scratch.0.join("received-pack-cache").join("v1");
    let mut slots = Vec::new();
    for namespace in std::fs::read_dir(root).unwrap() {
        let namespace = namespace.unwrap();
        assert!(namespace.file_type().unwrap().is_dir());
        for entry in std::fs::read_dir(namespace.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_str().unwrap();
            if name.starts_with("slot-") && name.ends_with(".rpack") {
                assert!(entry.file_type().unwrap().is_file());
                slots.push(entry.path());
            }
        }
    }
    slots.sort();
    slots
}

fn durable_slot(scratch: &Scratch) -> PathBuf {
    let mut slots = durable_slots(scratch);
    assert_eq!(slots.len(), 1, "one validated ingress has one durable slot");
    slots.pop().unwrap()
}

fn assert_reused(node: &OneNode, tip: GitOid, original: &[u8]) {
    let (head, selection) = prepare(node, tip, true, |_| {}).unwrap();
    assert_eq!(node.received_pack_cache().retained_entries(), 1);
    let payload = materialize(node, &head, &selection);
    let receipt = payload.receipt().received().expect("cold restored pack");
    assert!(payload.receipt().writer().is_none());
    assert_eq!(receipt.profile(), "received-pack-v1");
    assert_eq!(receipt.source_pack_count(), 1);
    assert_eq!(receipt.external_base_count(), 0);
    assert_eq!(receipt.object_count() as usize, selection.keys.len());
    assert_eq!(receipt.sha256(), &fgit_crypto::sha256_digest(original));
    assert_eq!(payload.basis(), head.basis());
    let output = payload.into_bytes().unwrap();
    assert_eq!(output, original);
    selective::assert_exact_selected_bytes(
        &output,
        node.object_format,
        &selection,
        &BTreeMap::new(),
    );
}

#[test]
fn a_new_service_configuration_recovers_the_original_pack_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch,
            node,
            pack,
            tip,
            ..
        } = received_fixture(format, ExtraObject::None);
        node.shutdown().unwrap();
        let slot = durable_slot(&scratch);
        assert!(std::fs::metadata(slot).unwrap().len() > pack.len() as u64);
        let reopened = reopen(&scratch, format, CACHE_BYTES);
        assert_reused(&reopened, tip, &pack);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn relative_node_roots_persist_and_restore_without_changing_the_process_directory() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch: _source_scratch,
            node: source,
            pack,
            tip,
            ..
        } = received_fixture(format, ExtraObject::None);
        source.shutdown().unwrap();
        let relative = PathBuf::from(format!(
            "fgit-relative-pack-restart-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let scratch = Scratch(std::env::current_dir().unwrap().join(&relative));
        let config = NodeConfig::new(
            relative.clone(),
            TenantId::from_bytes([0x62; 16]),
            RepositoryId::from_bytes([0x63; 16]),
        )
        .with_object_format(format)
        .with_received_pack_cache_bytes(CACHE_BYTES);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let admitted = receive(
            &node,
            &[(tip, b"refs/heads/main")],
            &pack,
            b"relative-restart-receive",
        )
        .unwrap();
        assert!(matches!(
            admitted.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        node.shutdown().unwrap();
        durable_slot(&scratch);

        let reopened = reopen_at(relative, format, CACHE_BYTES);
        assert_reused(&reopened, tip, &pack);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn a_cold_service_restores_external_deltas_for_complete_and_thin_fetches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch,
            node,
            pack,
            tip,
            public_objects,
            ..
        } = received_fixture(format, ExtraObject::None);
        let increment = composition::increment(format, tip);
        composition::receive_increment(&node, tip, &increment);
        node.shutdown().unwrap();
        assert_eq!(durable_slots(&scratch).len(), 2);

        let complete = reopen(&scratch, format, CACHE_BYTES);
        let (head, selection) = prepare(&complete, increment.tip, true, |_| {}).unwrap();
        assert_eq!(complete.received_pack_cache().retained_entries(), 2);
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            public_objects.union(&increment.objects).copied().collect()
        );
        let payload = materialize(&complete, &head, &selection);
        let receipt = payload
            .receipt()
            .received()
            .expect("restored complete cover");
        assert_eq!(receipt.profile(), "received-pack-concat-v1");
        assert_eq!(receipt.source_pack_count(), 2);
        assert_eq!(receipt.external_base_count(), 0);
        assert_eq!(receipt.object_count(), 9);
        assert_eq!(receipt.ref_delta_count(), 1);
        assert_eq!(
            receipt.output_bytes(),
            pack.len() + increment.pack.len() - 12 - format.digest_len()
        );
        selective::assert_exact_selected_bytes(
            &payload.into_bytes().unwrap(),
            format,
            &selection,
            &BTreeMap::new(),
        );
        complete.shutdown().unwrap();

        // Reopen AGAIN, so this client's external-base proof cannot use the
        // live representations restored by the complete fetch above.
        let thin = reopen(&scratch, format, CACHE_BYTES);
        let (head, selection) =
            prepare_fetch_after_graph(&thin, increment.tip, Some(tip), true, || {}).unwrap();
        assert!(selection.write_profile.thin);
        assert_eq!(thin.received_pack_cache().retained_entries(), 1);
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            increment.objects
        );
        let payload = materialize(&thin, &head, &selection);
        let receipt = payload.receipt().received().expect("restored thin source");
        assert_eq!(receipt.profile(), "received-pack-thin-v1");
        assert_eq!(receipt.source_pack_count(), 1);
        assert_eq!(receipt.external_base_count(), 1);
        assert_eq!(receipt.object_count(), 3);
        assert_eq!(receipt.ref_delta_count(), 1);
        let output = payload.into_bytes().unwrap();
        assert_eq!(output, increment.pack);
        let held = selective::decoded_objects(&pack, format, &BTreeMap::new());
        selective::assert_exact_selected_bytes(&output, format, &selection, &held);
        thin.shutdown().unwrap();
    }
}

#[test]
fn corrupt_or_missing_custody_falls_back_without_changing_the_selected_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for missing in [false, true] {
            let ReceivedFixture {
                scratch,
                node,
                pack,
                tip,
                ..
            } = received_fixture(format, ExtraObject::None);
            node.shutdown().unwrap();
            let slot = durable_slot(&scratch);
            let original = std::fs::read(&slot).unwrap();
            let permissions = std::fs::metadata(&slot).unwrap().permissions();
            if missing {
                std::fs::remove_file(&slot).unwrap();
            } else {
                let mut corrupt = original.clone();
                *corrupt.last_mut().unwrap() ^= 1;
                std::fs::write(&slot, corrupt).unwrap();
            }
            let reopened = reopen(&scratch, format, CACHE_BYTES);
            let (head, selection) = prepare(&reopened, tip, true, |_| {}).unwrap();
            assert_eq!(reopened.received_pack_cache().retained_entries(), 0);
            let payload = materialize(&reopened, &head, &selection);
            assert!(payload.receipt().received().is_none());
            assert!(payload.receipt().writer().is_some());
            let output = payload.into_bytes().unwrap();
            assert_ne!(
                output, pack,
                "stored ingress differs from native compression"
            );
            selective::assert_exact_selected_bytes(&output, format, &selection, &BTreeMap::new());
            reopened.shutdown().unwrap();

            // The same canonical repository and the same original custody form
            // the permitted twin. A miss must not damage canonical state.
            std::fs::write(&slot, original).unwrap();
            std::fs::set_permissions(&slot, permissions).unwrap();
            let restored = reopen(&scratch, format, CACHE_BYTES);
            assert_reused(&restored, tip, &pack);
            restored.shutdown().unwrap();
        }
    }
}

#[test]
fn zero_budget_ignores_existing_custody_and_a_later_enabled_service_can_reuse_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch,
            node,
            pack,
            tip,
            ..
        } = received_fixture(format, ExtraObject::None);
        node.shutdown().unwrap();
        let slot = durable_slot(&scratch);
        let original = std::fs::read(&slot).unwrap();
        let disabled = reopen(&scratch, format, 0);
        let (head, selection) = prepare(&disabled, tip, true, |_| {}).unwrap();
        let payload = materialize(&disabled, &head, &selection);
        assert!(payload.receipt().writer().is_some());
        assert!(payload.receipt().received().is_none());
        assert_eq!(disabled.received_pack_cache().retained_entries(), 0);
        selective::assert_exact_selected_bytes(
            &payload.into_bytes().unwrap(),
            format,
            &selection,
            &BTreeMap::new(),
        );
        disabled.shutdown().unwrap();
        assert_eq!(std::fs::read(slot).unwrap(), original);

        let enabled = reopen(&scratch, format, CACHE_BYTES);
        assert_reused(&enabled, tip, &pack);
        enabled.shutdown().unwrap();
    }
}

/// Obtain the authentic graph before disrupting a blob, but leave both cold
/// hydration and materialization afterward. A pack is not a repair authority.
fn prepare_after_graph(
    node: &OneNode,
    tip: GitOid,
    after_graph: impl FnOnce(),
) -> Result<(MaterializedAdmission, PreparedUploadPack), NodePackMaterializationRefusal> {
    prepare_fetch_after_graph(node, tip, None, false, after_graph)
}

fn prepare_fetch_after_graph(
    node: &OneNode,
    tip: GitOid,
    have: Option<GitOid>,
    thin: bool,
    after_graph: impl FnOnce(),
) -> Result<(MaterializedAdmission, PreparedUploadPack), NodePackMaterializationRefusal> {
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
        Packet::Data(format!("want {tip}\n").into_bytes()),
    ];
    if let Some(have) = have {
        packets.push(Packet::Data(format!("have {have}\n").into_bytes()));
    }
    if thin {
        packets.push(Packet::Data(b"thin-pack\n".to_vec()));
    }
    packets.extend([
        Packet::Data(b"ofs-delta\n".to_vec()),
        Packet::Data(b"done\n".to_vec()),
        Packet::Flush,
    ]);
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
    let context = node.session_pack_materialization_context(&deadline);
    after_graph();
    node.prepare_upload_pack_selection(&head, &scope, &fetch, &deadline, &context, &mut || true)
        .map(|selection| (head, selection))
}

#[test]
fn valid_custody_cannot_replace_a_missing_or_corrupt_canonical_blob() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for missing in [false, true] {
            let ReceivedFixture {
                scratch,
                node,
                pack,
                tip,
                public_objects,
                ..
            } = received_fixture(format, ExtraObject::None);
            let blob = public_objects
                .iter()
                .copied()
                .find(|id| {
                    node.read_git_object(*id).unwrap().envelope().object_kind()
                        == fgit_object_fabric::ObjectKind::Blob
                })
                .unwrap();
            let path = stored_object_path(&node, blob);
            let original = std::fs::read(&path).unwrap();
            let permissions = std::fs::metadata(&path).unwrap().permissions();
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            node.shutdown().unwrap();
            let slot = durable_slot(&scratch);
            let custody = std::fs::read(&slot).unwrap();
            let custody_permissions = std::fs::metadata(&slot).unwrap().permissions();

            let reopened = reopen(&scratch, format, CACHE_BYTES);
            let prepared = prepare_after_graph(&reopened, tip, || {
                if missing {
                    std::fs::remove_file(&path).unwrap();
                } else {
                    std::fs::write(&path, &corrupt).unwrap();
                }
            });
            if let Ok((head, selection)) = prepared {
                assert!(
                    reopened
                        .materialize_prepared_upload_pack(
                            &head,
                            &selection,
                            reopened.request_context().authority(),
                            &Cell::new(None),
                            None,
                            &mut || true,
                        )
                        .is_err(),
                    "untrusted compressed custody cannot conceal canonical object loss"
                );
            }
            assert_eq!(reopened.received_pack_cache().retained_entries(), 0);
            if missing {
                assert!(
                    !path.exists(),
                    "hydration must not repair canonical storage"
                );
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), corrupt);
            }
            reopened.shutdown().unwrap();

            std::fs::write(&path, original).unwrap();
            std::fs::set_permissions(&path, permissions).unwrap();
            std::fs::write(&slot, custody).unwrap();
            std::fs::set_permissions(&slot, custody_permissions).unwrap();
            let restored = reopen(&scratch, format, CACHE_BYTES);
            assert_reused(&restored, tip, &pack);
            restored.shutdown().unwrap();
        }
    }
}

#[test]
fn a_cold_pack_cannot_reintroduce_objects_after_their_only_ref_is_deleted() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let ReceivedFixture {
            scratch,
            node,
            tip,
            private,
            public_objects,
            ..
        } = received_fixture(format, ExtraObject::PrivateBranch);
        let private = private.unwrap();
        let (head, both) = prepare(&node, tip, true, |fetch| fetch.wants.push(private)).unwrap();
        assert!(
            materialize(&node, &head, &both)
                .receipt()
                .received()
                .is_some()
        );
        delete_private(&node, private);
        node.shutdown().unwrap();
        durable_slot(&scratch);

        let reopened = reopen(&scratch, format, CACHE_BYTES);
        let (head, public) = prepare(&reopened, tip, true, |_| {}).unwrap();
        assert_eq!(
            public
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            public_objects
        );
        selective::assert_exact_selected_subset(&reopened, &head, &public);
        assert!(prepare(&reopened, tip, true, |fetch| fetch.wants.push(private)).is_err());
        reopened.shutdown().unwrap();
    }
}
