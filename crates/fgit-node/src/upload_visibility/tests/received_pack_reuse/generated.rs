//! Native publication has no sender pack to reuse. Its first verified output
//! must become bounded custody for later exact selections and cold services.
use super::*;
use crate::pack_spool::{PackSpool, SpooledPack};
use crate::received_pack::GeneratedPackSelection;
use fgit_pack::{PackArtifactSink, PackWriteReceipt};

const CACHE_BYTES: usize = 2 * 1024 * 1024;

struct NativeFixture {
    scratch: Scratch,
    node: OneNode,
    source: ReceivedSource,
    tip: GitOid,
    private: GitOid,
    public: BTreeSet<GitOid>,
}

fn fixture(format: GitHashAlgorithm, cache_bytes: usize) -> NativeFixture {
    let (scratch, mut node) = empty_node(format);
    node.service_config.received_pack_cache =
        std::sync::Arc::new(crate::received_pack::ReceivedPackCache::new(cache_bytes));
    let mut source = MemorySource::new(format);
    let old = source.put(ObjectType::Blob, vec![b'x'; 8192]);
    let old_tree = source.tree(&[(b"100644", b"file", old)]);
    let ancestor = source.commit(old_tree, &[]);
    let mut body = vec![b'x'; 8192];
    body[4096] = b'y';
    let new = source.put(ObjectType::Blob, body);
    let tree = source.tree(&[(b"100644", b"file", new)]);
    let tip = source.commit(tree, &[ancestor]);
    let public = source.objects.keys().copied().collect();
    let secret = source.put(ObjectType::Blob, b"private native publication\n".to_vec());
    let tree = source.tree(&[(b"100644", b"secret", secret)]);
    let private = source.commit(tree, &[ancestor]);
    for (id, (kind, body)) in &source.objects {
        assert_eq!(
            node.put_git_object(*kind, body.clone()).unwrap().identity(),
            *id
        );
    }
    let objects: BTreeSet<_> = source.objects.keys().copied().collect();
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: closure.objects.len().try_into().unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let validated = validate_source_import(
        &[
            SourceRefUpdate {
                old: zero,
                new: tip,
                ref_name: b"refs/heads/main".to_vec(),
            },
            SourceRefUpdate {
                old: zero,
                new: private,
                ref_name: b"refs/heads/private".to_vec(),
            },
        ],
        &receipt,
        closure,
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64; 16]),
        idempotency_key: IdempotencyKey::new(b"generated-pack-native-publication".to_vec())
            .unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let admitted = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(admitted.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    NativeFixture {
        scratch,
        node,
        source: ReceivedSource(source),
        tip,
        private,
        public,
    }
}

fn spool(node: &OneNode, bytes: &[u8]) -> SpooledPack {
    let mut sink = PackSpool::new(node.storage_root());
    let mut temporary = sink.create_temporary().unwrap();
    sink.write_temporary(&mut temporary, bytes).unwrap();
    sink.promote_temporary(&mut temporary).unwrap();
    sink.into_promoted().unwrap()
}

fn retain(
    fixture: &NativeFixture,
    head: &MaterializedAdmission,
    selection: &PreparedUploadPack,
    pack: &mut SpooledPack,
    receipt: &PackWriteReceipt,
    live: &mut impl FnMut() -> bool,
) -> Result<(), NodePackMaterializationRefusal> {
    fixture.node.retain_generated_pack(
        head,
        pack,
        receipt,
        GeneratedPackSelection {
            keys: &selection.keys,
            thin_bases: &[],
            limits: &selection.limits,
        },
        live,
    )
}

#[test]
fn native_output_is_reused_without_any_second_fabric_body_read_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, CACHE_BYTES);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(
            payload.receipt().writer().is_some(),
            "first output keeps native writer evidence"
        );
        assert!(payload.receipt().received().is_none());
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 1);
        let bytes = payload.into_bytes().unwrap();
        selective::assert_exact_selected_bytes(&bytes, format, &selection, &BTreeMap::new());
        assert_eq!(
            selection
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            fixture.public
        );
        let (warm_head, warm) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(
            warm_head.basis(),
            head.basis(),
            "retention never publishes authority"
        );
        let payload = selective::without_fabric_objects(&fixture.node, &warm_head, &warm);
        let receipt = payload
            .receipt()
            .received()
            .expect("verified native representation");
        assert_eq!(receipt.profile(), "received-pack-v1");
        assert_eq!(receipt.object_count() as usize, fixture.public.len());
        assert_eq!(payload.into_bytes().unwrap(), bytes);
        fixture.node.shutdown().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn generated_partial_clones_and_hybrid_suffixes_restore_only_the_current_selection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, CACHE_BYTES);
        let (head, metadata) = prepare(&fixture.node, fixture.tip, true, |request| {
            request.filter = Some(ObjectFilter::BlobNone);
        })
        .unwrap();
        assert!(
            metadata
                .keys
                .iter()
                .all(|key| key.object_type != ObjectType::Blob)
        );
        let payload = materialize(&fixture.node, &head, &metadata);
        assert!(payload.receipt().writer().is_some());
        let metadata_bytes = payload.into_bytes().unwrap();
        selective::assert_exact_selected_bytes(
            &metadata_bytes,
            format,
            &metadata,
            &BTreeMap::new(),
        );
        fixture.node.shutdown().unwrap();

        let reopened = restart::reopen(&fixture.scratch, format, CACHE_BYTES);
        let (head, full) = prepare(&reopened, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(reopened.received_pack_cache().retained_entries(), 1);
        let payload = materialize(&reopened, &head, &full);
        let receipt = payload
            .receipt()
            .hybrid()
            .expect("restored metadata plus new native blobs");
        assert_eq!(
            receipt.reused().object_count() as usize,
            metadata.keys.len()
        );
        assert_eq!(receipt.written().object_count, 2);
        assert_eq!(reopened.received_pack_cache().retained_entries(), 2);
        let bytes = payload.into_bytes().unwrap();
        selective::assert_exact_selected_bytes(&bytes, format, &full, &BTreeMap::new());
        assert_eq!(
            full.keys.iter().map(|key| key.id).collect::<BTreeSet<_>>(),
            fixture.public
        );
        let (head, warm) = prepare(&reopened, fixture.tip, true, |_| {}).unwrap();
        let payload = selective::without_fabric_objects(&reopened, &head, &warm);
        assert_eq!(payload.receipt().received().unwrap().source_pack_count(), 2);
        selective::assert_exact_selected_bytes(
            &payload.into_bytes().unwrap(),
            format,
            &warm,
            &BTreeMap::new(),
        );
        reopened.shutdown().unwrap();

        let reopened = restart::reopen(&fixture.scratch, format, CACHE_BYTES);
        let (head, filtered) = prepare(&reopened, fixture.tip, true, |request| {
            request.filter = Some(ObjectFilter::BlobNone);
        })
        .unwrap();
        assert_eq!(filtered.keys, metadata.keys);
        assert_eq!(
            reopened.received_pack_cache().retained_entries(),
            1,
            "native blob custody is outside this filter"
        );
        let payload = selective::without_fabric_objects(&reopened, &head, &filtered);
        assert!(payload.receipt().received().is_some());
        assert_eq!(payload.into_bytes().unwrap(), metadata_bytes);
        reopened.shutdown().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn generated_custody_cannot_preserve_a_deleted_refs_disclosure_permission_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, CACHE_BYTES);
        let (head, both) = prepare(&fixture.node, fixture.tip, true, |request| {
            request.wants.push(fixture.private);
        })
        .unwrap();
        assert_eq!(both.keys.len(), fixture.source.0.objects.len());
        let payload = materialize(&fixture.node, &head, &both);
        assert!(payload.receipt().writer().is_some());
        drop(payload);
        delete_private(&fixture.node, fixture.private);
        let (head, public) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(
            public
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            fixture.public
        );
        selective::assert_exact_selected_subset(&fixture.node, &head, &public);
        assert!(
            prepare(&fixture.node, fixture.tip, true, |request| {
                request.wants.push(fixture.private);
            })
            .is_err()
        );
        fixture.node.shutdown().unwrap();

        let reopened = restart::reopen(&fixture.scratch, format, CACHE_BYTES);
        let (head, public) = prepare(&reopened, fixture.tip, true, |_| {}).unwrap();
        assert_eq!(
            public
                .keys
                .iter()
                .map(|key| key.id)
                .collect::<BTreeSet<_>>(),
            fixture.public
        );
        selective::assert_exact_selected_subset(&reopened, &head, &public);
        assert!(
            prepare(&reopened, fixture.tip, true, |request| {
                request.wants.push(fixture.private);
            })
            .is_err()
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_output_succeeds_unchanged_when_optional_custody_has_no_room_or_inflation_budget() {
    let mut reference = None;
    for case in 0..4 {
        let capacity = [0, 1024, 8192, CACHE_BYTES][case];
        let mut fixture = fixture(GitHashAlgorithm::Sha1, capacity);
        if case == 3 {
            fixture
                .node
                .service_config
                .git_daemon_receive_limits
                .pack
                .max_total_expanded_bytes = 1;
        }
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(payload.receipt().writer().is_some());
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 0);
        let bytes = payload.into_bytes().unwrap();
        selective::assert_exact_selected_bytes(
            &bytes,
            GitHashAlgorithm::Sha1,
            &selection,
            &BTreeMap::new(),
        );
        if let Some(expected) = &reference {
            assert_eq!(
                &bytes, expected,
                "optional custody cannot alter native response bytes"
            );
        } else {
            reference = Some(bytes);
        }
        fixture.node.shutdown().unwrap();
    }
}

#[test]
fn generated_capture_rechecks_native_bytes_and_canonical_integrity_and_keeps_cancellation_terminal()
{
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = fixture(format, CACHE_BYTES);
        let (head, selection) = prepare(&fixture.node, fixture.tip, true, |_| {}).unwrap();
        let (pack, receipt) = fixture
            .node
            .stream_pack_entries(
                &fixture.source,
                &selection.keys,
                &[],
                selection.write_profile,
                &selection.limits,
                &mut || true,
            )
            .unwrap();
        let bytes = pack.into_bytes().unwrap();
        let mut no_optional_time = spool(&fixture.node, &bytes);
        fixture
            .node
            .retain_generated_pack_with_budget(
                &head,
                &mut no_optional_time,
                &receipt,
                GeneratedPackSelection {
                    keys: &selection.keys,
                    thin_bases: &[],
                    limits: &selection.limits,
                },
                &mut || true,
                std::time::Duration::ZERO,
            )
            .unwrap();
        assert_eq!(
            fixture.node.received_pack_cache().retained_entries(),
            0,
            "optional expiry is a successful cache miss"
        );
        assert_eq!(no_optional_time.into_bytes().unwrap(), bytes);
        let mut no_optional_work = spool(&fixture.node, &bytes);
        let mut limits = selection.limits.clone();
        limits.max_delta_work = 0;
        fixture
            .node
            .retain_generated_pack(
                &head,
                &mut no_optional_work,
                &receipt,
                GeneratedPackSelection {
                    keys: &selection.keys,
                    thin_bases: &[],
                    limits: &limits,
                },
                &mut || true,
            )
            .unwrap();
        assert_eq!(
            fixture.node.received_pack_cache().retained_entries(),
            0,
            "optional work exhaustion is a successful cache miss"
        );
        assert_eq!(no_optional_work.into_bytes().unwrap(), bytes);
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut invalid = spool(&fixture.node, &corrupt);
        retain(
            &fixture,
            &head,
            &selection,
            &mut invalid,
            &receipt,
            &mut || true,
        )
        .unwrap();
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 0);
        assert_eq!(invalid.into_bytes().unwrap(), corrupt);

        let path = stored_object_path(&fixture.node, fixture.tip);
        let original = std::fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        let mut valid_pack = spool(&fixture.node, &bytes);
        retain(
            &fixture,
            &head,
            &selection,
            &mut valid_pack,
            &receipt,
            &mut || true,
        )
        .unwrap();
        assert_eq!(
            fixture.node.received_pack_cache().retained_entries(),
            0,
            "a valid trailer is not canonical custody"
        );
        std::fs::write(&path, original).unwrap();
        assert_eq!(valid_pack.into_bytes().unwrap(), bytes);

        let mut stopped = spool(&fixture.node, &bytes);
        let mut polls = 0;
        let result = retain(
            &fixture,
            &head,
            &selection,
            &mut stopped,
            &receipt,
            &mut || {
                polls += 1;
                polls != 3
            },
        );
        assert!(
            matches!(result, Err(NodePackMaterializationRefusal::Pack(error))
            if matches!(error.as_ref(), PackWriteError::Pack(PackError::DeadlineExceeded)))
        );
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 0);
        assert_eq!(stopped.into_bytes().unwrap(), bytes);

        let mut valid = spool(&fixture.node, &bytes);
        retain(
            &fixture,
            &head,
            &selection,
            &mut valid,
            &receipt,
            &mut || true,
        )
        .unwrap();
        assert_eq!(fixture.node.received_pack_cache().retained_entries(), 1);
        assert_eq!(valid.into_bytes().unwrap(), bytes);
        fixture.node.shutdown().unwrap();
    }
}
