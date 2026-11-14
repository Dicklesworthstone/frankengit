//! A native change must not force retained history through the pack encoder.
//!
//! These tests use real object placement, ordinary canonical admission, and
//! the production visibility/preflight/materialization path. Parking old fabric
//! files after preflight is a planted reread failure, not a timing assertion.
use super::*;

type NativeObjects = BTreeMap<GitOid, (ObjectType, Vec<u8>)>;

/// Produce a child through native placement and source admission, without ever
/// creating or receiving a pack for the new objects. The one retained sender
/// pack therefore cannot contain the child, its new tree, or its new blob.
fn native_change(fixture: &ReceivedFixture, edit_tree: bool) -> (GitOid, NativeObjects) {
    let node = &fixture.node;
    let parent = node.read_git_object(fixture.tip).unwrap();
    let first = parent.payload().split(|byte| *byte == b'\n').next().unwrap();
    let tree = GitOid::from_hex(
        node.object_format,
        std::str::from_utf8(first.strip_prefix(b"tree ").unwrap()).unwrap(),
    )
    .unwrap();
    let mut new_objects = NativeObjects::new();
    let tree = if edit_tree {
        let body = b"locally produced source change\n".to_vec();
        let blob = node
            .put_git_object(ObjectType::Blob, body.clone())
            .unwrap()
            .identity();
        new_objects.insert(blob, (ObjectType::Blob, body));
        let mut body = node.read_git_object(tree).unwrap().payload().to_vec();
        // The original tree contains only file; the new note entry sorts later.
        body.extend_from_slice(b"100644 note\0");
        body.extend_from_slice(blob.as_bytes());
        let tree = node
            .put_git_object(ObjectType::Tree, body.clone())
            .unwrap()
            .identity();
        new_objects.insert(tree, (ObjectType::Tree, body));
        tree
    } else {
        tree
    };
    let body = commit_bytes(tree, &[fixture.tip]);
    let child = node
        .put_git_object(ObjectType::Commit, body.clone())
        .unwrap()
        .identity();
    new_objects.insert(child, (ObjectType::Commit, body));

    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut objects = before.selected_closure().closure().objects().clone();
    objects.extend(new_objects.keys().copied());
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    let receipt = SourceImportReceipt {
        object_format: node.object_format,
        object_count: closure.objects.len().try_into().unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(
        &[SourceRefUpdate {
            old: fixture.tip,
            new: child,
            ref_name: b"refs/heads/main".to_vec(),
        }],
        &receipt,
        closure,
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64; 16]),
        idempotency_key: IdempotencyKey::new(b"hybrid-pack-native-change".to_vec()).unwrap(),
        object_format: node.object_format,
    };
    let admitted = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert_eq!(admitted.commands.len(), 1);
    assert!(matches!(
        admitted.commands[0].terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    ));
    assert_eq!(node.received_pack_cache().retained_entries(), 1);
    (child, new_objects)
}

struct ParkedObjects(Vec<(PathBuf, PathBuf)>);

impl ParkedObjects {
    fn new(node: &OneNode, ids: impl IntoIterator<Item = GitOid>) -> Self {
        let mut guard = Self(Vec::new());
        for id in ids {
            let original = stored_object_path(node, id);
            let parked = original.with_extension("hybrid-test-parked");
            assert!(!parked.exists());
            std::fs::rename(&original, &parked).unwrap();
            guard.0.push((original, parked));
        }
        guard
    }
}

impl Drop for ParkedObjects {
    fn drop(&mut self) {
        for (original, parked) in &self.0 {
            std::fs::rename(parked, original).unwrap();
        }
    }
}

fn expected_objects(fixture: &ReceivedFixture, added: NativeObjects) -> NativeObjects {
    let mut expected = selective::decoded_objects(
        &fixture.pack,
        fixture.node.object_format,
        &NativeObjects::new(),
    );
    expected.retain(|id, _| fixture.public_objects.contains(id));
    expected.extend(added);
    expected
}

#[test]
fn native_child_clone_reuses_old_entries_with_every_old_fabric_body_unavailable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let (tip, added) = native_change(&fixture, false);
        assert_eq!(
            added.len(),
            1,
            "one native commit must expose the all-or-nothing cliff"
        );
        let expected = expected_objects(&fixture, added);
        for ofs_delta in [true, false] {
            let (head, selection) = prepare(&fixture.node, tip, ofs_delta, |_| {}).unwrap();
            let old_files =
                ParkedObjects::new(&fixture.node, fixture.public_objects.iter().copied());
            let payload = materialize(&fixture.node, &head, &selection);
            assert_eq!(payload.basis(), head.basis());
            let receipt = payload
                .receipt()
                .hybrid()
                .expect("one new object joins retained history");
            assert_eq!(
                receipt.reused().object_count() as usize,
                fixture.public_objects.len()
            );
            assert_eq!(receipt.written().object_count, 1);
            assert_eq!(receipt.object_count() as usize, expected.len());
            let output = payload.into_bytes().unwrap();
            drop(old_files);

            assert_eq!(
                selective::decoded_objects(&output, format, &NativeObjects::new()),
                expected,
                "derive identities from emitted bodies, not cache membership hints"
            );
            let parsed = read_verified_pack(
                &output,
                format,
                &PackLimits::default(),
                &mut || true,
                &NativeChecksumVerifier,
            )
            .unwrap();
            if !ofs_delta {
                assert!(parsed.entries().iter().all(|entry| !matches!(
                    entry.delta_base.as_ref(),
                    Some(fgit_pack::ParsedDeltaBase::Ofs { .. })
                )));
            }

            // Re-admission verifies the emitted pack's complete commit/tree/blob
            // graph, native trailer and delta reconstruction in an empty node.
            let (_clone_scratch, clone) = empty_node(format);
            let admitted = receive(
                &clone,
                &[(tip, b"refs/heads/main")],
                &output,
                b"hybrid-native-child-clone",
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
            assert_eq!(
                cloned.selected_closure().closure().objects(),
                &expected.keys().copied().collect::<BTreeSet<_>>()
            );
            clone.shutdown().unwrap();
        }
        fixture.node.shutdown().unwrap();
    }
}

#[test]
fn native_source_edit_joins_three_new_objects_without_revealing_unselected_sender_entries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::Unreachable);
        let (tip, added) = native_change(&fixture, true);
        assert_eq!(added.len(), 3);
        let expected = expected_objects(&fixture, added);
        let (head, selection) = prepare(&fixture.node, tip, false, |_| {}).unwrap();
        let old_files =
            ParkedObjects::new(&fixture.node, fixture.public_objects.iter().copied());
        let payload = materialize(&fixture.node, &head, &selection);
        let receipt = payload
            .receipt()
            .hybrid()
            .expect("new source objects join retained history");
        assert_eq!(
            receipt.reused().object_count() as usize,
            fixture.public_objects.len()
        );
        assert_eq!(receipt.written().object_count, 3);
        let output = payload.into_bytes().unwrap();
        drop(old_files);
        assert_eq!(
            selective::decoded_objects(&output, format, &NativeObjects::new()),
            expected
        );
        let after = fixture
            .node
            .runtime()
            .block_on(fixture.node.materialize_admission())
            .unwrap();
        assert_eq!(
            after.basis(),
            head.basis(),
            "pack construction never publishes authority"
        );
        fixture.node.shutdown().unwrap();
    }
}

#[test]
fn missing_uncached_native_object_is_an_error_and_does_not_emit_a_partial_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let (tip, added) = native_change(&fixture, false);
        let (head, selection) = prepare(&fixture.node, tip, true, |_| {}).unwrap();
        let missing = ParkedObjects::new(&fixture.node, added.keys().copied());
        assert!(
            fixture
                .node
                .materialize_prepared_upload_pack(
                    &head,
                    &selection,
                    fixture.node.request_context().authority(),
                    &Cell::new(None),
                    None,
                    &mut || true,
                )
                .is_err(),
            "cached history does not establish the missing selected object's bytes"
        );
        drop(missing);
        let output = materialize(&fixture.node, &head, &selection)
            .into_bytes()
            .unwrap();
        assert_eq!(
            selective::decoded_objects(&output, format, &NativeObjects::new()),
            expected_objects(&fixture, added)
        );
        fixture.node.shutdown().unwrap();
    }
}

#[test]
fn an_oversized_stored_hybrid_retries_the_full_compressed_writer_with_the_original_ceiling() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = received_fixture(format, ExtraObject::None);
        let (tip, added) = native_change(&fixture, false);
        let (head, mut selection) = prepare(&fixture.node, tip, true, |_| {}).unwrap();
        let retained_bytes = {
            let payload = materialize(&fixture.node, &head, &selection);
            payload
                .receipt()
                .hybrid()
                .unwrap()
                .reused()
                .output_bytes()
        };
        // This ceiling holds the retained entries plus one header/trailer, but
        // cannot also fit the new commit. Recompressing the highly compressible
        // original bodies still fits; an optional cache representation is not
        // grounds to refuse that otherwise permitted transfer.
        selection.limits.max_input_bytes = retained_bytes;
        let payload = materialize(&fixture.node, &head, &selection);
        assert!(payload.receipt().hybrid().is_none());
        let written = payload
            .receipt()
            .writer()
            .expect("bounded native fallback");
        assert!(written.output_bytes <= retained_bytes);
        assert_eq!(written.object_count as usize, selection.keys.len());
        let output = payload.into_bytes().unwrap();
        assert_eq!(
            selective::decoded_objects(&output, format, &NativeObjects::new()),
            expected_objects(&fixture, added)
        );

        // The fallback retains the exact caller ceiling. It cannot evade a
        // limit too small for even one entry by using a default writer budget.
        selection.limits.max_input_bytes = 12 + format.digest_len();
        assert!(
            fixture
                .node
                .materialize_prepared_upload_pack(
                    &head,
                    &selection,
                    fixture.node.request_context().authority(),
                    &Cell::new(None),
                    None,
                    &mut || true,
                )
                .is_err()
        );
        fixture.node.shutdown().unwrap();
    }
}
