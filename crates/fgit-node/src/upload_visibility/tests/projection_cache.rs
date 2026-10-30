//! A visible projection is reused across sessions only at its exact basis,
//! roots and limits, and reuse reads no object (frankengit-8g42).
use super::*;
use std::path::Path;

fn session_deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    )
}

fn prepare(node: &OneNode) -> Result<VisibleUploadPack, NodeGitDaemonServeRefusal> {
    let request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    node.prepare_visible_upload_pack(
        &request,
        &materialized,
        &WireLimits::default(),
        &session_deadline(),
    )
}

/// The fixture's configuration, rebuilt: a new service with its own empty
/// projection cache over the same stored repository.
fn independent_config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_bytes([0x62; 16]),
        RepositoryId::from_bytes([0x63; 16]),
    )
    .with_object_format(format)
}

/// One stored object moved aside (the fabric names each file by its object
/// id) and put back on drop.
struct Hidden {
    stored: PathBuf,
    aside: PathBuf,
}

impl Hidden {
    fn object(root: &Path, id: GitOid) -> Self {
        let name = id.to_string();
        let stored = find_file(root, &name).expect("the fabric stores the object by id");
        let aside = stored.with_extension("hidden");
        std::fs::rename(&stored, &aside).unwrap();
        Self { stored, aside }
    }
}

impl Drop for Hidden {
    fn drop(&mut self) {
        std::fs::rename(&self.aside, &self.stored).unwrap();
    }
}

fn find_file(directory: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(directory).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().and_then(|file| file.to_str()) == Some(name) {
            return Some(path);
        }
    }
    None
}

/// Imports one new ref at an existing commit whose reachable `objects` are
/// already stored, as the fixture imports its own refs.
fn create_named_ref(
    node: &OneNode,
    tip: GitOid,
    objects: &BTreeSet<GitOid>,
    ref_name: &[u8],
    retry_key: &[u8],
) {
    let format = node.object_format;
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let updates = [SourceRefUpdate {
        old: zero,
        new: tip,
        ref_name: ref_name.to_vec(),
    }];
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects: objects.clone(),
    };
    let receipt = SourceImportReceipt {
        object_format: format,
        object_count: u32::try_from(closure.objects.len()).unwrap(),
        delete_only: false,
        origin: SourceImportOrigin::LocalGitDirectory,
    };
    let validated = validate_source_import(&updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64; 16]),
        idempotency_key: IdempotencyKey::new(retry_key.to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(imported.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
}

fn assert_same_projection(left: &VisibleUploadPack, right: &VisibleUploadPack) {
    assert_eq!(left.closure, right.closure);
    assert_eq!(*left.objects, *right.objects);
    assert_eq!(left.path_hashes, right.path_hashes);
}

#[test]
fn a_session_at_an_unchanged_basis_reuses_the_projection_without_reading_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            config,
            public,
            private,
            ancestor,
            ..
        } = fixture(format);
        let first = prepare(&node).unwrap();
        assert_eq!(node.upload_visibility_cache_stats(), (0, 1));
        let second = prepare(&node).unwrap();
        assert_eq!(node.upload_visibility_cache_stats(), (1, 1));
        assert_same_projection(&first, &second);
        assert!(second.repository().contains_want(public));
        assert!(second.repository().contains_want(private));

        // With a visible commit unreadable, only reuse can still answer.
        let hidden = Hidden::object(&scratch.0, ancestor);
        let reused = prepare(&node).unwrap();
        assert_eq!(node.upload_visibility_cache_stats(), (2, 1));
        assert_same_projection(&first, &reused);
        node.shutdown().unwrap();

        // Its twin: a service with its own empty cache must read the object.
        let cold = OneNode::open_existing(independent_config(&scratch.0, format)).unwrap();
        assert!(
            prepare(&cold).is_err(),
            "a recomputation reads every visible commit, so a missing one refuses"
        );
        assert_eq!(cold.upload_visibility_cache_stats(), (0, 1));
        drop(hidden);
        let recomputed = prepare(&cold).unwrap();
        assert_eq!(cold.upload_visibility_cache_stats(), (0, 2));
        assert_same_projection(&first, &recomputed);
        cold.shutdown().unwrap();

        // A child reopened from the original configuration shares its entry.
        let child = OneNode::open_existing(config).unwrap();
        assert_same_projection(&first, &prepare(&child).unwrap());
        assert_eq!(child.upload_visibility_cache_stats(), (3, 1));
        child.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn a_new_basis_recomputes_instead_of_serving_the_previous_projection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            public,
            private,
            private_blob,
            visible,
            ..
        } = fixture(format);
        let before = prepare(&node).unwrap();
        assert!(before.repository().contains_want(private));
        let (reused, computed) = node.upload_visibility_cache_stats();

        delete_private(&node, private);
        let after = prepare(&node).unwrap();
        assert_eq!(
            node.upload_visibility_cache_stats(),
            (reused, computed + 1),
            "the deletion moved the head, so the previous entry must not match"
        );
        assert_eq!(after.closure.objects(), &visible);
        assert!(after.repository().contains_want(public));
        assert!(!after.repository().contains_want(private));
        assert!(!after.repository().is_common(private_blob));

        // The new basis is now the one that is reused.
        let again = prepare(&node).unwrap();
        assert_eq!(
            node.upload_visibility_cache_stats(),
            (reused + 1, computed + 1)
        );
        assert_same_projection(&after, &again);
        node.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn a_service_with_tighter_limits_never_reuses_a_looser_projection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            config,
            ..
        } = fixture(format);
        let loose = prepare(&node).unwrap();
        node.shutdown().unwrap();

        // A clone of the configuration shares its cache; a one-byte disclosure
        // envelope refuses the first commit it reads.
        let strict =
            OneNode::open_existing(config.clone().with_selected_pack_byte_envelope(1)).unwrap();
        let refused = prepare(&strict);
        assert!(
            refused.is_err(),
            "the stricter limits must be applied, not the looser entry"
        );
        assert_eq!(strict.upload_visibility_cache_stats(), (0, 2));
        strict.shutdown().unwrap();

        // Its permitted twin: the original limits still reuse that entry.
        let twin = OneNode::open_existing(config).unwrap();
        assert_same_projection(&loose, &prepare(&twin).unwrap());
        assert_eq!(twin.upload_visibility_cache_stats(), (1, 2));
        twin.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn an_equal_ref_view_at_a_later_generation_is_recomputed_not_reused() {
    // CacheBinding's rule: an entry is never reused merely because an equal
    // view reappears at a different authenticated generation.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            node,
            public,
            visible,
            ..
        } = fixture(format);
        let first = prepare(&node).unwrap();
        create_named_ref(
            &node,
            public,
            &visible,
            b"refs/heads/extra",
            b"extra-create",
        );
        delete_named_ref(&node, public, b"refs/heads/extra", b"extra-delete");
        let (reused, computed) = node.upload_visibility_cache_stats();
        let later = prepare(&node).unwrap();
        assert_eq!(
            node.upload_visibility_cache_stats(),
            (reused, computed + 1),
            "two decisions later the refs are equal, but the basis is not"
        );
        assert_same_projection(&first, &later);
        node.shutdown().unwrap();
        drop(scratch);
    }
}
