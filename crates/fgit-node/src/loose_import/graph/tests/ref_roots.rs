//! Branch constraints must survive the ref-to-object traversal boundary.
use super::*;
use std::cell::Cell;

#[test]
fn ref_root_kind_uses_the_exact_raw_branch_namespace() {
    for name in [
        b"refs/heads/main".as_slice(),
        b"refs/heads/team/topic",
        b"refs/heads/\xff",
    ] {
        assert_eq!(
            fgit_git_object::required_ref_target_kind(name),
            Some(ObjectType::Commit)
        );
    }
    for name in [
        b"refs/tags/release".as_slice(),
        b"refs/notes/data",
        b"refs/remotes/origin/main",
        b"refs/heads-other/main",
        b"refs/heads",
        b"refs/Heads/main",
    ] {
        assert_eq!(
            fgit_git_object::required_ref_target_kind(name),
            None,
            "{name:?}"
        );
    }
}

#[test]
fn ref_root_alias_order_never_weakens_type_or_reloads_the_same_object() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let blob = objects.put(format, ObjectType::Blob, b"native blob".to_vec());
        let tree = objects.put(format, ObjectType::Tree, Vec::new());
        let tip = objects.commit(format, tree, &[], "branch commit");
        let tag = objects.tag(format, tip, "commit");
        for id in [blob, tree, tag, tip] {
            for reverse in [false, true] {
                let mut roots = [(id, None), (id, Some(ObjectType::Commit))];
                if reverse {
                    roots.reverse();
                }
                let reads = Cell::new(0_usize);
                let mut live = || true;
                let control = ImportControl::new(&mut live);
                let result = validate_typed_controlled(
                    roots,
                    format,
                    &limits(format),
                    Limits::default(),
                    |id| {
                        reads.set(reads.get() + 1);
                        objects.load(id)
                    },
                    &control,
                );
                if id == tip {
                    let result = result.unwrap();
                    assert_eq!(
                        result.objects.keys().copied().collect::<BTreeSet<_>>(),
                        BTreeSet::from([tree, tip])
                    );
                    assert_eq!(reads.get(), 2);
                } else {
                    assert!(matches!(result, Err(LooseGitImportRefusal::ObjectGraph {
                        identity, code: RefusalCode::EvidenceInvalid,
                    }) if identity == id));
                    assert_eq!(reads.get(), 1, "do not peel a branch's tag target");
                }
            }
        }
    }
}

#[test]
fn ref_root_checks_keep_enqueue_budgets_and_cancellation_before_reads() {
    let format = GitHashAlgorithm::Sha256;
    let mut objects = Objects::default();
    let blob = objects.put(format, ObjectType::Blob, b"bounded".to_vec());
    let reads = Cell::new(0);
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    let result = validate_typed_controlled(
        [(blob, Some(ObjectType::Commit))],
        format,
        &limits(format),
        Limits {
            objects: 0,
            ..Limits::default()
        },
        |id| {
            reads.set(reads.get() + 1);
            objects.load(id)
        },
        &control,
    );
    assert!(matches!(
        result,
        Err(LooseGitImportRefusal::ObjectLimitExceeded { limit: 0 })
    ));
    assert_eq!(reads.get(), 0);
    let mut stopped = || false;
    let cancelled = ImportControl::new(&mut stopped);
    let result = validate_typed_controlled(
        [(blob, Some(ObjectType::Commit))],
        format,
        &limits(format),
        Limits::default(),
        |id| {
            reads.set(reads.get() + 1);
            objects.load(id)
        },
        &cancelled,
    );
    assert!(matches!(
        result,
        Err(LooseGitImportRefusal::Interrupted {
            code: RefusalCode::CancellationInProgress,
            ..
        })
    ));
    assert_eq!(reads.get(), 0);
    // A stop observed immediately after the actual read wins over a wrong-kind
    // verdict, retaining the existing interruption/retry semantics.
    let running = Cell::new(true);
    let mut probe = || running.get();
    let interrupted = ImportControl::new(&mut probe);
    let result = validate_typed_controlled(
        [(blob, Some(ObjectType::Commit))],
        format,
        &limits(format),
        Limits::default(),
        |id| {
            running.set(false);
            objects.load(id)
        },
        &interrupted,
    );
    assert!(matches!(
        result,
        Err(LooseGitImportRefusal::Interrupted {
            code: RefusalCode::CancellationInProgress,
            ..
        })
    ));
}

#[test]
fn ref_roots_refuse_bad_loose_packed_and_mixed_sources_before_placement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in 0..3 {
            let scratch = Scratch::new();
            let root = scratch.0.join("source");
            let mut objects = Objects::default();
            let blob = objects.put(format, ObjectType::Blob, b"exact file\r\n\0bytes".to_vec());
            let tree = objects.tree(format, "100644", blob);
            let tip = objects.commit(format, tree, &[], "valid main");
            let tag = objects.tag(format, tip, "commit");
            source(
                &root,
                format,
                &objects,
                &[("refs/heads/main", tip)],
                layout == 1,
            );
            if layout == 2 {
                // The bad target lives in the verified pack; its native commit
                // dependency lives loose. Neither source can erase ref typing.
                let packed = Objects(BTreeMap::from([(tag, objects.0[&tag].clone())]));
                write_pack(&root, format, &packed);
                let hex = tag.to_string();
                fs::remove_file(root.join("objects").join(&hex[..2]).join(&hex[2..])).unwrap();
            }
            let mut node = scratch.node(format);
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = node.request_context();
            let before = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            for (n, bad) in [blob, tree, tag].into_iter().enumerate() {
                // Put the same OID under an unrestricted tag AND a branch;
                // aliases must strengthen constraints, never erase them.
                let packed_refs = format!(
                    "# pack-refs with: sorted\n{bad} refs/heads/secondary\n{bad} refs/tags/alias\n"
                );
                fs::write(root.join("packed-refs"), packed_refs).unwrap();
                let result = node.stage_loose_git_import(&root);
                assert!(
                    matches!(result, Err(LooseGitImportRefusal::ObjectGraph {
                    identity, code: RefusalCode::EvidenceInvalid,
                }) if identity == bad),
                    "layout={layout} case={n}"
                );
                let result = node
                    .runtime()
                    .block_on(node.import_loose_git_directory_durable_in(
                        &request,
                        &root,
                        PrincipalId::from_bytes([0x91; 16]),
                        b"rejected-ref-kind",
                    ));
                assert!(
                    result.is_err(),
                    "public import must not bypass the source guard"
                );
                assert_unstaged(&node, &objects);
                let after = node
                    .runtime()
                    .block_on(node.materialize_admission_in(&request))
                    .unwrap();
                assert_eq!(after.basis(), before.basis());
            }
            // Positive twin retains all four native kinds under non-branch
            // namespaces. It then crosses real canonical admission and reopen.
            fs::write(root.join("packed-refs"), format!(
                "# pack-refs with: sorted\n{tip} refs/heads/secondary\n{blob} refs/notes/data\n{blob} refs/tags/blob\n{tag} refs/tags/release\n{tree} refs/tags/tree\n"
            )).unwrap();
            let admitted = node
                .runtime()
                .block_on(node.import_loose_git_directory_durable_in(
                    &request,
                    &root,
                    PrincipalId::from_bytes([0x91; 16]),
                    b"valid-ref-kinds",
                ))
                .unwrap();
            assert!(
                admitted
                    .commands
                    .iter()
                    .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
            );
            let after = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            assert_eq!(
                after.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
                tip
            );
            assert_eq!(
                after.snapshot().refs[&RefName::try_new(b"refs/tags/release").unwrap()],
                tag
            );
            let config = scratch.config(format);
            // Use the fixture's exact existing configuration, not a second
            // repository at the same storage path.
            node.shutdown().unwrap();
            let reopened = OneNode::open_existing(config).unwrap();
            let request = reopened.request_context();
            let recovered = reopened
                .runtime()
                .block_on(reopened.materialize_admission_in(&request))
                .unwrap();
            assert_eq!(recovered.basis(), after.basis());
            reopened.shutdown().unwrap();
        }
    }
}
