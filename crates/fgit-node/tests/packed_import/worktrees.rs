//! Linked worktrees use the native import and durable admission paths, including
//! pack reconstruction, stable retry identity and reopening without the source.

use super::*;

fn import(node: &OneNode, source: &Path) -> AdmissionResult {
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.import_request_context(None),
            source,
            PrincipalId::from_bytes([0xc3; 16]),
            b"linked-worktree-import",
        ))
        .expect("linked worktree publishes through native source admission")
}

#[test]
fn packed_linked_worktrees_preserve_refs_native_objects_retry_and_cold_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for storage in [BlobStorage::Loose, BlobStorage::RefDeltaBeforeBase] {
            let scratch = ScratchDirectory::new();
            let scratch_root = fs::canonicalize(&scratch.0).unwrap();
            let common = scratch_root.join("main checkout/.git");
            let repository = write_packed_repository_with_format(&common, storage, format);
            let private = common.join("worktrees/topic");
            let worktree = scratch_root.join("linked checkout");
            fs::create_dir_all(private.join("refs/worktree")).unwrap();
            fs::create_dir_all(&worktree).unwrap();
            fs::write(private.join("commondir"), "../..\n").unwrap();
            fs::write(private.join("HEAD"), "ref: refs/heads/topic\n").unwrap();
            fs::write(
                private.join("refs/worktree/pin"),
                format!("{}\n", repository.commit),
            )
            .unwrap();
            // Ordinary refs are shared even though this worktree has a HEAD
            // different from the main checkout's HEAD.
            fs::write(
                common.join("packed-refs"),
                format!(
                    "{} refs/heads/topic\n{} refs/tags/v1\n",
                    repository.commit, repository.commit
                ),
            )
            .unwrap();
            fs::write(
                worktree.join(".git"),
                "gitdir: ../main checkout/.git/worktrees/topic\n",
            )
            .unwrap();
            let node_root = scratch_root.join("node");
            let node = serving_node_with_format(node_root.clone(), format);
            let before = node.runtime().block_on(node.read_authority_head()).unwrap();
            let cancelled = node.import_request_context(None);
            cancelled.cancel();
            assert!(matches!(
                node.runtime().block_on(node.import_loose_git_directory_durable_in(
                    &cancelled,
                    &worktree,
                    PrincipalId::from_bytes([0xc3; 16]),
                    b"linked-worktree-import",
                )),
                Err(NodeSourceImportRefusal::Staging(error))
                    if matches!(*error, LooseGitImportRefusal::Interrupted { .. })
            ));
            // A linked layout never grants permission to use outside object
            // alternates. The refused attempt leaves both authority and object
            // placement untouched, and the same key can still succeed later.
            fs::create_dir_all(common.join("objects/info")).unwrap();
            let alternates = common.join("objects/info/alternates");
            fs::write(&alternates, "outside-object-database\n").unwrap();
            assert!(matches!(
                node.runtime().block_on(node.import_loose_git_directory_durable_in(
                    &node.import_request_context(None),
                    &worktree,
                    PrincipalId::from_bytes([0xc3; 16]),
                    b"linked-worktree-import",
                )),
                Err(NodeSourceImportRefusal::Staging(error))
                    if matches!(*error, LooseGitImportRefusal::ObjectAlternatesUnsupported(_))
            ));
            fs::remove_file(alternates).unwrap();
            assert_eq!(
                node.runtime().block_on(node.read_authority_head()).unwrap(),
                before
            );
            for oid in [repository.commit, repository.tree, repository.blob] {
                assert!(node.read_git_object(oid).is_err());
            }

            let first = import(&node, &worktree);
            assert_eq!(first.commands.len(), 4);
            assert!(first.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            )));
            let expected = imported_state(&node, &node_root, &repository);
            let refs = [
                "refs/heads/main",
                "refs/heads/topic",
                "refs/tags/v1",
                "refs/worktree/pin",
            ]
            .map(|name| {
                (
                    RefName::try_new(name.as_bytes()).unwrap(),
                    repository.commit,
                )
            });
            assert_eq!(expected.0, BTreeMap::from(refs));
            assert_eq!(
                expected.1,
                BTreeSet::from([repository.commit, repository.tree, repository.blob])
            );
            assert_eq!(expected.2.len(), 3);
            assert_eq!(
                expected.3,
                vec![
                    repository.commit_body.clone(),
                    repository.tree_body.clone(),
                    repository.blob_body.clone()
                ]
            );
            let head = node.runtime().block_on(node.read_authority_head()).unwrap();
            let selected = node
                .runtime()
                .block_on(node.materialize_admission_in(&node.request_context()))
                .unwrap();
            assert_eq!(
                selected.snapshot().head_target,
                Some(RefName::try_new(b"refs/heads/main").unwrap()),
                "import leaves the destination's initial HEAD unchanged"
            );

            // Directory spelling and source location are not transaction
            // identity. Both a rewritten gitfile and its direct administrative
            // directory replay the original authority-selected decision.
            fs::write(
                worktree.join(".git"),
                format!("gitdir: {}\n", private.display()),
            )
            .unwrap();
            fs::write(
                private.join("commondir"),
                common.as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            assert_eq!(import(&node, &worktree), first);
            assert_eq!(import(&node, &private), first);
            assert_eq!(
                node.runtime().block_on(node.read_authority_head()).unwrap(),
                head
            );
            assert_eq!(imported_state(&node, &node_root, &repository), expected);
            node.shutdown().unwrap();
            fs::remove_dir_all(common.parent().unwrap()).unwrap();
            fs::remove_dir_all(worktree).unwrap();

            let mut reopened = OneNode::open_existing(
                NodeConfig::new(
                    node_root.clone(),
                    TenantId::from_bytes([0xa1; 16]),
                    RepositoryId::from_bytes([0xb2; 16]),
                )
                .with_object_format(format)
                .with_worker_threads(2),
            )
            .unwrap();
            reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
            assert_eq!(imported_state(&reopened, &node_root, &repository), expected);
            assert_eq!(
                reopened
                    .runtime()
                    .block_on(reopened.read_authority_head())
                    .unwrap(),
                head
            );
            reopened.shutdown().unwrap();
        }
    }
}
