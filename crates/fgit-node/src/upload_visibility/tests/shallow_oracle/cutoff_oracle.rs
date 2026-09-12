//! Real Git lifecycle against the native, reopened node, not a mock transport.
use super::*;

fn publish(node: &OneNode, updates: &[SourceRefUpdate], extra: &BTreeSet<GitOid>) {
    let request = node.request_context();
    let current = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let mut objects = current.selected_closure().closure().objects().clone();
    objects.extend(extra.iter().copied());
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
    let validated = validate_source_import(updates, &receipt, closure).unwrap();
    let context = AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x64; 16]),
        idempotency_key: IdempotencyKey::new(b"cutoff-oracle-history".to_vec()).unwrap(),
        object_format: node.object_format,
    };
    let result = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &validated,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(result.commands.iter().all(|command| matches!(
        command.terminal.outcome,
        fgit_types::DecisionOutcome::Committed { .. }
    )));
}

fn dated(node: &OneNode, parent: GitOid, timestamp: i64) -> Revision {
    let blob = node
        .put_git_object(
            ObjectType::Blob,
            format!("cutoff content at {timestamp}\r\n").into_bytes(),
        )
        .unwrap()
        .identity();
    let tree = node
        .put_git_object(
            ObjectType::Tree,
            tree_bytes(&[(b"100644", b"public", blob)]),
        )
        .unwrap()
        .identity();
    let body = format!(
        "tree {tree}\nparent {parent}\nauthor A <a@example.test> {timestamp} +0000\ncommitter C <c@example.test> {timestamp} +0000\n\ncutoff fixture\n"
    );
    let commit = node
        .put_git_object(ObjectType::Commit, body.into_bytes())
        .unwrap()
        .identity();
    (commit, tree, blob)
}

#[test]
#[ignore = "requires source/binary-verified Git 2.54.0 and Bubblewrap via FGIT_ORACLE_ROOT"]
fn pinned_git_cutoffs_clone_widen_checkout_and_unshallow() {
    let oracle =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/e2e/oracle/oracle.sh");
    let output = Command::new(&oracle)
        .args(["create-run", "git-2.54.0", "cutoff-node"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verified oracle unavailable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            mut node,
            config,
            public,
            private,
            private_blob,
            ancestor,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let first = dated(&node, public, 1700000000);
        let second = dated(&node, first.0, 1700001000);
        let third = dated(&node, second.0, 1700002000);
        let fourth = dated(&node, third.0, 1700003000);
        let inner = node
            .put_git_object(ObjectType::Tag, tag_bytes(first.0, "commit"))
            .unwrap()
            .identity();
        let tag = node
            .put_git_object(ObjectType::Tag, tag_bytes(inner, "tag"))
            .unwrap()
            .identity();
        let mut extra = BTreeSet::from([inner, tag]);
        for (c, t, b) in [first, second, third, fourth] {
            extra.extend([c, t, b]);
        }
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        publish(
            &node,
            &[
                SourceRefUpdate {
                    old: public,
                    new: fourth.0,
                    ref_name: b"refs/heads/public".to_vec(),
                },
                SourceRefUpdate {
                    old: zero,
                    new: tag,
                    ref_name: b"refs/tags/cut-old".to_vec(),
                },
                SourceRefUpdate {
                    old: zero,
                    new: second.0,
                    ref_name: b"refs/heads/cut-new".to_vec(),
                },
            ],
            &extra,
        );
        let expected_file = node.read_git_object(fourth.2).unwrap().payload().to_vec();
        node.shutdown().unwrap();
        node = OneNode::open_existing(config).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let repository =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        for version in ["0", "1", "2"] {
            for (mode, initial, widen, profile) in [
                ("since", "1700002000;-", "1700001000;-", "blob:none"),
                ("exclude", "-;cut-new", "-;cut-old", "full"),
                (
                    "combined",
                    "1700001000;cut-new",
                    "1700001000;refs/tags/cut-old",
                    "tree:0",
                ),
            ] {
                let client = format!("cutoff-{}-{version}-{mode}", format.as_str());
                let context = node.request_context();
                let before = node
                    .runtime()
                    .block_on(node.materialize_admission_in(&context))
                    .unwrap()
                    .basis()
                    .clone();
                let initial = format!("{initial};{profile}");
                let (returned, _) = live_client(
                    node,
                    &listener,
                    command(
                        &run,
                        "cutoff-clone",
                        &client,
                        &[&endpoint, &repository, version, &initial],
                    ),
                );
                node = returned;
                assert_eq!(markers(&run, &client), BTreeSet::from([third.0]));
                assert_eq!(
                    history(&run, &client),
                    BTreeSet::from([third.0.to_string(), fourth.0.to_string()])
                );
                let initial_ids = inventory(&run, &client);
                let expected: BTreeSet<_> = match profile {
                    "full" => [third.0, third.1, third.2, fourth.0, fourth.1, fourth.2]
                        .into_iter()
                        .collect(),
                    "blob:none" => [third.0, third.1, fourth.0, fourth.1].into_iter().collect(),
                    "tree:0" => [third.0, fourth.0].into_iter().collect(),
                    _ => unreachable!(),
                };
                assert_eq!(
                    initial_ids,
                    expected.iter().map(ToString::to_string).collect()
                );
                checked(command(&run, "fsck", &client, &[]));
                let tip = fourth.0.to_string();
                let (returned, _) = live_client(
                    node,
                    &listener,
                    command(
                        &run,
                        "checkout",
                        &client,
                        &[&endpoint, &repository, version, &tip],
                    ),
                );
                node = returned;
                assert_eq!(
                    std::fs::read(
                        PathBuf::from(&run)
                            .join("work")
                            .join(&client)
                            .join("public")
                    )
                    .unwrap(),
                    expected_file
                );
                let widen = format!("{widen};{profile}");
                let (returned, _) = live_client(
                    node,
                    &listener,
                    command(
                        &run,
                        "cutoff-fetch",
                        &client,
                        &[&endpoint, &repository, version, &widen],
                    ),
                );
                node = returned;
                assert_eq!(markers(&run, &client), BTreeSet::from([second.0]));
                assert_eq!(
                    history(&run, &client),
                    BTreeSet::from([
                        second.0.to_string(),
                        third.0.to_string(),
                        fourth.0.to_string()
                    ])
                );
                checked(command(&run, "fsck", &client, &[]));
                let (returned, _) = live_client(
                    node,
                    &listener,
                    command(
                        &run,
                        "unshallow",
                        &client,
                        &[&endpoint, &repository, version, "-"],
                    ),
                );
                node = returned;
                assert!(markers(&run, &client).is_empty());
                assert_eq!(
                    history(&run, &client),
                    [ancestor, public, first.0, second.0, third.0, fourth.0]
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect()
                );
                checked(command(&run, "fsck", &client, &[]));
                let final_ids = inventory(&run, &client);
                assert!(!final_ids.contains(&private.to_string()));
                assert!(!final_ids.contains(&private_blob.to_string()));
                let context = node.request_context();
                let after = node
                    .runtime()
                    .block_on(node.materialize_admission_in(&context))
                    .unwrap();
                assert_eq!(
                    after.basis(),
                    &before,
                    "fetch and lazy hydration do not mutate canonical state"
                );
                println!(
                    "PINNED_CUTOFF_CELL format={} protocol={version} mode={mode} profile={profile} clone_widen_checkout_unshallow=passed",
                    format.as_str()
                );
            }
        }
        node.shutdown().unwrap();
        drop(scratch);
    }
}
