use super::*;
use fgit_pack::full_bundle::IncrementalBundle;

fn sync_export(node: &OneNode, names: &[&str], prerequisites: &[GitOid]) -> IncrementalBundle {
    let request = node.request_context();
    node.runtime()
        .block_on(node.export_incremental_git_bundle_in(
            &request,
            &names.iter().map(|name| reference(name)).collect::<Vec<_>>(),
            prerequisites,
            &RefVisibility::new(),
            None,
        ))
        .unwrap()
        .1
}
fn sync_import(
    node: &OneNode,
    bytes: &[u8],
    expectations: &[(&str, Option<GitOid>)],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime().block_on(
        node.import_incremental_git_bundle_durable_in(
            &request,
            &session(key),
            bytes,
            &expectations
                .iter()
                .map(|(name, old)| (reference(name), *old))
                .collect::<Vec<_>>(),
            AdmissionLimits::default(),
        ),
    )
}
fn seed(source: &OneNode, destination: &OneNode, base: GitOid) {
    accepted(apply(
        source,
        &[create("refs/heads/seed", base)],
        "seed-branch",
    ));
    let mut visibility = RefVisibility::new();
    visibility
        .push_rule(b"refs/heads/main", &Default::default())
        .unwrap();
    accepted(import(
        destination,
        export(source, &visibility).bytes(),
        "seed-transfer",
    ));
    accepted(apply(
        destination,
        &[create("refs/heads/main", base)],
        "seed-main",
    ));
}
fn pack_count(bytes: &[u8]) -> u32 {
    let bundle =
        FullBundleInput::parse_incremental(bytes, FullBundleLimits::default(), &mut || true)
            .unwrap();
    let pack = fgit_pack::read_verified_pack(
        bundle.pack_bytes(),
        bundle.format(),
        &Default::default(),
        &mut || true,
        &fgit_pack::NativeChecksumVerifier,
    )
    .unwrap();
    u32::try_from(pack.entries().len()).unwrap()
}
#[test]
fn incremental_transfer_excludes_prerequisite_history_and_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = Scratch::new();
        let (source, base, child, _) = fixture(&a, format);
        let b = Scratch::new();
        let mut destination = empty_node(&b, format);
        seed(&source, &destination, base);
        assert!(destination.read_git_object(child).is_err());
        let before_source = snapshot(&source);
        let artifact = sync_export(&source, &["refs/heads/main"], &[base]);
        assert_eq!(artifact.pack_receipt().object_count, 1);
        assert_eq!(pack_count(artifact.bytes()), 1);
        assert_eq!(snapshot(&source).basis(), before_source.basis());
        let before = snapshot(&destination);
        let result = accepted(sync_import(
            &destination,
            artifact.bytes(),
            &[("refs/heads/main", Some(base))],
            "synchronize",
        ));
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&reference("refs/heads/main")], child);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_native_transfer(&source, &destination, child);
        assert!(
            sync_import(
                &destination,
                artifact.bytes(),
                &[("refs/heads/main", None)],
                "synchronize"
            )
            .is_err(),
            "changed expected-old is not a retry"
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        destination = OneNode::open_existing(b.config(format)).unwrap();
        destination.push_quota.limit.max_events = 0;
        let mut replay = artifact.bytes().to_vec();
        let last = replay.len() - 1;
        replay[last] ^= 1;
        assert_eq!(
            sync_import(
                &destination,
                &replay,
                &[("refs/heads/main", Some(base))],
                "synchronize"
            )
            .unwrap(),
            result,
            "known exact outcomes do not re-admit transport or charge mutation quota"
        );
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
#[test]
fn empty_incremental_pack_reuses_only_declared_history_and_cas_is_atomic() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = Scratch::new();
        let (source, base, child, _) = fixture(&a, format);
        let b = Scratch::new();
        let destination = empty_node(&b, format);
        seed(&source, &destination, base);
        accepted(apply(
            &source,
            &[create("refs/heads/copy", base)],
            "copy-source",
        ));
        let zero = sync_export(&source, &["refs/heads/copy"], &[base]);
        assert_eq!(zero.pack_receipt().object_count, 0);
        assert_eq!(pack_count(zero.bytes()), 0);
        accepted(sync_import(
            &destination,
            zero.bytes(),
            &[("refs/heads/copy", None)],
            "reuse-without-pack-objects",
        ));
        assert_eq!(
            snapshot(&destination).snapshot().refs[&reference("refs/heads/copy")],
            base
        );
        accepted(apply(
            &source,
            &[create("refs/heads/new", child)],
            "new-source",
        ));
        let bundle = sync_export(&source, &["refs/heads/main", "refs/heads/new"], &[base]);
        let before = snapshot(&destination);
        let wrong = [("refs/heads/main", None), ("refs/heads/new", None)];
        let refused =
            sync_import(&destination, bundle.bytes(), &wrong, "old-tip-mismatch").unwrap();
        assert!(refused.session.atomic);
        assert!(
            refused
                .commands
                .iter()
                .all(|item| matches!(item.terminal.outcome, DecisionOutcome::Refused { .. }))
        );
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        let decided = snapshot(&destination);
        assert_eq!(
            sync_import(&destination, bundle.bytes(), &wrong, "old-tip-mismatch").unwrap(),
            refused
        );
        assert_eq!(snapshot(&destination).basis(), decided.basis());
        accepted(sync_import(
            &destination,
            bundle.bytes(),
            &[("refs/heads/main", Some(base)), ("refs/heads/new", None)],
            "both-leases",
        ));
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs[&reference("refs/heads/main")], child);
        assert_eq!(after.snapshot().refs[&reference("refs/heads/new")], child);
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
#[test]
fn missing_wrong_kind_undeclared_and_deleted_prerequisites_never_stage_the_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = Scratch::new();
        let (source, base, child, blob) = fixture(&a, format);
        let artifact = sync_export(&source, &["refs/heads/main"], &[base]);
        let b = Scratch::new();
        let destination = empty_node(&b, format);
        let before = snapshot(&destination);
        assert!(
            sync_import(
                &destination,
                artifact.bytes(),
                &[("refs/heads/main", None)],
                "missing-base"
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), before.basis());
        seed(&source, &destination, base);
        let stable = snapshot(&destination);
        let replace_base = |id: GitOid| {
            let text =
                String::from_utf8(artifact.bytes()[..artifact.header_bytes()].to_vec()).unwrap();
            [
                text.replace(&format!("-{base} "), &format!("-{id} "))
                    .into_bytes(),
                artifact.bytes()[artifact.header_bytes()..].to_vec(),
            ]
            .concat()
        };
        assert!(
            sync_import(
                &destination,
                &replace_base(blob),
                &[("refs/heads/main", Some(base))],
                "blob-prerequisite"
            )
            .is_err()
        );
        let mut corrupt = artifact.bytes().to_vec();
        let end = corrupt.len() - 1;
        corrupt[end] ^= 1;
        assert!(
            sync_import(
                &destination,
                &corrupt,
                &[("refs/heads/main", Some(base))],
                "bad-checksum"
            )
            .is_err()
        );
        assert!(sync_import(&destination, artifact.bytes(), &[], "no-expectations").is_err());
        assert_eq!(snapshot(&destination).basis(), stable.basis());
        assert!(destination.read_git_object(child).is_err());
        let unrelated_tree = destination
            .put_git_object(fgit_git_object::ObjectType::Tree, Vec::new())
            .unwrap()
            .identity();
        let unrelated=destination.put_git_object(fgit_git_object::ObjectType::Commit,
            format!("tree {unrelated_tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nunrelated\n").into_bytes()).unwrap().identity();
        // Merely placed bytes are not authority: even a well-formed unrelated
        // prerequisite cannot grant access to the otherwise available base.
        assert!(
            sync_import(
                &destination,
                &replace_base(unrelated),
                &[("refs/heads/main", Some(base))],
                "unselected-base"
            )
            .is_err()
        );
        let unrelated_source = b.0.join("unrelated-source");
        fs::create_dir_all(unrelated_source.join("refs/heads")).unwrap();
        fs::write(
            unrelated_source.join("HEAD"),
            b"ref: refs/heads/unrelated\n",
        )
        .unwrap();
        fs::write(unrelated_source.join("config"),match format {
            GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        loose(&unrelated_source, format, GitObjectKind::Tree, "tree", b"");
        loose(
            &unrelated_source,
            format,
            GitObjectKind::Commit,
            "commit",
            destination.read_git_object(unrelated).unwrap().payload(),
        );
        fs::write(
            unrelated_source.join("refs/heads/unrelated"),
            format!("{unrelated}\n"),
        )
        .unwrap();
        let request = destination.request_context();
        let imported = destination
            .runtime()
            .block_on(destination.import_loose_git_directory_durable_in(
                &request,
                &unrelated_source,
                principal(),
                b"import-unrelated",
            ))
            .unwrap();
        assert!(
            imported
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let selected_unrelated = snapshot(&destination);
        assert!(
            sync_import(
                &destination,
                &replace_base(unrelated),
                &[("refs/heads/main", Some(base))],
                "undeclared-visible-dependency"
            )
            .is_err(),
            "visible but undeclared base must not repair the incremental closure"
        );
        assert_eq!(snapshot(&destination).basis(), selected_unrelated.basis());
        assert!(destination.read_git_object(child).is_err());
        for name in ["refs/heads/main", "refs/heads/seed"] {
            accepted(apply(
                &destination,
                &[RefCommand {
                    name: reference(name),
                    expected_old: ExpectedOld::Exactly(base),
                    proposed_new: ProposedNew::Delete,
                    force: false,
                }],
                &format!("delete-{name}"),
            ));
        }
        let deleted = snapshot(&destination);
        assert!(destination.read_git_object(base).is_ok());
        assert!(
            sync_import(
                &destination,
                artifact.bytes(),
                &[("refs/heads/main", None)],
                "disconnected-base"
            )
            .is_err()
        );
        assert_eq!(snapshot(&destination).basis(), deleted.basis());
        assert!(destination.read_git_object(child).is_err());
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 127) as u8;
        n >>= 7;
        out.push(byte | if n != 0 { 128 } else { 0 });
        if n == 0 {
            break;
        }
    }
}
fn stored_zlib(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(length.to_le_bytes());
    out.extend((!length).to_le_bytes());
    out.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), v| {
        let a = (a + u32::from(*v)) % 65521;
        (a, (b + a) % 65521)
    });
    out.extend(((b << 16) | a).to_be_bytes());
    out
}
fn thin_bundle(
    format: GitHashAlgorithm,
    base: GitOid,
    old: &[u8],
    new_id: GitOid,
    new: &[u8],
) -> Vec<u8> {
    let mut delta = Vec::new();
    varint(old.len(), &mut delta);
    varint(new.len(), &mut delta);
    for chunk in new.chunks(127) {
        delta.push(chunk.len() as u8);
        delta.extend(chunk);
    }
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    let mut length = delta.len();
    let mut header = vec![0x70 | (length as u8 & 15)];
    length >>= 4;
    while length != 0 {
        let i = header.len() - 1;
        header[i] |= 128;
        header.push((length & 127) as u8);
        length >>= 7;
    }
    pack.extend(header);
    pack.extend(base.as_bytes());
    pack.extend(stored_zlib(&delta));
    match format {
        GitHashAlgorithm::Sha1 => pack.extend(fgit_crypto::sha1_digest(&pack)),
        GitHashAlgorithm::Sha256 => pack.extend(fgit_crypto::sha256_digest(&pack)),
    }
    let signature = match format {
        GitHashAlgorithm::Sha1 => "# v2 git bundle\n",
        GitHashAlgorithm::Sha256 => "# v3 git bundle\n@object-format=sha256\n",
    };
    [
        format!("{signature}-{base} base comment\n{new_id} refs/heads/main\n\n").into_bytes(),
        pack,
    ]
    .concat()
}
#[test]
fn actual_ref_delta_incremental_bundle_reconstructs_from_authorized_original_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = Scratch::new();
        let (source, base, child, _) = fixture(&a, format);
        let b = Scratch::new();
        let destination = empty_node(&b, format);
        seed(&source, &destination, base);
        let old = source.read_git_object(base).unwrap();
        let new = source.read_git_object(child).unwrap();
        let bytes = thin_bundle(format, base, old.payload(), child, new.payload());
        accepted(sync_import(
            &destination,
            &bytes,
            &[("refs/heads/main", Some(base))],
            "thin-native-transfer",
        ));
        assert_native_transfer(&source, &destination, child);
        assert_eq!(
            snapshot(&destination).snapshot().refs[&reference("refs/heads/main")],
            child
        );
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
#[test]
fn incremental_atomic_update_cannot_bypass_repository_required_review_protection() {
    use fgit_forge::ExpectedVersion;
    use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let a = Scratch::new();
        let (source, base, child, _) = fixture(&a, format);
        let b = Scratch::new();
        let destination = empty_node(&b, format);
        seed(&source, &destination, base);
        accepted(apply(
            &source,
            &[create("refs/heads/new", child)],
            "new-tip",
        ));
        let command = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: fgit_types::PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![principal()],
                branches: vec![ProtectedBranch {
                    name: reference("refs/heads/main"),
                    reviewers: vec![PrincipalId::from_bytes([9; 16])],
                }],
            },
        };
        let request = destination.request_context();
        let installed = destination
            .runtime()
            .block_on(destination.admit_review_protection_durable_in(
                &request,
                &session("protect"),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            installed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = snapshot(&destination);
        let artifact = sync_export(&source, &["refs/heads/main", "refs/heads/new"], &[base]);
        let result = sync_import(
            &destination,
            artifact.bytes(),
            &[("refs/heads/main", Some(base)), ("refs/heads/new", None)],
            "protected-sync",
        )
        .unwrap();
        assert!(result.commands.iter().all(|item| matches!(
            item.terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        )));
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        assert_eq!(
            snapshot(&destination).snapshot().outbox,
            before.snapshot().outbox
        );
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn small_mapped_fetch_accepts_a_large_full_bundle_advertisement() {
    use fgit_pack::full_bundle::fetch::BundleRefMapping;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, _, child, _) = fixture(&source_root, format);
        let full = export(&source, &RefVisibility::new());
        let mut bytes = match format {
            GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
            GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        for i in 0..80 {
            bytes.extend_from_slice(format!("{child} refs/heads/wide{i:02}\n").as_bytes());
        }
        bytes.push(b'\n');
        bytes.extend_from_slice(&full.bytes()[full.header_bytes()..]);
        let target_root = Scratch::new();
        let destination = empty_node(&target_root, format);
        let request = destination.request_context();
        let mapping = BundleRefMapping {
            source: reference("refs/heads/wide79"),
            destination: reference("refs/remotes/upstream/main"),
            expected_old: None,
        };
        let result = accepted(destination.runtime().block_on(
            destination.fetch_full_git_bundle_durable_in(
                &request,
                &session("one-of-many"),
                &bytes,
                &[mapping],
                AdmissionLimits {
                    max_commands: 1,
                    ..AdmissionLimits::default()
                },
            ),
        ));
        assert_eq!(result.commands.len(), 1);
        let selected = snapshot(&destination);
        assert_eq!(selected.snapshot().refs.len(), 1);
        assert_eq!(
            selected.snapshot().refs[&reference("refs/remotes/upstream/main")],
            child
        );
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}

#[test]
fn optional_head_advertisement_does_not_consume_an_incremental_mutation_slot() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, base, child, _) = fixture(&source_root, format);
        let target_root = Scratch::new();
        let destination = empty_node(&target_root, format);
        seed(&source, &destination, base);
        let artifact = sync_export(&source, &["refs/heads/main"], &[base]);
        let mut bytes = artifact.bytes()[..artifact.header_bytes() - 1].to_vec();
        bytes.extend_from_slice(format!("{child} HEAD\n\n").as_bytes());
        bytes.extend_from_slice(&artifact.bytes()[artifact.header_bytes()..]);
        let request = destination.request_context();
        let result = accepted(destination.runtime().block_on(
            destination.import_incremental_git_bundle_durable_in(
                &request,
                &session("one-plus-head"),
                &bytes,
                &[(reference("refs/heads/main"), Some(base))],
                AdmissionLimits {
                    max_commands: 1,
                    ..AdmissionLimits::default()
                },
            ),
        ));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(
            snapshot(&destination).snapshot().refs[&reference("refs/heads/main")],
            child
        );
        destination.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
