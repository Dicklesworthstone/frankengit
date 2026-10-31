//! Real authority/fabric recovery after deleting the original source. These
//! exercise checkpoint preservation, continuation, and interrupted publication.
use super::*;

fn advance(node: &OneNode, commit: GitOid) {
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([3; 16]),
        IdempotencyKey::new(b"after-checkpoint-restore".to_vec()).unwrap(),
    );
    let command = RefCommand {
        name: RefName::try_new(b"refs/heads/after-restore").unwrap(),
        expected_old: ExpectedOld::Absent,
        proposed_new: ProposedNew::Update(commit),
        force: false,
    };
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &request,
            &session,
            &[command],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

#[test]
fn checkpointed_backup_preserves_exact_root_and_capsule_then_accepts_a_successor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (input, pin, commit, original) = checkpoint_fixture(&scratch, format, true);
        let original = original.unwrap();
        assert_eq!(&fs::read(&input).unwrap()[..8], b"FGSRC002");
        assert!(!scratch.0.join("source-node").exists());
        assert!(!scratch.0.join("source.git").exists());
        let preflight = scratch.0.join("preflight");
        let mut receipt = Vec::new();
        super::super::verify::run(
            &[
                "verify".into(),
                input.to_str().unwrap().into(),
                preflight.to_str().unwrap().into(),
                "--trusted-local".into(),
                "--expected-sha256".into(),
                hex(&pin),
                "--verification-instance".into(),
                "992".into(),
            ],
            &mut receipt,
            None,
        )
        .unwrap();
        let receipt = String::from_utf8(receipt).unwrap();
        assert!(receipt.contains("\"retained_outcome_checkpoint_verified\":true"));
        assert!(receipt.contains("\"git_payloads_written\":false"));
        assert!(!preflight.exists());
        let options = options(&input, scratch.0.join("restored"), pin);
        let receipt = execute(&options).unwrap();
        assert!(receipt.contains("\"transport_version\":2"));
        assert!(receipt.contains("\"retained_outcome_checkpoint_verified\":true"));
        assert!(options.output.join("manifests").is_dir());
        with_node(node_config(&options.output, format), |node| {
            let request = node.request_context();
            let unchanged = node
                .runtime()
                .block_on(node.checkpoint_outcomes_in(&request, Default::default()))
                .unwrap();
            assert!(!unchanged.published);
            assert_eq!(unchanged.checkpoint_root, original.checkpoint_root);
            assert_eq!(unchanged.capsule_id, original.capsule_id);
            assert_eq!(unchanged.published_head, original.published_head);
            advance(node, commit);
            let successor = node
                .runtime()
                .block_on(node.checkpoint_outcomes_in(&request, Default::default()))
                .unwrap();
            assert!(successor.published);
            assert_eq!(successor.decisions, original.decisions + 1);
            assert_ne!(successor.checkpoint_root, original.checkpoint_root);
            let (body, _) = node
                .runtime()
                .block_on(
                    fgit_chronicle::load_verified_outcome_index_checkpoint_async(
                        &node.authority,
                        request.authority(),
                        &fgit_codec::CryptoBodyIdentity,
                        &node.outcome_checkpoint_fabric,
                        successor.checkpoint_root,
                    ),
                )
                .unwrap();
            assert_eq!(
                body.predecessor_checkpoint_root,
                Some(original.checkpoint_root)
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn checkpoint_evidence_survives_every_restore_boundary_and_lost_response_retry() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let (input, pin, _, original) = checkpoint_fixture(&scratch, format, true);
    let original = original.unwrap();
    for (index, stage) in [
        Stage::Intent,
        Stage::Authority,
        Stage::Objects,
        Stage::QuarantineVerified,
        Stage::DataPrepared,
        Stage::Published,
        Stage::FinalVerified,
        Stage::Cleaned,
    ]
    .into_iter()
    .enumerate()
    {
        let mut options = options(&input, scratch.0.join(format!("restore-{index}")), pin);
        stop(&options, stage);
        assert_eq!(
            options.output.join("authority.fsqlite").exists(),
            matches!(
                stage,
                Stage::Published | Stage::FinalVerified | Stage::Cleaned
            )
        );
        options.resume = true;
        assert!(
            execute(&options)
                .unwrap()
                .contains("\"retained_outcome_checkpoint_verified\":true")
        );
        let before = snapshot(&options.output);
        assert!(
            execute(&options)
                .unwrap()
                .contains("\"already_published\":true")
        );
        assert_eq!(snapshot(&options.output), before);
        with_node(node_config(&options.output, format), |node| {
            let request = node.request_context();
            let receipt = node
                .runtime()
                .block_on(node.checkpoint_outcomes_in(&request, Default::default()))
                .unwrap();
            assert!(!receipt.published);
            assert_eq!(receipt.checkpoint_root, original.checkpoint_root);
            assert_eq!(receipt.capsule_id, original.capsule_id);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn legacy_archive_restores_with_explicitly_absent_retained_evidence() {
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    assert_eq!(&fs::read(&input).unwrap()[..8], b"FGSRC001");
    let receipt = execute(&options(&input, scratch.0.join("legacy"), pin)).unwrap();
    assert!(receipt.contains("\"transport_version\":1"));
    assert!(receipt.contains("\"retained_outcome_checkpoint_verified\":false"));
}

fn evidence_section(bytes: &[u8]) -> (usize, usize) {
    let authority = u64::from_be_bytes(bytes[57..65].try_into().unwrap()) as usize;
    let start = 65 + authority;
    let length = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap()) as usize;
    (start, start + 8 + length)
}

#[test]
fn generic_capsule_without_a_root_preserves_the_nearest_retained_archive() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let mut intervening = None;
    let (input, pin, _, original) =
        checkpoint_fixture_with(&scratch, format, true, |node, original| {
            let original = original.unwrap();
            let request = node.request_context();
            let selected = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            let key = fgit_authority::body_key_for_id(original.capsule_id.as_internal_object_id())
                .unwrap();
            let read = node
                .runtime()
                .block_on(fgit_authority::AsyncAuthorityStore::read_immutable(
                    &node.authority,
                    request.authority(),
                    &key,
                ))
                .unwrap();
            let fgit_authority::ImmutableRead::Present(bytes) = read else {
                panic!("selected capsule absent")
            };
            let capsule: fgit_chronicle::RepositoryCapsuleBody =
                fgit_codec::decode_body(&bytes, fgit_codec::DecodeLimits::DEFAULT).unwrap();
            let pointer =
                fgit_chronicle::CapsulePointer::restored_root(original.capsule_id, &capsule);
            let frozen = node
                .runtime()
                .block_on(fgit_chronicle::freeze_capsule_async(
                    &node.authority,
                    request.authority(),
                    &fgit_codec::CryptoBodyIdentity,
                    selected.authenticated().receipt(),
                    Some(&pointer),
                    fgit_chronicle::CapsuleClosure {
                        object_closure_root: capsule.object_closure_root,
                        segment_manifest_root: capsule.segment_manifest_root,
                        backup_profile: fgit_chronicle::BackupProfile::DecisionHistoryOnly,
                    },
                ))
                .unwrap();
            assert_eq!(frozen.capsule().outcome_index_checkpoint_root, None);
            let activated = node
                .runtime()
                .block_on(fgit_chronicle::activate_frozen_capsule_async(
                    &node.authority,
                    request.authority(),
                    selected.authenticated().receipt(),
                    &frozen,
                ))
                .unwrap();
            intervening = Some(activated.pointer().capsule_id());
        });
    let original = original.unwrap();
    let options = options(&input, scratch.0.join("generic-capsule"), pin);
    assert!(
        execute(&options)
            .unwrap()
            .contains("\"retained_outcome_checkpoint_verified\":true")
    );
    with_node(node_config(&options.output, format), |node| {
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(selected.basis().body().last_checkpoint_id, intervening);
        let rebound = node
            .runtime()
            .block_on(node.checkpoint_outcomes_in(&request, Default::default()))
            .unwrap();
        assert!(rebound.published);
        assert_eq!(rebound.checkpoint_root, original.checkpoint_root);
        assert_ne!(Some(rebound.capsule_id), intervening);
        Ok(())
    })
    .unwrap();
}

#[test]
fn v2_wrong_root_and_missing_section_refuse_even_with_a_new_file_pin() {
    let scratch = Scratch::new();
    let (input, _, _, _) = checkpoint_fixture(&scratch, GitHashAlgorithm::Sha256, true);
    let original = fs::read(&input).unwrap();
    let (start, end) = evidence_section(&original);
    let mut wrong_root = original.clone();
    wrong_root[start + 8 + 3] ^= 1;
    let mut missing = original.clone();
    missing.drain(start + 8..end);
    missing[start..start + 8].copy_from_slice(&0_u64.to_be_bytes());
    let mut oversized = original;
    oversized[start..start + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    for (index, bytes) in [wrong_root, missing, oversized].into_iter().enumerate() {
        let file = scratch.0.join(format!("invalid-{index}.fg"));
        fs::write(&file, &bytes).unwrap();
        let pin = super::super::super::super::sha256(&bytes);
        let options = options(&file, scratch.0.join(format!("invalid-{index}")), pin);
        let error = execute(&options).unwrap_err();
        assert!(
            error.contains("checkpoint") || error.contains("limit"),
            "{error}"
        );
        assert!(!options.output.join("authority.fsqlite").exists());
    }
}

#[test]
fn old_source_only_archive_with_a_checkpoint_pointer_keeps_legacy_semantics() {
    let scratch = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (input, _, _, _) = checkpoint_fixture(&scratch, format, true);
    let mut legacy = fs::read(&input).unwrap();
    let (start, end) = evidence_section(&legacy);
    legacy.drain(start..end);
    legacy[..8].copy_from_slice(b"FGSRC001");
    fs::write(&input, &legacy).unwrap();
    let pin = super::super::super::super::sha256(&legacy);
    let options = options(&input, scratch.0.join("legacy-with-pointer"), pin);
    let receipt = execute(&options).unwrap();
    assert!(receipt.contains("\"retained_outcome_checkpoint_verified\":false"));
    with_node(node_config(&options.output, format), |node| {
        let request = node.request_context();
        assert!(
            node.runtime()
                .block_on(node.checkpoint_outcomes_in(&request, Default::default()))
                .is_err(),
            "source-only recovery cannot claim that absent retained bytes survived"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn corrupt_checkpoint_manifest_is_preserved_and_never_publishes_authority() {
    let scratch = Scratch::new();
    let (input, pin, _, _) = checkpoint_fixture(&scratch, GitHashAlgorithm::Sha256, true);
    let mut options = options(&input, scratch.0.join("corrupt-manifest"), pin);
    stop(&options, Stage::Objects);
    let directory = options.output.join(".restore-quarantine/manifests");
    let files: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let original = fs::read(&files[0]).unwrap();
    let mut corrupted = original.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(&files[0], &corrupted).unwrap();
    options.resume = true;
    assert!(execute(&options).is_err());
    assert!(!options.output.join("authority.fsqlite").exists());
    assert_eq!(fs::read(&files[0]).unwrap(), corrupted);
    fs::write(&files[0], original).unwrap();
    execute(&options).unwrap();
    // Published recovery is verification-only. Missing retained evidence cannot
    // be hidden by successful genesis replay or repaired during a lost reply.
    let published: Vec<_> = fs::read_dir(options.output.join("manifests"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    fs::remove_file(&published[0]).unwrap();
    let before = snapshot(&options.output);
    assert!(execute(&options).unwrap_err().contains("checkpoint"));
    assert_eq!(snapshot(&options.output), before);
    assert!(!published[0].exists());
    let rejected = scratch.0.join("must-not-export.fg");
    let error = super::super::super::run(
        &[
            "export".into(),
            options.output.to_str().unwrap().into(),
            rejected.to_str().unwrap().into(),
            TENANT.into(),
            REPOSITORY.into(),
            "--trusted-local".into(),
            "--object-format".into(),
            "sha256".into(),
        ],
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(error.contains("checkpoint"), "{error}");
    assert!(
        !rejected.exists(),
        "missing selected evidence cannot silently downgrade an export to V1"
    );
}

#[test]
fn current_checkpoint_section_counts_toward_the_original_total_archive_budget() {
    let scratch = Scratch::new();
    let (input, pin, _, _) = checkpoint_fixture(&scratch, GitHashAlgorithm::Sha1, true);
    let length = fs::metadata(&input).unwrap().len();
    let mut too_small = options(&input, scratch.0.join("too-small"), pin);
    too_small.profile.transfer.max_archive_bytes = length - 1;
    assert!(execute(&too_small).is_err());
    assert!(!too_small.output.exists());
    let mut exact = options(&input, scratch.0.join("exact"), pin);
    exact.profile.transfer.max_archive_bytes = length;
    assert!(
        execute(&exact)
            .unwrap()
            .contains("\"retained_outcome_checkpoint_verified\":true")
    );
}
