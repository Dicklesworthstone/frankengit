//! Ref roots carry kinds just as commit/tree/tag edges do. These fixtures
//! exercise real pack decoding, authority selection, admission and persistence.
use super::*;

fn branch_request(format: GitHashAlgorithm, id: GitOid) -> ReceiveRequest {
    let mut value = request(format, &[id]);
    value.commands[0].ref_name = b"refs/heads/target".to_vec();
    value
}
fn materialized(node: &OneNode) -> crate::MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}
fn selected<'a>(
    node: &'a OneNode,
    at: &crate::MaterializedAdmission,
) -> ProductionQuarantineValidator<'a> {
    node.production_quarantine_validator(
        at,
        PackLimits::default(),
        ParseLimits {
            tree_reference_bytes: node.object_format.digest_len(),
            ..ParseLimits::default()
        },
    )
    .unwrap()
}
fn admit(
    node: &OneNode,
    at: &crate::MaterializedAdmission,
    requested: &ReceiveRequest,
    pack: &QuarantinedPack,
    receipt: &QuarantineReceipt,
    key: &[u8],
) -> fgit_admission::AdmissionResult {
    let mut handoff =
        ProductionReceiveQuarantineHandoff::new(selected(node, at), at.basis().clone());
    handoff
        .handoff_with_deadline(requested, Some(pack), receipt, &mut || true)
        .unwrap();
    let validated = handoff.into_validated_receive().unwrap();
    let context = node.request_context();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x73; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    node.runtime()
        .block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &context,
            &session,
            &validated,
            fgit_admission::AdmissionLimits::default(),
        ))
        .unwrap()
}

#[test]
fn ref_roots_reject_uploaded_noncommits_in_either_alias_order_before_any_staging() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let at = materialized(&node);
        let blob = raw(format, ObjectType::Blob, b"plain contents".to_vec());
        let tree = tree(format, &[("100644", "file", blob.id)]);
        let tip = commit(format, tree.id, &[], "valid commit");
        let tag = tag(format, tip.id, "commit");
        let all = [blob, tree, tip.clone(), tag];
        let (pack, receipt) = packed(format, &all.iter().map(full).collect::<Vec<_>>());
        for bad in [&all[0], &all[1], &all[3]] {
            for reverse in [false, true] {
                let mut requested = request(format, &[tip.id, bad.id, bad.id]);
                requested.commands[0].ref_name = b"refs/heads/valid".to_vec();
                requested.commands[1].ref_name = b"refs/tags/alias".to_vec();
                requested.commands[2].ref_name = b"refs/heads/invalid".to_vec();
                if reverse {
                    requested.commands.reverse();
                }
                let mut handoff = ProductionReceiveQuarantineHandoff::new(
                    selected(&node, &at),
                    at.basis().clone(),
                );
                assert_eq!(
                    handoff.handoff_with_deadline(&requested, Some(&pack), &receipt, &mut || true),
                    Err(ReceiveError::AuthoritativeRefusal(
                        RefusalCode::EvidenceInvalid
                    ))
                );
                assert!(handoff.into_validated_receive().is_err());
                for object in &all {
                    assert!(node.read_git_object(object.id).is_err());
                }
                assert_eq!(materialized(&node).basis(), at.basis());
            }
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_roots_reject_reconstructed_noncommits_but_keep_valid_delta_dependencies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let at = materialized(&node);
        let base = raw(format, ObjectType::Blob, b"transport delta base".to_vec());
        let result = raw(format, ObjectType::Blob, b"target bytes".to_vec());
        let (pack, receipt) = packed(format, &[delta(&base, &result), full(&base)]);
        let validator = selected(&node, &at);
        assert_eq!(
            validator.validate(
                &branch_request(format, result.id),
                Some(&pack),
                &receipt,
                &mut || true
            ),
            Err(RefusalCode::EvidenceInvalid)
        );
        assert!(node.read_git_object(base.id).is_err() && node.read_git_object(result.id).is_err());
        let closure = validator
            .validate(
                &request(format, &[result.id]),
                Some(&pack),
                &receipt,
                &mut || true,
            )
            .unwrap();
        assert_eq!(closure.objects, BTreeSet::from([base.id, result.id]));
        assert_eq!(
            materialized(&node).basis(),
            at.basis(),
            "staged tags do not publish refs"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_roots_enforce_omitted_targets_after_visibility_and_keep_commit_and_tag_twins() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let mut node = node(format, &scratch);
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let at = materialized(&node);
        let blob = raw(format, ObjectType::Blob, b"public blob".to_vec());
        let tree = tree(format, &[("100644", "file", blob.id)]);
        let tip = commit(format, tree.id, &[], "visible commit");
        let tag = tag(format, tip.id, "commit");
        let all = [blob, tree, tip.clone(), tag];
        let (pack, receipt) = packed(format, &all.iter().map(full).collect::<Vec<_>>());
        let mut initial = request(format, &all.iter().map(|o| o.id).collect::<Vec<_>>());
        initial.commands[2].ref_name = b"refs/heads/main".to_vec();
        initial.capabilities.push(
            fgit_wire::Capability::parse(b"atomic", &fgit_wire::WireLimits::default()).unwrap(),
        );
        let published = admit(&node, &at, &initial, &pack, &receipt, b"valid-ref-roots");
        assert!(
            published
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let at = materialized(&node);
        let (empty, empty_receipt) = packed(format, &[]);
        for bad in [&all[0], &all[1], &all[3]] {
            let validator = selected(&node, &at);
            assert_eq!(
                validator.validate(
                    &branch_request(format, bad.id),
                    Some(&empty),
                    &empty_receipt,
                    &mut || true
                ),
                Err(RefusalCode::EvidenceInvalid)
            );
            assert_eq!(materialized(&node).basis(), at.basis());
            // Omitted raw objects remain legitimate tag targets without being
            // re-uploaded, reinterpreted as commits, or needlessly restaged.
            assert_eq!(
                validator
                    .validate(
                        &request(format, &[bad.id]),
                        Some(&empty),
                        &empty_receipt,
                        &mut || true
                    )
                    .unwrap()
                    .objects,
                BTreeSet::from([bad.id])
            );
        }
        let mut reused = branch_request(format, tip.id);
        reused.capabilities.push(
            fgit_wire::Capability::parse(b"atomic", &fgit_wire::WireLimits::default()).unwrap(),
        );
        let admitted = admit(
            &node,
            &at,
            &reused,
            &empty,
            &empty_receipt,
            b"reuse-valid-commit",
        );
        assert!(
            admitted
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        let after = materialized(&node);
        assert_eq!(
            after.snapshot().refs[&RefName::try_new(b"refs/heads/target").unwrap()],
            tip.id
        );
        node.shutdown().unwrap();
        let config = NodeConfig::new(
            scratch.path().to_path_buf(),
            TenantId::from_bytes([0x71; 16]),
            RepositoryId::from_bytes([0x72; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let node = OneNode::open_existing(config).unwrap();
        assert_eq!(materialized(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_roots_do_not_disclose_the_kind_of_unselected_originals_or_override_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let present = node
            .put_git_object(ObjectType::Blob, b"unselected bytes".to_vec())
            .unwrap()
            .identity();
        let absent = raw(format, ObjectType::Blob, b"absent bytes".to_vec()).id;
        let at = materialized(&node);
        let validator = selected(&node, &at);
        let (empty, receipt) = packed(format, &[]);
        for id in [present, absent] {
            assert_eq!(
                validator.validate(
                    &branch_request(format, id),
                    Some(&empty),
                    &receipt,
                    &mut || true
                ),
                Err(RefusalCode::ObjectClosureIncomplete)
            );
            assert_eq!(
                validator.validate(
                    &branch_request(format, id),
                    Some(&empty),
                    &receipt,
                    &mut || false
                ),
                Err(RefusalCode::CancellationInProgress)
            );
        }
        assert_eq!(materialized(&node).basis(), at.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn ref_root_kind_of_thin_delta_results_is_checked_only_after_base_authorization() {
    // The parent fixture explicitly supplies authority-selected IDs. Revoke
    // their visibility while preserving exact native bytes and selection.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let node = node(format, &scratch);
        let base = raw(format, ObjectType::Blob, b"private delta base".to_vec());
        node.put_git_object(ObjectType::Blob, base.body.clone())
            .unwrap();
        let different = raw(format, ObjectType::Blob, b"reconstructed target".to_vec());
        for result in [&base, &different] {
            let (pack, receipt) = packed(format, &[delta(&base, result)]);
            let visible = selected_validator(&node, format, &[base.id], PackLimits::default());
            let mut hidden = selected_validator(&node, format, &[base.id], PackLimits::default());
            hidden.visible_roots.clear();
            let requested = branch_request(format, result.id);
            assert_eq!(
                hidden.validate(&requested, Some(&pack), &receipt, &mut || true),
                Err(RefusalCode::ObjectClosureIncomplete),
                "unauthorized originals must not expose their kind through a ref mismatch"
            );
            assert_eq!(
                visible.validate(&requested, Some(&pack), &receipt, &mut || true),
                Err(RefusalCode::EvidenceInvalid),
                "authorized original bytes still cannot produce a blob-valued branch"
            );
            assert!(
                node.read_git_object(different.id).is_err(),
                "refusal never stages the result"
            );
        }
        node.shutdown().unwrap();
    }
}
