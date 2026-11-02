use super::*;
use crate::received_pack::VerifiedReceivedObject;
use fgit_pack::{PackOrderKey, read_verified_pack_owned};

mod recency;

fn node_for(format: GitHashAlgorithm) -> (ScratchDirectory, OneNode) {
    let scratch = ScratchDirectory::new();
    let node = OneNode::init(
        NodeConfig::new(
            scratch.path().to_path_buf(),
            TenantId::from_bytes([0x81; 16]),
            RepositoryId::from_bytes([0x82; 16]),
        )
        .with_object_format(format),
    )
    .unwrap()
    .0;
    (scratch, node)
}

fn retained_blob(
    node: &OneNode,
    body: &[u8],
) -> (QuarantinedPack, Vec<u8>, VerifiedReceivedObject) {
    let id = fgit_crypto::git_object_id(node.object_format, GitObjectKind::Blob, body);
    let source = OneObjectSource {
        object: CanonicalPackObject::new(id, ObjectType::Blob, body.to_vec(), Vec::new(), 0, 0),
    };
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        node.object_format,
        PackWriteProfile::STORED_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[id], &mut || true)
    .unwrap();
    let (raw, _) = PackWriter::new(limits.clone())
        .write(&plan, &mut || true)
        .unwrap();
    let pack = read_verified_pack_owned(
        raw.clone(),
        node.object_format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
        64 * 1024 * 1024,
    )
    .unwrap();
    (
        pack,
        raw,
        VerifiedReceivedObject {
            id,
            kind: ObjectType::Blob,
            bytes: body.len(),
        },
    )
}

fn key(hint: VerifiedReceivedObject) -> PackOrderKey {
    PackOrderKey {
        id: hint.id,
        object_type: hint.kind,
        recency: 0,
        path_hash: 0,
    }
}

fn stored_path(node: &OneNode, id: GitOid) -> PathBuf {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    node.storage_root()
        .join("objects")
        .join(hex(&node.namespace))
        .join(hex(&id.algorithm().code_point().to_be_bytes()))
        .join(id.to_string())
}

#[test]
fn cold_custody_reconstructs_spooled_objects_and_preserves_sender_bytes_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node) = node_for(format);
        let body = b"a canonical payload independently verified after restart";
        let (pack, raw, hint) = retained_blob(&node, body);
        node.put_git_object(ObjectType::Blob, body.to_vec())
            .unwrap();
        let authorized = BTreeSet::from([hint.id]);
        let validator = ProductionQuarantineValidator::new(
            &node,
            selected_closure(authorized.clone()),
            PackLimits::default(),
            ParseLimits::default(),
        )
        .with_resident_budgets(0, 0)
        .for_received_pack_restoration();
        let pending = validator
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true,
            )
            .unwrap()
            .expect("cold bytes matched the independently verified fabric payload");
        assert_eq!(node.received_pack_cache().retained_entries(), 0);
        pending.commit();
        let reused = node
            .received_pack_cache()
            .try_reuse(&[key(hint)], &PackLimits::default(), true, &mut || true)
            .unwrap()
            .unwrap();
        assert_eq!(reused.into_bytes().unwrap(), raw);
        assert_eq!(node.read_git_object(hint.id).unwrap().payload(), body);
        node.shutdown().unwrap();
    }
}

#[test]
fn persisted_hints_do_not_authorize_identity_kind_length_or_extra_scope() {
    let (_scratch, node) = node_for(GitHashAlgorithm::Sha1);
    let body = b"the independently verified native bytes";
    let (pack, _, hint) = retained_blob(&node, body);
    node.put_git_object(ObjectType::Blob, body.to_vec())
        .unwrap();
    let other = fgit_crypto::git_object_id(node.object_format, GitObjectKind::Blob, b"other");
    let authorized = BTreeSet::from([hint.id, other]);
    let validator = ProductionQuarantineValidator::new(
        &node,
        selected_closure(authorized.clone()),
        PackLimits::default(),
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    for bad in [
        VerifiedReceivedObject { id: other, ..hint },
        VerifiedReceivedObject {
            kind: ObjectType::Tree,
            ..hint
        },
        VerifiedReceivedObject {
            bytes: hint.bytes + 1,
            ..hint
        },
    ] {
        assert!(
            validator
                .restore_received_pack(
                    &pack,
                    &[bad],
                    &authorized,
                    &mut ResolutionBudget::new(),
                    &mut || true
                )
                .unwrap()
                .is_none()
        );
    }
    assert!(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &BTreeSet::new(),
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_none()
    );
    let unselected = ProductionQuarantineValidator::new(
        &node,
        empty_selected_closure(),
        PackLimits::default(),
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    assert!(
        unselected
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    node.shutdown().unwrap();
}

#[test]
fn missing_or_corrupt_canonical_evidence_never_gets_repaired_from_cached_bytes() {
    let (_scratch, node) = node_for(GitHashAlgorithm::Sha1);
    let body = b"cache contents cannot repair canonical authority";
    let (pack, _, hint) = retained_blob(&node, body);
    let authorized = BTreeSet::from([hint.id]);
    let validator = ProductionQuarantineValidator::new(
        &node,
        selected_closure(authorized.clone()),
        PackLimits::default(),
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    assert!(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_none()
    );
    assert!(
        node.read_git_object(hint.id).is_err(),
        "restoration never stages missing objects"
    );
    node.put_git_object(ObjectType::Blob, body.to_vec())
        .unwrap();
    let path = stored_path(&node, hint.id);
    let original = fs::read(&path).unwrap();
    let commitment =
        fgit_crypto::git_payload_commitment(GitObjectKind::Blob, body, CANONICAL_CODEC_VERSION);
    let commitment_at = original
        .windows(32)
        .position(|bytes| bytes == commitment.digest().as_bytes())
        .unwrap();
    for offset in [original.len() - 1, commitment_at] {
        let mut corrupt = original.clone();
        corrupt[offset] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(
            validator
                .restore_received_pack(
                    &pack,
                    &[hint],
                    &authorized,
                    &mut ResolutionBudget::new(),
                    &mut || true
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            corrupt,
            "cache validation is read-only"
        );
    }
    fs::write(&path, &original).unwrap();
    assert!(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    node.shutdown().unwrap();
}

#[test]
fn rejected_candidates_keep_their_resolution_charge_for_later_candidates() {
    let (_scratch, node) = node_for(GitHashAlgorithm::Sha1);
    let body = b"only one native reconstruction fits this operation";
    let (pack, _, hint) = retained_blob(&node, body);
    node.put_git_object(ObjectType::Blob, body.to_vec())
        .unwrap();
    let authorized = BTreeSet::from([hint.id]);
    let validator = ProductionQuarantineValidator::new(
        &node,
        selected_closure(authorized.clone()),
        PackLimits {
            max_total_expanded_bytes: body.len(),
            ..PackLimits::default()
        },
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    let bad = VerifiedReceivedObject {
        kind: ObjectType::Tree,
        ..hint
    };
    let mut budget = ResolutionBudget::new();
    assert!(
        validator
            .restore_received_pack(&pack, &[bad], &authorized, &mut budget, &mut || true)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        validator.restore_received_pack(&pack, &[hint], &authorized, &mut budget, &mut || true),
        Err(RefusalCode::ResourceBudgetExceeded)
    ));
    assert!(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(node.received_pack_cache().retained_entries(), 0);
    node.shutdown().unwrap();
}

#[test]
fn cancellation_during_cold_validation_is_a_stop_and_never_installs_partial_custody() {
    let (_scratch, node) = node_for(GitHashAlgorithm::Sha1);
    let body = b"cooperative cold revalidation";
    let (pack, _, hint) = retained_blob(&node, body);
    node.put_git_object(ObjectType::Blob, body.to_vec())
        .unwrap();
    let authorized = BTreeSet::from([hint.id]);
    let validator = ProductionQuarantineValidator::new(
        &node,
        selected_closure(authorized.clone()),
        PackLimits::default(),
        ParseLimits::default(),
    )
    .with_resident_budgets(0, 0)
    .for_received_pack_restoration();
    let mut probes = 0;
    drop(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || {
                    probes += 1;
                    true
                },
            )
            .unwrap()
            .unwrap(),
    );
    for stop in [1, probes / 2, probes - 1] {
        let mut current = 0;
        let result = validator.restore_received_pack(
            &pack,
            &[hint],
            &authorized,
            &mut ResolutionBudget::new(),
            &mut || {
                current += 1;
                // Deliberately one-shot: a later successful checkpoint must not
                // erase an earlier resolver or fabric cancellation.
                current != stop
            },
        );
        assert!(matches!(result, Err(RefusalCode::CancellationInProgress)));
        assert_eq!(node.received_pack_cache().retained_entries(), 0);
    }
    node.shutdown().unwrap();
}

#[test]
fn external_ref_bases_require_current_selected_or_held_scope_and_canonical_payloads() {
    let (_scratch, node) = node_for(GitHashAlgorithm::Sha1);
    let base = b"cold-base";
    let target = b"cold-base!";
    let base_id = node
        .put_git_object(ObjectType::Blob, base.to_vec())
        .unwrap()
        .identity();
    let target_id = node
        .put_git_object(ObjectType::Blob, target.to_vec())
        .unwrap()
        .identity();
    let raw = thin_ref_delta_pack(base_id, base, target);
    let limits = PackLimits::default();
    let pack = read_verified_pack_owned(
        raw.clone(),
        node.object_format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
        64 * 1024 * 1024,
    )
    .unwrap();
    let hint = VerifiedReceivedObject {
        id: target_id,
        kind: ObjectType::Blob,
        bytes: target.len(),
    };
    let authorized = BTreeSet::from([base_id, target_id]);
    let validator = ProductionQuarantineValidator::new(
        &node,
        selected_closure(authorized.clone()),
        limits.clone(),
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    assert!(
        validator
            .restore_received_pack(
                &pack,
                &[hint],
                &BTreeSet::from([target_id]),
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_none()
    );
    let unselected_base = ProductionQuarantineValidator::new(
        &node,
        selected_closure(BTreeSet::from([target_id])),
        limits.clone(),
        ParseLimits::default(),
    )
    .for_received_pack_restoration();
    assert!(
        unselected_base
            .restore_received_pack(
                &pack,
                &[hint],
                &authorized,
                &mut ResolutionBudget::new(),
                &mut || true
            )
            .unwrap()
            .is_none()
    );
    validator
        .restore_received_pack(
            &pack,
            &[hint],
            &authorized,
            &mut ResolutionBudget::new(),
            &mut || true,
        )
        .unwrap()
        .unwrap()
        .commit();
    assert!(
        node.received_pack_cache()
            .try_reuse(&[key(hint)], &limits, true, &mut || true)
            .unwrap()
            .is_none()
    );
    let thin = node
        .received_pack_cache()
        .try_reuse_with_held(
            &[key(hint)],
            &limits,
            true,
            &[(base_id, ObjectType::Blob)],
            &mut || true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(thin.receipt().profile(), "received-pack-thin-v1");
    assert_eq!(thin.into_bytes().unwrap(), raw);
    node.shutdown().unwrap();
}
