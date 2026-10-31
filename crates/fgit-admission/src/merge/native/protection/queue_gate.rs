//! Lower the authority-selected queue predicate into fg043's protected-ref
//! engine. A receipt here is an attempt-local projection of authenticated queue
//! replay, never caller evidence. The exact committed triple remains its durable
//! provenance; generic NativeMerge policy receipts assert no queue privilege.

use super::*;
use crate::merge::native::queue::ValidatedQueueLanding;
use fgit_reference::effect::RefEffect;

pub(super) fn enforce(
    policy: &ReviewProtection,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    effects: &BTreeMap<RefName, RefEffect>,
    principal: Option<PrincipalId>,
    landing: Option<&ValidatedQueueLanding>,
) -> Result<(), ProjectionFailure> {
    for (target, effect) in effects {
        if !policy
            .branch(target)
            .is_some_and(|rule| rule.require_merge_queue)
        {
            continue;
        }
        let mut receipts = Vec::new();
        let instant = fgit_policy::PolicyInstant::from_seconds(0);
        if let Some(landing) = landing {
            landing
                .verify_effect(basis, principal, target, refs.get(target).copied(), effect)
                .map_err(ProjectionFailure::Refuse)?;
            // This deterministic one-evaluation window is not a wall-clock
            // lease. The non-exportable proof already binds the exact basis,
            // actor, old/new tips, queue state and sealed event root, and is
            // re-minted after every CAS miss. No later attempt can reuse it.
            receipts.push(
                fgit_policy::EvidenceReceipt::try_new(
                    fgit_policy::EvidenceKind::try_new(b"merge_queue").map_err(|_| {
                        ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid)
                    })?,
                    fgit_policy::IssuerLabel::try_new(b"native_queue_admission").map_err(|_| {
                        ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid)
                    })?,
                    target.clone(),
                    instant,
                    fgit_policy::PolicyInstant::from_seconds(1),
                )
                .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?,
            );
        }
        let effects = BTreeMap::from([(target.clone(), effect.clone())]);
        let updates = crate::policy_bridge::ref_updates_from_effects(refs, &effects)
            .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
        // The closed rule below observes only the update and merge_queue
        // receipt. Compatibility principal attributes are neither consulted
        // nor offered to the separately enforced installed DSL/auth gate.
        let input = crate::policy_bridge::build_input_root(
            principal.unwrap_or(PrincipalId::from_bytes([0; 16])),
            crate::policy_bridge::default_principal_snapshot_id(),
            updates,
            instant,
        )
        .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
        let input = fgit_policy::PolicyInputRoot::try_new(
            input.principal().clone(),
            input.updates().to_vec(),
            &receipts,
            &[],
            instant,
        )
        .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?;
        let rule = fgit_policy::ProtectedRefRule {
            // The native policy selected this exact byte-oriented target
            // above. A closed universal matcher cannot erase a non-UTF8 name.
            pattern: fgit_policy::RefPattern::compile("**")
                .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?,
            allow_actors: BTreeSet::new(),
            allow_principal_kinds: BTreeSet::new(),
            allow_teams: BTreeSet::new(),
            allow_capabilities: BTreeSet::new(),
            min_authentication: None,
            reviews: None,
            checks: None,
            max_commit_bytes: None,
            durability: None,
            flags: fgit_policy::ProtectionBits::REQUIRE_MERGE_QUEUE
                .with(fgit_policy::ProtectionBits::ALLOW_CREATION)
                .with(fgit_policy::ProtectionBits::ALLOW_DELETIONS)
                .with(fgit_policy::ProtectionBits::ALLOW_FORCE_PUSH),
        };
        let verdict = fgit_policy::evaluate_protected_ref(&[rule], &input, target);
        if !verdict.is_protected || verdict.decision != fgit_policy::Decision::Allow {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_forge::event::protection::ProtectedBranch;
    use fgit_types::GitHashAlgorithm;

    #[test]
    fn exact_queue_rules_cover_creation_update_delete_fanout_and_non_utf8_names() {
        let head = fgit_codec::harness::genesis_head();
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head,
        );
        let principal = PrincipalId::from_bytes([0x31; 16]);
        let topic = RefName::try_new(b"refs/heads/topic").unwrap();
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let old = GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
            let new = GitOid::from_hex(format, &"22".repeat(format.digest_len())).unwrap();
            for target in [
                RefName::try_new(b"refs/heads/main").unwrap(),
                RefName::try_new(b"refs/heads/raw-\xff").unwrap(),
            ] {
                let policy = ReviewProtection {
                    administrators: vec![principal],
                    branches: vec![ProtectedBranch {
                        name: target.clone(),
                        reviewers: Vec::new(),
                        required_approvals: 0,
                        required_checks: Vec::new(),
                        require_merge_queue: true,
                    }],
                    ref_policy: None,
                };
                policy.validate().unwrap();
                for (previous, effect) in [
                    (None, RefEffect::Set(new)),
                    (Some(old), RefEffect::Set(new)),
                    (Some(old), RefEffect::Delete),
                ] {
                    let refs = previous
                        .map(|oid| (target.clone(), oid))
                        .into_iter()
                        .collect();
                    let effects = BTreeMap::from([(target.clone(), effect.clone())]);
                    assert!(matches!(
                        enforce(&policy, &basis, &refs, &effects, Some(principal), None),
                        Err(ProjectionFailure::Refuse(
                            RefusalCode::ProtectedRefTransitionDenied
                        ))
                    ));
                    let fanout = BTreeMap::from([
                        (target.clone(), effect),
                        (topic.clone(), RefEffect::Set(new)),
                    ]);
                    assert!(matches!(
                        enforce(&policy, &basis, &refs, &fanout, Some(principal), None),
                        Err(ProjectionFailure::Refuse(
                            RefusalCode::ProtectedRefTransitionDenied
                        ))
                    ));
                    enforce(
                        &policy,
                        &basis,
                        &refs,
                        &BTreeMap::from([(topic.clone(), RefEffect::Set(new))]),
                        Some(principal),
                        None,
                    )
                    .unwrap();
                    enforce(
                        &policy,
                        &basis,
                        &refs,
                        &BTreeMap::new(),
                        Some(principal),
                        None,
                    )
                    .unwrap();
                }
            }
        }
    }
}
