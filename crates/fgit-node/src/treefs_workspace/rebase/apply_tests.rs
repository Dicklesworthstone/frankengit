//! End-to-end publication through the native rebase API, not a test publisher.
use super::*;
use crate::{MaterializedAdmission, NodeWorkspaceRefusal};
use fgit_admission::AdmissionResult;

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}
fn prepared(node: &OneNode, f: &Fixture, empty: bool) -> (GitOid, Vec<u8>) {
    let mut inputs = rebase_inputs(f);
    if empty {
        inputs.upstream = f.source;
    }
    let artifact = node
        .runtime()
        .block_on(node.prepare_rebase_bundle_in(
            &node.request_context(),
            &topic_ref(),
            &main_ref(),
            inputs,
            &Default::default(),
            None,
            &committer(),
            PreparationLimits::default(),
        ))
        .unwrap();
    let RebasePreparation::Clean(plan) = artifact.outcome else {
        panic!("clean rebase expected");
    };
    (plan.commit, artifact.bundle.unwrap())
}
fn apply(
    node: &OneNode,
    f: &Fixture,
    candidate: GitOid,
    bundle: &[u8],
    key: &[u8],
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.apply_rebase_bundle_durable_in(
        &node.request_context(),
        principal(),
        key,
        &topic_ref(),
        f.source,
        f.target,
        candidate,
        bundle,
    ))
}
fn committed(result: Result<AdmissionResult, NodeWorkspaceRefusal>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.commands.len(), 1);
    assert_eq!(result.session.tx_ids, vec![result.commands[0].tx_id]);
    assert!(
        matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ),
        "{result:?}"
    );
    result
}
fn empty_pack_bundle(format: GitHashAlgorithm, onto: GitOid, candidate: GitOid) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = match format {
        GitHashAlgorithm::Sha1 => fgit_crypto::sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => fgit_crypto::sha256_digest(&pack).to_vec(),
    };
    pack.extend(checksum);
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{onto} onto\n{candidate} refs/heads/topic\n\n",
        format.as_str()
    )
    .into_bytes();
    bundle.extend(pack);
    bundle
}

fn new_bundle_objects(node: &OneNode, format: GitHashAlgorithm, bundle: &[u8]) -> Vec<GitOid> {
    let pack = fgit_pack::read_verified_pack(
        bundle_pack(bundle),
        format,
        &PackLimits::default(),
        &mut || true,
        &fgit_pack::NativeChecksumVerifier,
    )
    .unwrap();
    pack.entries()
        .iter()
        .filter_map(|entry| {
            let kind = match entry.header.kind {
                fgit_pack::EntryKind::Commit => GitObjectKind::Commit,
                fgit_pack::EntryKind::Tree => GitObjectKind::Tree,
                fgit_pack::EntryKind::Blob => GitObjectKind::Blob,
                fgit_pack::EntryKind::Tag => GitObjectKind::Tag,
                _ => panic!("rebase fixture is a no-delta candidate pack"),
            };
            let id = git_object_id(format, kind, &entry.inflated);
            match node.read_git_object(id) {
                Ok(_) => None,
                Err(crate::NodeRefusal::Fabric(error))
                    if matches!(
                        *error,
                        fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent
                    ) =>
                {
                    Some(id)
                }
                other => panic!("unexpected candidate lookup: {other:?}"),
            }
        })
        .collect()
}

fn assert_discarded(node: &OneNode, objects: &[GitOid]) {
    assert!(!objects.is_empty(), "the refusal must exercise new objects");
    for id in objects {
        assert!(
            matches!(node.read_git_object(*id),
            Err(crate::NodeRefusal::Fabric(error))
                if matches!(*error, fgit_object_fabric::fabric::StoreRefusal::ObjectAbsent)),
            "refused candidate object {id} must not be placed"
        );
    }
    assert_eq!(
        fs::read_dir(node.storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
}

fn one_commit_bundle(format: GitHashAlgorithm, onto: GitOid, body: Vec<u8>) -> (GitOid, Vec<u8>) {
    use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
    struct Source(CanonicalPackObject);
    impl CanonicalObjectSource for Source {
        fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
            if *id == self.0.id() {
                Ok(self.0.clone())
            } else {
                Err(PackWriteError::MissingCanonicalObject(*id))
            }
        }
    }
    let id = git_object_id(format, GitObjectKind::Commit, &body);
    let source = Source(CanonicalPackObject::new(
        id,
        fgit_git_object::ObjectType::Commit,
        body,
        Vec::new(),
        0,
        0,
    ));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[id], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{onto} onto\n{id} refs/heads/topic\n\n",
        format.as_str()
    )
    .into_bytes();
    bundle.extend(pack);
    (id, bundle)
}

#[test]
fn reviewed_series_publishes_atomically_and_recovers_after_reopen_without_serving_or_quota() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, false);
        let result = committed(apply(&node, &f, candidate, &bundle, b"native-rebase"));
        let after = snapshot(&node);
        assert_eq!(after.snapshot().refs[&topic_ref()], candidate);
        assert_eq!(after.snapshot().refs[&main_ref()], f.target);
        assert_eq!(after.snapshot().outbox, before.snapshot().outbox);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_eq!(
            apply(&node, &f, candidate, &bundle, b"native-rebase").unwrap(),
            result
        );
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.push_quota.limit.max_events = 0;
        assert_eq!(
            apply(&reopened, &f, candidate, &bundle, b"native-rebase").unwrap(),
            result
        );
        // A historical terminal retry succeeds, while a new request cannot
        // use that path to bypass a stopped cell or exhausted intake quota.
        assert!(apply(&reopened, &f, candidate, &bundle, b"new-attempt").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn zero_commit_rebase_uses_the_source_lease_and_preserves_the_workspace_contract() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, true);
        assert_eq!(candidate, f.target);
        let request = node.request_context();
        assert!(
            node.runtime()
                .block_on(node.apply_workspace_bundle_durable_in(
                    &request,
                    principal(),
                    b"not-a-workspace",
                    &topic_ref(),
                    f.source,
                    candidate,
                    &bundle,
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        let result = committed(apply(&node, &f, candidate, &bundle, b"empty-rebase"));
        assert_eq!(snapshot(&node).snapshot().refs[&topic_ref()], f.target);
        assert_eq!(
            apply(&node, &f, candidate, &bundle, b"empty-rebase").unwrap(),
            result
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn changed_source_has_one_recoverable_refusal_and_cannot_overwrite_the_branch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let (candidate, bundle) = prepared(&node, &f, false);
        let unpublished = new_bundle_objects(&node, format, &bundle);
        assert!(unpublished.contains(&candidate));
        let command = fgit_authority::RefCommand {
            name: topic_ref(),
            expected_old: fgit_authority::ExpectedOld::Exactly(f.source),
            proposed_new: fgit_authority::ProposedNew::Update(f.advanced),
            force: false,
        };
        let session = crate::LoopbackReceiveSession::authenticated(
            principal(),
            fgit_authority::IdempotencyKey::new(b"move-source".to_vec()).unwrap(),
        );
        node.runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session,
                &[command],
                Default::default(),
            ))
            .unwrap();
        let before = snapshot(&node);
        assert_eq!(before.snapshot().refs[&topic_ref()], f.advanced);
        let refused = apply(&node, &f, candidate, &bundle, b"stale-rebase").unwrap();
        assert!(matches!(
            refused.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: fgit_types::RefusalCode::ExpectedOldRefMismatch,
                ..
            }
        ));
        assert_eq!(snapshot(&node).snapshot().refs, before.snapshot().refs);
        let terminal_head = snapshot(&node).basis().id();
        assert_eq!(
            apply(&node, &f, candidate, &bundle, b"stale-rebase").unwrap(),
            refused
        );
        assert_eq!(snapshot(&node).basis().id(), terminal_head);
        assert_discarded(&node, &unpublished);
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_mismatched_non_linear_and_cancelled_artifacts_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let (candidate, bundle) = prepared(&node, &f, false);
        let unpublished = new_bundle_objects(&node, format, &bundle);
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(apply(&node, &f, candidate, &corrupt, b"corrupt").is_err());
        assert!(apply(&node, &f, f.source, &bundle, b"wrong-candidate").is_err());
        let wrong_onto =
            String::from_utf8_lossy(&bundle[..bundle.len() - bundle_pack(&bundle).len()])
                .replace(&format!("-{} ", f.target), &format!("-{} ", f.base))
                .into_bytes();
        let wrong_onto = [wrong_onto, bundle_pack(&bundle).to_vec()].concat();
        assert!(apply(&node, &f, candidate, &wrong_onto, b"wrong-onto").is_err());
        let unrelated = empty_pack_bundle(format, f.target, f.source);
        assert!(apply(&node, &f, f.source, &unrelated, b"unrelated").is_err());
        let request = node.request_context();
        request.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.apply_rebase_bundle_durable_in(
                    &request,
                    principal(),
                    b"cancel",
                    &topic_ref(),
                    f.source,
                    f.target,
                    candidate,
                    &bundle
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        assert_discarded(&node, &unpublished);
        // Refusal twins use the same real artifact and node as the permitted case.
        committed(apply(&node, &f, candidate, &bundle, b"permitted"));
        for id in &unpublished {
            node.read_git_object(*id).unwrap();
        }
        assert_eq!(
            fs::read_dir(node.storage_root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        let committed_head = snapshot(&node).basis().id();
        let empty = empty_pack_bundle(format, f.target, f.target);
        assert!(apply(&node, &f, f.target, &empty, b"permitted").is_err());
        assert_eq!(snapshot(&node).basis().id(), committed_head);
        node.shutdown().unwrap();
    }
}

#[test]
fn multi_parent_rebase_is_discarded_after_quarantine_and_linear_twin_still_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let before = snapshot(&node);
        let target = node.read_git_object(f.target).unwrap();
        let tree_line = target
            .payload()
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap();
        assert!(tree_line.starts_with(b"tree "));
        let mut body = tree_line.to_vec();
        body.extend(format!(
            "\nparent {}\nparent {}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nnot a linear replay\n",
            f.target, f.source,
        ).as_bytes());
        drop(target);
        let (nonlinear, bundle) = one_commit_bundle(format, f.target, body);
        for key in [b"nonlinear-first".as_slice(), b"nonlinear-again"] {
            assert!(matches!(
                apply(&node, &f, nonlinear, &bundle, key),
                Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                    "rebase publication accepts only a single-parent series"
                ))
            ));
            assert_eq!(snapshot(&node).basis(), before.basis());
            assert_discarded(&node, &[nonlinear]);
        }
        let (candidate, permitted) = prepared(&node, &f, false);
        committed(apply(&node, &f, candidate, &permitted, b"linear-twin"));
        assert_eq!(snapshot(&node).snapshot().refs[&topic_ref()], candidate);
        assert_discarded(&node, &[nonlinear]);
        node.shutdown().unwrap();
    }
}
