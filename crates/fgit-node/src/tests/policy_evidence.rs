//! Native persisted evidence checks, including a real two-decision receive
//! microbatch. These are native regressions, not a transport E2E claim.

use super::*;
use crate::{DurableAdmissionEvidence, LoopbackReceiveSession, read_policy_decision_in};
use fgit_admission::evidence::PolicyDecisionRecord;
use fgit_reference::effect::FoldBasis;
use fgit_reference::intent::{Intent, RefIntent, Statement};
use fgit_reference::refs::ExpectedRefState;
use fgit_types::{HeadGeneration, MismatchPolicy, RootLayoutVersion};

struct EmptyClosure;
impl QuarantineValidator for EmptyClosure {
    fn validate(
        &self,
        _: &ReceiveRequest,
        _: Option<&fgit_pack::QuarantinedPack>,
        _: &QuarantineReceipt,
        _: &mut impl fgit_pack::Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::default())?,
            objects: BTreeSet::new(),
        })
    }
}

fn evidence(record: &fgit_codec::RepositoryCommitRecord) -> CommitEvidence {
    CommitEvidence {
        principal_snapshot_id: record.principal_snapshot_id,
        forge_event_batch_root: record.forge_event_batch_root,
        policy_decision_root: record.policy_decision_root,
        invariant_evidence_root: record.invariant_evidence_root,
        outbox_effect_root: record.outbox_effect_root,
        retention_delta_root: record.retention_delta_root,
    }
}

fn deletion_model(
    context: &AdmissionContext,
    record: &fgit_codec::RepositoryCommitRecord,
    current: &CanonicalRefState,
    name: RefName,
    old: GitOid,
) -> (TransactionRequest, TransactionFoldReport) {
    let request = TransactionRequest {
        tx_id: record.tx_id,
        tenant: context.tenant_id,
        repository: context.repository_id,
        principal: context.principal_id,
        schema: fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        idempotency_key: ModelIdempotencyKey::new(fgit_types::AsciiSlug::from_static("receive")),
        canonical_request_digest: record.canonical_request_digest,
        statements: vec![Statement {
            intents: vec![Intent::Ref(RefIntent::Delete {
                name,
                expected: ExpectedRefState::Exact(old),
            })],
            mismatch_policy: MismatchPolicy::TxnAbort,
        }],
        promised_closure: BTreeSet::new(),
        atomic: false,
        durability: DurabilityProfile::CanonicalSource,
    };
    let fold = fgit_txn::IntentEvaluator::new().evaluate(
        FoldBasis {
            refs: current.refs(),
            forge_positions: &BTreeMap::new(),
            retention: &BTreeSet::new(),
            outbox: &BTreeMap::new(),
        },
        &request,
    );
    (request, fold)
}

#[test]
fn published_policy_evidence_reopens_replays_microbatch_overlays_and_rejects_orphans() {
    for algorithm in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for layout in [
            RootLayoutVersion::LegacyWholeBody,
            RootLayoutVersion::RefStateMerkleV1,
        ] {
            let scratch = ScratchDirectory::new();
            let config = test_config(scratch.path().to_path_buf())
                .with_object_format(algorithm)
                .with_root_layout(layout);
            let (node, _) = OneNode::init(config.clone()).unwrap();
            let authority_request = node.request_context();
            let stored = node
                .put_git_object(ObjectType::Blob, b"policy receipt retained source".to_vec())
                .unwrap();
            let zero =
                GitOid::from_hex(algorithm, &"00".repeat(stored.identity().as_bytes().len()))
                    .unwrap();
            let names = [
                RefName::try_new(b"refs/heads/topic-one").unwrap(),
                RefName::try_new(b"refs/heads/topic-\xff").unwrap(),
            ];
            let objects = BTreeSet::from([stored.identity()]);
            let closure = ValidatedClosure {
                object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                    objects.clone(),
                ))
                .unwrap(),
                objects,
            };
            let updates = names
                .iter()
                .map(|name| SourceRefUpdate {
                    old: zero,
                    new: stored.identity(),
                    ref_name: name.as_bytes().to_vec(),
                })
                .collect::<Vec<_>>();
            let imported = validate_source_import(
                &updates,
                &SourceImportReceipt {
                    object_format: algorithm,
                    object_count: 1,
                    delete_only: false,
                    origin: SourceImportOrigin::LocalGitDirectory,
                },
                closure,
            )
            .unwrap();
            let (mut context, _, _) = evidence_request(&node);
            context.idempotency_key =
                fgit_authority::IdempotencyKey::new(b"policy-evidence-seed".to_vec()).unwrap();
            node.runtime()
                .block_on(node.admit_validated_source_import_durable_in(
                    &authority_request,
                    &context,
                    &imported,
                    AdmissionLimits::default(),
                ))
                .unwrap();
            let before = node
                .runtime()
                .block_on(node.materialize_admission_in(&authority_request))
                .unwrap();
            let basis = before.basis().clone();
            let mut current = CanonicalRefState::new_with_head_target(
                before.snapshot().refs.clone(),
                before.snapshot().head_target.clone().unwrap(),
            )
            .unwrap();

            let receive = ReceiveRequest {
                commands: names
                    .iter()
                    .map(|name| ReceiveCommand {
                        old: stored.identity(),
                        new: zero,
                        ref_name: name.as_bytes().to_vec(),
                    })
                    .collect(),
                capabilities: Vec::new(),
                push_options: Vec::new(),
                certificate: None,
            };
            let validated = validate_receive(
                &receive,
                None,
                &QuarantineReceipt {
                    object_format: algorithm,
                    object_count: 0,
                    pack_bytes: 0,
                    delete_only: true,
                },
                &EmptyClosure,
                &mut || true,
            )
            .unwrap();
            context.idempotency_key =
                fgit_authority::IdempotencyKey::new(b"policy-evidence-delete-batch".to_vec())
                    .unwrap();
            let admitted = node
                .runtime()
                .block_on(node.admit_validated_receive_durable_in(
                    &authority_request,
                    &context,
                    &validated,
                    AdmissionLimits::default(),
                ))
                .unwrap();
            assert_eq!(admitted.commands.len(), 2);
            let after = node
                .runtime()
                .block_on(node.materialize_admission_in(&authority_request))
                .unwrap();
            let batch = node
                .runtime()
                .block_on(read_decision_batch_body_async(
                    &node.authority,
                    authority_request.authority(),
                    after.basis().body().decision_tail_id.unwrap(),
                ))
                .unwrap();
            assert_eq!(
                batch.committed_rcrs.len(),
                2,
                "the real receive driver publishes one two-decision microbatch"
            );

            let mut retained = Vec::new();
            for (index, committed) in batch.committed_rcrs.iter().enumerate() {
                assert_eq!(committed.tx_id, admitted.commands[index].tx_id);
                let (model, fold) = deletion_model(
                    &context,
                    committed,
                    &current,
                    names[index].clone(),
                    stored.identity(),
                );
                let proof = node
                    .runtime()
                    .block_on(node.admission_materializer.read_decision_evidence_in(
                        &node.authority,
                        authority_request.authority(),
                        context.clone(),
                        &basis,
                        &model,
                        &fold,
                        evidence(committed),
                        &|| false,
                    ))
                    .unwrap();
                assert_eq!(
                    proof.commit_evidence(&basis, &model, &fold).unwrap(),
                    evidence(committed)
                );
                let PolicyDecisionRecord::Evaluated(record) = proof.bodies.policy_decision() else {
                    panic!("real ref changes must retain evaluated policy evidence")
                };
                assert_eq!(
                    record.ref_basis_root(),
                    fgit_admission::ref_state_root(layout, &current).unwrap()
                );
                assert_eq!(record.inputs()[0].previous(), Some(&stored.identity()));
                assert!(record.inputs()[0].next().is_none());
                record.replay().unwrap();
                if index == 1 {
                    assert_ne!(
                        record.ref_basis_root(),
                        basis.body().ref_root,
                        "the second decision names the actual accepted first-decision overlay"
                    );
                    let mut orphan_refs = current.refs().clone();
                    orphan_refs.insert(
                        RefName::try_new(b"refs/tags/unpublished").unwrap(),
                        stored.identity(),
                    );
                    let orphan = CanonicalRefState::new_with_head_target(
                        orphan_refs,
                        current.head_target().unwrap().clone(),
                    )
                    .unwrap();
                    node.runtime()
                        .block_on(node.admission_materializer.stage_ref_state_for_layout_in(
                            &node.authority,
                            authority_request.authority(),
                            node.repository_id(),
                            layout,
                            orphan.clone(),
                        ))
                        .unwrap();
                    let forged_bodies = node
                        .runtime()
                        .block_on(
                            fgit_admission::merge::native::protection::direct_decision_evidence_at(
                                &node.authority,
                                authority_request.authority(),
                                &context,
                                &basis,
                                &orphan,
                                layout,
                                &model,
                                &fold,
                                &|| false,
                            ),
                        )
                        .unwrap();
                    node.runtime()
                        .block_on(node.admission_materializer.stage_evidence_bodies_in(
                            &node.authority,
                            authority_request.authority(),
                            &forged_bodies,
                            &|| false,
                        ))
                        .unwrap();
                    let forged = DurableAdmissionEvidence::from_bodies(
                        context.clone(),
                        &basis,
                        &model,
                        forged_bodies,
                    )
                    .unwrap();
                    assert!(matches!(
                        node.runtime().block_on(
                            node.admission_materializer.read_decision_evidence_in(
                                &node.authority,
                                authority_request.authority(),
                                context.clone(),
                                &basis,
                                &model,
                                &fold,
                                forged.commit_evidence_record(),
                                &|| false,
                            )
                        ),
                        Err(AdmissionMaterializationRefusal::CanonicalRoot(
                            RefusalCode::EvidenceInvalid
                        ))
                    ));
                }
                retained.push((
                    model,
                    fold,
                    evidence(committed),
                    proof.bodies.policy_decision().encode().unwrap(),
                ));
                current = current.apply(&fold_effect_delete(&names[index])).unwrap();
            }
            node.shutdown().unwrap();

            let reopened = OneNode::open_existing(config).unwrap();
            let request = reopened.request_context();
            for (model, fold, expected, frame) in retained {
                assert!(matches!(
                    reopened.runtime().block_on(
                        reopened.admission_materializer.read_decision_evidence_in(
                            &reopened.authority,
                            request.authority(),
                            context.clone(),
                            &basis,
                            &model,
                            &fold,
                            expected,
                            &|| true,
                        )
                    ),
                    Err(AdmissionMaterializationRefusal::Cancelled)
                ));
                let proof = reopened
                    .runtime()
                    .block_on(reopened.admission_materializer.read_decision_evidence_in(
                        &reopened.authority,
                        request.authority(),
                        context.clone(),
                        &basis,
                        &model,
                        &fold,
                        expected,
                        &|| false,
                    ))
                    .unwrap();
                assert_eq!(proof.bodies.policy_decision().encode().unwrap(), frame);
                let decoded = reopened
                    .runtime()
                    .block_on(read_policy_decision_in(
                        &reopened.authority,
                        request.authority(),
                        reopened.repository_id(),
                        expected.policy_decision_root,
                        &|| false,
                    ))
                    .unwrap();
                assert_eq!(decoded.encode().unwrap(), frame);
            }
            reopened.shutdown().unwrap();
        }
    }
}

fn fold_effect_delete(name: &RefName) -> BTreeMap<RefName, fgit_reference::effect::RefEffect> {
    BTreeMap::from([(name.clone(), fgit_reference::effect::RefEffect::Delete)])
}

#[test]
fn activated_policy_refuses_legacy_evidence_downgrade_and_accepts_exact_new_receipt() {
    let scratch = ScratchDirectory::new();
    let (mut node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    // Protection administration is a staging write; a bootstrapping cell refuses it.
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let (context, mut model, _) = evidence_request(&node);
    let object = node
        .put_git_object(ObjectType::Blob, b"policy proof subject".to_vec())
        .unwrap();
    model.statements = vec![Statement {
        intents: vec![Intent::Ref(RefIntent::Update {
            name: RefName::try_new(b"refs/tags/topic").unwrap(),
            expected: ExpectedRefState::Absent,
            new: object.identity(),
            force: false,
        })],
        mismatch_policy: MismatchPolicy::TxnAbort,
    }];
    for active in [false, true] {
        if active {
            let before = node
                .runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap();
            let command = fgit_forge::event::protection::ProtectionCommand {
                expected_version: fgit_forge::ExpectedVersion::NewStream,
                expected_epoch: before.basis().body().policy_epoch,
                protection: fgit_forge::event::protection::ReviewProtection {
                    administrators: vec![context.principal_id],
                    branches: Vec::new(),
                    ref_policy: Some(
                        fgit_forge::event::protection::compile_ref_policy(
                            "policy p { default allow }",
                        )
                        .unwrap(),
                    ),
                },
            };
            let session = LoopbackReceiveSession::authenticated(
                context.principal_id,
                fgit_authority::IdempotencyKey::new(b"activate-downgrade-test".to_vec()).unwrap(),
            );
            let (_, outcome) = node
                .runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &request,
                    &session,
                    &command,
                    AdmissionLimits::default(),
                ))
                .unwrap();
            assert!(matches!(
                outcome.outcome,
                fgit_types::DecisionOutcome::Committed { .. }
            ));
        }
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let current = CanonicalRefState::new_with_head_target(
            selected.snapshot().refs.clone(),
            selected.snapshot().head_target.clone().unwrap(),
        )
        .unwrap();
        let fold = fgit_txn::IntentEvaluator::new().evaluate(
            FoldBasis {
                refs: current.refs(),
                forge_positions: &BTreeMap::new(),
                retention: &BTreeSet::new(),
                outbox: &BTreeMap::new(),
            },
            &model,
        );
        let legacy = fgit_admission::evidence::DecisionEvidenceBodies::derive(
            &context,
            selected.basis(),
            &model,
            &fold,
        )
        .unwrap();
        let mut candidates = vec![legacy];
        if active {
            candidates.push(
                node.runtime()
                    .block_on(
                        fgit_admission::merge::native::protection::direct_decision_evidence_at(
                            &node.authority,
                            request.authority(),
                            &context,
                            selected.basis(),
                            &current,
                            selected.root_layout(),
                            &model,
                            &fold,
                            &|| false,
                        ),
                    )
                    .unwrap(),
            );
        }
        for (index, bodies) in candidates.into_iter().enumerate() {
            node.runtime()
                .block_on(node.admission_materializer.stage_evidence_bodies_in(
                    &node.authority,
                    request.authority(),
                    &bodies,
                    &|| false,
                ))
                .unwrap();
            let provider = DurableAdmissionEvidence::from_bodies(
                context.clone(),
                selected.basis(),
                &model,
                bodies,
            )
            .unwrap();
            let observed =
                node.runtime()
                    .block_on(node.admission_materializer.read_decision_evidence_in(
                        &node.authority,
                        request.authority(),
                        context.clone(),
                        selected.basis(),
                        &model,
                        &fold,
                        provider.commit_evidence_record(),
                        &|| false,
                    ));
            if active && index == 0 {
                assert!(matches!(
                    observed,
                    Err(AdmissionMaterializationRefusal::CanonicalRoot(
                        RefusalCode::EvidenceInvalid
                    ))
                ));
            } else {
                observed.unwrap();
            }
        }
    }
    node.shutdown().unwrap();
}
