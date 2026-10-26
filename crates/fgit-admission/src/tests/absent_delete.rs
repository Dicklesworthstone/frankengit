//! Regression coverage for l6mb through canonical ref-state materialization.
//! These admission fixtures supply already-validated object identities. Wire
//! parsing and the production quarantine handoff are exercised separately.

use fgit_reference::effect::{AbsorptionReason, IntentDisposition};

use super::*;

fn native_oid(format: GitObjectFormat, seed: u8) -> GitOid {
    match format {
        GitObjectFormat::Sha1 => GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([seed; 20])),
        GitObjectFormat::Sha256 => GitOid::Sha256(fgit_types::GitOidSha256::from_bytes([seed; 32])),
    }
}

fn command(format: GitObjectFormat, name: &[u8], old: u8, new: u8) -> ReceiveCommand {
    ReceiveCommand {
        old: native_oid(format, old),
        new: native_oid(format, new),
        ref_name: name.to_vec(),
    }
}

fn receive(
    format: GitObjectFormat,
    commands: Vec<ReceiveCommand>,
    atomic: bool,
) -> ValidatedReceive {
    let mut value = completion(commands, atomic);
    let deletes_only = value.request.deletes_only();
    value.receipt = QuarantineReceipt {
        object_format: format,
        object_count: u32::try_from(value.closure.objects.len()).unwrap(),
        pack_bytes: if deletes_only { 0 } else { 64 },
        delete_only: deletes_only,
    };
    value.closure.object_closure_root =
        permitted_object_closure_root(&PermittedObjectClosure::new(value.closure.objects.clone()))
            .unwrap();
    value
}

fn context_for(format: GitObjectFormat, key: &[u8]) -> AdmissionContext {
    AdmissionContext {
        object_format: format,
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        ..context()
    }
}

fn head(store: &MemoryAuthorityStore, context: &AdmissionContext) -> RepositoryAuthorityHeadBody {
    read_basis(store, &context.head_key)
        .unwrap()
        .0
        .body()
        .clone()
}

fn refs(
    store: &MemoryAuthorityStore,
    staging: &FailOnceCanonicalStore,
    context: &AdmissionContext,
) -> BTreeMap<RefName, GitOid> {
    staging
        .resolve_ref_state(head(store, context).ref_root)
        .unwrap()
        .refs()
        .clone()
}

#[test]
fn absent_delete_lowers_to_an_explicit_identity_noop_and_stays_in_the_seal() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context_for(format, b"mixed-noop");
        let validated = receive(
            format,
            vec![
                command(format, b"refs/heads/absent", 0, 0),
                command(format, b"refs/heads/created", 0, 8),
            ],
            true,
        );
        let plan = plan_session(
            &context,
            &receive_input(&validated),
            AdmissionLimits::default(),
        )
        .expect("the zero pair has defined authority semantics");
        let semantic = &plan.lowered[0].semantic;
        assert_eq!(semantic.ref_commands().len(), 2);
        assert_eq!(
            semantic.ref_commands()[0].expected_old,
            fgit_authority::ExpectedOld::Absent
        );
        assert_eq!(
            semantic.ref_commands()[0].proposed_new,
            fgit_authority::ProposedNew::Delete
        );
        let model = model_request(&context, semantic, plan.tx_ids[0], &validated.closure).unwrap();
        let snapshot = AdmissionSnapshot::default();
        let fold = IntentEvaluator::new().evaluate(snapshot.as_fold_basis(), &model);
        assert_eq!(
            fold.effects().unwrap().refs,
            BTreeMap::from([(
                RefName::try_new(b"refs/heads/created").unwrap(),
                RefEffect::Set(native_oid(format, 8)),
            )])
        );
        assert_eq!(
            fold.mappings[0].disposition,
            IntentDisposition::Absorbed(AbsorptionReason::IdentityEffect)
        );
        assert!(fold.is_total_for(&model));

        let without_noop = receive(
            format,
            vec![command(format, b"refs/heads/created", 0, 8)],
            true,
        );
        let other = plan_session(
            &context,
            &receive_input(&without_noop),
            AdmissionLimits::default(),
        )
        .unwrap();
        assert_ne!(
            plan.tx_ids, other.tx_ids,
            "silently dropping the no-op would change the sealed request"
        );
    }
}

#[test]
fn absent_delete_has_the_same_conditional_identity_for_source_import() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let context = context_for(format, b"source-absent-delete");
        let validated = receive(
            format,
            vec![command(format, b"refs/heads/absent", 0, 0)],
            true,
        );
        let import = validate_source_import(
            &[SourceRefUpdate {
                old: native_oid(format, 0),
                new: native_oid(format, 0),
                ref_name: b"refs/heads/absent".to_vec(),
            }],
            &SourceImportReceipt {
                object_format: format,
                object_count: 0,
                delete_only: true,
                origin: SourceImportOrigin::LocalGitDirectory,
            },
            validated.closure.clone(),
        )
        .unwrap();
        let push_plan = plan_session(
            &context,
            &receive_input(&validated),
            AdmissionLimits::default(),
        )
        .unwrap();
        let import_plan = plan_session(
            &context,
            &source_import_input(&import),
            AdmissionLimits::default(),
        )
        .unwrap();
        assert_eq!(push_plan.tx_ids, import_plan.tx_ids);
        assert_eq!(
            push_plan.lowered[0].semantic,
            import_plan.lowered[0].semantic
        );

        let (store, staging, projection) = canonical_store_with_genesis(&context);
        let before = head(&store, &context).ref_root;
        let admitted = admit_validated_source_import(
            &store,
            &context,
            &import,
            AdmissionLimits::default(),
            &projection,
        )
        .unwrap();
        assert_eq!(admitted.command_statuses(), vec![ReceiveCommandStatus::Ok]);
        assert_eq!(head(&store, &context).ref_root, before);
        assert!(refs(&store, &staging, &context).is_empty());
    }
}

#[test]
fn absent_only_deletes_keep_ref_state_and_recover_the_original_terminal_outcome() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            let context = context_for(format, b"absent-only");
            let (store, staging, projection) = canonical_store_with_genesis(&context);
            let before = head(&store, &context);
            let validated = receive(
                format,
                vec![command(format, b"refs/heads/absent", 0, 0)],
                atomic,
            );
            let plan = plan_session(
                &context,
                &receive_input(&validated),
                AdmissionLimits::default(),
            )
            .unwrap();
            let result = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            )
            .expect("an absent-ref deletion is an admitted no-op");
            assert_eq!(result.command_statuses(), vec![ReceiveCommandStatus::Ok]);
            assert_eq!(head(&store, &context).ref_root, before.ref_root);
            assert!(refs(&store, &staging, &context).is_empty());
            let after = head(&store, &context);

            let seal = fgit_authority::read_seal(
                &store,
                context.tenant_id,
                context.repository_id,
                result.commands[0].tx_id,
            )
            .unwrap()
            .expect("the original request remains sealed");
            assert_eq!(
                seal.canonical_request_digest,
                fgit_authority::canonical_request_digest(&plan.lowered[0].semantic).unwrap()
            );
            let retried = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
            assert_eq!(result, retried);
            assert_eq!(
                head(&store, &context),
                after,
                "a retry cannot publish a second no-op decision"
            );
        }
    }
}

#[test]
fn absent_delete_beside_create_publishes_the_create_atomically_or_per_ref() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            let context = context_for(format, b"absent-and-create");
            let (store, staging, projection) = canonical_store_with_genesis(&context);
            let validated = receive(
                format,
                vec![
                    command(format, b"refs/heads/absent", 0, 0),
                    command(format, b"refs/heads/created", 0, 8),
                ],
                atomic,
            );
            let result = admit_validated_receive(
                &store,
                &context,
                &validated,
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
            assert_eq!(result.command_statuses(), vec![ReceiveCommandStatus::Ok; 2]);
            assert_eq!(result.session.tx_ids.len(), if atomic { 1 } else { 2 });
            assert_eq!(
                refs(&store, &staging, &context),
                BTreeMap::from([(
                    RefName::try_new(b"refs/heads/created").unwrap(),
                    native_oid(format, 8),
                )])
            );
        }
    }
}

#[test]
fn zero_old_cannot_delete_a_present_ref_or_abort_unrelated_non_atomic_commands() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        for atomic in [false, true] {
            let seed = context_for(format, b"seed-present");
            let (store, staging, projection) = canonical_store_with_genesis(&seed);
            admit_validated_receive(
                &store,
                &seed,
                &receive(
                    format,
                    vec![command(format, b"refs/heads/present", 0, 7)],
                    true,
                ),
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
            let context = context_for(format, b"stale-zero-delete");
            let result = admit_validated_receive(
                &store,
                &context,
                &receive(
                    format,
                    vec![
                        command(format, b"refs/heads/present", 0, 0),
                        command(format, b"refs/heads/created", 0, 8),
                    ],
                    atomic,
                ),
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
            assert!(matches!(
                result.commands[0].terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::ExpectedOldRefMismatch,
                    ..
                }
            ));
            let current = refs(&store, &staging, &context);
            assert_eq!(
                current.get(&RefName::try_new(b"refs/heads/present").unwrap()),
                Some(&native_oid(format, 7))
            );
            assert_eq!(
                current.contains_key(&RefName::try_new(b"refs/heads/created").unwrap()),
                !atomic
            );
            if atomic {
                assert_eq!(result.commands[0].terminal, result.commands[1].terminal);
            } else {
                assert_eq!(result.command_statuses()[1], ReceiveCommandStatus::Ok);
            }

            let correct = context_for(format, b"correct-delete");
            let allowed = admit_validated_receive(
                &store,
                &correct,
                &receive(
                    format,
                    vec![command(format, b"refs/heads/present", 7, 0)],
                    atomic,
                ),
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
            assert_eq!(allowed.command_statuses(), vec![ReceiveCommandStatus::Ok]);
            assert!(
                !refs(&store, &staging, &correct)
                    .contains_key(&RefName::try_new(b"refs/heads/present").unwrap())
            );
        }
    }
}

#[test]
fn hidden_absent_and_present_deletes_refuse_before_ref_state_evaluation() {
    for present in [false, true] {
        let format = GitObjectFormat::Sha1;
        let seed = context_for(format, b"seed-hidden");
        let (store, staging, projection) = canonical_store_with_genesis(&seed);
        if present {
            admit_validated_receive(
                &store,
                &seed,
                &receive(
                    format,
                    vec![command(format, b"refs/private/secret", 0, 7)],
                    true,
                ),
                AdmissionLimits::default(),
                &projection,
            )
            .unwrap();
        }
        let mut policy = RefVisibility::new();
        policy
            .push_rule(b"refs/private", &fgit_wire::WireLimits::default())
            .unwrap();
        staging.stage_hidden_ref_policy(head(&store, &seed).configuration_root, policy);
        let before = head(&store, &seed).ref_root;
        let context = context_for(format, b"hidden-zero-delete");
        let result = admit_validated_receive(
            &store,
            &context,
            &receive(
                format,
                vec![command(format, b"refs/private/secret", 0, 0)],
                true,
            ),
            AdmissionLimits::default(),
            &projection,
        )
        .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ));
        assert_eq!(head(&store, &context).ref_root, before);
        assert_eq!(
            result.command_statuses(),
            vec![ReceiveCommandStatus::Rejected {
                message: b"stale info".to_vec()
            }]
        );

        let visible = context_for(format, b"visible-zero-delete");
        let result = admit_validated_receive(
            &store,
            &visible,
            &receive(
                format,
                vec![command(format, b"refs/heads/absent", 0, 0)],
                true,
            ),
            AdmissionLimits::default(),
            &projection,
        )
        .unwrap();
        assert_eq!(result.command_statuses(), vec![ReceiveCommandStatus::Ok]);
    }
}
