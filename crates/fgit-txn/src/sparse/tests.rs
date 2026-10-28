use super::*;

use fgit_reference::effect::{FoldReport, NetEffectFolder, ReferenceFolder};
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, IdempotencyKey, OutboxIntent, RetentionClass,
    Statement,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_types::vocabulary::MismatchPolicy;
use fgit_types::{GitHashAlgorithm, GitOidSha1, GitOidSha256, SchemaFamily, SchemaId};

use crate::{IntentEvaluator, canonical_fold_bytes};

fn oid(format: GitHashAlgorithm, seed: u8) -> GitOid {
    match format {
        GitHashAlgorithm::Sha1 => GitOid::Sha1(GitOidSha1::from_bytes([seed; 20])),
        GitHashAlgorithm::Sha256 => GitOid::Sha256(GitOidSha256::from_bytes([seed; 32])),
    }
}

fn name(value: &str) -> RefName {
    RefName::try_new(value.as_bytes()).unwrap()
}

fn request(statements: Vec<Statement>) -> TransactionRequest {
    let mut mint = IdentityMint::new(0x5eed_0098);
    let mut builder = RequestBuilder::new(
        mint.tenant(),
        mint.repository(),
        mint.principal(),
        SchemaId::new(SchemaFamily::from_static("fgit/sparse-fold-test"), 1, 0),
        IdempotencyKey::new(label("sparse-fold")),
    );
    for statement in statements {
        builder = builder.statement(statement.mismatch_policy, statement.intents);
    }
    builder.build(&mut mint)
}

fn statements(policy: MismatchPolicy, intents: Vec<Intent>) -> Vec<Statement> {
    vec![Statement {
        mismatch_policy: policy,
        intents,
    }]
}

fn update(target: &str, expected: ExpectedRefState, new: GitOid) -> Intent {
    Intent::Ref(RefIntent::Update {
        name: name(target),
        expected,
        new,
        force: false,
    })
}

fn assert_reference(basis: &SparseBasis, request: &TransactionRequest) -> FoldReport {
    let full = ReferenceFolder.fold(basis.as_basis(), request);
    let sparse = IntentEvaluator.evaluate(basis.as_basis(), request);
    assert_eq!(
        sparse, full,
        "complete effects and source attribution differ"
    );
    assert_eq!(
        canonical_fold_bytes(request, &sparse),
        canonical_fold_bytes(request, &full),
        "normal-form bytes or their refusal differ"
    );
    assert!(sparse.is_total_for(request));
    sparse
}

fn fixture(format: GitHashAlgorithm) -> (SparseBasis, Vec<Intent>) {
    let mut mint = IdentityMint::new(0x5eed_0099);
    let first = oid(format, 1);
    let second = oid(format, 2);
    let stream = ForgeStreamId::new(label("active-stream"));
    let exhausted = ForgeStreamId::new(label("exhausted-stream"));
    let present_root = RetentionRoot {
        object: first,
        class: RetentionClass::GraceTombstone,
    };
    let absent_root = RetentionRoot {
        object: second,
        class: RetentionClass::LegalHold,
    };
    let delivery = OutboxDeliveryKey::new(label("bound-delivery"));
    let parameters = mint.digest();
    let changed_parameters = mint.digest();
    let mut basis = SparseBasis::default();
    basis.refs.insert(name("refs/heads/present"), first);
    basis
        .forge_positions
        .insert(stream, ForgeStreamPosition::new(2));
    basis
        .forge_positions
        .insert(exhausted, ForgeStreamPosition::new(u64::MAX));
    basis.retention.insert(present_root);
    basis.outbox.insert(delivery, parameters);
    let append = |stream, position| {
        Intent::Forge(ForgeIntent {
            stream,
            expected_position: ForgeStreamPosition::new(position),
            event: ForgeEventKind::IssueChanged {
                issue: ForgeEntityId::new(label("issue")),
            },
        })
    };
    let intents = vec![
        update("refs/heads/present", ExpectedRefState::Exact(first), second),
        update("refs/heads/present", ExpectedRefState::Any, first),
        update("refs/heads/present", ExpectedRefState::Exact(second), first),
        update("refs/heads/absent", ExpectedRefState::Absent, second),
        Intent::Ref(RefIntent::Delete {
            name: name("refs/heads/present"),
            expected: ExpectedRefState::Any,
        }),
        Intent::Ref(RefIntent::Delete {
            name: name("refs/heads/absent"),
            expected: ExpectedRefState::Absent,
        }),
        append(stream, 2),
        append(stream, 3),
        append(exhausted, u64::MAX),
        append(ForgeStreamId::new(label("new-stream")), 0),
        Intent::Retention(RetentionIntent::AddRoot(present_root)),
        Intent::Retention(RetentionIntent::RemoveRoot(present_root)),
        Intent::Retention(RetentionIntent::AddRoot(absent_root)),
        Intent::Retention(RetentionIntent::RemoveRoot(absent_root)),
        Intent::Outbox(OutboxIntent {
            delivery_key: delivery,
            parameters,
        }),
        Intent::Outbox(OutboxIntent {
            delivery_key: delivery,
            parameters: changed_parameters,
        }),
        Intent::Outbox(OutboxIntent {
            delivery_key: OutboxDeliveryKey::new(label("new-delivery")),
            parameters,
        }),
    ];
    (basis, intents)
}

#[test]
fn all_target_families_match_full_basis_under_ordering_and_mismatch_policies() {
    // Full-basis ReferenceFolder is the independent projection oracle. Two
    // arbitrary operations followed by a repeat expose identity attribution,
    // inverse cancellation, overwrite, read-your-writes, delivery-key reuse,
    // exhausted streams, first abort, and statement-local continuation.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (basis, intents) = fixture(format);
        for left in &intents {
            for right in &intents {
                for policy in MismatchPolicy::ALL {
                    let request = request(vec![
                        Statement {
                            mismatch_policy: *policy,
                            intents: vec![left.clone()],
                        },
                        Statement {
                            mismatch_policy: MismatchPolicy::StatementError,
                            intents: vec![right.clone(), left.clone()],
                        },
                    ]);
                    assert_reference(&basis, &request);
                }
            }
        }
    }
}

#[test]
fn sparse_fold_keeps_the_transition_producer_when_later_intents_restate_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (basis, _) = fixture(format);
        let intent = update("refs/heads/present", ExpectedRefState::Any, oid(format, 2));
        let request = request(statements(
            MismatchPolicy::TxnAbort,
            vec![intent.clone(), intent],
        ));
        let report = assert_reference(&basis, &request);
        assert!(matches!(
            report.mappings[0].disposition,
            fgit_reference::effect::IntentDisposition::Surviving(_)
        ));
        assert_eq!(
            report.mappings[1].disposition,
            fgit_reference::effect::IntentDisposition::Absorbed(
                fgit_reference::effect::AbsorptionReason::IdentityEffect
            )
        );
    }
}

#[test]
fn repository_size_does_not_expand_a_single_ref_fold_footprint() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut basis, _) = fixture(format);
        let mut mint = IdentityMint::new(0x5eed_0100);
        for index in 0..16_384 {
            basis.refs.insert(
                name(&format!("refs/tags/unrelated-{index:05}")),
                oid(format, 8),
            );
            basis.forge_positions.insert(
                ForgeStreamId::new(label(&format!("unrelated-{index:05}"))),
                ForgeStreamPosition::new(u64::MAX),
            );
            basis.outbox.insert(
                OutboxDeliveryKey::new(label(&format!("unrelated-{index:05}"))),
                mint.digest(),
            );
        }
        let request = request(statements(
            MismatchPolicy::TxnAbort,
            vec![update(
                "refs/heads/present",
                ExpectedRefState::Exact(oid(format, 1)),
                oid(format, 2),
            )],
        ));
        let selected = SparseBasis::select(basis.as_basis(), &request);
        assert_eq!(selected.refs.len(), 1);
        assert!(selected.forge_positions.is_empty());
        assert!(selected.retention.is_empty());
        assert!(selected.outbox.is_empty());
        let result = assert_reference(&basis, &request);
        assert_eq!(result.effects().unwrap().target_count(), 1);

        let empty = request_with_no_intents();
        let selected = SparseBasis::select(basis.as_basis(), &empty);
        assert!(selected.refs.is_empty());
        assert!(selected.forge_positions.is_empty());
        assert!(selected.retention.is_empty());
        assert!(selected.outbox.is_empty());
        assert!(
            assert_reference(&basis, &empty)
                .effects()
                .unwrap()
                .is_empty()
        );
    }
}

fn request_with_no_intents() -> TransactionRequest {
    request(statements(MismatchPolicy::TxnAbort, Vec::new()))
}

#[test]
fn atomic_command_envelope_keeps_full_report_and_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut basis, _) = fixture(format);
        let mut intents = Vec::new();
        for index in 0..4096 {
            let target = format!("refs/tags/atomic-{index:05}");
            basis.refs.insert(name(&target), oid(format, 1));
            intents.push(update(
                &target,
                ExpectedRefState::Exact(oid(format, 1)),
                oid(format, 2),
            ));
        }
        let request = request(statements(MismatchPolicy::TxnAbort, intents));
        let result = assert_reference(&basis, &request);
        assert_eq!(result.effects().unwrap().refs.len(), 4096);
    }
}
