//! Discussion publication owns only its independent stream and outbox.
use super::*;
use crate::harness::{IdentityMint, RequestBuilder, label};
use crate::intent::{ForgeEntityId, ForgeIntent};
use crate::state::{GenesisConfiguration, PrincipalCapabilities};
use fgit_types::{GitHashAlgorithm, MismatchPolicy, RegistryEpoch, SchemaFamily, SchemaId};

fn fixture(may_publish: bool) -> (RepositoryState, TransactionRequest) {
    let mut mint = IdentityMint::new(95_021);
    let tenant = mint.tenant();
    let repository = mint.repository();
    let principal = mint.principal();
    let schema = SchemaId::new(SchemaFamily::from_static("fgit/txn-test"), 1, 0);
    let mut state = RepositoryState::genesis(GenesisConfiguration {
        tenant,
        repository,
        object_format: GitHashAlgorithm::Sha1,
        genesis_head_id: mint.head(),
        policy: PolicySnapshot {
            epoch: PolicyEpoch::FIRST,
            protected_scopes: BTreeSet::from([b"refs/heads".to_vec()]),
            principals: BTreeMap::from([(
                principal,
                PrincipalCapabilities {
                    may_publish_forge: may_publish,
                    ..PrincipalCapabilities::default()
                },
            )]),
            max_intents_per_transaction: 64,
            supported_schemas: BTreeSet::from([schema]),
            supported_durability: BTreeSet::from([DurabilityProfile::CanonicalSource]),
        },
        format_registry_epoch: RegistryEpoch::FIRST,
    });
    for (stream, version) in [("pull-request/1", 2), ("review/1/reviewer", 3)] {
        state.head.body.roots.forge_positions.insert(
            ForgeStreamId::new(label(stream)),
            ForgeStreamPosition::new(version),
        );
    }
    let request = RequestBuilder::new(
        tenant,
        repository,
        principal,
        schema,
        IdempotencyKey::new(label("discussion-comment")),
    )
    .statement(
        MismatchPolicy::TxnAbort,
        vec![Intent::Forge(ForgeIntent {
            stream: ForgeStreamId::new(label("conversation/1")),
            expected_position: ForgeStreamPosition::GENESIS,
            event: ForgeEventKind::PullRequestCommented {
                conversation: ForgeEntityId::new(label("conversation/1")),
            },
        })],
    )
    .build(&mut mint);
    (state, request)
}

#[test]
fn comment_requires_forge_capability_without_acquiring_ref_authority() {
    let (denied, request) = fixture(false);
    assert_eq!(
        evaluate(&denied, &request).verdict,
        PreparedVerdict::Refuse(RefusalCode::CapabilityScopeViolation)
    );
    let (allowed, request) = fixture(true);
    assert_eq!(named_ref(&request.statements[0].intents[0]), None);
    let PreparedVerdict::Commit(effects) = evaluate(&allowed, &request).verdict else {
        panic!("permitted comment")
    };
    assert!(effects.refs.is_empty() && effects.retention.is_empty());
    assert_eq!(effects.forge.len(), 1);
    assert!(
        effects
            .forge
            .contains_key(&ForgeStreamId::new(label("conversation/1")))
    );
}

#[test]
fn comment_witness_reads_its_own_stream_without_invalidating_pr_or_review_positions() {
    let (state, request) = fixture(true);
    let witness = build_witness(&state, &request, WitnessGranularity::Refined);
    assert!(witness.refs.is_empty());
    assert_eq!(witness.forge_positions.len(), 1);
    assert_eq!(
        witness
            .forge_positions
            .get(&ForgeStreamId::new(label("conversation/1"))),
        Some(&ForgeStreamPosition::GENESIS)
    );
    let mut changed = state.head.body.roots.clone();
    changed.forge_positions.insert(
        ForgeStreamId::new(label("conversation/1")),
        ForgeStreamPosition::new(1),
    );
    assert!(!witness.is_reusable_against(
        &changed,
        state.head.body.generation,
        state.head.body.configuration.epoch
    ));
    assert_eq!(
        evaluate(&state, &request).verdict,
        evaluate(&state, &request).verdict
    );
}
