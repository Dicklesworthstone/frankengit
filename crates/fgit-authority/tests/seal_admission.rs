//! Seal admission: three typed outcomes, and reuse rejected before any seal.

use fgit_authority::{
    AuthorityStore, ExpectedOld, IdempotencyKey, Interleaving, MemoryAuthorityStore, ProposedNew,
    RefCommand, RequestRejection, SealAdmission, SealAttempt, SealFailure, SemanticRequest,
    StoreInstanceId, bind_idempotency_key, read_seal, seal_request,
};
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::RequestRejectionCode;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0x33; 16])
}

fn request(target: &str, new: u8) -> SemanticRequest {
    SemanticRequest::build(
        SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0),
        GitHashAlgorithm::Sha1,
        true,
        vec![RefCommand {
            name: RefName::try_new(target.as_bytes()).expect("an admissible ref name"),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(GitOid::Sha1(GitOidSha1::from_bytes([new; 20]))),
            force: false,
        }],
        Vec::new(),
        Vec::new(),
    )
    .expect("an admissible request")
}

fn attempt(key: &[u8], target: &str, new: u8) -> SealAttempt {
    SealAttempt {
        tenant_id: tenant(),
        repository_id: repository(),
        authenticated_principal_id: principal(),
        idempotency_key: IdempotencyKey::new(key.to_vec()).expect("a bounded key"),
        request: request(target, new),
    }
}

#[test]
fn sealing_twice_yields_one_identity_and_an_identical_retry() {
    let store = store();
    let attempt = attempt(b"key-1", "refs/heads/main", 0xAB);

    let first = seal_request(&store, &attempt).expect("the first seal");
    let second = seal_request(&store, &attempt).expect("the retry");

    assert!(first.is_created(), "the first attempt creates the seal");
    assert!(
        matches!(second, SealAdmission::IdenticalRetry { .. }),
        "a retry continues against the existing seal, observed {second:?}"
    );
    assert_eq!(
        first.tx_id(),
        second.tx_id(),
        "one logical mutation has one identity"
    );
    assert_eq!(
        first.seal_id(),
        second.seal_id(),
        "one seal body has one identity"
    );
}

#[test]
fn a_key_reused_with_a_different_request_is_rejected_before_any_seal() {
    let store = store();
    let original = attempt(b"key-1", "refs/heads/main", 0xAB);
    let usurper = attempt(b"key-1", "refs/heads/main", 0xCD);

    let admitted = seal_request(&store, &original).expect("the first seal");

    let failure = seal_request(&store, &usurper)
        .expect_err("the same key with a different canonical request must be rejected");
    let SealFailure::Rejected(rejection) = failure else {
        panic!("expected a pre-decision rejection, observed {failure:?}");
    };
    let RequestRejection::IdempotencyKeyReuse { bound, attempted } = *rejection;
    assert_eq!(
        bound,
        admitted.tx_id(),
        "the rejection must name the identity the key is already committed to"
    );
    assert_ne!(
        attempted,
        admitted.tx_id(),
        "the two attempts must not have aliased onto one identity"
    );
    assert_eq!(
        rejection.code(),
        RequestRejectionCode::IdempotencyKeyReuse,
        "the rejection uses the pre-seal vocabulary, not a terminal refusal code"
    );
}

#[test]
fn a_rejected_reuse_leaves_no_seal_behind() {
    let store = store();
    let original = attempt(b"key-1", "refs/heads/main", 0xAB);
    let usurper = attempt(b"key-1", "refs/heads/main", 0xCD);
    seal_request(&store, &original).expect("the first seal");

    let usurper_tx_id = usurper.derive().expect("a derivable identity").0;
    let _rejected = seal_request(&store, &usurper);

    assert!(
        read_seal(&store, tenant(), repository(), usurper_tx_id)
            .expect("a readable slot")
            .is_none(),
        "a pre-seal rejection is not repository history and must leave no seal"
    );
    assert!(
        read_seal(
            &store,
            tenant(),
            repository(),
            original.derive().expect("derivable").0
        )
        .expect("a readable slot")
        .is_some(),
        "the original seal must survive the rejected reuse"
    );
}

#[test]
fn the_same_key_in_a_different_repository_is_not_a_reuse() {
    let store = store();
    let here = attempt(b"key-1", "refs/heads/main", 0xAB);
    let mut elsewhere = attempt(b"key-1", "refs/heads/main", 0xAB);
    elsewhere.repository_id = RepositoryId::from_bytes([0x77; 16]);

    seal_request(&store, &here).expect("the first seal");
    let other = seal_request(&store, &elsewhere)
        .expect("an idempotency key is scoped to a repository and principal");
    assert!(other.is_created());
    assert_ne!(
        here.derive().expect("derivable").0,
        elsewhere.derive().expect("derivable").0,
        "the repository is part of the identity"
    );
}

#[test]
fn a_concurrent_double_create_produces_exactly_one_creation() {
    let store = store();
    // Two gateways derive the same identity independently from the same
    // request; the store, not the schedule, decides which one created it.
    let gateways = [
        attempt(b"key-1", "refs/heads/main", 0xAB),
        attempt(b"key-1", "refs/heads/main", 0xAB),
    ];
    let schedule = Interleaving::round_robin(2, 1);

    let mut created = 0_u32;
    let mut retried = 0_u32;
    let mut identities = Vec::new();
    for client in schedule.order() {
        let gateway = &gateways[client.index()];
        match seal_request(&store, gateway).expect("both attempts are admissible") {
            SealAdmission::Created { tx_id, .. } => {
                created += 1;
                identities.push(tx_id);
            }
            SealAdmission::IdenticalRetry { tx_id, .. } => {
                retried += 1;
                identities.push(tx_id);
            }
        }
    }

    assert_eq!(created, 1, "exactly one attempt creates the seal");
    assert_eq!(retried, 1, "the other continues against it");
    assert_eq!(
        identities.first(),
        identities.last(),
        "both gateways derived the same logical identity"
    );
}

#[test]
fn binding_a_key_is_idempotent_for_the_same_identity() {
    let store = store();
    let attempt = attempt(b"key-1", "refs/heads/main", 0xAB);
    let tx_id = attempt.derive().expect("a derivable identity").0;

    let first = bind_idempotency_key(&store, &attempt, tx_id).expect("the first binding");
    let second = bind_idempotency_key(&store, &attempt, tx_id).expect("a repeated binding");

    assert_eq!(first.tx_id(), tx_id);
    assert_eq!(second.tx_id(), tx_id);
    assert!(
        matches!(first, fgit_authority::KeyBinding::Bound(_)),
        "the first use binds"
    );
    assert!(
        matches!(second, fgit_authority::KeyBinding::Retry(_)),
        "the second use is a retry, not a rejection"
    );
}

#[test]
fn a_sealed_transaction_reads_back_with_its_stable_fields() {
    let store = store();
    let attempt = attempt(b"key-1", "refs/heads/main", 0xAB);
    let (tx_id, expected) = attempt.derive().expect("a derivable identity");
    seal_request(&store, &attempt).expect("the seal");

    let stored = read_seal(&store, tenant(), repository(), tx_id)
        .expect("a readable slot")
        .expect("a present seal");
    assert_eq!(stored, expected, "the seal body round-trips exactly");
    assert_eq!(stored.tx_id, tx_id);
    assert_eq!(stored.tenant_id, tenant());
    assert_eq!(stored.repository_id, repository());
    assert_eq!(stored.authenticated_principal_id, principal());
    assert_eq!(
        stored.request_schema,
        SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0)
    );
}

#[test]
fn a_seal_is_not_a_commit() {
    // A seal is durable identity, not an ordering or commit event: sealing
    // publishes nothing and moves no head.
    let store = store();
    let attempt = attempt(b"key-1", "refs/heads/main", 0xAB);
    seal_request(&store, &attempt).expect("the seal");

    let head_key = fgit_authority::HeadKey::new(b"repo/head".to_vec()).expect("an admissible key");
    assert_eq!(
        store.read_head(&head_key).expect("a readable slot"),
        fgit_authority::HeadRead::Absent,
        "sealing must not create or move a repository head"
    );
}
