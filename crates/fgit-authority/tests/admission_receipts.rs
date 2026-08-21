//! Admission receipts: recorded once, inherited by every retry.

use fgit_authority::{
    AdmissionInstant, AdmissionReceiptBody, ExpectedOld, IdempotencyKey, MemoryAuthorityStore,
    ProposedNew, RefCommand, SealAttempt, SemanticRequest, StoreInstanceId, read_admission,
    record_admission, seal_request,
};
use fgit_types::identity::{PrincipalId, RepositoryId, TenantId, TransactionSealId};
use fgit_types::label::{AsciiSlug, SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::PolicyEpoch;
use fgit_types::refs::RefName;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn attempt() -> SealAttempt {
    SealAttempt {
        tenant_id: TenantId::from_bytes([0x11; 16]),
        repository_id: RepositoryId::from_bytes([0x22; 16]),
        authenticated_principal_id: PrincipalId::from_bytes([0x33; 16]),
        idempotency_key: IdempotencyKey::new(b"key-1".to_vec()).expect("a bounded key"),
        request: SemanticRequest::build(
            SchemaId::new(SchemaFamily::from_static("receive-pack"), 1, 0),
            GitHashAlgorithm::Sha1,
            true,
            vec![RefCommand {
                name: RefName::try_new(b"refs/heads/main").expect("an admissible ref name"),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(GitOid::Sha1(GitOidSha1::from_bytes([0xAB; 20]))),
                force: false,
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("an admissible request"),
    }
}

fn receipt(
    seal_id: TransactionSealId,
    capability: &'static str,
    epoch: u64,
    issuer: u8,
    instant: u64,
) -> AdmissionReceiptBody {
    AdmissionReceiptBody {
        seal_id,
        admission_capability: AsciiSlug::from_static(capability),
        policy_epoch: PolicyEpoch::try_new(epoch).expect("a positive epoch"),
        issuer: PrincipalId::from_bytes([issuer; 16]),
        first_seen: AdmissionInstant::from_raw(instant),
    }
}

#[test]
fn the_first_admission_is_recorded() {
    let store = store();
    let seal_id = seal_request(&store, &attempt())
        .expect("the seal")
        .seal_id();

    let outcome = record_admission(&store, &receipt(seal_id, "push.write", 1, 0x44, 100))
        .expect("the first admission");
    assert!(outcome.is_first());
    assert_eq!(
        outcome.receipt().first_seen,
        AdmissionInstant::from_raw(100)
    );
    assert_eq!(outcome.receipt().seal_id, seal_id);
}

#[test]
fn a_retry_inherits_the_first_admission_rather_than_regenerating_it() {
    let store = store();
    let seal_id = seal_request(&store, &attempt())
        .expect("the seal")
        .seal_id();
    record_admission(&store, &receipt(seal_id, "push.write", 1, 0x44, 100))
        .expect("the first admission");

    // The retry arrives later, under a different capability, in a later policy
    // epoch, from a different issuer. None of that may overwrite the record.
    let outcome = record_admission(&store, &receipt(seal_id, "push.force", 7, 0x99, 900))
        .expect("a retry must not fail");

    assert!(
        !outcome.is_first(),
        "the retry did not record the admission"
    );
    let inherited = outcome.receipt();
    assert_eq!(
        inherited.first_seen,
        AdmissionInstant::from_raw(100),
        "first-seen must stay the first admission's, not the retry's"
    );
    assert_eq!(
        inherited.admission_capability,
        AsciiSlug::from_static("push.write"),
        "the capability must stay the one the request was admitted under"
    );
    assert_eq!(
        inherited.policy_epoch,
        PolicyEpoch::try_new(1).expect("positive"),
        "the pinned policy epoch must not drift forward on retry"
    );
    assert_eq!(inherited.issuer, PrincipalId::from_bytes([0x44; 16]));
}

#[test]
fn a_byte_identical_readmission_is_still_not_a_first_admission() {
    let store = store();
    let seal_id = seal_request(&store, &attempt())
        .expect("the seal")
        .seal_id();
    let same = receipt(seal_id, "push.write", 1, 0x44, 100);
    record_admission(&store, &same).expect("the first admission");

    let outcome = record_admission(&store, &same).expect("an identical readmission");
    assert!(
        !outcome.is_first(),
        "only one attempt may claim to have admitted the transaction"
    );
    assert_eq!(outcome.receipt(), &same);
}

#[test]
fn admission_is_separate_from_the_seal() {
    // A seal can exist with no admission record: they are separate immutable
    // objects, and the seal is durable identity rather than an admission.
    let store = store();
    let seal_id = seal_request(&store, &attempt())
        .expect("the seal")
        .seal_id();
    assert!(
        read_admission(&store, seal_id)
            .expect("a readable slot")
            .is_none(),
        "sealing must not fabricate an admission record"
    );

    record_admission(&store, &receipt(seal_id, "push.write", 1, 0x44, 100)).expect("admission");
    assert!(
        read_admission(&store, seal_id)
            .expect("a readable slot")
            .is_some()
    );
}

#[test]
fn two_seals_have_independent_admission_records() {
    let store = store();
    let first = attempt();
    let mut second = attempt();
    second.idempotency_key = IdempotencyKey::new(b"key-2".to_vec()).expect("a bounded key");

    let first_seal = seal_request(&store, &first)
        .expect("the first seal")
        .seal_id();
    let second_seal = seal_request(&store, &second)
        .expect("the second seal")
        .seal_id();
    assert_ne!(
        first_seal, second_seal,
        "different idempotency keys are different logical mutations"
    );

    record_admission(&store, &receipt(first_seal, "push.write", 1, 0x44, 100)).expect("first");
    let second_outcome =
        record_admission(&store, &receipt(second_seal, "push.force", 2, 0x55, 200))
            .expect("second");
    assert!(
        second_outcome.is_first(),
        "one seal's admission must not occupy another's slot"
    );
    assert_eq!(
        second_outcome.receipt().first_seen,
        AdmissionInstant::from_raw(200)
    );
}

#[test]
fn a_receipt_carries_the_admission_receipt_domain() {
    let store = store();
    let seal_id = seal_request(&store, &attempt())
        .expect("the seal")
        .seal_id();
    let body = receipt(seal_id, "push.write", 1, 0x44, 100);
    let identity = body.identity().expect("a derivable identity");
    assert_eq!(
        identity.as_internal_object_id().domain().as_str(),
        "frankengit/admission-receipt/v1",
        "an admission receipt must not be forgeable as another domain's body"
    );
}
