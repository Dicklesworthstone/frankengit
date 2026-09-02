#![forbid(unsafe_code)]
//! Public-path tests for bounded exact authority-head ancestry proofs.

use core::future::Future;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityHeadAncestryRefusal,
    AuthorityLimits, AuthorityStore, AuthorityVersionToken, CasOutcome, HeadInit, HeadKey,
    HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    authority_head_identity, body_key, initialize_repository,
    read_current_authority_head_descendant, read_current_authority_head_descendant_async,
};
use fgit_codec::{RepositoryAuthorityHeadBody, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
    RepositoryId,
};

fn store(instance: u64) -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance))
}

fn head_key() -> HeadKey {
    HeadKey::new(b"fg/head/v1/ancestry-tests".to_vec()).expect("an admissible head key")
}

const fn repository(marker: u8) -> RepositoryId {
    RepositoryId::from_bytes([marker; 16])
}

fn digest(marker: u8) -> Digest {
    Digest::new(
        IdentityDomain::RepositoryAuthorityHead.algorithm().id(),
        DigestBytes::try_new(&[marker; 32]).expect("a fixed-width digest"),
    )
}

fn head(
    repository_id: RepositoryId,
    generation: u64,
    predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::try_new(generation).expect("a positive generation"),
        predecessor_head_id,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(marker),
        forge_position_root: digest(marker.wrapping_add(1)),
        outcome_index_root: digest(marker.wrapping_add(2)),
        retention_root: digest(marker.wrapping_add(3)),
        outbox_root: digest(marker.wrapping_add(4)),
        configuration_root: digest(marker.wrapping_add(5)),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_id(value: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    authority_head_identity(value).expect("the head has a canonical identity")
}

fn stage_head(store: &MemoryAuthorityStore, value: &RepositoryAuthorityHeadBody) {
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, value)
        .expect("the head has an immutable body key");
    let bytes = encode_body(value).expect("the head encodes");
    assert!(matches!(
        store
            .put_if_absent(&key, &bytes)
            .expect("the immutable write succeeds"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
}

fn initialize(store: &MemoryAuthorityStore, value: &RepositoryAuthorityHeadBody) {
    assert!(matches!(
        initialize_repository(store, &head_key(), value).expect("the head initializes"),
        HeadInit::Created(_)
    ));
}

fn advance(
    store: &MemoryAuthorityStore,
    previous: &RepositoryAuthorityHeadBody,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let next = head(
        previous.repository_id,
        previous.generation.get() + 1,
        Some(head_id(previous)),
        marker,
    );
    stage_head(store, &next);
    let HeadRead::Present(receipt) = store.read_head(&head_key()).expect("the head reads") else {
        panic!("the initialized head must be present");
    };
    assert!(matches!(
        store
            .compare_exchange_head(
                &head_key(),
                receipt.token(),
                next.generation,
                &encode_body(&next).expect("the successor encodes"),
            )
            .expect("the conditional replacement succeeds"),
        CasOutcome::Committed(_)
    ));
    next
}

#[test]
fn exact_current_head_is_a_deterministic_zero_hop_proof() {
    let backing = store(71);
    let genesis = head(repository(0x71), 1, None, 0x11);
    initialize(&backing, &genesis);

    let first = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        0,
    )
    .expect("the current head is its own descendant");
    let second = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        0,
    )
    .expect("the same read remains deterministic");

    assert_eq!(first.head_id(), head_id(&genesis));
    assert_eq!(first.body(), &genesis);
    assert_eq!(first.ancestry().hops(), 0);
    assert_eq!(first.ancestry().ancestor_head_id(), head_id(&genesis));
    assert_eq!(first.ancestry().descendant_head_id(), head_id(&genesis));
    assert_eq!(first.ancestry(), second.ancestry());
    assert_eq!(
        first.ancestry().receipt_id(),
        second.ancestry().receipt_id(),
        "identical authenticated facts must have one receipt identity"
    );
}

#[test]
fn a_two_hop_descendant_binds_the_exact_current_version_token() {
    let backing = store(72);
    let genesis = head(repository(0x72), 1, None, 0x20);
    initialize(&backing, &genesis);
    let second = advance(&backing, &genesis, 0x21);
    let third = advance(&backing, &second, 0x22);

    let current = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        2,
    )
    .expect("the exact predecessor chain reaches genesis");
    let HeadRead::Present(receipt) = backing.read_head(&head_key()).expect("the head reads") else {
        panic!("the head must be present");
    };

    assert_eq!(current.head_id(), head_id(&third));
    assert_eq!(current.ancestry().hops(), 2);
    assert_eq!(current.ancestry().ancestor_generation(), genesis.generation);
    assert_eq!(current.ancestry().descendant_generation(), third.generation);
    assert_eq!(
        current.ancestry().descendant_version_token(),
        receipt.token(),
        "the ancestry result must bind the exact current slot version, not only the body"
    );
}

#[test]
fn equal_generation_does_not_turn_a_fork_into_a_descendant() {
    let backing = store(73);
    let expected = head(repository(0x73), 1, None, 0x31);
    let observed = head(repository(0x73), 1, None, 0x32);
    assert_ne!(head_id(&expected), head_id(&observed));
    initialize(&backing, &observed);

    let refusal = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        expected.repository_id,
        head_id(&expected),
        expected.generation,
        0,
    )
    .expect_err("generation equality alone must not prove ancestry");

    assert_eq!(
        refusal,
        AuthorityHeadAncestryRefusal::NotDescendant {
            expected: Box::new(head_id(&expected)),
            observed: Box::new(head_id(&observed)),
        }
    );
}

#[test]
fn repository_substitution_is_refused_before_history_is_walked() {
    let backing = store(74);
    let observed = head(repository(0x74), 1, None, 0x41);
    let expected = head(repository(0x75), 1, None, 0x42);
    initialize(&backing, &observed);

    let refusal = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        expected.repository_id,
        head_id(&expected),
        expected.generation,
        0,
    )
    .expect_err("a head from another repository must not enter the path");

    assert_eq!(
        refusal,
        AuthorityHeadAncestryRefusal::RepositoryMismatch {
            expected: expected.repository_id,
            observed: observed.repository_id,
        }
    );
}

#[test]
fn a_discontinuous_predecessor_generation_fails_closed() {
    let backing = store(75);
    let ancestor = head(repository(0x76), 1, None, 0x51);
    stage_head(&backing, &ancestor);
    let malformed = head(ancestor.repository_id, 3, Some(head_id(&ancestor)), 0x52);
    initialize(&backing, &malformed);

    let refusal = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        ancestor.repository_id,
        head_id(&ancestor),
        ancestor.generation,
        2,
    )
    .expect_err("a skipped generation must not produce an ancestry receipt");

    assert_eq!(
        refusal,
        AuthorityHeadAncestryRefusal::GenerationDiscontinuity {
            descendant: malformed.generation,
            predecessor: ancestor.generation,
        }
    );
}

#[test]
fn a_non_genesis_head_without_a_predecessor_is_refused() {
    let backing = store(76);
    let missing_ancestor = head(repository(0x77), 1, None, 0x61);
    let malformed = head(missing_ancestor.repository_id, 2, None, 0x62);
    initialize(&backing, &malformed);

    let refusal = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        malformed.repository_id,
        head_id(&missing_ancestor),
        missing_ancestor.generation,
        1,
    )
    .expect_err("a required predecessor cannot be inferred from generation");

    assert_eq!(
        refusal,
        AuthorityHeadAncestryRefusal::MissingPredecessor {
            head_id: Box::new(head_id(&malformed)),
            generation: malformed.generation,
        }
    );
}

#[test]
fn the_explicit_hop_limit_refuses_instead_of_truncating() {
    let backing = store(77);
    let genesis = head(repository(0x78), 1, None, 0x71);
    initialize(&backing, &genesis);
    let second = advance(&backing, &genesis, 0x72);
    let _third = advance(&backing, &second, 0x73);

    let refusal = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        1,
    )
    .expect_err("a short limit must not yield a partial positive proof");

    assert_eq!(
        refusal,
        AuthorityHeadAncestryRefusal::HopLimitExceeded {
            required: 2,
            limit: 1,
        }
    );
}

struct AsyncMirror<'a>(&'a MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncMirror<'_> {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        AuthorityStore::instance_id(self.0)
    }

    fn limits(&self) -> AuthorityLimits {
        AuthorityStore::limits(self.0)
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::put_if_absent(self.0, key, body))
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_immutable(self.0, key))
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::initialize_head(
            self.0, key, generation, body,
        ))
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_head(self.0, key))
    }

    fn compare_exchange_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::compare_exchange_head(
            self.0,
            key,
            expected,
            new_generation,
            new_body,
        ))
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &Self::Context,
        receipt: &fgit_authority::HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::authenticate_head_receipt(self.0, receipt))
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn synchronous_and_asynchronous_surfaces_return_the_same_proof() {
    let backing = store(78);
    let genesis = head(repository(0x79), 1, None, 0x81);
    initialize(&backing, &genesis);
    let second = advance(&backing, &genesis, 0x82);

    let synchronous = read_current_authority_head_descendant(
        &backing,
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        1,
    )
    .expect("the synchronous walk succeeds");
    let asynchronous = block_on(read_current_authority_head_descendant_async(
        &AsyncMirror(&backing),
        &(),
        &head_key(),
        genesis.repository_id,
        head_id(&genesis),
        genesis.generation,
        1,
    ))
    .expect("the asynchronous walk succeeds");

    assert_eq!(synchronous.head_id(), head_id(&second));
    assert_eq!(synchronous.head_id(), asynchronous.head_id());
    assert_eq!(synchronous.body(), asynchronous.body());
    assert_eq!(synchronous.authenticated(), asynchronous.authenticated());
    assert_eq!(synchronous.ancestry(), asynchronous.ancestry());
}
