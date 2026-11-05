use super::*;
use core::future::{Future, ready};
use std::cell::Cell;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    PutOutcome, StoreInstanceId, body_key, initialize_repository,
};
use fgit_codec::encode_body;
use fgit_crypto::IdentityDomain;
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
};

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
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        ready(self.0.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        ready(self.0.read_immutable(key))
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        ready(self.0.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        ready(self.0.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        token: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        ready(self.0.compare_exchange_head(key, token, generation, body))
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        ready(self.0.authenticate_head_receipt(receipt))
    }
}
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the actual in-memory authority operations are immediately ready"),
    }
}
fn key() -> HeadKey {
    HeadKey::new(b"fg/head/v1/donor-ancestry".to_vec()).unwrap()
}
fn root(marker: u8) -> Digest {
    Digest::new(
        IdentityDomain::RepositoryAuthorityHead.algorithm().id(),
        DigestBytes::try_new(&[marker; 32]).unwrap(),
    )
}
fn head(
    generation: u64,
    previous: Option<RepositoryAuthorityHeadId>,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x51; 16]),
        generation: HeadGeneration::try_new(generation).unwrap(),
        predecessor_head_id: previous,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root(marker),
        forge_position_root: root(marker.wrapping_add(1)),
        outcome_index_root: root(marker.wrapping_add(2)),
        retention_root: root(marker.wrapping_add(3)),
        outbox_root: root(marker.wrapping_add(4)),
        configuration_root: root(marker.wrapping_add(5)),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}
fn fixture(instance: u64) -> (MemoryAuthorityStore, RepositoryAuthorityHeadBody) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(instance));
    let genesis = head(1, None, 1);
    assert!(matches!(
        initialize_repository(&store, &key(), &genesis).unwrap(),
        HeadInit::Created(_)
    ));
    (store, genesis)
}
fn capture(store: &MemoryAuthorityStore) -> HeadReadReceipt {
    let HeadRead::Present(receipt) = store.read_head(&key()).unwrap() else {
        panic!("present initialized head");
    };
    receipt
}
fn advance(
    store: &MemoryAuthorityStore,
    previous: &RepositoryAuthorityHeadBody,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let next = head(
        previous.generation.get() + 1,
        Some(authority_head_identity(previous).unwrap()),
        marker,
    );
    let bytes = encode_body(&next).unwrap();
    let immutable = body_key(IdentityDomain::RepositoryAuthorityHead, &next).unwrap();
    assert!(matches!(
        store.put_if_absent(&immutable, &bytes).unwrap(),
        PutOutcome::Created
    ));
    assert!(matches!(
        store
            .compare_exchange_head(&key(), capture(store).token(), next.generation, &bytes)
            .unwrap(),
        CasOutcome::Committed(_)
    ));
    next
}
fn prove(
    store: &MemoryAuthorityStore,
    captured: &HeadReadReceipt,
    donor: &RepositoryAuthorityHeadBody,
    hops: usize,
) -> Result<AuthorityHeadAncestryReceipt, String> {
    block_on(authenticate(
        &AsyncMirror(store),
        &(),
        captured,
        donor.repository_id,
        DonorHead {
            key: key().as_bytes(),
            generation: donor.generation.get(),
            body: &encode_body(donor).unwrap(),
        },
        hops,
        || Ok(()),
    ))
}

#[test]
fn exact_ancestor_and_current_capture_return_one_bounded_proof() {
    let (store, first) = fixture(701);
    let second = advance(&store, &first, 2);
    let third = advance(&store, &second, 3);
    let captured = capture(&store);
    let proof = prove(&store, &captured, &first, 2).unwrap();
    assert_eq!(proof.hops(), 2);
    assert_eq!(
        proof.ancestor_head_id(),
        authority_head_identity(&first).unwrap()
    );
    assert_eq!(
        proof.descendant_head_id(),
        authority_head_identity(&third).unwrap()
    );
    assert_eq!(proof.descendant_version_token(), captured.token());
    assert_eq!(proof, prove(&store, &captured, &first, 2).unwrap());
    assert_eq!(prove(&store, &captured, &third, 1).unwrap().hops(), 0);
}

#[test]
fn a_newer_current_head_cannot_replace_the_exact_export_capture() {
    let (store, first) = fixture(702);
    let second = advance(&store, &first, 2);
    let captured = capture(&store);
    let _third = advance(&store, &second, 3);
    assert!(
        prove(&store, &captured, &first, 2)
            .unwrap_err()
            .contains("source head moved")
    );
    assert_eq!(
        prove(&store, &capture(&store), &first, 2).unwrap().hops(),
        2
    );
}

#[test]
fn an_identical_head_from_another_store_does_not_substitute_its_version_token() {
    let (store, first) = fixture(703);
    let (other, _) = fixture(704);
    let captured = capture(&store);
    let substituted = capture(&other);
    assert_eq!(captured.body(), substituted.body());
    assert_ne!(captured.token(), substituted.token());
    assert!(
        prove(&store, &substituted, &first, 1)
            .unwrap_err()
            .contains("source head moved")
    );
    assert!(prove(&store, &captured, &first, 1).is_ok());
}

#[test]
fn fork_future_and_short_hop_budget_refuse_without_generation_shortcuts() {
    let (store, first) = fixture(705);
    let second = advance(&store, &first, 2);
    let third = advance(&store, &second, 3);
    let captured = capture(&store);
    let same_generation_fork = head(1, None, 99);
    assert!(prove(&store, &captured, &same_generation_fork, 2).is_err());
    let future = head(4, Some(authority_head_identity(&third).unwrap()), 4);
    assert!(prove(&store, &captured, &future, 4).is_err());
    assert!(prove(&store, &captured, &first, 1).is_err());
    assert!(prove(&store, &captured, &first, 2).is_ok());
}

#[test]
fn malformed_or_misbound_donor_head_refuses_before_it_can_authorize_payloads() {
    let (store, first) = fixture(706);
    let captured = capture(&store);
    let bytes = encode_body(&first).unwrap();
    let slot = key();
    let cases = [
        (
            b"another-slot".as_slice(),
            1,
            bytes.as_slice(),
            first.repository_id,
        ),
        (slot.as_bytes(), 2, bytes.as_slice(), first.repository_id),
        (
            slot.as_bytes(),
            1,
            b"not a canonical head".as_slice(),
            first.repository_id,
        ),
        (
            slot.as_bytes(),
            1,
            bytes.as_slice(),
            RepositoryId::from_bytes([0x52; 16]),
        ),
    ];
    for (slot, generation, body, repository) in cases {
        assert!(
            block_on(authenticate(
                &AsyncMirror(&store),
                &(),
                &captured,
                repository,
                DonorHead {
                    key: slot,
                    generation,
                    body
                },
                1,
                || Ok(())
            ))
            .is_err()
        );
    }
}

#[test]
fn cancellation_before_or_after_the_authority_walk_yields_no_proof() {
    let (store, first) = fixture(707);
    let captured = capture(&store);
    let bytes = encode_body(&first).unwrap();
    for cancel_at in [1, 3] {
        let checkpoints = Cell::new(0);
        let failure = block_on(authenticate(
            &AsyncMirror(&store),
            &(),
            &captured,
            first.repository_id,
            DonorHead {
                key: key().as_bytes(),
                generation: 1,
                body: &bytes,
            },
            1,
            || {
                checkpoints.set(checkpoints.get() + 1);
                if checkpoints.get() == cancel_at {
                    Err("cancelled or expired".into())
                } else {
                    Ok(())
                }
            },
        ))
        .unwrap_err();
        assert!(failure.contains("cancelled or expired"));
        assert_eq!(checkpoints.get(), cancel_at);
    }
}
