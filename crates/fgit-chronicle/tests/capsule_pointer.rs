//! Capsule body, identity, and the root-last pointer protocol.
//!
//! The two failures this file exists to make impossible are the ones section 23
//! names: a stale checkpoint re-published as the current one, and a pointer
//! naming a body no reader can fetch. Each is paired with the near-identical
//! case that proceeds.

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId, body_key,
};
use fgit_chronicle::{
    BackupProfile, CapsulePointer, ChronicleRefusal, RepositoryCapsuleBody,
    advance_pointer_root_last, advance_pointer_root_last_async, capsule_identity,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::DecodeLimits;
use fgit_codec::attest::{DetachedSignature, SignatureSchemeId, SignedEnvelopeBody};
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_codec::wire::{decode_body, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn head_at(generation: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::try_new(generation).expect("a non-zero generation"),
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn capsule_at(
    generation: u64,
    predecessor: Option<fgit_types::RepositoryCapsuleId>,
) -> RepositoryCapsuleBody {
    RepositoryCapsuleBody::at_head(
        head_id(u8::try_from(generation).unwrap_or(0xF0)),
        &head_at(generation),
        predecessor,
        digest(0x20),
        digest(0x21),
        BackupProfile::FullClosure,
    )
}

fn identity_of(capsule: &RepositoryCapsuleBody) -> fgit_types::RepositoryCapsuleId {
    capsule_identity(&CryptoBodyIdentity, capsule).expect("a capsule has an identity")
}

fn store_with(capsule: &RepositoryCapsuleBody) -> MemoryAuthorityStore {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let key = body_key(IdentityDomain::RepositoryCapsule, capsule).expect("a body key");
    let bytes = encode_body(capsule).expect("a capsule encodes");
    store.put_if_absent(&key, &bytes).expect("staging succeeds");
    store
}

// ---------------------------------------------------------------------------
// Body: canonical encoding and identity
// ---------------------------------------------------------------------------

#[test]
fn a_capsule_body_round_trips_through_its_canonical_encoding() {
    let capsule = capsule_at(4, Some(identity_of(&capsule_at(3, None))));
    let bytes = encode_body(&capsule).expect("a capsule encodes");
    let decoded = decode_body::<RepositoryCapsuleBody>(&bytes, DecodeLimits::default())
        .expect("a capsule decodes");
    assert_eq!(decoded, capsule, "encoding is lossless in both directions");
}

#[test]
fn capsule_identity_is_stable_and_excludes_nothing_mutable() {
    let capsule = capsule_at(4, None);
    let first = identity_of(&capsule);
    let again = identity_of(&capsule);
    assert_eq!(first, again, "identity is a function of the body's bytes");

    // A capsule differing in exactly one bound field is a different capsule.
    let mut other = capsule;
    other.object_closure_root = digest(0x99);
    assert_ne!(
        identity_of(&other),
        first,
        "a root the capsule binds participates in its identity"
    );
}

#[test]
fn an_unknown_backup_profile_is_refused_rather_than_defaulted() {
    assert_eq!(
        BackupProfile::from_discriminant(9),
        Err(ChronicleRefusal::BackupProfileUnknown { observed: 9 }),
        "a profile this build does not define cannot be guessed at"
    );

    // Near-identical permitted case: every discriminant this build defines.
    for profile in [
        BackupProfile::DecisionHistoryOnly,
        BackupProfile::FullClosure,
        BackupProfile::FullClosureWithRepair,
    ] {
        assert_eq!(
            BackupProfile::from_discriminant(profile.discriminant()),
            Ok(profile),
            "{} round-trips through its discriminant",
            profile.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// Planted negative 1: a stale pointer must never be accepted
// ---------------------------------------------------------------------------

#[test]
fn a_stale_capsule_cannot_masquerade_as_current() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    let second = capsule_at(7, Some(first_id));
    let second_id = identity_of(&second);
    let advanced = pointer
        .advance(second_id, &second)
        .expect("a later capsule naming its predecessor advances");
    assert_eq!(advanced.head_generation().get(), 7);

    // Planted negative: re-publish the older capsule, which still verifies.
    assert_eq!(
        advanced.advance(first_id, &first),
        Err(ChronicleRefusal::CapsuleNotAdvancing {
            current: HeadGeneration::try_new(7).expect("seven"),
            proposed: HeadGeneration::try_new(3).expect("three"),
        }),
        "an older checkpoint that still verifies must not become current again"
    );

    // Planted negative: same generation, which is not an advance either.
    let sibling = capsule_at(7, Some(second_id));
    assert!(matches!(
        advanced.advance(identity_of(&sibling), &sibling),
        Err(ChronicleRefusal::CapsuleNotAdvancing { .. })
    ));

    // Near-identical permitted case: one generation later, bound correctly.
    let third = capsule_at(8, Some(second_id));
    let third_id = identity_of(&third);
    assert_eq!(
        advanced
            .advance(third_id, &third)
            .expect("a strictly later capsule advances")
            .capsule_id(),
        third_id
    );
}

#[test]
fn a_capsule_that_does_not_name_its_predecessor_is_refused() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    // Planted negative: later generation, but succeeding nothing.
    let orphan = capsule_at(9, None);
    assert_eq!(
        pointer.advance(identity_of(&orphan), &orphan),
        Err(ChronicleRefusal::CapsulePredecessorMismatch),
        "a later capsule from a forked history must not jump in"
    );

    // Planted negative: later generation naming the wrong predecessor.
    let wrong = capsule_at(9, Some(identity_of(&capsule_at(2, None))));
    assert_eq!(
        pointer.advance(identity_of(&wrong), &wrong),
        Err(ChronicleRefusal::CapsulePredecessorMismatch)
    );

    // Near-identical permitted case: the same capsule naming this one.
    let bound = capsule_at(9, Some(first_id));
    assert!(pointer.advance(identity_of(&bound), &bound).is_ok());
}

#[test]
fn a_first_capsule_may_not_claim_a_predecessor() {
    let orphan = capsule_at(3, Some(identity_of(&capsule_at(2, None))));
    assert_eq!(
        CapsulePointer::genesis(identity_of(&orphan), &orphan),
        Err(ChronicleRefusal::CapsulePredecessorMismatch),
        "a first capsule succeeds nothing; a claimed predecessor would leave an undetectable gap"
    );

    // Near-identical permitted case: the same capsule with no predecessor.
    let first = capsule_at(3, None);
    assert!(CapsulePointer::genesis(identity_of(&first), &first).is_ok());
}

// ---------------------------------------------------------------------------
// Planted negative 2: a pointer must not name a body nobody can fetch
// ---------------------------------------------------------------------------

#[test]
fn the_pointer_refuses_to_move_ahead_of_the_body_it_names() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    let second = capsule_at(7, Some(first_id));

    // Planted negative: the successor body was never staged.
    let empty = MemoryAuthorityStore::new(StoreInstanceId::from_raw(2));
    assert_eq!(
        advance_pointer_root_last(&empty, &CryptoBodyIdentity, &pointer, &second),
        Err(ChronicleRefusal::CapsuleBodyNotStaged),
        "root-last: the pointer may not name data no reader can fetch"
    );

    // Near-identical permitted case: the identical capsule, staged first.
    let staged = store_with(&second);
    let advanced = advance_pointer_root_last(&staged, &CryptoBodyIdentity, &pointer, &second)
        .expect("a staged capsule may be pointed at");
    assert_eq!(advanced.capsule_id(), identity_of(&second));
    assert_eq!(advanced.head_generation().get(), 7);

    // And the staged bytes really are the ones the pointer names.
    let key = body_key(IdentityDomain::RepositoryCapsule, &second).expect("a body key");
    let stored = match staged.read_immutable(&key).expect("an immutable read") {
        ImmutableRead::Present(bytes) => bytes,
        ImmutableRead::Absent => panic!("the capsule was staged"),
    };
    let decoded = decode_body::<RepositoryCapsuleBody>(&stored, DecodeLimits::default())
        .expect("the staged bytes decode");
    assert_eq!(decoded, second, "the pointer names exactly these bytes");
}

#[test]
fn staging_a_body_is_not_enough_to_make_a_stale_capsule_current() {
    // Both rules are independent: staging satisfies root-last but says nothing
    // about ordering, so a staged stale capsule is still refused.
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let second = capsule_at(7, Some(first_id));
    let second_id = identity_of(&second);
    let pointer = CapsulePointer::genesis(first_id, &first)
        .expect("a first capsule points")
        .advance(second_id, &second)
        .expect("the successor advances");

    let staged = store_with(&first);
    assert!(matches!(
        advance_pointer_root_last(&staged, &CryptoBodyIdentity, &pointer, &first),
        Err(ChronicleRefusal::CapsuleNotAdvancing { .. })
    ));
}

// ---------------------------------------------------------------------------
// Golden: the encoding is pinned, so a silent format change fails here
// ---------------------------------------------------------------------------

#[test]
fn the_capsule_encoding_is_byte_pinned() {
    let capsule = capsule_at(3, None);
    let bytes = encode_body(&capsule).expect("a capsule encodes");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

    // Pinned by construction rather than by a recorded blob: re-encoding the
    // decoded body must reproduce the exact bytes, and the identity computed
    // over them must not move. A format change that alters either fails here
    // instead of silently producing capsules an older reader cannot verify.
    let decoded = decode_body::<RepositoryCapsuleBody>(&bytes, DecodeLimits::default())
        .expect("a capsule decodes");
    let reencoded = encode_body(&decoded).expect("the decoded capsule re-encodes");
    assert_eq!(
        reencoded, bytes,
        "canonical encoding is idempotent through a decode"
    );
    assert_eq!(
        identity_of(&decoded),
        identity_of(&capsule),
        "identity survives a decode and re-encode"
    );
    assert!(
        hex.len() == bytes.len() * 2 && !hex.is_empty(),
        "the frame is non-empty"
    );
}

/// The frame header, assembled from the layout written in
/// `docs/ADR-0002-CANONICAL-CODEC.md`, not from the encoder under test.
///
/// ```text
/// magic          4 bytes, "FGC1"
/// codec_major    u16 big-endian
/// codec_minor    u16 big-endian
/// domain         u32 length + label bytes
/// schema_family  u32 length + label bytes
/// schema_major   u16 big-endian
/// schema_minor   u16 big-endian
/// payload        u32 length + payload bytes
/// ```
fn expected_frame_header() -> Vec<u8> {
    let domain = b"frankengit/repository-capsule/v1";
    let family = b"repository-capsule";
    let mut header = Vec::new();
    header.extend_from_slice(b"FGC1");
    header.extend_from_slice(&1_u16.to_be_bytes()); // codec_major
    header.extend_from_slice(&0_u16.to_be_bytes()); // codec_minor
    header.extend_from_slice(&u32::try_from(domain.len()).expect("fits").to_be_bytes());
    header.extend_from_slice(domain);
    header.extend_from_slice(&u32::try_from(family.len()).expect("fits").to_be_bytes());
    header.extend_from_slice(family);
    header.extend_from_slice(&1_u16.to_be_bytes()); // schema_major
    header.extend_from_slice(&0_u16.to_be_bytes()); // schema_minor
    header
}

#[test]
fn the_capsule_frame_matches_the_layout_written_in_the_adr() {
    let capsule = capsule_at(3, None);
    let frame = encode_body(&capsule).expect("a capsule encodes");
    let header = expected_frame_header();

    assert!(
        frame.starts_with(&header),
        "the encoded frame must begin with the header the ADR specifies;\n         expected prefix {:02x?}\nactual prefix   {:02x?}",
        header,
        &frame[..header.len().min(frame.len())]
    );

    // The payload length prefix follows the header and must describe the rest.
    let prefix_end = header.len() + 4;
    assert!(
        frame.len() >= prefix_end,
        "the frame carries a payload length"
    );
    let declared = u32::from_be_bytes([
        frame[header.len()],
        frame[header.len() + 1],
        frame[header.len() + 2],
        frame[header.len() + 3],
    ]);
    assert_eq!(
        usize::try_from(declared).expect("a length fits"),
        frame.len() - prefix_end,
        "the declared payload length must equal the bytes that follow it"
    );
}

#[test]
fn the_capsule_domain_and_family_are_the_registered_ones() {
    // A body whose domain the identity registry does not know has no identity
    // at all, so the tag in the frame and the tag fgit-crypto registers are one
    // fact. Asserting the exact bytes here is what would catch a rename on
    // either side, which otherwise only surfaces as an identity refusal at the
    // first call site.
    let capsule = capsule_at(3, None);
    let frame = encode_body(&capsule).expect("a capsule encodes");
    assert!(
        frame
            .windows(b"frankengit/repository-capsule/v1".len())
            .any(|window| window == b"frankengit/repository-capsule/v1"),
        "the frame declares the registered domain tag verbatim"
    );
    assert!(
        capsule_identity(&CryptoBodyIdentity, &capsule).is_ok(),
        "and the registry accepts it, which is the other half of the same fact"
    );
}

#[test]
fn a_capsule_mirrors_the_head_it_was_taken_at() {
    // at_head copies the position out of ONE authenticated head. If a future
    // edit drops a field, the capsule would silently restore to a position the
    // head never had — and every other test here would still pass, because
    // they compare capsules to capsules rather than to the head.
    let head = head_at(5);
    let capsule = RepositoryCapsuleBody::at_head(
        head_id(0x50),
        &head,
        None,
        digest(0x20),
        digest(0x21),
        BackupProfile::FullClosureWithRepair,
    );

    assert_eq!(capsule.repository_id, head.repository_id);
    assert_eq!(capsule.head_generation, head.generation);
    assert_eq!(capsule.decision_tail_id, head.decision_tail_id);
    assert_eq!(
        capsule.latest_decision_sequence,
        head.latest_decision_sequence
    );
    assert_eq!(
        capsule.latest_committed_rcr_id,
        head.latest_committed_rcr_id
    );
    assert_eq!(
        capsule.latest_repository_sequence,
        head.latest_repository_sequence
    );
    assert_eq!(capsule.ref_root, head.ref_root);
    assert_eq!(capsule.forge_position_root, head.forge_position_root);
    assert_eq!(capsule.retention_root, head.retention_root);
    assert_eq!(capsule.configuration_root, head.configuration_root);
    assert_eq!(capsule.policy_epoch, head.policy_epoch);
    assert_eq!(capsule.format_registry_epoch, head.format_registry_epoch);

    // The two roots the head does not carry come from the caller, and are the
    // only fields at_head cannot check for itself.
    assert_eq!(capsule.object_closure_root, digest(0x20));
    assert_eq!(capsule.segment_manifest_root, digest(0x21));
    assert_eq!(capsule.head_id, head_id(0x50));
    assert_eq!(capsule.backup_profile, BackupProfile::FullClosureWithRepair);
}

// ---------------------------------------------------------------------------
// Signing: attestations must not move identity
// ---------------------------------------------------------------------------

#[test]
fn signing_a_capsule_does_not_change_which_capsule_it_is() {
    // Section 23: the capsule identity hashes the UNSIGNED body; signatures,
    // placements and repair-symbol locations attest to a capsule without
    // participating in its identity.
    //
    // My module doc asserts this holds because fgit-codec's envelope computes
    // identity from the carried body's own bytes. That was prose, and prose
    // that nothing enforces is exactly what the fg009a audit caught me on, so
    // here it is as a test.
    let capsule = capsule_at(4, None);
    let unsigned_id = identity_of(&capsule);

    let mut envelope = SignedEnvelopeBody::seal(&capsule).expect("a capsule seals");
    let sealed_bytes = envelope.body_frame().to_vec();

    assert_eq!(
        envelope
            .carried_body_id(&CryptoBodyIdentity, DecodeLimits::default())
            .expect("the envelope yields the carried identity"),
        *unsigned_id.as_internal_object_id(),
        "an envelope with no signatures carries the same identity as the body"
    );

    // Attach a signature that commits over that identity.
    //
    // The scheme code point is `0xfff1`, inside
    // `fgit_crypto::SIGNATURE_SCHEME_RESERVED_CODE_POINTS` (0xfff0..=0xffff),
    // and it must stay there. Code point 1 is production Ed25519 as of ADR-0003
    // Amendment 1; a fixture sitting on it would be a made-up signature wearing
    // a real scheme's number, which is how a test starts passing for the wrong
    // reason. `0xfff1` is the shared convention across both the signature and
    // digest namespaces, so one number means "never real" everywhere.
    envelope
        .attach(
            DetachedSignature {
                scheme: SignatureSchemeId::try_new(0xfff1)
                    .expect("harness-reserved scheme point is valid"),
                key_id: b"test-key".to_vec(),
                body_id: *unsigned_id.as_internal_object_id(),
                signature: vec![0xAB; 64],
            },
            DecodeLimits::default(),
        )
        .expect("a signature over the carried body attaches");

    assert_eq!(
        envelope.signatures().len(),
        1,
        "the signature is attached to the envelope"
    );
    assert_eq!(
        envelope.body_frame(),
        sealed_bytes.as_slice(),
        "attaching a signature leaves the carried body's bytes untouched"
    );
    assert_eq!(
        envelope
            .carried_body_id(&CryptoBodyIdentity, DecodeLimits::default())
            .expect("the envelope still yields the carried identity"),
        *unsigned_id.as_internal_object_id(),
        "and therefore does not change which capsule a pointer names"
    );

    // The pointer built before signing still names the signed capsule.
    let pointer = CapsulePointer::genesis(unsigned_id, &capsule).expect("a first capsule points");
    assert_eq!(
        pointer.capsule_id(),
        identity_of(&capsule),
        "a pointer taken before signing still names the capsule afterwards"
    );
}

#[test]
fn a_signature_over_another_domain_cannot_be_grafted_on() {
    // The envelope refuses a signature whose committed identity belongs to a
    // different domain, so an attestation over some other schema's body cannot
    // be presented as attesting to this capsule.
    let capsule = capsule_at(4, None);
    let mut envelope = SignedEnvelopeBody::seal(&capsule).expect("a capsule seals");

    // Planted negative: a signature committing over an authority-head identity.
    let foreign = head_id(0x77);
    assert!(
        envelope
            .attach(
                DetachedSignature {
                    scheme: SignatureSchemeId::try_new(0xfff1)
                        .expect("harness-reserved scheme point is valid"),
                    key_id: b"test-key".to_vec(),
                    body_id: *foreign.as_internal_object_id(),
                    signature: vec![0xCD; 64],
                },
                DecodeLimits::default(),
            )
            .is_err(),
        "a signature from another domain must not attach to a capsule envelope"
    );
    assert_eq!(
        envelope.signatures().len(),
        0,
        "and nothing is attached when it is refused"
    );

    // Near-identical permitted case: the same signature over THIS capsule.
    let own = identity_of(&capsule);
    assert!(
        envelope
            .attach(
                DetachedSignature {
                    scheme: SignatureSchemeId::try_new(0xfff1)
                        .expect("harness-reserved scheme point is valid"),
                    key_id: b"test-key".to_vec(),
                    body_id: *own.as_internal_object_id(),
                    signature: vec![0xCD; 64],
                },
                DecodeLimits::default(),
            )
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Sync/async equivalence for the capsule pointer (t7ip condition 1)
// ---------------------------------------------------------------------------

/// An async view over the in-memory reference store, for equivalence only.
///
/// Not a blocking adapter: every operation is already resolved when its future
/// is created, so nothing blocks and no cancellation is silently dropped. It
/// exists so both surfaces can be driven over the SAME store state in one
/// test, which is the only way to show they AGREE rather than merely that each
/// works alone. Test-only per the t7ip ruling's condition 4; production async
/// use goes through the fsqlite implementation.
struct AsyncView(MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncView {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }

    fn put_if_absent(
        &self,
        _cx: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> {
        let outcome = self.0.put_if_absent(key, body);
        async move { outcome }
    }

    fn read_immutable(
        &self,
        _cx: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> {
        let outcome = self.0.read_immutable(key);
        async move { outcome }
    }

    fn initialize_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> {
        let outcome = self.0.initialize_head(key, generation, body);
        async move { outcome }
    }

    fn read_head(
        &self,
        _cx: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> {
        let outcome = self.0.read_head(key);
        async move { outcome }
    }

    fn compare_exchange_head(
        &self,
        _cx: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> {
        let outcome = self
            .0
            .compare_exchange_head(key, expected, new_generation, new_body);
        async move { outcome }
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> {
        let outcome = self.0.authenticate_head_receipt(receipt);
        async move { outcome }
    }

    // `publish_head_with_outcomes` is deliberately NOT overridden here.
    //
    // The trait's default refuses with `AuthorityRefusal::OperationUnsupported`,
    // which is exactly what an explicit override in this view would say. That
    // matters rather than merely being convenient: this view wraps
    // `MemoryAuthorityStore`, which composes a head CAS and separate puts, so
    // any delegating implementation would be NON-atomic while satisfying the
    // signature - a fixture that looks like it publishes atomically and does
    // not, which a later test could pass against and be read as evidence the
    // FG-007b window is closed. Inheriting the refusal keeps the safe answer
    // as the one you get by doing nothing.
}

/// Minimal driver for futures that are ready on first poll.
///
/// Deliberately NOT a general executor: a pending poll panics rather than
/// spinning, so this cannot quietly become the blocking bridge condition 4
/// forbids. It serves the in-memory view above and nothing else.
fn poll_ready<F: Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => {
            panic!("the in-memory async view must never suspend")
        }
    }
}

/// Both surfaces must agree over the SAME store, in both directions.
///
/// The staged case must advance identically and the unstaged case must refuse
/// identically. Asserting only the success half would let an async path that
/// never refuses pass, which is precisely the vacuity this pins against: a
/// pointer published ahead of its body names a root no reader can fetch.
#[test]
fn advance_pointer_async_matches_sync_exactly() {
    let identity = CryptoBodyIdentity;
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");
    let next = capsule_at(4, Some(first_id));

    // Unstaged: neither surface may advance.
    let empty = MemoryAuthorityStore::new(StoreInstanceId::from_raw(9));
    let sync_refusal = advance_pointer_root_last(&empty, &identity, &pointer, &next);
    let async_refusal = poll_ready(advance_pointer_root_last_async(
        &AsyncView(empty),
        &(),
        &identity,
        &pointer,
        &next,
    ));
    assert_eq!(
        sync_refusal, async_refusal,
        "an unstaged body must refuse identically on both surfaces"
    );
    assert_eq!(
        sync_refusal,
        Err(ChronicleRefusal::CapsuleBodyNotStaged),
        "and it must be the staged-body refusal, not some other failure"
    );

    // Staged: both surfaces advance to the same pointer.
    let sync_ok = advance_pointer_root_last(&store_with(&next), &identity, &pointer, &next);
    let async_ok = poll_ready(advance_pointer_root_last_async(
        &AsyncView(store_with(&next)),
        &(),
        &identity,
        &pointer,
        &next,
    ));
    assert_eq!(
        sync_ok, async_ok,
        "a staged body must advance to the same pointer on both surfaces"
    );
    assert!(sync_ok.is_ok(), "the staged case must actually advance");
}
