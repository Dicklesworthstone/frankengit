#![forbid(unsafe_code)]
//! FG-021b: an independent adversary against the object fabric's fault behaviour.
//!
//! These tests are written by a different agent than the fabric, and they
//! deliberately attack through the **public** surface only: no reach into
//! `fgit_object_fabric` internals, no edits to its `src`. What they attack is
//! the property the fabric's own documentation claims and that a storage layer
//! is easiest to get wrong under fault — that a failed operation is *reported*
//! as failed, and that nothing it left behind is quietly promoted to something
//! stronger than it earned.
//!
//! # The three confusions this file exists to prevent
//!
//! **Existence is not visibility, and visibility is not durability.**
//! AGENTS.md §5.4 requires staged, visible, and durable to stay distinct. The
//! reference fabric inserts an object and *then* checks its
//! `AfterObjectInsert` fault point, so a fault there leaves the object present
//! while the caller is told the write failed. That is legitimate for a
//! content-addressed immutable store — the bytes were verified before insert —
//! but only while the object never claims more than `staged`. The moment a
//! post-fault object reports `visible` or `durable`, a caller can read a
//! publication guarantee out of a write that failed.
//!
//! **A failed write must not leave a committed obligation.** The placement path
//! reserves against a caller-supplied [`ObligationLedger`], and every fault
//! branch settles that reservation as an *abort*, not a commit. If a fault
//! path ever committed instead, the resource ledger would record work the
//! system never performed — and the acceptance line for this bead is that
//! obligation debt matches the injected backlog exactly, which is only
//! checkable because `fgit-resource` refuses to let an obligation vanish.
//!
//! **A refusal must be typed, not silent.** Every fault class below asserts a
//! specific [`StoreRefusal`] variant. Asserting merely `is_err()` would pass
//! against a fabric that refused everything for the wrong reason, which is the
//! failure mode an adversarial suite is supposed to catch rather than exhibit.
//!
//! # Non-claims
//!
//! `ReferenceMemoryFabric` is explicitly non-durable and its own docs say so.
//! Nothing here is evidence about a durable placement profile, media loss, or
//! replication. These are drills against the *reference* backend's fault
//! algebra; a durable backend owes the same properties and its own campaign.

use asupersync::Outcome;
use asupersync::runtime::{Runtime, RuntimeConfig};
use asupersync::types::Budget;
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, ImmutableObjectFabric, ManifestLimits,
    ObjectRange, PlacementAdmission, PlacementBackend, PutIfAbsent, ReferenceFaultPoint,
    RetentionRootProposal, RuntimeImmutableObjectFabric, StoreRefusal, VerifiedObject,
    VerifiedStreamBudget,
};
use fgit_object_fabric::fabric::{PlacementReceipt, SegmentManifest};
use fgit_object_fabric::reference::{ReferenceMemoryConfig, ReferenceMemoryFabric};
use fgit_object_fabric::{CryptoDigest, DigestAlgorithm, ObjectEnvelope, ObjectKind};
use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{LeakDisposition, ObligationLedger};
use fgit_resource::{OpaqueHandle, RegionId};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1,
    PublicationEpoch, RepositoryAuthorityHeadId,
};

const NAMESPACE: &[u8] = b"fg021b-adversary";

/// The REAL native Git identity of a payload.
///
/// The first version of this fixture invented an identity (`[n; 20]`) and the
/// fabric refused every object with `NativeObjectIdentityMismatch` — correctly.
/// `VerifiedObject::new` recomputes the native id from the bytes, so an
/// identity is not something a test gets to assert. Deriving it here is not a
/// workaround; it is the property under test holding.
fn oid_for(payload: &[u8]) -> GitOid {
    fgit_crypto::git_object_id(
        fgit_crypto::GitObjectFormat::Sha1,
        fgit_crypto::GitObjectKind::Blob,
        payload,
    )
}

fn handle(bytes: &[u8]) -> OpaqueHandle {
    OpaqueHandle::new(bytes).expect("fixture handle must be bounded")
}

/// A verified object whose bytes genuinely match their envelope.
///
/// Built through the same public constructor production callers use, so a
/// rejection below is about the fault under test rather than a malformed
/// fixture.
fn verified(payload: &[u8]) -> VerifiedObject {
    VerifiedObject::new(envelope_for(payload, oid_for(payload)), payload.to_vec())
        .expect("fixture object must verify")
}

/// Build an envelope claiming `claimed_identity` for `payload`.
///
/// An envelope may claim any identity — the refusal happens one layer up, in
/// `VerifiedObject::new`, which recomputes the native id from the bytes. That
/// split is what lets a test claim a false identity and watch the object type
/// refuse it, so this helper deliberately does not validate the claim.
fn envelope_for(payload: &[u8], claimed_identity: GitOid) -> ObjectEnvelope {
    let digest = CryptoDigest;
    let commitment = digest
        .payload_commitment(ObjectKind::Blob, payload)
        .expect("fixture commitment must be available");
    ObjectEnvelope::new(
        NAMESPACE.to_vec(),
        claimed_identity,
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture length must fit u64"),
        commitment,
        b"raw".to_vec(),
        [7; 32],
        None,
        &Default::default(),
    )
    .expect("an envelope may claim any identity, so this must build")
}

fn fabric(fault: Option<ReferenceFaultPoint>) -> ReferenceMemoryFabric {
    let config = ReferenceMemoryConfig::new(
        NAMESPACE.to_vec(),
        handle(b"failure-domain-a"),
        handle(b"encryption-dependency"),
        1 << 20,
        ManifestLimits::default(),
    )
    .expect("reference config must be valid");
    let config = match fault {
        Some(point) => config.with_fault_injection(point),
        None => config,
    };
    ReferenceMemoryFabric::open(config).expect("reference fabric must open")
}

/// A root ledger with enough budget for the drills below.
fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Bytes, 1 << 20).with(Grade::Objects, 64),
    )
}

/// Close the ledger and require its own terminal verdict to be quiescent.
///
/// This replaced an earlier `outstanding().is_empty()` check, and the reason is
/// the better assertion: `close()` is the resource crate's *terminal* verdict,
/// and it is the only thing that distinguishes "nothing outstanding right now"
/// from "every obligation reached a terminal state and the region settled".
///
/// It is also mandatory. An `ObligationLedger` dropped without `close()` is
/// itself a leak — `ledger_dropped_without_close` — and under
/// `LeakDisposition::FailFast` it raises. The first version of this suite
/// dropped every ledger and every drill failed inside `fgit-resource` rather
/// than in the fabric. That guard doing its job is why these tests now assert
/// the right thing.
fn close_quiescent(ledger: ObligationLedger) {
    let outcome = ledger.close();
    assert!(
        outcome.is_quiescent(),
        "the ledger must settle every obligation the drill opened: {outcome:?}"
    );
}

fn admission(ledger: &ObligationLedger) -> PlacementAdmission<'_> {
    let grant = ledger
        .grant(ResourceVector::single(Grade::Bytes, 4096).with(Grade::Objects, 1))
        .expect("ledger must issue the placement grant");
    PlacementAdmission::new(ledger, grant)
}

#[test]
fn a_fault_before_the_write_refuses_and_stores_nothing() {
    // The unambiguous half: the write never happened, so nothing is present
    // and the caller is told so with the exact fault point.
    let store = fabric(Some(ReferenceFaultPoint::BeforeObjectInsert));
    let ledger = ledger();

    let refusal = store
        .put_if_absent(verified(b"payload-one"), admission(&ledger))
        .expect_err("an injected pre-write fault must refuse");

    assert_eq!(
        refusal,
        StoreRefusal::ReferenceFaultInjected {
            point: ReferenceFaultPoint::BeforeObjectInsert
        },
        "the refusal must name the fault point, not merely be an error"
    );
    assert_eq!(
        store
            .read_whole(oid_for(b"payload-one"))
            .expect_err("nothing was written"),
        StoreRefusal::ObjectAbsent,
        "a pre-write fault must leave no trace"
    );

    close_quiescent(ledger);
}

#[test]
fn a_fault_after_the_write_refuses_and_never_claims_visibility() {
    // The ambiguous half, and the one that matters. The fabric inserts and
    // THEN faults, so the object is present while the caller was told the
    // write failed. That is acceptable for a content-addressed store only
    // while the object claims nothing beyond `staged` — AGENTS.md §5.4.
    let store = fabric(Some(ReferenceFaultPoint::AfterObjectInsert));
    let ledger = ledger();

    let refusal = store
        .put_if_absent(verified(b"payload-two"), admission(&ledger))
        .expect_err("an injected post-write fault must still refuse");
    assert_eq!(
        refusal,
        StoreRefusal::ReferenceFaultInjected {
            point: ReferenceFaultPoint::AfterObjectInsert
        }
    );

    // The object may well be readable — it was verified before insertion, and
    // a content-addressed store loses nothing by serving verified bytes. What
    // it must never do is report a publication epoch the failed write did not
    // earn.
    //
    // `read_whole` deliberately exposes no epochs, so the observable channel is
    // a retry: the `AlreadyPresent` branch runs BEFORE the fault check, which
    // means the same faulted fabric will tell us exactly what the failed write
    // left behind.
    let retry = store
        .put_if_absent(verified(b"payload-two"), admission(&ledger))
        .expect("a retry observes what the failed write left, rather than re-faulting");

    match retry {
        PutIfAbsent::AlreadyPresent { epochs, .. } => {
            assert!(
                epochs.contains(PublicationEpoch::Staged),
                "the object the failed write left behind is staged"
            );
            assert!(
                !epochs.contains(PublicationEpoch::Visible),
                "a write that FAILED must never leave a canonically visible object"
            );
            assert!(
                !epochs.contains(PublicationEpoch::Durable),
                "a write that FAILED must never leave a durable object"
            );
        }
        PutIfAbsent::Created { .. } => panic!(
            "the failed write left nothing at all, so the post-insert fault point is unreachable \
             and this drill proves nothing — check the fault ordering"
        ),
    }

    close_quiescent(ledger);
}

#[test]
fn a_failed_write_settles_its_obligation_as_an_abort_not_a_commit() {
    // The acceptance line: obligation debt must match the injected backlog
    // exactly. `fgit-resource` will not let a reservation simply vanish, so
    // the check is that the ledger is quiescent afterwards — every obligation
    // the failed write opened was closed, and closed as an abort.
    let store = fabric(Some(ReferenceFaultPoint::AfterObjectInsert));
    let ledger = ledger();

    let _refusal = store
        .put_if_absent(verified(b"payload-three"), admission(&ledger))
        .expect_err("the injected fault must refuse");

    assert!(
        ledger.leaks().is_empty(),
        "a failed placement must not leak an obligation: {:?}",
        ledger.leaks()
    );
    close_quiescent(ledger);
}

#[test]
fn a_clean_write_settles_its_obligation_too() {
    // The paired permitted case. Without it, the assertion above would pass
    // against a fabric that never opened an obligation at all.
    let store = fabric(None);
    let ledger = ledger();

    let outcome = store
        .put_if_absent(verified(b"payload-four"), admission(&ledger))
        .expect("an unfaulted write must succeed");
    assert!(matches!(outcome, PutIfAbsent::Created { .. }));

    assert!(ledger.leaks().is_empty());
    close_quiescent(ledger);
}

#[test]
fn retrying_the_identical_object_is_idempotent_and_still_only_staged() {
    // Duplicated operation. A retry after an ambiguous failure is the normal
    // client behaviour, and it must not double-charge or promote the object.
    let store = fabric(None);
    let ledger = ledger();

    let first = store
        .put_if_absent(verified(b"payload-five"), admission(&ledger))
        .expect("first write succeeds");
    assert!(matches!(first, PutIfAbsent::Created { .. }));

    let second = store
        .put_if_absent(verified(b"payload-five"), admission(&ledger))
        .expect("an identical retry is idempotent, not an error");
    match second {
        PutIfAbsent::AlreadyPresent { epochs, .. } => {
            assert!(epochs.contains(PublicationEpoch::Staged));
            assert!(
                !epochs.contains(PublicationEpoch::Durable),
                "an idempotent retry must not manufacture durability"
            );
        }
        PutIfAbsent::Created { .. } => {
            panic!("a second identical write must not report Created")
        }
    }

    close_quiescent(ledger);
}

#[test]
fn an_object_cannot_even_be_built_while_claiming_another_identity() {
    // This drill started life as "the store refuses a different body under the
    // same identity". It cannot be written that way, and the reason is the
    // stronger result: `VerifiedObject::new` recomputes the native Git id from
    // the bytes, so an object claiming an identity its payload does not produce
    // is UNCONSTRUCTABLE. The attack never reaches the store.
    //
    // Asserting the refusal at construction is therefore the honest form —
    // testing it at the store would test a path the type already forecloses.
    let envelope = envelope_for(b"a-body", oid_for(b"a-different-body"));

    let refusal = VerifiedObject::new(envelope, b"a-body".to_vec())
        .expect_err("an object whose bytes do not produce its claimed identity must be refused");
    assert_eq!(
        refusal,
        StoreRefusal::NativeObjectIdentityMismatch,
        "the refusal must name the identity mismatch"
    );

    // Paired permitted case: the same payload with its own identity verifies.
    let honest = envelope_for(b"a-body", oid_for(b"a-body"));
    VerifiedObject::new(honest, b"a-body".to_vec())
        .expect("an object whose bytes produce its identity verifies");
}

#[test]
fn a_range_read_is_refused_unless_it_covers_the_whole_verified_body() {
    // This drill was written expecting an in-bounds SUB-range to read. It does
    // not, and the reason is a stronger property than the one I set out to
    // test: this backend verifies the complete immutable body before serving
    // anything, so a strict sub-range is refused as `PartialRangeUnverified`
    // rather than served unverified. The no-unverified-range rule is enforced,
    // not merely documented.
    //
    // Three distinct outcomes, so the test can fail in three distinct ways:
    //   past the end   -> RangeOutOfBounds        (or refused at construction)
    //   inside, strict -> PartialRangeUnverified  (never silently clamped)
    //   full span      -> the exact bytes
    let store = fabric(None);
    let ledger = ledger();
    let payload_bytes = b"0123456789".to_vec();
    let length = u64::try_from(payload_bytes.len()).expect("fits");

    store
        .put_if_absent(verified(&payload_bytes), admission(&ledger))
        .expect("write succeeds");

    // 1. Past the end. Clamping silently would hand back fewer bytes than
    //    asked for while reporting success.
    match ObjectRange::new(8, 8, length) {
        Err(refusal) => assert_eq!(
            refusal,
            StoreRefusal::RangeOutOfBounds,
            "an over-long range must be refused at construction"
        ),
        Ok(range) => assert_eq!(
            store
                .read_range_verified(oid_for(&payload_bytes), range)
                .expect_err("an over-long range must not read"),
            StoreRefusal::RangeOutOfBounds
        ),
    }

    // 2. In bounds but strict: refused, because it cannot be verified alone.
    let strict = ObjectRange::new(2, 4, length).expect("an in-bounds range is constructible");
    assert_eq!(
        store
            .read_range_verified(oid_for(&payload_bytes), strict)
            .expect_err("a strict sub-range must not be served unverified"),
        StoreRefusal::PartialRangeUnverified,
        "a partial range must be refused, never clamped and never served unverified"
    );

    // 3. The full span is the one range this backend can verify, and it
    //    returns the exact bytes. Without this arm the two refusals above
    //    would pass against a fabric that refused every range.
    let whole = ObjectRange::new(0, length, length).expect("the full span is valid");
    let read = store
        .read_range_verified(oid_for(&payload_bytes), whole)
        .expect("a full-span verified range reads");
    assert_eq!(read.bytes, payload_bytes);

    close_quiescent(ledger);
}

#[test]
fn reading_an_absent_object_is_a_typed_absence_not_an_empty_success() {
    let store = fabric(None);
    assert_eq!(
        store
            .read_whole(oid_for(b"never-written"))
            .expect_err("an absent object must refuse"),
        StoreRefusal::ObjectAbsent,
        "absence must be typed, never an empty successful read"
    );
}

/// A canonical manifest for the manifest-path fault drills.
///
/// Deliberately entry-free. `ManifestEntry`'s fields are private and it has no
/// public constructor, so an external adversary **cannot synthesize manifest
/// entries at all** — the only public routes to a populated manifest are
/// `SegmentManifest::from_verified_segment`, which requires a genuinely
/// verified segment reader, and decoding bytes that already verify.
///
/// That is a hardening property worth naming rather than working around: a
/// manifest describing objects that were never verified is unconstructable
/// from outside the crate. These drills only need the manifest to reach the
/// fault points, so an empty one is the honest minimum rather than a
/// concession.
fn manifest_fixture() -> SegmentManifest {
    SegmentManifest::new(
        NAMESPACE.to_vec(),
        [9; 32],
        Vec::new(),
        vec![PlacementReceipt::new(
            PlacementBackend::MemoryReference,
            handle(b"locator"),
            handle(b"failure-domain-a"),
            handle(b"encryption-dependency"),
        )],
        &ManifestLimits::default(),
    )
    .expect("an entry-free manifest with one placement is canonical")
}

/// A retention-root proposal for the retention-path fault drills.
fn proposal_fixture() -> RetentionRootProposal {
    RetentionRootProposal::new(
        RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[7; 32]).expect("fixture digest must fit"),
        ),
        Digest::new(
            DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
            DigestBytes::try_new(&[9; 32]).expect("fixture digest must fit"),
        ),
        Vec::new(),
    )
    .expect("an empty-manifest proposal is well formed")
}

#[test]
fn every_declared_fault_point_produces_its_own_named_refusal() {
    // Coverage WITH ITS DENOMINATOR. `ReferenceFaultPoint` declares eight
    // variants and this drill exercises all eight, across the three entry
    // points that reach them.
    //
    // The first version of this test covered only the two reachable through
    // `put_if_absent` and would have reported "every declared fault point"
    // while testing a quarter of them. TurquoiseWillow confirmed all eight are
    // live rather than reserved, so testing six fewer and calling it coverage
    // would have been exactly the missing-denominator failure this suite is
    // meant to catch in other people's work.
    //
    // A point that silently did nothing would otherwise be indistinguishable
    // from one that works.
    let object_points = [
        ReferenceFaultPoint::BeforeObjectInsert,
        ReferenceFaultPoint::AfterObjectInsert,
    ];
    let manifest_points = [
        ReferenceFaultPoint::BeforeManifestInsert,
        ReferenceFaultPoint::AfterManifestInsert,
    ];
    let retention_points = [
        ReferenceFaultPoint::BeforeRetentionBody,
        ReferenceFaultPoint::AfterRetentionBody,
        ReferenceFaultPoint::BeforeRetentionRoot,
        ReferenceFaultPoint::AfterRetentionRoot,
    ];
    let permissive = Registry {
        permits_deletion: true,
        revalidates: true,
    };

    let mut covered = 0_usize;

    for point in object_points {
        let store = fabric(Some(point));
        let ledger = ledger();
        let refusal = store
            .put_if_absent(verified(b"fault-probe"), admission(&ledger))
            .expect_err("an armed object-path fault must refuse");
        assert_eq!(
            refusal,
            StoreRefusal::ReferenceFaultInjected { point },
            "fault point {point} must name itself in its refusal"
        );
        let outcome = ledger.close();
        assert!(
            outcome.is_quiescent(),
            "fault point {point} must settle its obligation: {outcome:?}"
        );
        covered += 1;
    }

    for point in manifest_points {
        let store = fabric(Some(point));
        let refusal = store
            .write_manifest(&manifest_fixture())
            .expect_err("an armed manifest-path fault must refuse");
        assert_eq!(
            refusal,
            StoreRefusal::ReferenceFaultInjected { point },
            "fault point {point} must name itself in its refusal"
        );
        covered += 1;
    }

    for point in retention_points {
        let store = fabric(Some(point));
        let refusal = store
            .publish_retention_root(&permissive, &proposal_fixture())
            .expect_err("an armed retention-path fault must refuse");
        assert_eq!(
            refusal,
            StoreRefusal::ReferenceFaultInjected { point },
            "fault point {point} must name itself in its refusal"
        );
        covered += 1;
    }

    // The denominator, asserted rather than implied. If a ninth variant is
    // added and this drill is not extended, this line fails and says so.
    assert_eq!(
        covered, 8,
        "all eight declared ReferenceFaultPoint variants must be exercised"
    );
}

// ---------------------------------------------------------------------------
// Lifecycle resurrection
// ---------------------------------------------------------------------------

/// A retention registry that answers exactly as the drill requires.
///
/// Deliberately explicit rather than permissive: a registry that allowed every
/// deletion would make the retained-object drill vacuous.
struct Registry {
    permits_deletion: bool,
    revalidates: bool,
}

impl AuthenticatedRetentionRegistry for Registry {
    fn revalidate_root(&self, _proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
        if self.revalidates {
            Ok(())
        } else {
            Err(StoreRefusal::RetentionRevalidationFailed)
        }
    }

    fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
        if self.permits_deletion {
            Ok(())
        } else {
            Err(StoreRefusal::DeletionRetained)
        }
    }
}

#[test]
fn a_retained_object_cannot_be_deleted() {
    // The registry is authority over deletion. A fabric that deleted anyway
    // would let GC outrun the retention decision — §5.5.
    let store = fabric(None);
    let ledger = ledger();
    store
        .put_if_absent(verified(b"retained"), admission(&ledger))
        .expect("write succeeds");

    let refusal = store
        .delete_if_unretained(
            &Registry {
                permits_deletion: false,
                revalidates: true,
            },
            oid_for(b"retained"),
        )
        .expect_err("a retained object must not be deletable");
    assert_eq!(refusal, StoreRefusal::DeletionRetained);

    // And it is still there afterwards.
    store
        .read_whole(oid_for(b"retained"))
        .expect("a refused deletion must not have deleted anything");

    close_quiescent(ledger);
}

#[test]
fn a_resurrected_object_is_staged_only_and_never_regains_canonical_status() {
    // The resurrection drill. An object is deleted, then reappears — the
    // shape a stale replica, a replayed write, or a recovered backup produces.
    // The reappeared placement must NOT come back canonical: it is staged
    // pending authority revalidation, exactly as a first write would be.
    let store = fabric(None);
    let ledger = ledger();
    let permissive = Registry {
        permits_deletion: true,
        revalidates: true,
    };

    store
        .put_if_absent(verified(b"body"), admission(&ledger))
        .expect("initial write succeeds");
    assert_eq!(
        store
            .delete_if_unretained(&permissive, oid_for(b"body"))
            .expect("an unretained object deletes"),
        DeletionReceipt::Deleted
    );
    assert_eq!(
        store.read_whole(oid_for(b"body")).expect_err("it is gone"),
        StoreRefusal::ObjectAbsent
    );

    // It reappears.
    let resurrected = store
        .put_if_absent(verified(b"body"), admission(&ledger))
        .expect("the object can be written again");

    match resurrected {
        PutIfAbsent::Created { epochs, .. } => {
            assert!(epochs.contains(PublicationEpoch::Staged));
            assert!(
                !epochs.contains(PublicationEpoch::Visible),
                "a resurrected placement must not return canonically visible"
            );
            assert!(
                !epochs.contains(PublicationEpoch::Durable),
                "a resurrected placement must not return durable"
            );
        }
        PutIfAbsent::AlreadyPresent { .. } => {
            panic!("the delete did not actually remove the object, so this drill proves nothing")
        }
    }

    close_quiescent(ledger);
}

#[test]
fn deleting_an_absent_object_is_idempotent_rather_than_an_error() {
    // Paired permitted case for the deletion refusal above, and the property a
    // retry-safe GC needs.
    let store = fabric(None);
    assert_eq!(
        store
            .delete_if_unretained(
                &Registry {
                    permits_deletion: true,
                    revalidates: true
                },
                oid_for(b"never-existed")
            )
            .expect("deleting nothing is not an error"),
        DeletionReceipt::AlreadyAbsent
    );
}

#[test]
fn a_retention_root_the_registry_refuses_does_not_publish() {
    // Authority revalidation gates publication. A fabric that published a root
    // the registry refused would let placement outrun the retention decision.
    let store = fabric(None);
    let proposal = RetentionRootProposal::new(
        RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[7; 32]).expect("fixture digest must fit"),
        ),
        Digest::new(
            DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
            DigestBytes::try_new(&[9; 32]).expect("fixture digest must fit"),
        ),
        Vec::new(),
    )
    .expect("an empty-manifest proposal is well formed");

    let refusal = store
        .publish_retention_root(
            &Registry {
                permits_deletion: true,
                revalidates: false,
            },
            &proposal,
        )
        .expect_err("a refused revalidation must not publish");
    assert_eq!(refusal, StoreRefusal::RetentionRevalidationFailed);
}

// ---------------------------------------------------------------------------
// Failure-domain placement-record accuracy
// ---------------------------------------------------------------------------

/// A fabric in a named failure domain.
fn fabric_in_domain(domain: &[u8]) -> ReferenceMemoryFabric {
    let config = ReferenceMemoryConfig::new(
        NAMESPACE.to_vec(),
        handle(domain),
        handle(b"encryption-dependency"),
        1 << 20,
        ManifestLimits::default(),
    )
    .expect("reference config must be valid");
    ReferenceMemoryFabric::open(config).expect("reference fabric must open")
}

#[test]
fn a_placement_record_names_the_domain_that_actually_holds_it() {
    // Failure-domain loss is only survivable if the placement record says
    // WHERE a copy lives. A receipt that reported the wrong domain — or the
    // same domain for every backend — would make a domain-loss drill
    // unfalsifiable: you could not tell which copies you had just lost.
    let east = fabric_in_domain(b"failure-domain-east");
    let west = fabric_in_domain(b"failure-domain-west");
    let ledger_east = ledger();
    let ledger_west = ledger();
    let payload_bytes = b"replicated-body".to_vec();

    let east_placement = match east
        .put_if_absent(verified(&payload_bytes), admission(&ledger_east))
        .expect("east write succeeds")
    {
        PutIfAbsent::Created { placement, .. } | PutIfAbsent::AlreadyPresent { placement, .. } => {
            placement
        }
    };
    let west_placement = match west
        .put_if_absent(verified(&payload_bytes), admission(&ledger_west))
        .expect("west write succeeds")
    {
        PutIfAbsent::Created { placement, .. } | PutIfAbsent::AlreadyPresent { placement, .. } => {
            placement
        }
    };

    assert_eq!(
        east_placement.failure_domain(),
        handle(b"failure-domain-east"),
        "a placement must name the domain that actually holds it"
    );
    assert_eq!(
        west_placement.failure_domain(),
        handle(b"failure-domain-west")
    );
    assert_ne!(
        east_placement.failure_domain(),
        west_placement.failure_domain(),
        "two domains must be distinguishable, or a domain-loss drill cannot say what was lost"
    );

    // The identical body is content-addressed to the identical id in both
    // domains — which is exactly why the placement record, not the object id,
    // is what tells you where a copy lives.
    assert_eq!(
        east.read_whole(oid_for(&payload_bytes))
            .expect("east holds it")
            .object
            .payload(),
        west.read_whole(oid_for(&payload_bytes))
            .expect("west holds it")
            .object
            .payload()
    );

    // Losing east must not make west's copy unreadable, and must not silently
    // rewrite west's placement record.
    drop(east);
    let after_loss = west
        .read_whole(oid_for(&payload_bytes))
        .expect("west survives the loss of east");
    assert_eq!(
        after_loss.placement.failure_domain(),
        handle(b"failure-domain-west"),
        "the surviving placement record must be unchanged by another domain's loss"
    );

    close_quiescent(ledger_east);
    close_quiescent(ledger_west);
}

#[test]
fn a_placement_record_names_the_backend_that_holds_it() {
    // The reference backend must not impersonate the durable one. A receipt
    // claiming LocalFilesystem from an in-memory store would let a caller
    // treat non-durable evidence as durable placement.
    let store = fabric(None);
    let ledger = ledger();

    let placement = match store
        .put_if_absent(verified(b"backend-probe"), admission(&ledger))
        .expect("write succeeds")
    {
        PutIfAbsent::Created { placement, .. } | PutIfAbsent::AlreadyPresent { placement, .. } => {
            placement
        }
    };

    assert_eq!(
        placement.backend(),
        PlacementBackend::MemoryReference,
        "the non-durable reference profile must identify itself as such"
    );
    assert_ne!(
        placement.backend(),
        PlacementBackend::LocalFilesystem,
        "an in-memory store must never claim a durable filesystem placement"
    );

    close_quiescent(ledger);
}

// ---------------------------------------------------------------------------
// Cancellation mid-stream
// ---------------------------------------------------------------------------

#[test]
fn cancellation_surfaces_as_cancelled_and_never_collapses_into_a_refusal() {
    // `RuntimeImmutableObjectFabric` returns a four-valued `Outcome`, and its
    // own docs say why: it "preserves all four Asupersync outcome arms instead
    // of collapsing cancellation or containment into StoreRefusal".
    //
    // That distinction is load-bearing for a storage layer. A cancelled read
    // reported as `Err(StoreRefusal)` tells a caller the STORE refused it,
    // which is a statement about the data. Cancellation is a statement about
    // the CALLER. Conflating them is how a retry loop concludes an object is
    // corrupt when its own budget expired.
    //
    // Driven with a zero poll quota rather than an expired deadline: a budget
    // with no polls left fails its first checkpoint deterministically, whereas
    // a past deadline depends on where the runtime clock happens to start.
    // This drives asupersync directly because `fgit-runtime` is not a
    // dependency of this crate and adding one for a test would enlarge the
    // graph to reach a runtime that is already here.
    let runtime = Runtime::with_config(RuntimeConfig::default()).expect("a runtime builds");
    let store = fabric(None);
    let ledger = ledger();
    let payload_bytes = b"stream-me".to_vec();

    store
        .put_if_absent(verified(&payload_bytes), admission(&ledger))
        .expect("write succeeds");

    let budget = VerifiedStreamBudget::new(1 << 16, 4096).expect("a bounded stream budget");
    let exhausted = runtime.request_cx_with_budget(Budget::new().with_poll_quota(0));

    let outcome = runtime.block_on(async {
        store
            .open_verified_stream(&exhausted, oid_for(&payload_bytes), budget)
            .await
    });

    match outcome {
        Outcome::Cancelled(_) => {}
        Outcome::Err(refusal) => panic!(
            "cancellation collapsed into a store refusal ({refusal:?}); a caller cannot tell \
             'you ran out of budget' from 'this object is bad'"
        ),
        Outcome::Ok(_) => {
            panic!("a context with no polls remaining must not complete a verified stream")
        }
        Outcome::Panicked(payload) => panic!("unexpected panic: {payload:?}"),
    }

    // Paired permitted case: a healthy context streams the same object, so the
    // assertion above cannot pass against a fabric that cancels everything.
    let healthy = runtime.request_cx_with_budget(
        Budget::new()
            .with_poll_quota(100_000)
            .with_cost_quota(100_000),
    );
    let healthy_outcome = runtime.block_on(async {
        store
            .open_verified_stream(&healthy, oid_for(&payload_bytes), budget)
            .await
    });
    assert!(
        matches!(healthy_outcome, Outcome::Ok(_)),
        "a healthy context must open the stream, got {healthy_outcome:?}"
    );

    drop(healthy);
    drop(exhausted);
    close_quiescent(ledger);
    assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
}
