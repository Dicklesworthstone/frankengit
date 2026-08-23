#![forbid(unsafe_code)]
//! Independent protocol probes for the authenticated GC epoch worker.
//!
//! These fixtures are observability doubles only: the authority records staged
//! tombstones so assertions can inspect the worker, while the production path
//! is the `ImmutableObjectFabric` blanket implementation of `GcPhysicalStore`.
//! No fixture is used as a candidate source or retention authority in product
//! code.

use std::cell::{Cell, RefCell};

use asupersync::{Cx, Outcome};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, FabricCapability,
    RetentionRootProposal, StoreRefusal,
};
use fgit_repair::gc::{
    AuthenticatedGcAuthority, GcCandidate, GcCandidateBatch, GcCandidateDisposition,
    GcCandidateRevalidation, GcCreationReceipt, GcEpoch, GcGraceHorizons, GcPhysicalStore,
    GcProfile, GcRefusal, GcRootClass, GcTombstone, GcWorker,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1,
    RepositoryAuthorityHeadId,
};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
const CONDITIONAL_DELETE: &[FabricCapability] = &[FabricCapability::ConditionalDeletion];
const NO_DELETE: &[FabricCapability] = &[];

fn head(fill: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture algorithm slot is non-zero"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[fill; 32]).expect("fixture head digest has a valid width"),
    )
}

fn digest(fill: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture algorithm slot is non-zero"),
        DigestBytes::try_new(&[fill; 32]).expect("fixture root digest has a valid width"),
    )
}

fn identity(fill: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([fill; GitOidSha1::LEN]))
}

fn epoch(sequence: u64) -> GcEpoch {
    let root = RetentionRootProposal::new(head(3), digest(5), Vec::new())
        .expect("empty manifest set is canonical retention evidence");
    GcEpoch::new(root, sequence, GcRootClass::ALL.to_vec())
        .expect("every plan-required root class is materialized")
}

fn candidate(object: GitOid, creation_sequence: u64, grace_until: u64) -> GcCandidate {
    GcCandidate::new(
        object,
        GcCreationReceipt::new(head(7), creation_sequence),
        GcGraceHorizons::new(
            grace_until,
            grace_until,
            grace_until,
            grace_until,
            grace_until,
        ),
    )
}

struct FixtureAuthority {
    batch: GcCandidateBatch,
    exact_reachable: bool,
    accelerator_reachable: Option<bool>,
    revalidation: GcCandidateRevalidation,
    root_current: Cell<bool>,
    deletion_permitted: Cell<bool>,
    loaded: Cell<u32>,
    tombstones: RefCell<Vec<GcTombstone>>,
}

impl FixtureAuthority {
    fn one(
        epoch: GcEpoch,
        candidate: GcCandidate,
        exact_reachable: bool,
        accelerator_reachable: Option<bool>,
        revalidation: GcCandidateRevalidation,
    ) -> Self {
        let batch = GcCandidateBatch::new(epoch, 0, vec![candidate])
            .expect("one candidate is canonically ordered");
        Self {
            batch,
            exact_reachable,
            accelerator_reachable,
            revalidation,
            root_current: Cell::new(true),
            deletion_permitted: Cell::new(true),
            loaded: Cell::new(0),
            tombstones: RefCell::new(Vec::new()),
        }
    }

    fn tombstones(&self) -> Vec<GcTombstone> {
        self.tombstones.borrow().clone()
    }
}

impl AuthenticatedRetentionRegistry for FixtureAuthority {
    fn revalidate_root(&self, proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
        if self.root_current.get() && proposal == self.batch.epoch().root_proposal() {
            Ok(())
        } else {
            Err(StoreRefusal::RetentionRevalidationFailed)
        }
    }

    fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
        if self.deletion_permitted.get() {
            Ok(())
        } else {
            Err(StoreRefusal::DeletionRetained)
        }
    }
}

impl AuthenticatedGcAuthority for FixtureAuthority {
    fn load_candidates(
        &self,
        _after: Option<GitOid>,
        _limit: u16,
    ) -> Result<GcCandidateBatch, GcRefusal> {
        self.loaded.set(self.loaded.get().saturating_add(1));
        Ok(self.batch.clone())
    }

    fn exact_reachable(&self, _epoch: &GcEpoch, _identity: GitOid) -> Result<bool, GcRefusal> {
        Ok(self.exact_reachable)
    }

    fn accelerator_reachable(
        &self,
        _epoch: &GcEpoch,
        _identity: GitOid,
    ) -> Result<Option<bool>, GcRefusal> {
        Ok(self.accelerator_reachable)
    }

    fn stage_tombstone(&self, tombstone: &GcTombstone) -> Result<(), GcRefusal> {
        self.tombstones.borrow_mut().push(tombstone.clone());
        Ok(())
    }

    fn revalidate_candidate(
        &self,
        _tombstone: &GcTombstone,
    ) -> Result<GcCandidateRevalidation, GcRefusal> {
        Ok(self.revalidation)
    }
}

struct FixtureFabric {
    supports_conditional_deletion: bool,
    already_absent: bool,
    delete_calls: Cell<u32>,
}

impl FixtureFabric {
    const fn conditional() -> Self {
        Self {
            supports_conditional_deletion: true,
            already_absent: false,
            delete_calls: Cell::new(0),
        }
    }
}

impl GcPhysicalStore for FixtureFabric {
    fn capabilities(&self) -> FabricCapabilities {
        if self.supports_conditional_deletion {
            FabricCapabilities::new(CONDITIONAL_DELETE)
        } else {
            FabricCapabilities::new(NO_DELETE)
        }
    }

    fn delete_if_authorized(
        &self,
        registry: &impl AuthenticatedRetentionRegistry,
        object: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        registry.permits_placement_deletion(object)?;
        self.delete_calls
            .set(self.delete_calls.get().saturating_add(1));
        if self.already_absent {
            Ok(DeletionReceipt::AlreadyAbsent)
        } else {
            Ok(DeletionReceipt::Deleted)
        }
    }
}

fn worker() -> GcWorker {
    GcWorker::new(GcProfile::new(1).expect("one candidate is a non-empty page bound"))
}

#[test]
fn every_plan_root_class_is_required_in_the_authenticated_epoch() {
    let root = RetentionRootProposal::new(head(3), digest(5), Vec::new())
        .expect("empty manifest set is canonical retention evidence");
    assert_eq!(
        GcEpoch::new(root, 40, vec![GcRootClass::RefsAndSafety]),
        Err(GcRefusal::IncompleteRootClassMaterialization {
            expected: GcRootClass::ALL.len(),
            observed: 1,
        })
    );
}

#[test]
fn objects_created_after_the_gc_basis_are_protected_without_tombstones() {
    let basis = epoch(40);
    let object = identity(11);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 41, 40),
        false,
        Some(false),
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker().sweep(&cx, &source, &fabric, None) else {
        panic!("a newer creation receipt must protect rather than reject the page");
    };
    assert_eq!(
        report.dispositions,
        vec![GcCandidateDisposition::ProtectedByNewerCreation {
            identity: object,
            creation_sequence: 41,
            basis_sequence: 40,
        }]
    );
    assert!(
        source.tombstones().is_empty(),
        "a newer creation receipt must stop before logical deletion evidence"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "a newer creation receipt must stop before physical deletion"
    );
}

#[test]
fn accelerator_disagreement_refuses_before_any_tombstone_or_delete() {
    let basis = epoch(40);
    let object = identity(12);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 40),
        false,
        Some(true),
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();

    assert_eq!(
        worker().sweep(&cx, &source, &fabric, None),
        Outcome::Err(GcRefusal::AcceleratorDisagrees {
            identity: object,
            exact_reachable: false,
            accelerator_reachable: true,
        })
    );
    assert!(
        source.tombstones().is_empty(),
        "the exact/accelerator disagreement must prevent even logical deletion"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "an accelerator is only a consistency check and must never authorize deletion"
    );
}

#[test]
fn logical_tombstone_is_distinct_from_physical_deletion() {
    let basis = epoch(40);
    let object = identity(13);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 41),
        false,
        None,
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker().sweep(&cx, &source, &fabric, None) else {
        panic!("an active grace horizon must retain a logical tombstone");
    };
    assert_eq!(
        report.dispositions,
        vec![GcCandidateDisposition::Tombstoned {
            identity: object,
            grace_until: 41,
        }]
    );
    let tombstones = source.tombstones();
    assert_eq!(
        tombstones.len(),
        1,
        "logical deletion evidence must persist"
    );
    assert_eq!(tombstones[0].candidate().identity(), object);
    assert_eq!(tombstones[0].epoch().root_set_digest(), digest(5));
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "the same grace horizon that permits a tombstone forbids physical deletion"
    );
}

#[test]
fn revalidation_prevents_physical_deletion_when_an_object_becomes_retained() {
    let basis = epoch(40);
    let object = identity(14);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 40),
        false,
        Some(false),
        GcCandidateRevalidation::NowRetained,
    );
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker().sweep(&cx, &source, &fabric, None) else {
        panic!("current revalidation must keep an object safe rather than fail open");
    };
    assert_eq!(
        report.dispositions,
        vec![GcCandidateDisposition::RetainedOnRevalidation { identity: object }]
    );
    assert_eq!(
        source.tombstones().len(),
        1,
        "mark evidence remains immutable"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "later retention must stop the sweep after a prior logical tombstone"
    );
}

#[test]
fn stale_root_proof_refuses_before_physical_deletion() {
    let basis = epoch(40);
    let object = identity(15);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 40),
        false,
        Some(false),
        GcCandidateRevalidation::StillUnretained,
    );
    source.root_current.set(false);
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();

    assert_eq!(
        worker().sweep(&cx, &source, &fabric, None),
        Outcome::Err(GcRefusal::RootRevalidation(
            StoreRefusal::RetentionRevalidationFailed
        ))
    );
    assert_eq!(
        source.tombstones().len(),
        1,
        "logical evidence remains, but a stale root proof cannot authorize sweep"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "root revalidation must happen before conditional physical deletion"
    );
}

#[test]
fn a_backend_without_conditional_deletion_preserves_logical_evidence_only() {
    let basis = epoch(40);
    let object = identity(16);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 40),
        false,
        None,
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric {
        supports_conditional_deletion: false,
        already_absent: false,
        delete_calls: Cell::new(0),
    };
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker().sweep(&cx, &source, &fabric, None) else {
        panic!("the typed no-physical-delete path must retain its logical tombstone");
    };
    assert_eq!(
        report.dispositions,
        vec![GcCandidateDisposition::PhysicalDeletionUnsupported { identity: object }]
    );
    assert_eq!(
        source.tombstones().len(),
        1,
        "logical evidence remains durable"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        0,
        "a backend lacking conditional deletion must not receive a delete call"
    );
}

#[test]
fn physical_deletion_emits_idempotent_evidence_after_current_authorization() {
    let basis = epoch(40);
    let object = identity(17);
    let source = FixtureAuthority::one(
        basis,
        candidate(object, 39, 40),
        false,
        Some(false),
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric {
        supports_conditional_deletion: true,
        already_absent: true,
        delete_calls: Cell::new(0),
    };
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker().sweep(&cx, &source, &fabric, None) else {
        panic!("current authority must permit an idempotent physical delete result");
    };
    assert_eq!(
        report.dispositions,
        vec![GcCandidateDisposition::AlreadyPhysicallyAbsent { identity: object }]
    );
    assert_eq!(
        source.tombstones().len(),
        1,
        "physical sweep follows logical evidence"
    );
    assert_eq!(
        fabric.delete_calls.get(),
        1,
        "one conditional deletion is attempted"
    );
}

#[test]
fn reasonless_cancellation_stops_before_authority_source_work() {
    let basis = epoch(40);
    let source = FixtureAuthority::one(
        basis,
        candidate(identity(18), 39, 40),
        false,
        None,
        GcCandidateRevalidation::StillUnretained,
    );
    let fabric = FixtureFabric::conditional();
    let cx = Cx::detached_cancel_context();
    cx.set_cancel_requested(true);

    assert_eq!(
        worker().sweep(&cx, &source, &fabric, None),
        Outcome::Err(GcRefusal::RuntimeCheckpointRejected)
    );
    assert_eq!(
        source.loaded.get(),
        0,
        "cancellation must precede source work"
    );
    assert!(
        source.tombstones().is_empty(),
        "cancellation must not stage a tombstone"
    );
}
