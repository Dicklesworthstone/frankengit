//! Authenticated root-mark-grace-revalidate garbage collection.
//!
//! This module owns the GC epoch protocol, not a second retention authority.
//! A caller supplies candidates from an authenticated authority basis; the
//! worker independently checks exact reachability, treats an accelerator only
//! as a consistency check, records immutable logical tombstones, waits for all
//! applicable logical grace horizons, and then asks the current authority to
//! authorize idempotent physical deletion through object fabric.
//!
//! The worker deliberately has no storage-listing API. A local directory,
//! cache, approximate reachability index, or projection may make work faster,
//! but none may manufacture a sweep candidate or authorize deletion.

use core::fmt;
use std::error::Error;

use asupersync::{Cx, Outcome};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, FabricCapability,
    ImmutableObjectFabric, RetentionRootProposal, StoreRefusal,
};
use fgit_types::{GitOid, RepositoryAuthorityHeadId};

/// Authenticated root-registry classes required in every GC epoch.
///
/// A class is present only when its contents were materialized into the
/// `GcEpoch` root-set digest by authority. The enum prevents a new root class
/// from silently being omitted by a caller that constructs an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GcRootClass {
    /// Current, protected, and hidden refs, reflogs, and safety roots.
    RefsAndSafety,
    /// Pull-request merge, queue, and evidence roots.
    PullRequestEvidence,
    /// Releases, packages, and artifact roots.
    ReleasesAndArtifacts,
    /// Legal holds, administrative pins, and security-incident roots.
    HoldsPinsAndIncidents,
    /// Unexpired capsules, backups, and restore roots.
    CapsulesBackupsAndRestore,
    /// Migration, replication, and federation roots.
    MigrationReplicationAndFederation,
    /// Staged transactions, objects, and live obligation roots.
    StagedAndObligationRoots,
    /// Grace tombstones and prior deletion proofs.
    GraceTombstonesAndDeletionProofs,
    /// Retained graph, search, and check material.
    DerivedRetentionMaterial,
}

impl GcRootClass {
    /// Canonical exhaustive order for root-registry materialization.
    pub const ALL: [Self; 9] = [
        Self::RefsAndSafety,
        Self::PullRequestEvidence,
        Self::ReleasesAndArtifacts,
        Self::HoldsPinsAndIncidents,
        Self::CapsulesBackupsAndRestore,
        Self::MigrationReplicationAndFederation,
        Self::StagedAndObligationRoots,
        Self::GraceTombstonesAndDeletionProofs,
        Self::DerivedRetentionMaterial,
    ];
}

/// A pinned authority head, policy sequence, and authenticated root-set proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcEpoch {
    root_proposal: RetentionRootProposal,
    sequence: u64,
    root_classes: Vec<GcRootClass>,
}

impl GcEpoch {
    /// Constructs an epoch from complete decision-publication retention evidence.
    pub fn new(
        root_proposal: RetentionRootProposal,
        sequence: u64,
        root_classes: Vec<GcRootClass>,
    ) -> Result<Self, GcRefusal> {
        if root_classes.len() != GcRootClass::ALL.len() {
            return Err(GcRefusal::IncompleteRootClassMaterialization {
                expected: GcRootClass::ALL.len(),
                observed: root_classes.len(),
            });
        }
        if root_classes
            .iter()
            .zip(GcRootClass::ALL)
            .any(|(observed, expected)| *observed != expected)
        {
            return Err(GcRefusal::NonCanonicalRootClassOrder);
        }
        Ok(Self {
            root_proposal,
            sequence,
            root_classes,
        })
    }

    /// Authority head pinned while materializing this exact root set.
    #[must_use]
    pub const fn authority_head(&self) -> RepositoryAuthorityHeadId {
        self.root_proposal.authority_head()
    }

    /// Authenticated root-set digest from decision publication.
    #[must_use]
    pub const fn root_set_digest(&self) -> fgit_types::Digest {
        self.root_proposal.retention_root()
    }

    /// Logical policy/decision sequence, never an ambient wall clock.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Retention proposal which must be revalidated immediately before sweep.
    #[must_use]
    pub const fn root_proposal(&self) -> &RetentionRootProposal {
        &self.root_proposal
    }

    /// Exhaustive root classes materialized into this epoch's root-set proof.
    #[must_use]
    pub fn root_classes(&self) -> &[GcRootClass] {
        &self.root_classes
    }
}

/// Authenticated creation evidence for one candidate object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcCreationReceipt {
    authority_head: RepositoryAuthorityHeadId,
    decision_sequence: u64,
}

impl GcCreationReceipt {
    /// Binds a creation to the authority decision which made it visible.
    #[must_use]
    pub const fn new(authority_head: RepositoryAuthorityHeadId, decision_sequence: u64) -> Self {
        Self {
            authority_head,
            decision_sequence,
        }
    }

    /// Authority head that issued this receipt.
    #[must_use]
    pub const fn authority_head(&self) -> RepositoryAuthorityHeadId {
        self.authority_head
    }

    /// Decision-stream sequence at which the object became visible.
    #[must_use]
    pub const fn decision_sequence(&self) -> u64 {
        self.decision_sequence
    }
}

/// Grace horizons which all need to mature before physical deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcGraceHorizons {
    replica: u64,
    repair: u64,
    backup: u64,
    legal_hold: u64,
    obligation: u64,
}

impl GcGraceHorizons {
    /// Builds the full replicated/repair/backup/hold/obligation horizon set.
    #[must_use]
    pub const fn new(
        replica: u64,
        repair: u64,
        backup: u64,
        legal_hold: u64,
        obligation: u64,
    ) -> Self {
        Self {
            replica,
            repair,
            backup,
            legal_hold,
            obligation,
        }
    }

    /// Latest horizon that must mature before physical deletion.
    #[must_use]
    pub const fn latest(self) -> u64 {
        let replica_or_repair = if self.replica > self.repair {
            self.replica
        } else {
            self.repair
        };
        let backup_or_hold = if self.backup > self.legal_hold {
            self.backup
        } else {
            self.legal_hold
        };
        let latest_without_obligation = if replica_or_repair > backup_or_hold {
            replica_or_repair
        } else {
            backup_or_hold
        };
        if latest_without_obligation > self.obligation {
            latest_without_obligation
        } else {
            self.obligation
        }
    }

    /// Whether every authority-supplied grace horizon has matured.
    #[must_use]
    pub const fn is_mature_at(self, sequence: u64) -> bool {
        sequence >= self.latest()
    }
}

/// Why exact authority reachability made an object a tombstone candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcTombstoneReason {
    /// The exact root traversal found no retaining path.
    ExactUnreachable,
}

/// One object considered from an authenticated, canonically ordered source page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcCandidate {
    identity: GitOid,
    creation: GcCreationReceipt,
    horizons: GcGraceHorizons,
}

impl GcCandidate {
    /// Constructs a candidate using authority-supplied creation and horizon evidence.
    #[must_use]
    pub const fn new(
        identity: GitOid,
        creation: GcCreationReceipt,
        horizons: GcGraceHorizons,
    ) -> Self {
        Self {
            identity,
            creation,
            horizons,
        }
    }

    /// Native Git object identity.
    #[must_use]
    pub const fn identity(&self) -> GitOid {
        self.identity
    }

    /// Creation receipt protecting objects newer than the pinned GC basis.
    #[must_use]
    pub const fn creation(&self) -> GcCreationReceipt {
        self.creation
    }

    /// All grace horizons attached to this authority-fed candidate.
    #[must_use]
    pub const fn horizons(&self) -> GcGraceHorizons {
        self.horizons
    }
}

/// Immutable logical-deletion evidence, distinct from physical deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcTombstone {
    epoch: GcEpoch,
    candidate: GcCandidate,
    reason: GcTombstoneReason,
}

impl GcTombstone {
    /// Creates a root-proof-carrying tombstone for an exactly unreachable object.
    #[must_use]
    pub const fn new(epoch: GcEpoch, candidate: GcCandidate, reason: GcTombstoneReason) -> Self {
        Self {
            epoch,
            candidate,
            reason,
        }
    }

    /// Pinned authority/root evidence for the logical deletion decision.
    #[must_use]
    pub const fn epoch(&self) -> &GcEpoch {
        &self.epoch
    }

    /// Object whose physical bytes remain protected until a later sweep authorization.
    #[must_use]
    pub const fn candidate(&self) -> GcCandidate {
        self.candidate
    }

    /// Exact retention finding retained with the tombstone.
    #[must_use]
    pub const fn reason(&self) -> GcTombstoneReason {
        self.reason
    }
}

/// Canonically ordered candidates from exactly one pinned GC epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcCandidateBatch {
    epoch: GcEpoch,
    remaining_candidates: u32,
    candidates: Vec<GcCandidate>,
}

impl GcCandidateBatch {
    /// Verifies strict native-object order before a worker accepts a page.
    pub fn new(
        epoch: GcEpoch,
        remaining_candidates: u32,
        candidates: Vec<GcCandidate>,
    ) -> Result<Self, GcRefusal> {
        let mut previous = None;
        for candidate in &candidates {
            if let Some(previous_identity) = previous {
                if candidate.identity() == previous_identity {
                    return Err(GcRefusal::DuplicateCandidate);
                }
                if candidate.identity() < previous_identity {
                    return Err(GcRefusal::NonCanonicalCandidateOrder);
                }
            }
            previous = Some(candidate.identity());
        }
        Ok(Self {
            epoch,
            remaining_candidates,
            candidates,
        })
    }

    /// Epoch that authenticated every candidate in this page.
    #[must_use]
    pub const fn epoch(&self) -> &GcEpoch {
        &self.epoch
    }

    /// Candidates still pending after this page.
    #[must_use]
    pub const fn remaining_candidates(&self) -> u32 {
        self.remaining_candidates
    }

    /// Strictly ordered candidates from the authenticated source.
    #[must_use]
    pub fn candidates(&self) -> &[GcCandidate] {
        &self.candidates
    }
}

/// Current-authority result returned immediately before physical deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcCandidateRevalidation {
    /// The object is still exactly unreachable and all protections remain clear.
    StillUnretained,
    /// A later authority basis retains the object.
    NowRetained,
    /// A later creation receipt protects the object from this older epoch.
    CreatedAfterBasis(GcCreationReceipt),
    /// A later authority basis extended one or more grace horizons.
    GraceExtended(GcGraceHorizons),
}

/// Final authority boundary for authenticated candidate material and revalidation.
///
/// Implementations obtain candidates from the authority-head/retention-root
/// decision stream. They must never substitute a placement listing, local
/// cache, or an approximate index for this source. The inherited registry
/// methods perform the root and deletion-authorization checks used by object
/// fabric at the actual physical-delete boundary.
pub trait AuthenticatedGcAuthority: AuthenticatedRetentionRegistry {
    /// Loads at most `limit` strictly ordered candidates following `after`.
    fn load_candidates(
        &self,
        after: Option<GitOid>,
        limit: u16,
    ) -> Result<GcCandidateBatch, GcRefusal>;

    /// Computes exact reachability from the epoch's authenticated root set.
    fn exact_reachable(&self, epoch: &GcEpoch, identity: GitOid) -> Result<bool, GcRefusal>;

    /// Optionally reports an accelerator result for a consistency check.
    ///
    /// `None` means no accelerator was available. A returned value must agree
    /// with [`Self::exact_reachable`], but can never replace it.
    fn accelerator_reachable(
        &self,
        epoch: &GcEpoch,
        identity: GitOid,
    ) -> Result<Option<bool>, GcRefusal>;

    /// Durably appends the root-proof-carrying logical tombstone.
    fn stage_tombstone(&self, tombstone: &GcTombstone) -> Result<(), GcRefusal>;

    /// Re-reads current authority for a mature tombstone immediately before sweep.
    fn revalidate_candidate(
        &self,
        tombstone: &GcTombstone,
    ) -> Result<GcCandidateRevalidation, GcRefusal>;
}

/// Small deletion adapter that keeps the GC protocol bound to object fabric.
///
/// The blanket implementation below is the production path. This narrow
/// adapter permits tests to observe the GC protocol without constructing a
/// complete placement backend; it is not a candidate source or durability
/// authority.
pub trait GcPhysicalStore {
    /// Exact physical capabilities exposed by this placement backend.
    fn capabilities(&self) -> FabricCapabilities;

    /// Performs one authority-authorized, idempotent physical deletion.
    fn delete_if_authorized(
        &self,
        registry: &impl AuthenticatedRetentionRegistry,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal>;
}

impl<T: ImmutableObjectFabric> GcPhysicalStore for T {
    fn capabilities(&self) -> FabricCapabilities {
        ImmutableObjectFabric::capabilities(self)
    }

    fn delete_if_authorized(
        &self,
        registry: &impl AuthenticatedRetentionRegistry,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        self.delete_if_unretained(registry, identity)
    }
}

/// Static bound for one cancellable GC page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcProfile {
    max_candidates: u16,
}

impl GcProfile {
    /// Creates a non-empty per-page candidate bound before source work begins.
    pub const fn new(max_candidates: u16) -> Result<Self, GcRefusal> {
        if max_candidates == 0 {
            return Err(GcRefusal::ZeroCandidateLimit);
        }
        Ok(Self { max_candidates })
    }

    /// Maximum candidates accepted from one authenticated source page.
    #[must_use]
    pub const fn max_candidates(&self) -> u16 {
        self.max_candidates
    }
}

/// Observable state of one candidate after the bounded GC protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcCandidateDisposition {
    /// Exact reachability retained the object at the pinned root.
    Retained { identity: GitOid },
    /// A later creation receipt protects this object from an old epoch.
    ProtectedByNewerCreation {
        /// Candidate object identity.
        identity: GitOid,
        /// Creation decision sequence.
        creation_sequence: u64,
        /// Pinned GC sequence that predates that creation.
        basis_sequence: u64,
    },
    /// Logical deletion is recorded, but a grace horizon remains active.
    Tombstoned {
        /// Candidate object identity.
        identity: GitOid,
        /// Latest still-active protection horizon.
        grace_until: u64,
    },
    /// A later authority root protected the object after tombstoning.
    RetainedOnRevalidation { identity: GitOid },
    /// A later creation receipt protected the object after tombstoning.
    ProtectedOnRevalidation {
        /// Candidate object identity.
        identity: GitOid,
        /// Current creation decision sequence.
        creation_sequence: u64,
    },
    /// A later authority root extended the object grace period.
    GraceExtendedOnRevalidation {
        /// Candidate object identity.
        identity: GitOid,
        /// Latest current protection horizon.
        grace_until: u64,
    },
    /// The physical backend has no conditional-deletion capability.
    PhysicalDeletionUnsupported { identity: GitOid },
    /// Conditional physical deletion removed the bytes.
    PhysicallyDeleted { identity: GitOid },
    /// Conditional physical deletion found an already absent object.
    AlreadyPhysicallyAbsent { identity: GitOid },
}

impl GcCandidateDisposition {
    /// Candidate identity named by this outcome.
    #[must_use]
    pub const fn identity(&self) -> GitOid {
        match *self {
            Self::Retained { identity }
            | Self::ProtectedByNewerCreation { identity, .. }
            | Self::Tombstoned { identity, .. }
            | Self::RetainedOnRevalidation { identity }
            | Self::ProtectedOnRevalidation { identity, .. }
            | Self::GraceExtendedOnRevalidation { identity, .. }
            | Self::PhysicalDeletionUnsupported { identity }
            | Self::PhysicallyDeleted { identity }
            | Self::AlreadyPhysicallyAbsent { identity } => identity,
        }
    }
}

/// Bounded evidence from one GC mark/grace/revalidate/sweep page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcReport {
    /// Epoch that supplied the root proof for this page.
    pub epoch: GcEpoch,
    /// Per-candidate results in canonical object-identity order.
    pub dispositions: Vec<GcCandidateDisposition>,
    /// Candidates still pending after the authenticated source page.
    pub remaining_candidates: u32,
    /// Last accepted object identity for the next canonical page.
    pub resume_after: Option<GitOid>,
}

/// Bounded root-mark-grace-revalidate-sweep worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcWorker {
    profile: GcProfile,
}

impl GcWorker {
    /// Creates a bounded worker; the profile validates all pre-source limits.
    #[must_use]
    pub const fn new(profile: GcProfile) -> Self {
        Self { profile }
    }

    /// Executes one cancellable GC page.
    ///
    /// The full page is exact-reachability preflighted before any tombstone or
    /// physical deletion is attempted. In particular, an accelerator mismatch
    /// refuses the page before the worker can sweep any object.
    pub fn sweep<Caps>(
        &self,
        cx: &Cx<Caps>,
        authority: &impl AuthenticatedGcAuthority,
        fabric: &impl GcPhysicalStore,
        after: Option<GitOid>,
    ) -> Outcome<GcReport, GcRefusal> {
        if let Some(outcome) = checkpoint(cx) {
            return outcome;
        }
        let batch = match authority.load_candidates(after, self.profile.max_candidates()) {
            Ok(batch) => batch,
            Err(refusal) => return Outcome::Err(refusal),
        };
        if batch.candidates().len() > usize::from(self.profile.max_candidates()) {
            return Outcome::Err(GcRefusal::BatchTooLarge {
                offered: batch.candidates().len(),
                maximum: self.profile.max_candidates(),
            });
        }

        let mut preflight = Vec::with_capacity(batch.candidates().len());
        let mut resume_after = after;
        for candidate in batch.candidates() {
            if let Some(outcome) = checkpoint(cx) {
                return outcome;
            }
            if let Some(previous) = resume_after
                && candidate.identity() <= previous
            {
                return Outcome::Err(GcRefusal::ResumeNotAdvanced {
                    previous,
                    observed: candidate.identity(),
                });
            }
            resume_after = Some(candidate.identity());
            let exact_reachable =
                match authority.exact_reachable(batch.epoch(), candidate.identity()) {
                    Ok(reachable) => reachable,
                    Err(refusal) => return Outcome::Err(refusal),
                };
            let accelerated =
                match authority.accelerator_reachable(batch.epoch(), candidate.identity()) {
                    Ok(reachable) => reachable,
                    Err(refusal) => return Outcome::Err(refusal),
                };
            if let Some(accelerator_reachable) = accelerated
                && accelerator_reachable != exact_reachable
            {
                return Outcome::Err(GcRefusal::AcceleratorDisagrees {
                    identity: candidate.identity(),
                    exact_reachable,
                    accelerator_reachable,
                });
            }
            if exact_reachable {
                preflight.push(PreflightDisposition::Retained(*candidate));
            } else if candidate.creation().decision_sequence() > batch.epoch().sequence() {
                preflight.push(PreflightDisposition::ProtectedByNewerCreation(*candidate));
            } else {
                preflight.push(PreflightDisposition::ExactUnreachable(*candidate));
            }
        }

        let mut dispositions = Vec::with_capacity(preflight.len());
        for disposition in preflight {
            if let Some(outcome) = checkpoint(cx) {
                return outcome;
            }
            match disposition {
                PreflightDisposition::Retained(candidate) => {
                    dispositions.push(GcCandidateDisposition::Retained {
                        identity: candidate.identity(),
                    });
                }
                PreflightDisposition::ProtectedByNewerCreation(candidate) => {
                    dispositions.push(GcCandidateDisposition::ProtectedByNewerCreation {
                        identity: candidate.identity(),
                        creation_sequence: candidate.creation().decision_sequence(),
                        basis_sequence: batch.epoch().sequence(),
                    });
                }
                PreflightDisposition::ExactUnreachable(candidate) => {
                    let tombstone = GcTombstone::new(
                        batch.epoch().clone(),
                        candidate,
                        GcTombstoneReason::ExactUnreachable,
                    );
                    if let Err(refusal) = authority.stage_tombstone(&tombstone) {
                        return Outcome::Err(refusal);
                    }
                    if !candidate.horizons().is_mature_at(batch.epoch().sequence()) {
                        dispositions.push(GcCandidateDisposition::Tombstoned {
                            identity: candidate.identity(),
                            grace_until: candidate.horizons().latest(),
                        });
                        continue;
                    }
                    if let Err(refusal) = authority.revalidate_root(batch.epoch().root_proposal()) {
                        return Outcome::Err(GcRefusal::RootRevalidation(refusal));
                    }
                    match authority.revalidate_candidate(&tombstone) {
                        Ok(GcCandidateRevalidation::StillUnretained) => {}
                        Ok(GcCandidateRevalidation::NowRetained) => {
                            dispositions.push(GcCandidateDisposition::RetainedOnRevalidation {
                                identity: candidate.identity(),
                            });
                            continue;
                        }
                        Ok(GcCandidateRevalidation::CreatedAfterBasis(receipt)) => {
                            dispositions.push(GcCandidateDisposition::ProtectedOnRevalidation {
                                identity: candidate.identity(),
                                creation_sequence: receipt.decision_sequence(),
                            });
                            continue;
                        }
                        Ok(GcCandidateRevalidation::GraceExtended(horizons)) => {
                            dispositions.push(
                                GcCandidateDisposition::GraceExtendedOnRevalidation {
                                    identity: candidate.identity(),
                                    grace_until: horizons.latest(),
                                },
                            );
                            continue;
                        }
                        Err(refusal) => return Outcome::Err(refusal),
                    }
                    if !fabric
                        .capabilities()
                        .supports(FabricCapability::ConditionalDeletion)
                    {
                        dispositions.push(GcCandidateDisposition::PhysicalDeletionUnsupported {
                            identity: candidate.identity(),
                        });
                        continue;
                    }
                    match fabric.delete_if_authorized(authority, candidate.identity()) {
                        Ok(DeletionReceipt::Deleted) => {
                            dispositions.push(GcCandidateDisposition::PhysicallyDeleted {
                                identity: candidate.identity(),
                            });
                        }
                        Ok(DeletionReceipt::AlreadyAbsent) => {
                            dispositions.push(GcCandidateDisposition::AlreadyPhysicallyAbsent {
                                identity: candidate.identity(),
                            });
                        }
                        Err(refusal) => return Outcome::Err(GcRefusal::PhysicalDeletion(refusal)),
                    }
                }
            }
        }
        Outcome::Ok(GcReport {
            epoch: batch.epoch().clone(),
            dispositions,
            remaining_candidates: batch.remaining_candidates(),
            resume_after,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreflightDisposition {
    Retained(GcCandidate),
    ProtectedByNewerCreation(GcCandidate),
    ExactUnreachable(GcCandidate),
}

/// Typed refusal from GC source admission, proof reconciliation, or deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcRefusal {
    /// A page with zero candidate capacity cannot make progress.
    ZeroCandidateLimit,
    /// The authority source returned more candidates than the pre-admitted bound.
    BatchTooLarge {
        /// Offered candidate count.
        offered: usize,
        /// Configured maximum candidate count.
        maximum: u16,
    },
    /// An authenticated page repeated one native object identity.
    DuplicateCandidate,
    /// An authenticated page was not strictly ordered by native object identity.
    NonCanonicalCandidateOrder,
    /// A GC epoch omitted one or more required authenticated root classes.
    IncompleteRootClassMaterialization {
        /// Number of plan-required root classes.
        expected: usize,
        /// Number of classes supplied by the authority source.
        observed: usize,
    },
    /// A GC epoch supplied the root classes out of their canonical order.
    NonCanonicalRootClassOrder,
    /// The source did not advance beyond the caller's accepted resume identity.
    ResumeNotAdvanced {
        /// Last accepted identity from the prior page.
        previous: GitOid,
        /// First invalid observed identity in this page.
        observed: GitOid,
    },
    /// An optional accelerator contradicted the independently exact traversal.
    AcceleratorDisagrees {
        /// Candidate whose accelerator answer was unsafe.
        identity: GitOid,
        /// Authority result from exact root traversal.
        exact_reachable: bool,
        /// Optional accelerator's contradictory result.
        accelerator_reachable: bool,
    },
    /// Current authority no longer authenticated the pinned root proof.
    RootRevalidation(StoreRefusal),
    /// Object fabric refused the authenticated conditional physical deletion.
    PhysicalDeletion(StoreRefusal),
    /// A source could not obtain or persist required authenticated GC evidence.
    AuthorityEvidenceUnavailable,
    /// Runtime cancellation was requested without a concrete cancellation reason.
    RuntimeCheckpointRejected,
}

impl fmt::Display for GcRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCandidateLimit => formatter.write_str("GC candidate limit must be non-zero"),
            Self::BatchTooLarge { offered, maximum } => write!(
                formatter,
                "GC source returned {offered} candidates; page bound is {maximum}"
            ),
            Self::DuplicateCandidate => {
                formatter.write_str("GC candidate page repeats a native object identity")
            }
            Self::NonCanonicalCandidateOrder => {
                formatter.write_str("GC candidate page is not in canonical native-object order")
            }
            Self::IncompleteRootClassMaterialization { expected, observed } => write!(
                formatter,
                "GC epoch materialized {observed} root classes; {expected} are required"
            ),
            Self::NonCanonicalRootClassOrder => {
                formatter.write_str("GC epoch root classes are not in canonical exhaustive order")
            }
            Self::ResumeNotAdvanced { .. } => {
                formatter.write_str("GC candidate page did not advance beyond its resume identity")
            }
            Self::AcceleratorDisagrees { .. } => formatter.write_str(
                "GC accelerator disagrees with exact authenticated reachability; deletion refused",
            ),
            Self::RootRevalidation(error) | Self::PhysicalDeletion(error) => {
                fmt::Display::fmt(error, formatter)
            }
            Self::AuthorityEvidenceUnavailable => {
                formatter.write_str("authenticated GC authority evidence is unavailable")
            }
            Self::RuntimeCheckpointRejected => {
                formatter.write_str("GC runtime checkpoint rejected without a cancellation reason")
            }
        }
    }
}

impl Error for GcRefusal {}

fn checkpoint<T, Caps>(cx: &Cx<Caps>) -> Option<Outcome<T, GcRefusal>> {
    if cx.checkpoint().is_ok() {
        return None;
    }
    cx.cancel_reason().map_or_else(
        || Some(Outcome::Err(GcRefusal::RuntimeCheckpointRejected)),
        |reason| Some(Outcome::Cancelled(reason)),
    )
}
