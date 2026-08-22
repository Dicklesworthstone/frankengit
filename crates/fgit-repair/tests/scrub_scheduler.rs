#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};

use asupersync::security::SecurityContext;
use asupersync::{CancelKind, Cx, Outcome};
use fgit_object_fabric::fabric::{ManifestLimits, SegmentManifest};
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope,
    ObjectKind, SegmentLimits, SegmentRecordInput,
};
use fgit_raptorq::{
    RaptorRefusal, RepairPlacementAuthority, VerifiedMicrosegment, protect_microsegment,
};
use fgit_repair::{
    AuthenticatedScrubBatch, AuthenticatedScrubSource, AuthenticatedScrubTarget, DurabilityHealth,
    DurabilityHealthLedger, DurableClass, HealthAlarm, HealthRecord, HealthThresholds,
    RepairOutcome, ScrubMode, ScrubObservation, ScrubProfile, ScrubRefusal, ScrubWorker,
    record_destructive_drill,
};
use fgit_resource::kinds::AuthorityRevalidation;
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1,
    RepositoryAuthorityHeadId, SegmentManifestId,
};

fn security() -> SecurityContext {
    SecurityContext::for_testing(78)
}

fn head(value: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[value; 32]).expect("32-byte corpus fixture body"),
    )
}

fn ledger(region: u64) -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        ResourceVector::from_grades(&[
            (Grade::Bytes, 64 * 1024),
            (Grade::CpuMicros, 10_000),
            (Grade::MemoryBytes, 64 * 1024),
        ]),
    )
}

fn canonical_segment(fill: u8) -> Vec<u8> {
    let limits = SegmentLimits::default();
    let payload = format!("scrub protected payload {fill}").into_bytes();
    let digest = CryptoDigest;
    let envelope = ObjectEnvelope::new(
        b"scrub-tenant".to_vec(),
        GitOid::Sha1(GitOidSha1::from_bytes([fill; GitOidSha1::LEN])),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("test payload fits u64"),
        digest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("canonical payload has a commitment"),
        b"canonical-codec".to_vec(),
        [fill; 32],
        None,
        &limits,
    )
    .expect("canonical test envelope builds");
    let mut builder = MicrosegmentBuilder::new(&digest, limits);
    builder
        .push(SegmentRecordInput { envelope, payload })
        .expect("canonical test record builds");
    builder
        .build()
        .expect("canonical test segment builds")
        .as_bytes()
        .to_vec()
}

fn target(fill: u8, basis: RepositoryAuthorityHeadId) -> AuthenticatedScrubTarget {
    let bytes = canonical_segment(fill);
    let context = security();
    let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &context)
        .expect("canonical segment is RaptorQ protected");
    let reader = MicrosegmentReader::open(&bytes, &CryptoDigest, &SegmentLimits::default())
        .expect("canonical segment is readable");
    let manifest =
        SegmentManifest::from_verified_segment(&reader, Vec::new(), &ManifestLimits::default())
            .expect("verified segment produces a manifest");
    AuthenticatedScrubTarget::new(
        protected.scope().clone(),
        manifest,
        basis,
        protected.symbols().to_vec(),
    )
    .expect("manifest and protected scope agree")
}

fn canonical_batch(
    basis: RepositoryAuthorityHeadId,
    sequence: u64,
    remaining: u32,
    mut targets: Vec<AuthenticatedScrubTarget>,
) -> AuthenticatedScrubBatch {
    targets.sort_by_key(AuthenticatedScrubTarget::identity);
    AuthenticatedScrubBatch::new(basis, sequence, remaining, targets)
        .expect("sorted targets form an authenticated batch")
}

fn profile(max_targets: u16, worker_repairs: u64) -> ScrubProfile {
    ScrubProfile::new(
        ScrubMode::Full,
        max_targets,
        u64::try_from(fgit_raptorq::MicrosegmentRaptorProfile::MAX_SOURCE_BYTES)
            .expect("profile limit fits u64"),
        ResourceVector::from_grades(&[(Grade::Bytes, 16 * 1024), (Grade::CpuMicros, 1_000)]),
        ResourceVector::from_grades(&[
            (Grade::Bytes, worker_repairs * 4_096),
            (Grade::CpuMicros, worker_repairs * 100),
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, 4_096), (Grade::CpuMicros, 100)]),
    )
    .expect("test scrub profile is internally bounded")
}

#[derive(Default)]
struct RecordingHealthLedger {
    records: RefCell<Vec<HealthRecord>>,
}

impl RecordingHealthLedger {
    fn records(&self) -> Vec<HealthRecord> {
        self.records.borrow().clone()
    }
}

impl DurabilityHealthLedger for RecordingHealthLedger {
    fn append(&self, record: HealthRecord) -> Result<(), ScrubRefusal> {
        self.records.borrow_mut().push(record);
        Ok(())
    }
}

struct ScriptedSource {
    batch: AuthenticatedScrubBatch,
    observations: Vec<ScrubObservation>,
    loaded: Cell<u32>,
    probed: Cell<u32>,
    published: Cell<u32>,
    /// Attempt index from which `publish_verified` refuses; `None` never refuses.
    ///
    /// Added for `frankengit-0om4`. The existing counters are untouched: a
    /// refused attempt does not increment `published`, so every assertion that
    /// already reads that counter keeps its original meaning.
    refuse_publish_from: Cell<Option<u32>>,
}

impl ScriptedSource {
    const fn new(batch: AuthenticatedScrubBatch, observations: Vec<ScrubObservation>) -> Self {
        Self {
            batch,
            observations,
            loaded: Cell::new(0),
            probed: Cell::new(0),
            published: Cell::new(0),
            refuse_publish_from: Cell::new(None),
        }
    }

    /// Refuse `publish_verified` from this attempt index onward.
    ///
    /// Attempts are counted in publication order, so `refusing_publish_from(1)`
    /// lets the first target publish and refuses the second -- the permitted
    /// case and the forbidden case in one run, differing only in the port's
    /// answer.
    fn refusing_publish_from(self, attempt: u32) -> Self {
        self.refuse_publish_from.set(Some(attempt));
        self
    }

    const fn probe_count(&self) -> u32 {
        self.probed.get()
    }
}

impl RepairPlacementAuthority for ScriptedSource {
    fn revalidate(
        &self,
        _manifest: &SegmentManifest,
        _authority_basis: RepositoryAuthorityHeadId,
    ) -> AuthorityRevalidation {
        AuthorityRevalidation::StillCurrent
    }

    fn publish_verified(
        &self,
        _candidate: &VerifiedMicrosegment,
        _manifest: &SegmentManifest,
        _authority_basis: RepositoryAuthorityHeadId,
    ) -> Result<(), RaptorRefusal> {
        let attempt = self.published.get();
        if self
            .refuse_publish_from
            .get()
            .is_some_and(|from| attempt >= from)
        {
            // A refusal DISTINCT from the one `repair_microsegment` reports, so
            // the probe shows the placement failure is MAPPED to
            // `PlacementPublicationRefused` rather than propagated verbatim.
            return Err(RaptorRefusal::AuthorityHeadMoved);
        }
        self.published.set(attempt.saturating_add(1));
        Ok(())
    }
}

impl AuthenticatedScrubSource for ScriptedSource {
    fn load_batch(
        &self,
        _after: Option<SegmentManifestId>,
        _limit: u16,
    ) -> Result<AuthenticatedScrubBatch, ScrubRefusal> {
        self.loaded.set(self.loaded.get().saturating_add(1));
        Ok(self.batch.clone())
    }

    fn probe(&self, _target: &AuthenticatedScrubTarget) -> Result<ScrubObservation, ScrubRefusal> {
        let index = usize::try_from(self.probed.get()).expect("probe count fits usize");
        let observation = self
            .observations
            .get(index)
            .copied()
            .expect("test source has one observation per target");
        self.probed.set(self.probed.get().saturating_add(1));
        Ok(observation)
    }
}

struct CancellingSource<Caps> {
    inner: ScriptedSource,
    cx: Cx<Caps>,
}

impl<Caps> RepairPlacementAuthority for CancellingSource<Caps> {
    fn revalidate(
        &self,
        manifest: &SegmentManifest,
        authority_basis: RepositoryAuthorityHeadId,
    ) -> AuthorityRevalidation {
        self.inner.revalidate(manifest, authority_basis)
    }

    fn publish_verified(
        &self,
        candidate: &VerifiedMicrosegment,
        manifest: &SegmentManifest,
        authority_basis: RepositoryAuthorityHeadId,
    ) -> Result<(), RaptorRefusal> {
        self.inner
            .publish_verified(candidate, manifest, authority_basis)
    }
}

impl<Caps> AuthenticatedScrubSource for CancellingSource<Caps> {
    fn load_batch(
        &self,
        after: Option<SegmentManifestId>,
        limit: u16,
    ) -> Result<AuthenticatedScrubBatch, ScrubRefusal> {
        self.inner.load_batch(after, limit)
    }

    fn probe(&self, target: &AuthenticatedScrubTarget) -> Result<ScrubObservation, ScrubRefusal> {
        let observation = self.inner.probe(target)?;
        if self.inner.probe_count() == 1 {
            self.cx
                .cancel_with(CancelKind::User, Some("cancel between scrub targets"));
        }
        Ok(observation)
    }
}

#[test]
fn missing_and_corrupt_placements_emit_suspects_and_reach_repair() {
    let basis = head(7);
    let batch = canonical_batch(basis, 40, 3, vec![target(1, basis), target(2, basis)]);
    let source = ScriptedSource::new(
        batch,
        vec![ScrubObservation::Missing, ScrubObservation::Corrupt],
    );
    let health = RecordingHealthLedger::default();
    let obligations = ledger(1);
    let worker = ScrubWorker::new(profile(2, 2), SegmentLimits::default());
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker.walk(&cx, &source, &obligations, &health, &security(), None)
    else {
        panic!("the seeded missing/corrupt repair path must proceed");
    };
    assert_eq!(report.suspect_targets, 2);
    assert_eq!(report.repairs_published, 2);
    assert_eq!(
        source.published.get(),
        2,
        "both suspects must enter repair publication"
    );
    let records = health.records();
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record, HealthRecord::Suspect { .. }))
            .count(),
        2,
        "the repair machine must be entered through durable Suspect evidence"
    );
    assert!(obligations.close().is_quiescent());
}

#[test]
fn foreground_floor_refuses_before_the_scrub_source_is_read() {
    let basis = head(8);
    let batch = canonical_batch(basis, 41, 0, vec![target(3, basis)]);
    let source = ScriptedSource::new(batch, vec![ScrubObservation::Verified]);
    let health = RecordingHealthLedger::default();
    let obligations = ObligationLedger::root(
        RegionId::new(2),
        LeakDisposition::RecordAndContinue,
        ResourceVector::from_grades(&[(Grade::Bytes, 19_000), (Grade::CpuMicros, 2_000)]),
    );
    let worker = ScrubWorker::new(profile(1, 1), SegmentLimits::default());
    let cx = Cx::detached_cancel_context();

    assert!(matches!(
        worker.walk(&cx, &source, &obligations, &health, &security(), None),
        Outcome::Err(ScrubRefusal::ForegroundFloorWouldBeViolated { .. })
    ));
    assert_eq!(
        source.loaded.get(),
        0,
        "foreground admission must precede source work"
    );
    assert!(obligations.close().is_quiescent());
}

#[test]
fn cancellation_between_targets_releases_worker_budget() {
    let basis = head(9);
    let batch = canonical_batch(basis, 42, 0, vec![target(4, basis), target(5, basis)]);
    let cx = Cx::detached_cancel_context();
    let source = CancellingSource {
        inner: ScriptedSource::new(
            batch,
            vec![ScrubObservation::Verified, ScrubObservation::Verified],
        ),
        cx: cx.clone(),
    };
    let health = RecordingHealthLedger::default();
    let obligations = ledger(3);
    let worker = ScrubWorker::new(profile(2, 1), SegmentLimits::default());

    assert!(matches!(
        worker.walk(&cx, &source, &obligations, &health, &security(), None),
        Outcome::Cancelled(_)
    ));
    assert_eq!(
        source.inner.probe_count(),
        1,
        "cancellation stops before the second target"
    );
    assert!(
        obligations.close().is_quiescent(),
        "cancellation must release the worker grant rather than leak it"
    );
}

#[test]
fn sample_selection_is_deterministic_across_input_order() {
    let basis = head(10);
    let targets = [target(6, basis), target(7, basis), target(8, basis)];
    let mode = ScrubMode::sample(1, 2).expect("one half is a valid sample");
    let mut first: Vec<_> = targets
        .iter()
        .map(AuthenticatedScrubTarget::identity)
        .filter(|identity| mode.selects(*identity))
        .collect();
    let mut second: Vec<_> = targets
        .iter()
        .rev()
        .map(AuthenticatedScrubTarget::identity)
        .filter(|identity| mode.selects(*identity))
        .collect();
    first.sort_unstable();
    second.sort_unstable();
    assert_eq!(
        first, second,
        "sample membership must not depend on source order"
    );
}

#[test]
fn noncanonical_authenticated_batch_is_refused_and_sorted_twin_proceeds() {
    let basis = head(11);
    let first = target(9, basis);
    let second = target(10, basis);
    let mut unordered = vec![first.clone(), second.clone()];
    unordered.sort_by_key(AuthenticatedScrubTarget::identity);
    unordered.reverse();
    assert!(matches!(
        AuthenticatedScrubBatch::new(basis, 43, 0, unordered),
        Err(ScrubRefusal::NonCanonicalTargetOrder)
    ));
    let mut sorted = vec![first, second];
    sorted.sort_by_key(AuthenticatedScrubTarget::identity);
    assert!(AuthenticatedScrubBatch::new(basis, 43, 0, sorted).is_ok());
}

#[test]
fn over_limit_batch_is_refused_before_any_placement_probe() {
    let basis = head(12);
    let batch = canonical_batch(basis, 44, 0, vec![target(11, basis), target(12, basis)]);
    let source = ScriptedSource::new(
        batch,
        vec![ScrubObservation::Verified, ScrubObservation::Verified],
    );
    let health = RecordingHealthLedger::default();
    let obligations = ledger(4);
    let worker = ScrubWorker::new(profile(1, 1), SegmentLimits::default());
    let cx = Cx::detached_cancel_context();

    assert!(matches!(
        worker.walk(&cx, &source, &obligations, &health, &security(), None),
        Outcome::Err(ScrubRefusal::BatchTooLarge { .. })
    ));
    assert_eq!(source.probe_count(), 0);
    assert!(obligations.close().is_quiescent());
}

#[test]
fn health_replay_tracks_injected_backlog_and_raises_threshold_alarm() {
    let basis = head(13);
    let target = target(13, basis).identity();
    let records = vec![
        HealthRecord::DestructiveDrillCompleted {
            class: DurableClass::MicrosegmentV1,
            sequence: 9,
        },
        HealthRecord::TargetChecked {
            class: DurableClass::MicrosegmentV1,
            sequence: 9,
            target,
            observation: ScrubObservation::Verified,
        },
        HealthRecord::TargetChecked {
            class: DurableClass::MicrosegmentV1,
            sequence: 10,
            target,
            observation: ScrubObservation::Corrupt,
        },
        HealthRecord::Suspect {
            class: DurableClass::MicrosegmentV1,
            sequence: 10,
            target,
            observation: ScrubObservation::Corrupt,
        },
        HealthRecord::Repair {
            class: DurableClass::MicrosegmentV1,
            sequence: 10,
            target,
            outcome: RepairOutcome::Refused(RaptorRefusal::DecodeFailed),
        },
        HealthRecord::WalkCompleted {
            class: DurableClass::MicrosegmentV1,
            sequence: 10,
            checked_targets: 1,
            skipped_targets: 0,
            remaining_targets: 3,
        },
    ];
    let health = DurabilityHealth::replay(&records).expect("ordered health records replay");
    let metrics = health.metrics();
    assert_eq!(metrics.suspect_targets, 1);
    assert_eq!(metrics.repairs_refused, 1);
    assert_eq!(metrics.checked_targets, 2);
    assert_eq!(metrics.last_walk_checked_targets, Some(1));
    assert_eq!(metrics.remaining_targets, 3);
    assert_eq!(metrics.coverage_per_mille(), 250);
    let alarms = health.alarms(13, HealthThresholds::new(2, 500, 2).expect("valid bounds"));
    assert!(alarms.iter().any(|alarm| matches!(
        alarm,
        HealthAlarm::CoverageBelowMinimum {
            observed: 250,
            minimum: 500
        }
    )));
    assert!(alarms.iter().any(|alarm| matches!(
        alarm,
        HealthAlarm::DestructiveDrillOverdue {
            last_drill: Some(9),
            ..
        }
    )));
}

#[test]
fn drill_cadence_flags_an_overdue_class_and_a_fresh_drill_proceeds() {
    let health = RecordingHealthLedger::default();
    record_destructive_drill(&health, 20).expect("drill evidence appends");
    let replayed = DurabilityHealth::replay(&health.records()).expect("drill evidence replays");
    let thresholds = HealthThresholds::new(100, 0, 2).expect("valid bounds");
    assert!(
        !replayed
            .alarms(22, thresholds)
            .iter()
            .any(|alarm| matches!(alarm, HealthAlarm::DestructiveDrillOverdue { .. })),
        "a drill inside cadence must proceed"
    );
    assert!(
        replayed.alarms(23, thresholds).iter().any(|alarm| matches!(
            alarm,
            HealthAlarm::DestructiveDrillOverdue {
                last_drill: Some(20),
                ..
            }
        )),
        "one sequence beyond cadence must raise the typed alarm"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

/// frankengit-0om4: a refused placement publication is reported as such.
///
/// # What this reaches, and why the refusal is attributable
///
/// `PlacementPublicationRefused` is raised inside `repair_microsegment` only
/// after the whole repair chain has already succeeded: manifest identity,
/// decode budget, the `RepairPermit` reservation, microsegment reconstruction,
/// reader open, `verify_segment_reality`, authority revalidation, and the
/// settlement pre-check. It is the last thing that can fail before publication.
///
/// So the probe drives the real chain rather than an inner helper, and the
/// FIRST target publishing is what proves every earlier stage works. The second
/// target differs in exactly one respect -- the placement port's answer -- which
/// is what makes its refusal attributable to that port and nothing else.
///
/// The scripted port returns `AuthorityHeadMoved`, deliberately NOT the refusal
/// under test, so the assertion also shows `repair_microsegment` MAPS a
/// placement failure to `PlacementPublicationRefused` rather than propagating
/// whatever the port said.
#[test]
fn a_refused_placement_publication_is_named_in_the_health_record() {
    let basis = head(7);
    let batch = canonical_batch(basis, 40, 3, vec![target(1, basis), target(2, basis)]);
    let source = ScriptedSource::new(
        batch,
        vec![ScrubObservation::Missing, ScrubObservation::Corrupt],
    )
    .refusing_publish_from(1);
    let health = RecordingHealthLedger::default();
    let obligations = ledger(1);
    let worker = ScrubWorker::new(profile(2, 2), SegmentLimits::default());
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker.walk(&cx, &source, &obligations, &health, &security(), None)
    else {
        panic!("a refused publication is a recorded outcome, not a walk failure");
    };

    assert_eq!(report.suspect_targets, 2, "both targets must enter repair");
    assert_eq!(
        (report.repairs_published, report.repairs_refused),
        (1, 1),
        "the permitted twin published and the refused one did not, in one run",
    );
    assert_eq!(
        source.published.get(),
        1,
        "a refused attempt must not increment the publication counter",
    );

    let records = health.records();
    let published = records
        .iter()
        .filter(|record| {
            matches!(
                record,
                HealthRecord::Repair {
                    outcome: RepairOutcome::Published,
                    ..
                }
            )
        })
        .count();
    let refused = records
        .iter()
        .filter(|record| {
            matches!(
                record,
                HealthRecord::Repair {
                    outcome: RepairOutcome::Refused(RaptorRefusal::PlacementPublicationRefused),
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        (published, refused),
        (1, 1),
        "the refusal must reach durable evidence NAMED, not merely counted; got {records:?}",
    );

    assert!(
        obligations.close().is_quiescent(),
        "the refused repair must settle its reservation rather than leak it",
    );
}

/// The permitted twin at the boundary the mode itself introduces.
///
/// `refusing_publish_from(2)` is one past the last attempt, so the scripted
/// failure mode is armed and never fires. Without this, the probe above is
/// equally satisfied by a harness that refuses whenever the mode is set at all,
/// which would prove nothing about the attempt index.
#[test]
fn an_armed_but_unreached_publish_refusal_leaves_every_repair_published() {
    let basis = head(7);
    let batch = canonical_batch(basis, 40, 3, vec![target(1, basis), target(2, basis)]);
    let source = ScriptedSource::new(
        batch,
        vec![ScrubObservation::Missing, ScrubObservation::Corrupt],
    )
    .refusing_publish_from(2);
    let health = RecordingHealthLedger::default();
    let obligations = ledger(1);
    let worker = ScrubWorker::new(profile(2, 2), SegmentLimits::default());
    let cx = Cx::detached_cancel_context();

    let Outcome::Ok(report) = worker.walk(&cx, &source, &obligations, &health, &security(), None)
    else {
        panic!("an unreached refusal must not disturb the repair path");
    };

    assert_eq!(
        (report.repairs_published, report.repairs_refused),
        (2, 0),
        "the mode is armed at an attempt index the run never reaches",
    );
    assert_eq!(source.published.get(), 2);
    assert!(obligations.close().is_quiescent());
}
