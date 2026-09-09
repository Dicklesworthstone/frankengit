//! Process-local ownership of one pinned workspace and its publication lease.

use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::{SealAttempt, SealFailure, TerminalOutcome};
use fgit_codec::CodecRefusal;
use fgit_crypto::{GitHashAlgorithm, GitOid};
use fgit_resource::{
    ContainmentFailure, Grade, LeakDisposition, LifecycleError, ObligationLedger,
    RegionCloseOutcome, RegionId, ReserveError, ReservedObligation, ResourceError, ResourceVector,
    SettledObligation,
};
use fgit_treefs::{
    AntiRollbackRefusal, BaseView, EpochRefusal, EpochSet, ExportLimits, ExportPlan, IntentLog,
    Overlay, OverlayRoot, OverlayStats, SessionRecord, TreeCapability, TreeEditIntent,
    WorkspaceAbortReason, WorkspaceLease, WorkspaceLeaseAbort, WorkspaceLeaseCommit,
    WorkspaceLeaseReservation, WorkspaceSnapshotBody,
};
use fgit_types::{DecisionOutcome, TxId};

static NEXT_REGION: AtomicU64 = AtomicU64::new(1);

/// Why the node-owned workspace could not advance or settle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceSessionRefusal {
    /// The pinned base and capability name different repositories.
    RepositoryMismatch,
    /// The owner already closed its resource ledger.
    Closed,
    /// The workspace lease has committed or aborted and cannot accept edits.
    Retired,
    /// A retained attempt requires same-store drain and outcome reconciliation.
    PublicationPending { tx_id: TxId },
    /// No publication attempt is retained by this owner.
    NoPendingPublication,
    /// Reconciliation names a different transaction from the retained attempt.
    PublicationMismatch,
    /// No node-validated export has been adopted.
    MissingExport,
    /// The proposed log does not preserve the already adopted intent prefix.
    IntentLogRewritten,
    /// The declared construction or reservation bound was exceeded.
    Capacity {
        resource: &'static str,
        observed: usize,
        limit: usize,
    },
    /// A proposed export contains bytes that do not match its object identities.
    InvalidExport,
    /// The process-local ledger label space was exhausted.
    RegionExhausted,
    /// Snapshot encoding failed.
    Codec(CodecRefusal),
    /// Workspace publication epochs were inconsistent.
    Epoch(EpochRefusal),
    /// The existing session anti-rollback guard rejected the generated advance.
    AntiRollback(AntiRollbackRefusal),
    /// The exact publication attempt could not derive its stable identity.
    Seal(Box<SealFailure>),
    /// Resource capacity could not be granted.
    Resource(ResourceError),
    /// A required reservation grade was unavailable.
    Reservation(ReserveError),
    /// Settlement was refused; the owner retains the returned obligation.
    Settlement(LifecycleError),
    /// Explicit ledger close did not prove quiescence.
    Containment(Box<ContainmentFailure>),
}

impl std::fmt::Display for WorkspaceSessionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workspace session refused: {self:?}")
    }
}

impl std::error::Error for WorkspaceSessionRefusal {}

/// Retained before the publication driver may issue any store write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingPublication {
    pub(super) attempt: SealAttempt,
    pub(super) tx_id: TxId,
}

/// The node map owns this value across dropped response futures.
#[derive(Debug)]
pub(super) struct SessionState<A: GitHashAlgorithm> {
    base: BaseView<A>,
    capability: TreeCapability,
    log: IntentLog,
    overlay: Overlay,
    session: SessionRecord<A>,
    plan: Option<ExportPlan<A>>,
    limits: ExportLimits,
    pending: Option<PendingPublication>,
    ledger: Option<ObligationLedger>,
    lease: Option<ReservedObligation<WorkspaceLease>>,
}

impl<A: GitHashAlgorithm> SessionState<A> {
    pub(super) fn new(
        base: BaseView<A>,
        capability: TreeCapability,
        limits: ExportLimits,
    ) -> Result<Self, WorkspaceSessionRefusal> {
        if base.repository_id() != capability.repository_id() {
            return Err(WorkspaceSessionRefusal::RepositoryMismatch);
        }
        for (resource, limit) in [
            ("overlay bytes", limits.max_total_bytes),
            ("overlay entries", limits.max_objects),
        ] {
            if limit == 0 {
                return Err(WorkspaceSessionRefusal::Capacity {
                    resource,
                    observed: 1,
                    limit,
                });
            }
        }
        let region = NEXT_REGION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| WorkspaceSessionRefusal::RegionExhausted)?;
        let capacity = ResourceVector::from_grades(&[
            (Grade::Bytes, limits.max_total_bytes as u64),
            (Grade::Objects, limits.max_objects as u64),
        ]);
        // ExportLimits is this owner's declared root capacity. This ledger is
        // accounting for local workspace custody, never repository authority.
        let ledger =
            ObligationLedger::root(RegionId::new(region), LeakDisposition::FailFast, capacity);
        let grant = match ledger.grant(capacity) {
            Ok(grant) => grant,
            Err(error) => {
                return Err(close_after_constructor_error(
                    ledger,
                    WorkspaceSessionRefusal::Resource(error),
                ));
            }
        };
        let reservation = WorkspaceLeaseReservation {
            workspace_id: capability.workspace_id(),
            reserved_bytes: limits.max_total_bytes as u64,
            reserved_entries: limits.max_objects as u64,
        };
        let lease = match ledger.reserve::<WorkspaceLease>(reservation, grant) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(close_after_constructor_error(
                    ledger,
                    WorkspaceSessionRefusal::Reservation(error),
                ));
            }
        };
        let overlay = Overlay::new();
        let initial = snapshot(&base, &capability, &overlay, EpochSet::new());
        Ok(Self {
            base,
            capability,
            log: IntentLog::new(),
            overlay,
            session: SessionRecord::open(initial),
            plan: None,
            limits,
            pending: None,
            ledger: Some(ledger),
            lease: Some(lease),
        })
    }

    pub(super) const fn base(&self) -> &BaseView<A> {
        &self.base
    }
    pub(super) const fn capability(&self) -> &TreeCapability {
        &self.capability
    }
    pub(super) const fn capability_mut(&mut self) -> &mut TreeCapability {
        &mut self.capability
    }
    pub(super) const fn log(&self) -> &IntentLog {
        &self.log
    }
    pub(super) const fn overlay(&self) -> &Overlay {
        &self.overlay
    }
    pub(super) const fn plan(&self) -> Option<&ExportPlan<A>> {
        self.plan.as_ref()
    }
    pub(super) const fn limits(&self) -> ExportLimits {
        self.limits
    }
    pub(super) const fn snapshot(&self) -> &WorkspaceSnapshotBody<A> {
        self.session.latest()
    }
    pub(super) fn tree(&self) -> &GitOid<A> {
        self.plan
            .as_ref()
            .map_or_else(|| self.base.base_tree_oid(), ExportPlan::root_tree)
    }
    pub(super) const fn pending(&self) -> Option<&PendingPublication> {
        self.pending.as_ref()
    }
    pub(super) const fn is_retired(&self) -> bool {
        self.lease.is_none()
    }
    pub(super) const fn is_closed(&self) -> bool {
        self.ledger.is_none()
    }

    fn require_editable(&self) -> Result<(), WorkspaceSessionRefusal> {
        if self.is_closed() {
            return Err(WorkspaceSessionRefusal::Closed);
        }
        if self.is_retired() {
            return Err(WorkspaceSessionRefusal::Retired);
        }
        if let Some(pending) = &self.pending {
            return Err(WorkspaceSessionRefusal::PublicationPending {
                tx_id: pending.tx_id,
            });
        }
        Ok(())
    }

    /// Accept only the node's evaluated overlay/export, deriving the immutable
    /// snapshot here. No caller-supplied snapshot or epoch enters this method.
    pub(super) fn adopt(
        &mut self,
        log: IntentLog,
        overlay: Overlay,
        plan: ExportPlan<A>,
    ) -> Result<(), WorkspaceSessionRefusal> {
        self.require_editable()?;
        if !log.intents().starts_with(self.log.intents()) {
            return Err(WorkspaceSessionRefusal::IntentLogRewritten);
        }
        check_limit("intent count", log.len(), self.limits.max_objects)?;
        let intent_bytes = log.intents().iter().try_fold(0usize, |total, intent| {
            let added = match intent {
                TreeEditIntent::Write { content, .. } => content.len(),
                TreeEditIntent::CreateSymlink { link_target, .. } => link_target.len(),
                TreeEditIntent::RecordConflictMarkers { marker, .. } => marker.len(),
                _ => 0,
            };
            total
                .checked_add(added)
                .ok_or(WorkspaceSessionRefusal::Capacity {
                    resource: "intent bytes",
                    observed: usize::MAX,
                    limit: self.limits.max_total_bytes,
                })
        })?;
        check_limit("intent bytes", intent_bytes, self.limits.max_total_bytes)?;
        let stats = overlay.stats();
        check_limit(
            "overlay bytes",
            stats.body_bytes,
            self.limits.max_total_bytes,
        )?;
        check_limit(
            "overlay entries",
            stats.entry_count,
            self.limits.max_objects,
        )?;
        check_limit(
            "export objects",
            plan.object_count(),
            self.limits.max_objects,
        )?;
        let export_bytes = plan.objects().try_fold(0usize, |total, object| {
            total
                .checked_add(object.body().len())
                .ok_or(WorkspaceSessionRefusal::Capacity {
                    resource: "export bytes",
                    observed: usize::MAX,
                    limit: self.limits.max_total_bytes,
                })
        })?;
        check_limit("export bytes", export_bytes, self.limits.max_total_bytes)?;
        if !plan.verify_all() {
            return Err(WorkspaceSessionRefusal::InvalidExport);
        }
        self.lease
            .as_ref()
            .ok_or(WorkspaceSessionRefusal::Retired)?
            .can_settle(&charges(stats))
            .map_err(WorkspaceSessionRefusal::Settlement)?;
        let epochs = self
            .snapshot()
            .epochs()
            .stage()
            .publish()
            .map_err(WorkspaceSessionRefusal::Epoch)?;
        let proposed = snapshot(&self.base, &self.capability, &overlay, epochs);
        let mut next = self.session.clone();
        if let Err(error) = next.adopt(proposed) {
            // The TreeFS lease contract forbids continuing on an anti-rollback
            // refusal; the current snapshot itself remains unchanged.
            let _settled = self.abort_lease(WorkspaceAbortReason::RollbackRefused)?;
            return Err(WorkspaceSessionRefusal::AntiRollback(error));
        }
        self.log = log;
        self.overlay = overlay;
        self.plan = Some(plan);
        self.session = next;
        Ok(())
    }

    pub(super) fn begin_publication(
        &mut self,
        attempt: SealAttempt,
    ) -> Result<TxId, WorkspaceSessionRefusal> {
        self.require_editable()?;
        if self.plan.is_none() {
            return Err(WorkspaceSessionRefusal::MissingExport);
        }
        if attempt.repository_id != self.base.repository_id() {
            return Err(WorkspaceSessionRefusal::RepositoryMismatch);
        }
        let (tx_id, _) = attempt
            .derive()
            .map_err(|error| WorkspaceSessionRefusal::Seal(Box::new(error)))?;
        self.pending = Some(PendingPublication { attempt, tx_id });
        Ok(tx_id)
    }

    /// The node calls this only after same-store drain and authenticated lookup
    /// for tx_id. None means proven undecided after that drain, never a failed
    /// lookup or a dropped response. Errors retain both pending attempt and lease.
    pub(super) fn reconcile_publication(
        &mut self,
        tx_id: TxId,
        outcome: Option<&TerminalOutcome>,
    ) -> Result<Option<SettledObligation<WorkspaceLease>>, WorkspaceSessionRefusal> {
        if self.is_closed() {
            return Err(WorkspaceSessionRefusal::Closed);
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(WorkspaceSessionRefusal::NoPendingPublication)?;
        if pending.tx_id != tx_id {
            return Err(WorkspaceSessionRefusal::PublicationMismatch);
        }
        let committed = outcome
            .is_some_and(|terminal| matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        if !committed {
            self.pending = None;
            return Ok(None);
        }
        let stats = self.overlay.stats();
        let actual = charges(stats);
        let receipt = WorkspaceLeaseCommit {
            workspace_id: self.capability.workspace_id(),
            snapshot_digest: self
                .snapshot()
                .snapshot_digest()
                .map_err(WorkspaceSessionRefusal::Codec)?,
            epochs: self.snapshot().epochs(),
            observed: stats,
        };
        self.lease
            .as_ref()
            .ok_or(WorkspaceSessionRefusal::Retired)?
            .can_settle(&actual)
            .map_err(WorkspaceSessionRefusal::Settlement)?;
        let lease = self.lease.take().ok_or(WorkspaceSessionRefusal::Retired)?;
        let settled = match lease.commit_internal(receipt, &actual) {
            Ok(settled) => settled,
            Err(refused) => {
                let error = refused.error();
                self.lease = Some(refused.into_obligation());
                return Err(WorkspaceSessionRefusal::Settlement(error));
            }
        };
        self.pending = None;
        Ok(Some(settled))
    }

    fn abort_lease(
        &mut self,
        reason: WorkspaceAbortReason,
    ) -> Result<Option<SettledObligation<WorkspaceLease>>, WorkspaceSessionRefusal> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(None);
        };
        let stats = self.overlay.stats();
        let actual = charges(stats);
        lease
            .can_settle(&actual)
            .map_err(WorkspaceSessionRefusal::Settlement)?;
        let receipt = WorkspaceLeaseAbort {
            workspace_id: self.capability.workspace_id(),
            reason,
            discarded: stats,
        };
        let lease = self.lease.take().ok_or(WorkspaceSessionRefusal::Retired)?;
        match lease.abort(receipt, &actual) {
            Ok(settled) => Ok(Some(settled)),
            Err(refused) => {
                let error = refused.error();
                self.lease = Some(refused.into_obligation());
                Err(WorkspaceSessionRefusal::Settlement(error))
            }
        }
    }

    pub(super) fn close(&mut self) -> Result<RegionCloseOutcome, WorkspaceSessionRefusal> {
        if let Some(pending) = &self.pending {
            return Err(WorkspaceSessionRefusal::PublicationPending {
                tx_id: pending.tx_id,
            });
        }
        if self.is_closed() {
            return Err(WorkspaceSessionRefusal::Closed);
        }
        let _settled = self.abort_lease(WorkspaceAbortReason::Discarded)?;
        match self
            .ledger
            .take()
            .ok_or(WorkspaceSessionRefusal::Closed)?
            .close()
        {
            outcome @ RegionCloseOutcome::Quiescent(_) => Ok(outcome),
            RegionCloseOutcome::ContainmentFailure(failure) => {
                Err(WorkspaceSessionRefusal::Containment(Box::new(failure)))
            }
        }
    }
}

fn snapshot<A: GitHashAlgorithm>(
    base: &BaseView<A>,
    capability: &TreeCapability,
    overlay: &Overlay,
    epochs: EpochSet,
) -> WorkspaceSnapshotBody<A> {
    WorkspaceSnapshotBody::new(
        capability.workspace_id(),
        base.repository_id(),
        base.base_rcr_id(),
        *base.base_commit_oid(),
        *base.base_tree_oid(),
        OverlayRoot::of(overlay),
        epochs,
    )
}

fn charges(stats: OverlayStats) -> ResourceVector {
    ResourceVector::from_grades(&[
        (Grade::Bytes, stats.body_bytes as u64),
        (Grade::Objects, stats.entry_count as u64),
    ])
}

fn check_limit(
    resource: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), WorkspaceSessionRefusal> {
    if observed > limit {
        Err(WorkspaceSessionRefusal::Capacity {
            resource,
            observed,
            limit,
        })
    } else {
        Ok(())
    }
}

fn close_after_constructor_error(
    ledger: ObligationLedger,
    error: WorkspaceSessionRefusal,
) -> WorkspaceSessionRefusal {
    match ledger.close() {
        RegionCloseOutcome::Quiescent(_) => error,
        RegionCloseOutcome::ContainmentFailure(failure) => {
            WorkspaceSessionRefusal::Containment(Box::new(failure))
        }
    }
}

#[cfg(test)]
mod tests {
    use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, SemanticRequest};
    use fgit_crypto::{GitObjectKind, NativeObjectIdentity, Sha1};
    use fgit_git_object::ParseLimits;
    use fgit_resource::{ObligationState, TerminalEvidence};
    use fgit_treefs::{
        EntryClass, ExportPlanner, FileMode, ObjectSource, ObjectSourceError, PathPolicy,
        ReadGrant, TreePath, WorkspaceId,
    };
    use fgit_types::{
        CodecVersion, DecisionSequence, DigestAlgorithmId, DigestBytes, GitHashAlgorithm as Format,
        GitOid as AnyOid, GitOidSha1, PrincipalId, RefName, RefusalCode, RefusalRecordId,
        RepositoryCommitId, RepositoryId, SchemaFamily, SchemaId, TenantId,
    };

    use super::*;

    /// The real empty Git tree is sufficient for this pure owner model. Node
    /// authority selection and publication are exercised by node integration tests.
    struct EmptyTree;
    impl ObjectSource<Sha1> for EmptyTree {
        fn read_object(
            &self,
            oid: &GitOid<Sha1>,
            kind: GitObjectKind,
            _: &ReadGrant,
        ) -> Result<Vec<u8>, ObjectSourceError> {
            if kind == GitObjectKind::Tree && *oid == GitOid::of_object(GitObjectKind::Tree, b"") {
                Ok(Vec::new())
            } else {
                Err(ObjectSourceError::NotFound {
                    oid_hex: String::new(),
                })
            }
        }
    }

    fn rcr() -> RepositoryCommitId {
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[7; 32]).expect("digest"),
        )
    }

    fn fixture(limits: ExportLimits) -> SessionState<Sha1> {
        let tree = GitOid::<Sha1>::of_object(GitObjectKind::Tree, b"");
        let tree_hex: String = tree
            .digest_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let commit = format!(
            "tree {tree_hex}\nauthor Owner <owner@example.test> 1 +0000\ncommitter Owner <owner@example.test> 1 +0000\n\nbase\n"
        );
        let repository = RepositoryId::from_bytes([2; 16]);
        let base = BaseView::new(
            repository,
            rcr(),
            GitOid::of_object(GitObjectKind::Commit, commit.as_bytes()),
            tree,
            ParseLimits::default(),
            PathPolicy::default(),
        );
        let capability = TreeCapability::new(
            WorkspaceId::from_bytes([3; 16]),
            repository,
            vec![path()],
            vec![path()],
        );
        SessionState::new(base, capability, limits).expect("bounded owner")
    }

    fn path() -> TreePath {
        TreePath::parse_default(b"file").expect("path")
    }

    fn append(log: &IntentLog, body: &[u8]) -> IntentLog {
        let mut log = log.clone();
        log.push(TreeEditIntent::Write {
            path: path(),
            content: body.to_vec(),
            mode: FileMode::Regular,
            entry_class: EntryClass::Content,
        });
        log
    }

    fn proposed(state: &SessionState<Sha1>, log: &IntentLog) -> (Overlay, ExportPlan<Sha1>) {
        let (overlay, evaluation) = log.evaluate(&|_| false);
        assert!(evaluation.errors().is_empty());
        let mut capability = state.capability().clone();
        let plan = ExportPlanner::new(ExportLimits::default(), ParseLimits::default())
            .plan(
                state.base(),
                &EmptyTree,
                &mut capability,
                &overlay,
                0,
                &|| false,
            )
            .expect("real export planner");
        (overlay, plan)
    }

    fn attempt(state: &SessionState<Sha1>, key: u8) -> SealAttempt {
        SealAttempt {
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: state.base().repository_id(),
            authenticated_principal_id: PrincipalId::from_bytes([4; 16]),
            idempotency_key: IdempotencyKey::new(vec![key]).expect("key"),
            request: SemanticRequest::build(
                SchemaId::new(SchemaFamily::from_static("workspace-owner-test"), 1, 0),
                Format::Sha1,
                true,
                vec![RefCommand {
                    name: RefName::try_new(b"refs/heads/result").expect("ref"),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(AnyOid::Sha1(GitOidSha1::from_bytes(
                        state
                            .base()
                            .base_commit_oid()
                            .digest_bytes()
                            .try_into()
                            .expect("sha1 width"),
                    ))),
                    force: false,
                }],
                Vec::new(),
                Vec::new(),
            )
            .expect("canonical request"),
        }
    }

    fn adopted() -> SessionState<Sha1> {
        let mut state = fixture(ExportLimits::default());
        let log = append(state.log(), b"first");
        let (overlay, plan) = proposed(&state, &log);
        state.adopt(log, overlay, plan).expect("adopt");
        state
    }

    #[test]
    fn snapshots_follow_actual_overlay_and_replay_without_claiming_durability() {
        let mut left = adopted();
        let mut right = adopted();
        assert_eq!(left.snapshot(), right.snapshot());
        assert_eq!(left.tree(), right.tree());
        assert_eq!(left.snapshot().epochs().staged().get(), 1);
        assert_eq!(left.snapshot().epochs().visible().get(), 1);
        assert_eq!(left.snapshot().epochs().durable().get(), 0);
        for state in [&mut left, &mut right] {
            let before = state.snapshot().clone();
            let rewritten = append(&IntentLog::new(), b"changed prefix");
            let (overlay, plan) = proposed(state, &rewritten);
            assert_eq!(
                state.adopt(rewritten, overlay, plan),
                Err(WorkspaceSessionRefusal::IntentLogRewritten)
            );
            assert_eq!(state.snapshot(), &before);
            let log = append(state.log(), b"second");
            let (overlay, plan) = proposed(state, &log);
            state.adopt(log, overlay, plan).expect("cumulative advance");
            assert_eq!(
                state.snapshot().overlay_root(),
                OverlayRoot::of(state.overlay())
            );
            assert_eq!(state.snapshot().epochs().staged().get(), 2);
            assert_eq!(state.snapshot().epochs().visible().get(), 2);
            assert_eq!(state.snapshot().epochs().durable().get(), 0);
        }
        assert_eq!(left.snapshot(), right.snapshot());
        assert_eq!(left.tree(), right.tree());
        assert!(left.close().expect("close").is_quiescent());
        assert!(right.close().expect("close").is_quiescent());
    }

    #[test]
    fn refused_capacity_preserves_snapshot_and_permitted_twin_advances() {
        let mut state = fixture(ExportLimits {
            max_total_bytes: 64,
            max_objects: 4,
            max_tree_entries: 4,
        });
        let before = state.snapshot().clone();
        let excessive = append(state.log(), &[9; 65]);
        let (overlay, plan) = proposed(&state, &excessive);
        assert!(matches!(
            state.adopt(excessive, overlay, plan),
            Err(WorkspaceSessionRefusal::Capacity { .. })
        ));
        assert_eq!(state.snapshot(), &before);
        assert!(state.log().is_empty());
        assert_eq!(state.overlay().stats().body_bytes, 0);
        let permitted = append(state.log(), b"ok");
        let (overlay, plan) = proposed(&state, &permitted);
        state
            .adopt(permitted, overlay, plan)
            .expect("within reservation");
        assert_eq!(state.overlay().stats().body_bytes, 2);
        assert!(state.close().expect("close").is_quiescent());
        assert!(state.is_closed());
    }

    #[test]
    fn pending_publication_freezes_custody_and_canonical_commit_settles_actual_receipt() {
        let mut state = adopted();
        let original = attempt(&state, 1);
        let expected = original.derive().expect("identity").0;
        assert_eq!(
            state
                .begin_publication(original.clone())
                .expect("retain before publication"),
            expected
        );
        assert_eq!(state.pending().expect("retained").attempt, original);
        assert!(matches!(
            state.close(),
            Err(WorkspaceSessionRefusal::PublicationPending { .. })
        ));
        let log = append(state.log(), b"blocked");
        let (overlay, plan) = proposed(&state, &log);
        assert!(matches!(
            state.adopt(log, overlay, plan),
            Err(WorkspaceSessionRefusal::PublicationPending { .. })
        ));
        assert!(
            state
                .reconcile_publication(expected, None)
                .expect("drained undecided")
                .is_none()
        );
        assert!(!state.is_retired());
        let tx_id = state
            .begin_publication(original)
            .expect("retry same exact attempt");
        assert_eq!(tx_id, expected);
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(1).expect("sequence"),
            outcome: DecisionOutcome::Committed {
                repository_commit_id: rcr(),
            },
        };
        let settled = state
            .reconcile_publication(tx_id, Some(&terminal))
            .expect("observed canonical commit")
            .expect("commit receipt");
        assert_eq!(settled.state(), ObligationState::Acknowledged);
        match settled.evidence() {
            TerminalEvidence::Acknowledged(receipt, _) => {
                assert_eq!(
                    receipt.snapshot_digest,
                    state.snapshot().snapshot_digest().expect("snapshot digest")
                );
                assert_eq!(receipt.epochs, state.snapshot().epochs());
                assert_eq!(receipt.observed, state.overlay().stats());
                assert_eq!(receipt.epochs.durable().get(), 0);
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
        drop(settled);
        assert!(state.is_retired());
        assert!(state.pending().is_none());
        assert!(
            state
                .close()
                .expect("retired owner closes without a leak")
                .is_quiescent()
        );
    }

    #[test]
    fn terminal_refusal_keeps_edits_and_close_aborts_with_actual_stats() {
        let mut state = adopted();
        let tx_id = state.begin_publication(attempt(&state, 2)).expect("begin");
        let terminal = TerminalOutcome {
            decision_sequence: DecisionSequence::try_new(1).expect("sequence"),
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                refusal_record_id: RefusalRecordId::from_digest(
                    DigestAlgorithmId::try_new(1).expect("algorithm"),
                    CodecVersion::new(1, 0),
                    DigestBytes::try_new(&[8; 32]).expect("digest"),
                ),
            },
        };
        assert!(
            state
                .reconcile_publication(tx_id, Some(&terminal))
                .expect("canonical refusal")
                .is_none()
        );
        assert!(!state.is_retired());
        let actual = state.overlay().stats();
        let settled = state
            .abort_lease(WorkspaceAbortReason::Discarded)
            .expect("abort")
            .expect("lease");
        match settled.evidence() {
            TerminalEvidence::Aborted(receipt) => assert_eq!(receipt.discarded, actual),
            other => panic!("unexpected evidence: {other:?}"),
        }
        assert!(state.close().expect("close").is_quiescent());
    }
}
