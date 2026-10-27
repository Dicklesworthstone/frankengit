#![forbid(unsafe_code)]
//! Public-path Beads ownership tests. Scripted transports test refusal and
//! ambiguity; the explicitly selected real-br test uses an actual private
//! tracker and fresh processes, never the repository's task database.

use std::collections::VecDeque;

use fgit_agent::beads::{
    BEADS_HISTORY_KEY, BeadsClaimOutcome, BeadsClaimRequest, BeadsReadSource,
    BeadsReconciliationStage, BeadsRefusal, BeadsTaskRecord, BeadsTransport, BeadsTransportRefusal,
    BeadsWriteOutcome, MAX_BEADS_JSON_BYTES, beads_adapter_identity, execute_beads_claim,
    reconcile_beads_claim,
};
use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
    RunId, SituationComponent, SituationComponentKind, SituationOmissionReason, WorkConflict,
    WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_resource::{Grade, ResourceVector};
use fgit_schema::json::{self, Value};
use fgit_types::{Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId};

// Exercise the product process implementation in its owning host crate.
#[cfg(unix)]
use super::process as native_transport;

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).unwrap();
    Digest::new(root.algorithm(), DigestBytes::try_new(&[byte; 32]).unwrap())
}

fn authority() -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).unwrap();
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: digest(0x35),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(9911));
    let key = HeadKey::new(b"beads-native-test".to_vec()).unwrap();
    let read = match initialize_repository(&store, &key, &body).unwrap() {
        HeadInit::Created(read) => read,
        _ => panic!("fresh store"),
    };
    let authenticated = store.authenticate_head_receipt(&read).unwrap();
    AuthorityReadReceipt::from_authenticated_head(&authenticated, LogicalTime::new(10), [0x71; 32])
        .unwrap()
}

fn run(authority: &AuthorityReadReceipt, id: u128) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(id),
        authority.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, 16_384), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(100),
    )
    .unwrap()
}

fn control(
    record: &BeadsTaskRecord,
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
) -> (
    AgentControlPulse,
    AgentChangePlan,
    fgit_agent::AuthorityBoundTaskClaimApplication,
) {
    let snapshot = record
        .unclaimed_snapshot(authority, LogicalTime::new(20))
        .unwrap();
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(
                kind,
                authority.authority_head_id(),
                *snapshot.generation(),
            )
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).unwrap(); 32],
            )
        }
    });
    let situation = AgentSituationReceipt::build(
        authority.clone(),
        Some(run),
        None,
        LogicalTime::new(20),
        components,
    )
    .unwrap();
    let item = WorkItem::new(
        snapshot.task_id(),
        *snapshot.generation(),
        snapshot.phase(),
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&situation, vec![item]).unwrap();
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run)).unwrap();
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        run.allowed_operation_classes(),
        ResourceVector::from_grades(&[(Grade::Bytes, 4_096), (Grade::CpuMicros, 5_000)]),
        PlanStopConditionSet::MANDATORY,
        RejectedShortcutSet::BASELINE,
        PlanApproval::NotRequired {
            policy_root: digest(0x62),
        },
    )
    .with_surfaces(vec![surface], vec![surface])
    .with_checkpoints(vec![PlanCheckpoint::new(
        PlanCheckpointId::from_bytes([0x63; 32]),
        PlanCheckpointPurpose::ImplementSlice,
        digest(0x64),
        digest(0x65),
    )])
    .with_evidence_plan(vec![PlanEvidenceRequirement::new(
        PlanRequirementId::from_bytes([0x66; 32]),
        EvidenceClass::Executed,
        digest(0x67),
        false,
    )]);
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).unwrap();
    let application = snapshot
        .claim(
            &pulse,
            &plan,
            run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            beads_adapter_identity(),
            digest(0x72),
        )
        .unwrap();
    (pulse, plan, application)
}

fn prepare(
    record: &BeadsTaskRecord,
    authority: &AuthorityReadReceipt,
    run: &IntentRun,
) -> BeadsClaimRequest {
    let (pulse, plan, application) = control(record, authority, run);
    BeadsClaimRequest::prepare(record, &application, &pulse, &plan, run).unwrap()
}

fn initial_bytes() -> Vec<u8> {
    br#"[{"id":"work-abc","title":"Real task","status":"open","priority":1,"updated_at":"2026-10-27T01:02:03.123456789Z","agent_context":"{\"constraints\":[\"keep me\"]}"}]"#.to_vec()
}

fn initial() -> BeadsTaskRecord {
    BeadsTaskRecord::parse_show_json("work-abc", &initial_bytes()).unwrap()
}

fn successor_bytes(request: &BeadsClaimRequest) -> Vec<u8> {
    json::Value::Array(vec![json::object([
        ("id", json::text(request.id())),
        ("title", json::text("Real task")),
        ("status", json::text("in_progress")),
        ("assignee", json::text(request.actor())),
        ("updated_at", json::text("2026-10-27T01:02:04.123456789Z")),
        ("agent_context", json::text(request.agent_context_json())),
    ])])
    .encode(MAX_BEADS_JSON_BYTES)
    .unwrap()
    .into_bytes()
}

struct Scripted {
    reads: VecDeque<Result<Vec<u8>, BeadsTransportRefusal>>,
    ready: Vec<u8>,
    write: BeadsWriteOutcome,
    flush: BeadsWriteOutcome,
    claims: usize,
    flushes: usize,
    shows: usize,
    clocks: VecDeque<LogicalTime>,
}

impl Scripted {
    fn new(reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: reads.into_iter().map(Ok).collect(),
            ready: initial_bytes(),
            write: BeadsWriteOutcome::Completed,
            flush: BeadsWriteOutcome::Completed,
            claims: 0,
            flushes: 0,
            shows: 0,
            clocks: [LogicalTime::new(25); 2].into(),
        }
    }
}
impl BeadsTransport for Scripted {
    fn observed_at(&mut self) -> LogicalTime {
        self.clocks.pop_front().unwrap_or(LogicalTime::new(25))
    }
    fn show(
        &mut self,
        _id: &str,
        _source: BeadsReadSource,
    ) -> Result<Vec<u8>, BeadsTransportRefusal> {
        self.shows += 1;
        self.reads.pop_front().expect("no unexpected read")
    }
    fn ready_unassigned(&mut self) -> Result<Vec<u8>, BeadsTransportRefusal> {
        Ok(self.ready.clone())
    }
    fn claim(&mut self, _request: &BeadsClaimRequest) -> BeadsWriteOutcome {
        self.claims += 1;
        self.write
    }
    fn flush(&mut self) -> BeadsWriteOutcome {
        self.flushes += 1;
        self.flush
    }
}

#[test]
fn exact_history_survives_restart_and_preserves_user_context() {
    let authority = authority();
    let run = run(&authority, 7);
    let request = prepare(&initial(), &authority, &run);
    let context = json::parse(request.agent_context_json().as_bytes()).unwrap();
    assert_eq!(
        context.object().unwrap()["constraints"],
        Value::Array(vec![json::text("keep me")])
    );
    assert!(context.object().unwrap().contains_key(BEADS_HISTORY_KEY));
    let successor = successor_bytes(&request);
    let reparsed = BeadsTaskRecord::parse_show_json("work-abc", &successor).unwrap();
    assert_eq!(reparsed.history(), Some(request.history()));
    assert_eq!(
        reparsed.history().unwrap().run_commitment(),
        run.commitment().unwrap().as_bytes()
    );
    assert_eq!(
        reparsed.history().unwrap().authority_read_receipt_id(),
        authority.receipt_id().unwrap().as_bytes()
    );
    assert_eq!(
        reparsed.unclaimed_snapshot(&authority, LogicalTime::new(90)),
        Err(BeadsRefusal::NotOpenUnassigned)
    );
    let mut transport = Scripted::new(vec![initial_bytes(), successor.clone(), successor]);
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::Confirmed(_)
    ));
    assert_eq!(
        (transport.claims, transport.flushes, transport.shows),
        (1, 1, 3)
    );
}

#[test]
fn lost_response_reconciles_without_repeating_claim() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let successor = successor_bytes(&request);
    let mut transport = Scripted::new(vec![initial_bytes(), successor.clone(), successor]);
    transport.write = BeadsWriteOutcome::Uncertain {
        quiescent: true,
        reason: BeadsTransportRefusal::ProcessFailed,
    };
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::Confirmed(_)
    ));
    assert_eq!(transport.claims, 1);
}

#[test]
fn flush_failure_retains_request_and_only_readonly_reconciliation_can_settle_it() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let successor = successor_bytes(&request);
    let mut transport = Scripted::new(vec![initial_bytes()]);
    transport.flush = BeadsWriteOutcome::NotStarted(BeadsTransportRefusal::Cancelled);
    let BeadsClaimOutcome::NeedsReconciliation { request, stage, .. } =
        execute_beads_claim(&mut transport, request).unwrap()
    else {
        panic!("must retain debt");
    };
    assert_eq!(stage, BeadsReconciliationStage::Flush);
    let mut probe = Scripted::new(vec![successor.clone(), successor]);
    assert!(matches!(
        reconcile_beads_claim(&mut probe, request),
        BeadsClaimOutcome::Confirmed(_)
    ));
    assert_eq!((probe.claims, probe.flushes), (0, 0));
}

#[test]
fn nonquiescent_writer_cannot_be_settled_by_matching_rows() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut transport = Scripted::new(vec![initial_bytes()]);
    transport.write = BeadsWriteOutcome::Uncertain {
        quiescent: false,
        reason: BeadsTransportRefusal::TimeLimit,
    };
    let BeadsClaimOutcome::NeedsReconciliation { request, stage, .. } =
        execute_beads_claim(&mut transport, request).unwrap()
    else {
        panic!("must retain debt");
    };
    assert_eq!(stage, BeadsReconciliationStage::Claim);
    assert_eq!((transport.shows, transport.flushes), (1, 0));
    let mut probe = Scripted::new(vec![]);
    assert!(matches!(
        reconcile_beads_claim(&mut probe, request),
        BeadsClaimOutcome::NeedsReconciliation { .. }
    ));
    assert_eq!(probe.shows, 0);
}

#[test]
fn nonquiescent_export_and_unattempted_request_cannot_be_confirmed() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut untouched = Scripted::new(vec![]);
    assert!(matches!(
        reconcile_beads_claim(&mut untouched, request),
        BeadsClaimOutcome::NeedsReconciliation { .. }
    ));
    assert_eq!(untouched.shows, 0);
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut transport = Scripted::new(vec![initial_bytes()]);
    transport.flush = BeadsWriteOutcome::Uncertain {
        quiescent: false,
        reason: BeadsTransportRefusal::TimeLimit,
    };
    let BeadsClaimOutcome::NeedsReconciliation { request, stage, .. } =
        execute_beads_claim(&mut transport, request).unwrap()
    else {
        panic!("unjoined export retains debt");
    };
    assert_eq!(stage, BeadsReconciliationStage::Flush);
    let mut probe = Scripted::new(vec![]);
    assert!(matches!(
        reconcile_beads_claim(&mut probe, request),
        BeadsClaimOutcome::NeedsReconciliation { .. }
    ));
    assert_eq!(probe.shows, 0);
}

#[test]
fn missing_export_or_predecessor_after_ambiguous_write_never_proves_abort() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut transport = Scripted::new(vec![initial_bytes(), initial_bytes(), initial_bytes()]);
    transport.write = BeadsWriteOutcome::Uncertain {
        quiescent: true,
        reason: BeadsTransportRefusal::ProcessFailed,
    };
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::NeedsReconciliation {
            stage: BeadsReconciliationStage::Confirmation,
            ..
        }
    ));
    assert_eq!(transport.claims, 1);

    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let successor = successor_bytes(&request);
    let mut transport = Scripted::new(vec![initial_bytes(), successor]);
    transport
        .reads
        .push_back(Err(BeadsTransportRefusal::Unavailable));
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::NeedsReconciliation {
            stage: BeadsReconciliationStage::ExportRead,
            ..
        }
    ));
}

#[test]
fn different_run_body_with_same_numeric_id_refuses_before_any_io() {
    let authority = authority();
    let good = run(&authority, 7);
    let changed = IntentRun::new_authenticated(
        good.run_id(),
        authority.clone(),
        good.allowed_operation_classes(),
        ResourceVector::from_grades(&[(Grade::Bytes, 8192)]),
        good.expiry(),
    )
    .unwrap();
    let (pulse, plan, application) = control(&initial(), &authority, &good);
    assert_eq!(
        BeadsClaimRequest::prepare(&initial(), &application, &pulse, &plan, &changed),
        Err(BeadsRefusal::ControlBinding)
    );
}

#[test]
fn expired_between_read_and_dispatch_performs_no_mutation() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut transport = Scripted::new(vec![initial_bytes()]);
    transport.clocks = [LogicalTime::new(25), LogicalTime::new(80)].into();
    assert_eq!(
        execute_beads_claim(&mut transport, request),
        Err(BeadsRefusal::Expired)
    );
    assert_eq!((transport.claims, transport.flushes), (0, 0));
}

#[test]
fn readiness_and_changed_predecessor_refuse_without_claim() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let mut transport = Scripted::new(vec![initial_bytes()]);
    transport.ready = b"[]".to_vec();
    assert_eq!(
        execute_beads_claim(&mut transport, request),
        Err(BeadsRefusal::NotReady)
    );
    assert_eq!(transport.claims, 0);
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let changed = String::from_utf8(initial_bytes())
        .unwrap()
        .replace("Real task", "Changed task")
        .into_bytes();
    let mut transport = Scripted::new(vec![changed]);
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::Conflict { .. }
    ));
    assert_eq!(transport.claims, 0);
}

#[test]
fn malformed_id_duplicate_keys_truncated_history_and_oversized_json_refuse() {
    assert_eq!(
        BeadsTaskRecord::parse_show_json("-other", &initial_bytes()),
        Err(BeadsRefusal::TaskIdentity)
    );
    assert_eq!(
        BeadsTaskRecord::parse_show_json("work-else", &initial_bytes()),
        Err(BeadsRefusal::TaskIdentity)
    );
    let duplicate = String::from_utf8(initial_bytes()).unwrap().replace(
        "\"status\":\"open\"",
        "\"status\":\"open\",\"status\":\"closed\"",
    );
    assert!(BeadsTaskRecord::parse_show_json("work-abc", duplicate.as_bytes()).is_err());
    assert!(
        BeadsTaskRecord::parse_show_json("work-abc", &vec![b' '; MAX_BEADS_JSON_BYTES + 1])
            .is_err()
    );
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let successor = successor_bytes(&request);
    for end in [0, successor.len() / 2, successor.len() - 1] {
        assert!(BeadsTaskRecord::parse_show_json("work-abc", &successor[..end]).is_err());
    }
    let mut document = json::parse(&successor).unwrap();
    let Value::Array(rows) = &mut document else {
        unreachable!()
    };
    let Value::Object(fields) = &mut rows[0] else {
        unreachable!()
    };
    fields.insert("assignee".into(), json::text("different-owner"));
    let forged = document.encode(MAX_BEADS_JSON_BYTES).unwrap();
    let historical = BeadsTaskRecord::parse_show_json("work-abc", forged.as_bytes()).unwrap();
    assert_eq!(historical.history(), Some(request.history()));
    let mut transport = Scripted::new(vec![forged.into_bytes()]);
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::Conflict { .. }
    ));
    assert_eq!((transport.claims, transport.flushes), (0, 0));
}

#[test]
fn closed_task_retains_inspectable_history_without_current_claim_authority() {
    let authority = authority();
    let request = prepare(&initial(), &authority, &run(&authority, 7));
    let body = String::from_utf8(successor_bytes(&request))
        .unwrap()
        .replace("\"in_progress\"", "\"closed\"");
    let record = BeadsTaskRecord::parse_show_json("work-abc", body.as_bytes()).unwrap();
    assert_eq!(record.status(), "closed");
    assert_eq!(record.history(), Some(request.history()));
    let mut transport = Scripted::new(vec![body.into_bytes()]);
    assert!(matches!(
        execute_beads_claim(&mut transport, request).unwrap(),
        BeadsClaimOutcome::Conflict { .. }
    ));
    assert_eq!((transport.claims, transport.flushes), (0, 0));
}

/// Native process tests are explicit because the workspace does not install br.
/// The parent supplies a checksum-verified v0.7.6 executable. All task mutations
/// happen under the unique private temporary tracker created by this test.
#[cfg(unix)]
mod native {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    static LIVE: fn() -> bool = || true;
    static NOW: fn() -> LogicalTime = || LogicalTime::new(25);

    struct Native {
        program: PathBuf,
        root: PathBuf,
        process: native_transport::BeadsProcess<'static>,
        barrier: Option<Arc<Barrier>>,
        lose_claim_reply: bool,
        stop_before_flush: bool,
        calls: usize,
    }
    impl Native {
        fn command(&self, args: &[String]) -> Output {
            Command::new(&self.program)
                .current_dir(&self.root)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("NO_COLOR", "1")
                .arg("--db")
                .arg(self.root.join(".beads/beads.db"))
                .arg("--no-auto-import")
                .arg("--no-auto-flush")
                .args(args)
                .output()
                .expect("native br process runs")
        }
        fn new(program: &Path, root: &Path) -> Self {
            Self {
                program: program.to_path_buf(),
                root: root.to_path_buf(),
                process: native_transport::BeadsProcess::open(
                    program,
                    &root.join(".beads"),
                    Instant::now() + Duration::from_secs(60),
                    &LIVE,
                    &NOW,
                )
                .unwrap(),
                barrier: None,
                lose_claim_reply: false,
                stop_before_flush: false,
                calls: 0,
            }
        }
        fn create(&self, title: &str) -> String {
            let output = self.command(&[
                "create".into(),
                "--title".into(),
                title.into(),
                "--json".into(),
            ]);
            assert!(
                output.status.success(),
                "create: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value = json::parse(&output.stdout).unwrap();
            value.object().unwrap()["id"].text().unwrap().to_owned()
        }
    }
    impl BeadsTransport for Native {
        fn observed_at(&mut self) -> LogicalTime {
            self.process.observed_at()
        }
        fn show(
            &mut self,
            id: &str,
            source: BeadsReadSource,
        ) -> Result<Vec<u8>, BeadsTransportRefusal> {
            self.process.show(id, source)
        }
        fn ready_unassigned(&mut self) -> Result<Vec<u8>, BeadsTransportRefusal> {
            self.process.ready_unassigned()
        }
        fn claim(&mut self, request: &BeadsClaimRequest) -> BeadsWriteOutcome {
            self.calls += 1;
            if let Some(barrier) = &self.barrier {
                barrier.wait();
            }
            let outcome = self.process.claim(request);
            if outcome == BeadsWriteOutcome::Completed && self.lose_claim_reply {
                BeadsWriteOutcome::Uncertain {
                    quiescent: true,
                    reason: BeadsTransportRefusal::ProcessFailed,
                }
            } else {
                outcome
            }
        }
        fn flush(&mut self) -> BeadsWriteOutcome {
            if self.stop_before_flush {
                return BeadsWriteOutcome::NotStarted(BeadsTransportRefusal::Cancelled);
            }
            self.process.flush()
        }
    }

    #[test]
    #[ignore = "requires checksum-verified br 0.7.6 via FGIT_BEADS_NATIVE_BR"]
    fn real_br_two_clients_history_and_fresh_process_reconciliation() {
        let program = PathBuf::from(
            std::env::var_os("FGIT_BEADS_NATIVE_BR").expect("explicit br executable"),
        );
        assert!(program.is_absolute());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("fgit-beads-native-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let init = Command::new(&program)
            .current_dir(&root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["init", "--prefix", "fgittest"])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let mut first = Native::new(&program, &root);
        let id = first.create("Two exact native owners race");
        let bytes = first.show(&id, BeadsReadSource::Database).unwrap();
        let record = BeadsTaskRecord::parse_show_json(&id, &bytes).unwrap();
        let authority = authority();
        let request_a = prepare(&record, &authority, &run(&authority, 7));
        let request_b = prepare(&record, &authority, &run(&authority, 8));
        let actor_a = request_a.actor().to_owned();
        let actor_b = request_b.actor().to_owned();
        let barrier = Arc::new(Barrier::new(2));
        // Construct each host in its owning worker; its callbacks are local
        // lifetime bounds and need not be Send/Sync to support actual clients.
        let program_a = program.clone();
        let root_a = root.clone();
        let barrier_a = barrier.clone();
        let a = std::thread::spawn(move || {
            let mut client = Native::new(&program_a, &root_a);
            client.barrier = Some(barrier_a);
            (execute_beads_claim(&mut client, request_a), client.calls)
        });
        let program_b = program.clone();
        let root_b = root.clone();
        let b = std::thread::spawn(move || {
            let mut client = Native::new(&program_b, &root_b);
            client.barrier = Some(barrier);
            (execute_beads_claim(&mut client, request_b), client.calls)
        });
        let (a, a_calls) = a.join().unwrap();
        let (b, b_calls) = b.join().unwrap();
        let results = [a.unwrap(), b.unwrap()];
        assert_eq!(a_calls, 1);
        assert_eq!(b_calls, 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, BeadsClaimOutcome::Confirmed(_)))
                .count(),
            1,
            "native race outcomes: {results:?}"
        );
        let mut restarted = Native::new(&program, &root);
        let saved = restarted.show(&id, BeadsReadSource::Export).unwrap();
        let recovered = BeadsTaskRecord::parse_show_json(&id, &saved).unwrap();
        assert!([Some(actor_a.as_str()), Some(actor_b.as_str())].contains(&recovered.assignee()));
        assert_eq!(
            recovered.history().unwrap().actor(),
            recovered.assignee().unwrap()
        );

        // A successful DB write with a lost reply still yields one confirmed
        // history after an explicit export and fresh process reads.
        let id = restarted.create("A response can be lost after commit");
        let bytes = restarted.show(&id, BeadsReadSource::Database).unwrap();
        let record = BeadsTaskRecord::parse_show_json(&id, &bytes).unwrap();
        let request = prepare(&record, &authority, &run(&authority, 9));
        restarted.lose_claim_reply = true;
        assert!(matches!(
            execute_beads_claim(&mut restarted, request).unwrap(),
            BeadsClaimOutcome::Confirmed(_)
        ));
        assert_eq!(restarted.calls, 1);

        // Stopping before export retains debt. A new host may flush once and
        // reconcile the retained request, without ever repeating the claim.
        let mut stopped = Native::new(&program, &root);
        let id = stopped.create("Recover from stop before export");
        let bytes = stopped.show(&id, BeadsReadSource::Database).unwrap();
        let record = BeadsTaskRecord::parse_show_json(&id, &bytes).unwrap();
        let request = prepare(&record, &authority, &run(&authority, 10));
        let expected_history = request.history().clone();
        stopped.stop_before_flush = true;
        let BeadsClaimOutcome::NeedsReconciliation { request, stage, .. } =
            execute_beads_claim(&mut stopped, request).unwrap()
        else {
            panic!("export interruption retains debt");
        };
        assert_eq!(stage, BeadsReconciliationStage::Flush);
        assert_eq!(stopped.calls, 1);
        drop(stopped);
        let mut fresh = Native::new(&program, &root);
        assert_eq!(fresh.flush(), BeadsWriteOutcome::Completed);
        let BeadsClaimOutcome::Confirmed(confirmation) = reconcile_beads_claim(&mut fresh, request)
        else {
            panic!("fresh exact views confirm native ownership");
        };
        assert_eq!(confirmation.export().history(), Some(&expected_history));
        assert_eq!(fresh.calls, 0);
        // Keep the private fixture on failure for diagnosis; successful fixtures
        // contain no user data and are entirely created by this one test.
        std::fs::remove_dir_all(&root).unwrap();
    }
}
