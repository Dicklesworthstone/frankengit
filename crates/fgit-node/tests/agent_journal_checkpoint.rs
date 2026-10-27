#![forbid(unsafe_code)]
//! Actual embedded issuance-ledger reopen and native journal recovery. The
//! repository advances through ordinary native merge admission between capture
//! and recovery; no reference-authority substitute is used in this test.

#[path = "fast_forward_command/fixture.rs"]
mod fixture;

use fgit_agent::{
    AgentInstanceId, AuthorityReadReceipt, Capability, CapabilityId, ClassSet, EffectId,
    EffectRequest, IntentRun, LogicalTime, OperationClass, RunId,
    effect_journal::EffectJournalPosition,
};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::{OneNode, agent_journal::AgentJournalHostRefusal};
use fgit_resource::{Grade, RegionId, ResourceVector};
use fgit_types::GitHashAlgorithm;
use fixture::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_pin(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
#[ignore = "child helper invoked by the restart test with independently passed pins"]
fn child_recovers_original_run_from_persisted_issuance() {
    let root = std::path::PathBuf::from(
        std::env::var_os("FG_AGENT_CHECKPOINT_CHILD_ROOT").expect("child fixture"),
    );
    let format = match std::env::var("FG_AGENT_CHECKPOINT_CHILD_FORMAT")
        .unwrap()
        .as_str()
    {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => panic!("child object format"),
    };
    let run_id = RunId::new(
        std::env::var("FG_AGENT_CHECKPOINT_CHILD_RUN")
            .unwrap()
            .parse()
            .unwrap(),
    );
    let run_pin = decode_pin(&std::env::var("FG_AGENT_CHECKPOINT_CHILD_PIN").unwrap());
    let tail = EffectJournalPosition {
        entries: std::env::var("FG_AGENT_CHECKPOINT_CHILD_ENTRIES")
            .unwrap()
            .parse()
            .unwrap(),
        bytes: std::env::var("FG_AGENT_CHECKPOINT_CHILD_BYTES")
            .unwrap()
            .parse()
            .unwrap(),
        digest: decode_pin(&std::env::var("FG_AGENT_CHECKPOINT_CHILD_DIGEST").unwrap()),
    };
    let node = OneNode::open_existing(config(&root, format)).unwrap();
    let request = node.request_context();
    let recovered = node
        .runtime()
        .block_on(node.recover_agent_journal_in(
            &request,
            &root.join("agent-journals"),
            run_id,
            &run_pin,
            tail,
        ))
        .unwrap();
    let report = recovered
        .reconciliation_report(LogicalTime::new(200))
        .unwrap();
    assert!(!report.run_open_at_observation());
    assert_eq!(report.counts().aborted(), 1);
    assert_eq!(report.run_commitment().as_bytes(), &run_pin);
    std::fs::write(
        root.join("child-recovery-report"),
        report.report_id().as_bytes(),
    )
    .unwrap();
    node.shutdown().unwrap();
}

#[test]
fn original_run_and_nonempty_journal_recover_after_head_advance_and_node_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let fixture = fixture(&scratch.0, format, false);
        let directory = scratch.0.join("agent-journals");
        std::fs::create_dir(&directory).unwrap();
        let request = fixture.node.request_context();
        let authenticated = fixture
            .node
            .runtime()
            .block_on(fixture.node.authenticate_authority_head_in(&request))
            .unwrap();
        let original_generation = authenticated.receipt().generation();
        let authority = AuthorityReadReceipt::from_authenticated_head(
            &authenticated,
            LogicalTime::new(7),
            [73; 32],
        )
        .unwrap();
        let original_head = authority.authority_head_id();
        let scope = ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]);
        let budget = ResourceVector::single(Grade::Bytes, 1000);
        let run_id = RunId::new(149);
        let run =
            IntentRun::new_authenticated(run_id, authority, scope, budget, LogicalTime::new(100))
                .unwrap();
        let expected_run = *run.commitment().unwrap().as_bytes();
        let capability = Capability::issue(
            CapabilityId::new(9),
            scope,
            budget,
            LogicalTime::new(7),
            LogicalTime::new(100),
        )
        .unwrap();
        let mut broker = fixture
            .node
            .runtime()
            .block_on(fixture.node.create_restorable_agent_broker_in(
                &request,
                &directory,
                run,
                authenticated.receipt(),
                RegionId::new(1),
                AgentInstanceId::new(1),
            ))
            .unwrap();
        let grant = broker
            .request_low_risk(
                &capability,
                LogicalTime::new(9),
                &EffectRequest {
                    effect_id: EffectId::new(1),
                    parent_effect_id: None,
                    operation: OperationClass::ReadCanonicalObject,
                    cost: ResourceVector::single(Grade::Bytes, 12),
                    input_commitment: [85; 32],
                },
            )
            .unwrap();
        broker.abort_low_risk(grant).unwrap();
        let tail = broker.durable_position().unwrap().unwrap();
        assert_eq!(tail.entries, 2);
        assert!(broker.close().is_quiescent());
        drop(authenticated);

        let (_, terminal) = fixture
            .node
            .runtime()
            .block_on(fixture.node.fast_forward_pull_request_durable_in(
                &request,
                &session(b"agent-checkpoint-head-advance"),
                PullRequestNumber::FIRST,
                AggregateVersion::FIRST,
                &topic_ref(),
                fixture.source,
                &main_ref(),
                fixture.target,
                Default::default(),
                Default::default(),
            ))
            .unwrap();
        committed(terminal);
        let current = fixture
            .node
            .runtime()
            .block_on(fixture.node.authenticate_authority_head_in(&request))
            .unwrap()
            .receipt()
            .generation();
        assert!(current > original_generation);
        fixture.node.shutdown().unwrap();

        // These pins come from the original live run and broker, not from the
        // files the child reads. A controller retains this receipt separately.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "child_recovers_original_run_from_persisted_issuance",
                "--nocapture",
            ])
            .env("FG_AGENT_CHECKPOINT_CHILD_ROOT", &scratch.0)
            .env(
                "FG_AGENT_CHECKPOINT_CHILD_FORMAT",
                if format == GitHashAlgorithm::Sha1 {
                    "sha1"
                } else {
                    "sha256"
                },
            )
            .env("FG_AGENT_CHECKPOINT_CHILD_RUN", run_id.value().to_string())
            .env("FG_AGENT_CHECKPOINT_CHILD_PIN", hex(&expected_run))
            .env(
                "FG_AGENT_CHECKPOINT_CHILD_ENTRIES",
                tail.entries.to_string(),
            )
            .env("FG_AGENT_CHECKPOINT_CHILD_BYTES", tail.bytes.to_string())
            .env("FG_AGENT_CHECKPOINT_CHILD_DIGEST", hex(&tail.digest))
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "fresh-process recovery failed: {status}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fresh-process recovery exceeded its bounded lifetime");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Reopen without bringing the node into service. Inspection of an
        // original run is not new work and needs no renewed grant or expiry.
        let node = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        let request = node.request_context();
        let recovered = node
            .runtime()
            .block_on(node.recover_agent_journal_in(
                &request,
                &directory,
                run_id,
                &expected_run,
                tail,
            ))
            .unwrap();
        assert_eq!(
            recovered.original_run().commitment().unwrap().as_bytes(),
            &expected_run
        );
        assert_eq!(recovered.original_run().resource_budget(), budget);
        assert_eq!(recovered.original_run().expiry(), LogicalTime::new(100));
        assert_eq!(
            recovered
                .original_run()
                .authority_read_receipt()
                .unwrap()
                .authority_head_id(),
            original_head
        );
        let report = recovered
            .reconciliation_report(LogicalTime::new(200))
            .unwrap();
        assert!(!report.run_open_at_observation());
        assert_eq!(report.counts().aborted(), 1);
        assert_eq!(report.counts().total(), 1);
        assert_eq!(
            std::fs::read(scratch.0.join("child-recovery-report"))
                .unwrap()
                .as_slice(),
            report.report_id().as_bytes()
        );
        let repeated = node
            .runtime()
            .block_on(node.recover_agent_journal_in(
                &request,
                &directory,
                run_id,
                &expected_run,
                tail,
            ))
            .unwrap();
        assert_eq!(
            repeated
                .reconciliation_report(LogicalTime::new(200))
                .unwrap()
                .report_id(),
            report.report_id()
        );
        assert!(
            node.runtime()
                .block_on(
                    node.recover_agent_journal_in(&request, &directory, run_id, &[99; 32], tail,)
                )
                .is_err()
        );
        let mut wrong_tail = tail;
        wrong_tail.digest = [99; 32];
        assert!(
            node.runtime()
                .block_on(node.recover_agent_journal_in(
                    &request,
                    &directory,
                    run_id,
                    &expected_run,
                    wrong_tail,
                ))
                .is_err()
        );
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(matches!(
            node.runtime().block_on(node.recover_agent_journal_in(
                &cancelled,
                &directory,
                run_id,
                &expected_run,
                tail,
            )),
            Err(AgentJournalHostRefusal::Cancelled)
        ));
        assert_eq!(
            node.runtime()
                .block_on(node.authenticate_authority_head_in(&request))
                .unwrap()
                .receipt()
                .generation(),
            current
        );
        node.shutdown().unwrap();
    }
}
