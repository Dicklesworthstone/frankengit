//! Terminal metadata is adversarial; ownership still has to settle.
#![forbid(unsafe_code)]

use fgit_resource::kinds::{ContainmentClass, ExitClass, NetworkPolicy, RunnerReaped, SandboxProfile};
use fgit_runner::{
    BuildCommand, BuildInputCapsule, CheckOutcome, Commitment, ContainmentSubstrate,
    ForkPolicy, JobRequest, LogRedactor, ResourceCeilings, ResourceUsage,
    RunnerControlPlane, RunnerPolicy, RunnerRefusal, RunnerText, SandboxPlan,
    SecretBroker, SecretRequest, SourceObject, SubstrateObservation, SubstrateRefusal,
    TrustDomain, MAX_ARTIFACTS,
};

fn text(value: &str) -> RunnerText { RunnerText::parse("test", value).unwrap() }
fn hash(value: &[u8]) -> Commitment { Commitment::of_bytes(value) }
fn ceilings() -> ResourceCeilings { ResourceCeilings::new(100, 100, 100, 0, 2, 100).unwrap() }
fn policy() -> RunnerPolicy {
    RunnerPolicy::new(TrustDomain::new(text("settlement")), SandboxProfile::ProcessIsolated,
        NetworkPolicy::Denied, ceilings()).unwrap()
}
fn capsule() -> BuildInputCapsule {
    BuildInputCapsule::new(hash(b"head"), vec![SourceObject::new(hash(b"source"), 6)],
        hash(b"lock"), text("pinned-toolchain"), BuildCommand::new(text("check"), vec![]).unwrap(), vec![]).unwrap()
}
struct Worker(Vec<Commitment>);
impl ContainmentSubstrate for Worker {
    fn launch(&mut self, _: &SandboxPlan) -> Result<SubstrateObservation, SubstrateRefusal> {
        Ok(SubstrateObservation {
            exit: ExitClass::Succeeded,
            usage: ResourceUsage { cpu_micros: 1, memory_bytes: 1, disk_bytes: 1,
                network_bytes: 0, processes: 1, wall_clock_millis: 1 },
            reaped: RunnerReaped { processes_reaped: 1, containment: ContainmentClass::Cooperative },
            log_redaction: LogRedactor::new(vec![]).unwrap().redact(b"complete log").unwrap().receipt(),
            artifacts: self.0.clone(),
        })
    }
}

#[test]
fn malformed_terminal_artifacts_revoke_every_secret_and_restore_capacity() {
    for artifacts in [vec![hash(b"duplicate"); 2], vec![hash(b"oversize"); MAX_ARTIFACTS + 1]] {
        let mut broker = SecretBroker::default();
        let mut controller = RunnerControlPlane::new(ceilings(), 1).unwrap();
        let leases = ["TOKEN_A", "TOKEN_B"].into_iter().map(|name| broker.issue(
            SecretRequest::new(text(name), policy().trust_domain().clone(), ForkPolicy::TrustedOnly, 10), 0).unwrap()
        ).collect::<Vec<_>>();
        let admitted = controller.admit(capsule(), policy(),
            JobRequest::new(false, leases.clone(), vec![], 1).unwrap(), &mut broker, 1).unwrap();
        assert!(matches!(controller.admit(capsule(), policy(),
            JobRequest::new(false, vec![], vec![], 2).unwrap(), &mut broker, 1),
            Err(RunnerRefusal::NoRunnerCapacity)));
        let expected = if artifacts.len() > MAX_ARTIFACTS {
            RunnerRefusal::CollectionTooLarge { field: "artifacts", limit: MAX_ARTIFACTS }
        } else { RunnerRefusal::DuplicateArtifactCommitment };
        let error = controller.execute(admitted, &mut Worker(artifacts), &mut broker).unwrap_err();
        assert_eq!(error, expected);
        assert!(leases.into_iter().all(|lease| broker.is_revoked(lease)));
        let next = controller.admit(capsule(), policy(),
            JobRequest::new(false, vec![], vec![], 3).unwrap(), &mut broker, 2).unwrap();
        let receipt = controller.execute(next, &mut Worker(vec![hash(b"valid")]), &mut broker).unwrap();
        assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
        receipt.verify_evidence().unwrap();
    }
}

#[test]
fn rejected_secret_batch_does_not_bind_the_valid_prefix_or_consume_capacity() {
    let mut broker = SecretBroker::default();
    let mut controller = RunnerControlPlane::new(ceilings(), 1).unwrap();
    let first = broker.issue(SecretRequest::new(text("FIRST"), policy().trust_domain().clone(),
        ForkPolicy::TrustedOnly, 10), 0).unwrap();
    let expired = broker.issue(SecretRequest::new(text("EXPIRED"), policy().trust_domain().clone(),
        ForkPolicy::TrustedOnly, 1), 0).unwrap();
    assert!(matches!(controller.admit(capsule(), policy(),
        JobRequest::new(false, vec![first, expired], vec![], 1).unwrap(), &mut broker, 2),
        Err(RunnerRefusal::SecretAlreadyExpired)));
    let admitted = controller.admit(capsule(), policy(),
        JobRequest::new(false, vec![first], vec![], 2).unwrap(), &mut broker, 2).unwrap();
    let receipt = controller.execute(admitted, &mut Worker(vec![]), &mut broker).unwrap();
    assert_eq!(receipt.outcome(), CheckOutcome::Succeeded);
    assert!(broker.is_revoked(first));
    assert!(!broker.is_revoked(expired));
}
