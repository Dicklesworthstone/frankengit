#![forbid(unsafe_code)]
//! Adversarial, public-surface checks for the runner containment control plane.
//!
//! This corpus deliberately does not claim that it executes hostile commands
//! against an operating-system sandbox: `fgit-runner` currently owns the
//! typed control plane and substrate contract, while a platform substrate owns
//! that execution boundary. It verifies that the control plane refuses every
//! weakening request before launch and preserves terminal containment receipts.

use fgit_resource::kinds::{
    ContainmentClass, ExitClass, NetworkPolicy, RunnerReaped, SandboxProfile,
};
use fgit_runner::{
    BuildInputCapsule, CheckOutcome, Commitment, ContainmentSubstrate, ForbiddenProbe, ForkPolicy,
    JobRequest, ResourceCeilings, ResourceDimension, ResourceUsage, RunnerControlPlane,
    RunnerPolicy, RunnerRefusal, RunnerText, SecretBroker, SecretRequest, SourceObject,
    SubstrateObservation, SubstrateRefusal, TrustDomain,
};

fn text(value: &str) -> RunnerText {
    RunnerText::parse("hostile-corpus", value).expect("fixture text is canonical")
}

fn commitment(label: &str) -> Commitment {
    Commitment::of_bytes(label.as_bytes())
}

fn capsule() -> BuildInputCapsule {
    BuildInputCapsule::new(
        commitment("authority"),
        vec![SourceObject::new(commitment("source"), 19)],
        commitment("dependency-lock"),
        text("nightly-2026-08-20"),
        Vec::new(),
    )
    .expect("fixture capsule is admitted")
}

fn ceilings() -> ResourceCeilings {
    ResourceCeilings::new(100, 100, 100, 0, 1, 100).expect("fixture ceilings are valid")
}

fn cancellation_ceilings() -> ResourceCeilings {
    ResourceCeilings::new(100, 100, 100, 0, 3, 100)
        .expect("three-process cancellation fixture ceiling is valid")
}

fn policy(domain: &str) -> RunnerPolicy {
    policy_with_ceilings(domain, ceilings())
}

fn policy_with_ceilings(domain: &str, resource_ceilings: ResourceCeilings) -> RunnerPolicy {
    RunnerPolicy::new(
        TrustDomain::new(text(domain)),
        SandboxProfile::ProcessIsolated,
        NetworkPolicy::Denied,
        resource_ceilings,
    )
    .expect("Linux process-isolated denied-egress policy is supported")
}

const fn usage(network_bytes: u64, processes: u32) -> ResourceUsage {
    ResourceUsage {
        cpu_micros: 1,
        memory_bytes: 1,
        disk_bytes: 1,
        network_bytes,
        processes,
        wall_clock_millis: 1,
    }
}

fn observation(
    exit: ExitClass,
    observed_usage: ResourceUsage,
    processes_reaped: u32,
    containment: ContainmentClass,
) -> SubstrateObservation {
    SubstrateObservation {
        exit,
        usage: observed_usage,
        reaped: RunnerReaped {
            processes_reaped,
            containment,
        },
        log_root: commitment("runner-log-root"),
        artifacts: vec![commitment("artifact-root")],
    }
}

struct FixedSubstrate(Result<SubstrateObservation, SubstrateRefusal>);

impl ContainmentSubstrate for FixedSubstrate {
    fn launch(
        &mut self,
        _plan: &fgit_runner::SandboxPlan,
    ) -> Result<SubstrateObservation, SubstrateRefusal> {
        self.0.clone()
    }
}

#[test]
fn ambient_and_metadata_exfiltration_fixtures_are_refused_before_admission() {
    for probe in [
        ForbiddenProbe::MetadataService,
        ForbiddenProbe::AmbientCredential,
    ] {
        assert_eq!(
            JobRequest::new(false, Vec::new(), vec![probe], 1),
            Err(RunnerRefusal::ForbiddenProbeRequested { probe })
        );
    }

    assert!(JobRequest::new(false, Vec::new(), Vec::new(), 1).is_ok());
}

#[test]
fn network_egress_weakening_is_refused_and_observed_egress_is_terminated() {
    assert_eq!(
        RunnerPolicy::new(
            TrustDomain::new(text("trusted")),
            SandboxProfile::ProcessIsolated,
            NetworkPolicy::Allowlisted,
            ceilings(),
        ),
        Err(RunnerRefusal::UnsupportedNetworkPolicy {
            network: NetworkPolicy::Allowlisted,
        })
    );
    assert_eq!(
        RunnerPolicy::new(
            TrustDomain::new(text("trusted")),
            SandboxProfile::ProcessIsolated,
            NetworkPolicy::Unrestricted,
            ceilings(),
        ),
        Err(RunnerRefusal::UnsupportedNetworkPolicy {
            network: NetworkPolicy::Unrestricted,
        })
    );

    let mut broker = SecretBroker::default();
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("capacity");
    let admitted = control
        .admit(
            capsule(),
            policy("trusted"),
            JobRequest::new(false, Vec::new(), Vec::new(), 2).expect("safe request"),
            &mut broker,
            1,
        )
        .expect("admitted before substrate launch");
    let mut substrate = FixedSubstrate(Ok(observation(
        ExitClass::ResourceCeiling,
        usage(1, 1),
        1,
        ContainmentClass::NonCooperative,
    )));
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("terminal containment receipt");

    assert_eq!(
        receipt.outcome(),
        CheckOutcome::ResourceCeiling {
            dimension: ResourceDimension::NetworkBytes,
        }
    );
    assert_eq!(receipt.reaped().processes_reaped, 1);
    assert_eq!(
        receipt.reaped().containment,
        ContainmentClass::NonCooperative
    );
}

#[test]
fn missing_filesystem_isolation_refuses_without_unconfined_fallback_and_revokes_secrets() {
    let mut broker = SecretBroker::default();
    let secret = broker
        .issue(
            SecretRequest::new(
                text("DEPLOY_TOKEN"),
                TrustDomain::new(text("trusted")),
                ForkPolicy::TrustedOnly,
                10,
            ),
            1,
        )
        .expect("short-lived handle");
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("capacity");
    let admitted = control
        .admit(
            capsule(),
            policy("trusted"),
            JobRequest::new(false, vec![secret], Vec::new(), 3).expect("safe request"),
            &mut broker,
            1,
        )
        .expect("admitted before isolation establishment");
    let mut substrate = FixedSubstrate(Err(SubstrateRefusal::IsolationUnavailable));
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("typed pre-launch refusal is receipted");

    assert_eq!(
        receipt.outcome(),
        CheckOutcome::SubstrateRefused {
            refusal: SubstrateRefusal::IsolationUnavailable,
        }
    );
    assert_eq!(receipt.reaped().processes_reaped, 0);
    assert!(broker.is_revoked(secret));
}

#[test]
fn cancellation_reaps_the_full_observed_tree_and_keeps_the_cancelled_outcome() {
    let mut broker = SecretBroker::default();
    let cancellation_ceilings = cancellation_ceilings();
    let mut control = RunnerControlPlane::new(cancellation_ceilings, 1).expect("capacity");
    let admitted = control
        .admit(
            capsule(),
            policy_with_ceilings("trusted", cancellation_ceilings),
            JobRequest::new(false, Vec::new(), Vec::new(), 4).expect("safe request"),
            &mut broker,
            1,
        )
        .expect("admitted before cancellation");
    let mut substrate = FixedSubstrate(Ok(observation(
        ExitClass::Cancelled,
        usage(0, 3),
        3,
        ContainmentClass::NonCooperative,
    )));
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("cancelled terminal receipt");

    assert_eq!(receipt.outcome(), CheckOutcome::Cancelled);
    assert_eq!(receipt.reaped().processes_reaped, 3);
    assert_eq!(
        receipt.reaped().containment,
        ContainmentClass::NonCooperative
    );
}

#[test]
fn forked_work_cannot_reuse_trusted_cache_or_secret_authority() {
    let trusted = policy("trusted");
    let untrusted = policy("untrusted");
    assert_ne!(
        fgit_runner::CacheNamespace::for_capsule(trusted.trust_domain(), &capsule()),
        fgit_runner::CacheNamespace::for_capsule(untrusted.trust_domain(), &capsule())
    );

    let mut broker = SecretBroker::default();
    let secret = broker
        .issue(
            SecretRequest::new(
                text("DEPLOY_TOKEN"),
                TrustDomain::new(text("trusted")),
                ForkPolicy::TrustedOnly,
                10,
            ),
            1,
        )
        .expect("trusted handle");
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("capacity");
    assert_eq!(
        control.admit(
            capsule(),
            trusted,
            JobRequest::new(true, vec![secret], Vec::new(), 5).expect("fork request"),
            &mut broker,
            1,
        ),
        Err(RunnerRefusal::SecretForbiddenForFork)
    );
    assert_eq!(
        control.admit(
            capsule(),
            untrusted,
            JobRequest::new(false, vec![secret], Vec::new(), 6).expect("untrusted request"),
            &mut broker,
            1,
        ),
        Err(RunnerRefusal::SecretTrustDomainMismatch)
    );
}

#[test]
fn stored_check_receipts_disclose_neither_secret_class_nor_secret_material() {
    let mut broker = SecretBroker::default();
    let secret = broker
        .issue(
            SecretRequest::new(
                text("DEPLOY_TOKEN"),
                TrustDomain::new(text("trusted")),
                ForkPolicy::TrustedOnly,
                10,
            ),
            1,
        )
        .expect("secret handle");
    let mut control = RunnerControlPlane::new(ceilings(), 1).expect("capacity");
    let admitted = control
        .admit(
            capsule(),
            policy("trusted"),
            JobRequest::new(false, vec![secret], Vec::new(), 7).expect("safe request"),
            &mut broker,
            1,
        )
        .expect("admitted run");
    let mut substrate = FixedSubstrate(Ok(observation(
        ExitClass::Succeeded,
        usage(0, 1),
        1,
        ContainmentClass::Cooperative,
    )));
    let receipt = control
        .execute(admitted, &mut substrate, &mut broker)
        .expect("terminal receipt");

    assert!(!format!("{receipt:?}").contains("DEPLOY_TOKEN"));
    assert_eq!(receipt.revoked_secrets(), 1);
    assert!(broker.is_revoked(secret));
}
