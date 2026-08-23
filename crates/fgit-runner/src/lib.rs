#![forbid(unsafe_code)]
//! Typed runner containment control plane.
//!
//! This crate owns the immutable input capsule, trust-scoped cache key, secret
//! lease binding, resource accounting, and receipt evidence around one hostile
//! CI job.  It does not pretend that a policy object is an operating-system
//! boundary: the OS-specific boundary is supplied through
//! [`ContainmentSubstrate`].  A platform that cannot provide that contract is
//! refused before a job is admitted; there is no in-process or weaker fallback.
//!
//! The first supported profile is the ADR-0007 Linux process-isolation profile
//! with denied egress.  This control-plane slice deliberately records only a
//! substrate observation.  Creating namespaces/cgroups and owning their
//! Asupersync region is a substrate implementation concern, while this crate
//! keeps the same capsule, secret, cache, resource, and receipt rules for each
//! future platform.
//!
//! # Non-claims
//!
//! A successful receipt says that the named substrate reported the declared
//! outcome for the exact capsule.  It is not a proof that the checked source is
//! correct, and this crate alone does not claim that Linux namespaces are a
//! multi-tenant boundary.  In particular, fixture substrates exercise the
//! control plane only; the hostile execution corpus must run against a real
//! registered substrate.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fgit_claim::ClaimRank;
use fgit_codec::{DecodeLimits, Encoder};
use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes, sha256_digest};
use fgit_evidence::{
    EvidenceArtifact, EvidenceContext, EvidenceRecord, EvidenceRecordBody, EvidenceText,
    ReplayCompleteness,
};
use fgit_resource::OpaqueHandle;
use fgit_resource::kinds::{
    ContainmentClass, ExitClass, NetworkPolicy, RunnerFinished, RunnerReaped, RunnerRequest,
    SandboxProfile,
};

/// Maximum number of source objects bound into one capsule.
pub const MAX_SOURCE_OBJECTS: usize = 4_096;
/// Maximum number of environment bindings admitted into one capsule.
pub const MAX_ENVIRONMENT_BINDINGS: usize = 128;
/// Maximum number of brokered secret handles a job may receive.
pub const MAX_SECRET_LEASES: usize = 64;
/// Maximum number of artifact commitments recorded in one receipt.
pub const MAX_ARTIFACTS: usize = 1_024;
/// Maximum bytes accepted in one canonical runner text field.
pub const MAX_RUNNER_TEXT_BYTES: usize = 256;

const CAPSULE_DOMAIN: &[u8] = b"frankengit/build-input-capsule/v1\0";
const CACHE_DOMAIN: &[u8] = b"frankengit/runner-cache-key/v1\0";

/// A registered SHA-256 commitment used for runner inputs and outputs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Commitment(Digest);

impl Commitment {
    /// Computes the fixed SHA-256 commitment of `bytes`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest = sha256_digest(bytes);
        let body = DigestBytes::try_new(&digest)
            .expect("a SHA-256 digest always has the registered 32-byte width");
        Self(Digest::new(DigestAlgorithm::Sha256.id(), body))
    }

    /// Adopts an existing registered SHA-256 commitment.
    pub fn try_from_digest(digest: Digest) -> Result<Self, RunnerRefusal> {
        if digest.algorithm() != DigestAlgorithm::Sha256.id() {
            return Err(RunnerRefusal::UnsupportedDigestAlgorithm {
                observed: digest.algorithm().code_point(),
            });
        }
        Ok(Self(digest))
    }

    /// The tagged digest carried by this commitment.
    #[must_use]
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// Canonical bounded text accepted by runner protocol values.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunnerText(String);

impl RunnerText {
    /// Parses one ASCII, whitespace-free protocol field.
    pub fn parse(field: &'static str, value: &str) -> Result<Self, RunnerRefusal> {
        if value.is_empty() {
            return Err(RunnerRefusal::InvalidText {
                field,
                reason: "must not be empty",
            });
        }
        if value.len() > MAX_RUNNER_TEXT_BYTES {
            return Err(RunnerRefusal::InvalidText {
                field,
                reason: "exceeds the bounded canonical length",
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(RunnerRefusal::InvalidText {
                field,
                reason: "must contain printable ASCII without whitespace",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The canonical bytes represented by this field.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunnerText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One verified object in the exact source closure supplied to a build.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceObject {
    commitment: Commitment,
    byte_len: u64,
}

impl SourceObject {
    /// Names one source object and the verified length it had at admission.
    #[must_use]
    pub const fn new(commitment: Commitment, byte_len: u64) -> Self {
        Self {
            commitment,
            byte_len,
        }
    }

    /// The verified content commitment.
    #[must_use]
    pub const fn commitment(self) -> Commitment {
        self.commitment
    }

    /// The verified byte length.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }
}

/// One explicitly admitted environment binding.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentBinding {
    name: RunnerText,
    value: RunnerText,
}

impl EnvironmentBinding {
    /// Builds a portable upper-case environment binding.
    pub fn new(name: RunnerText, value: RunnerText) -> Result<Self, RunnerRefusal> {
        let valid_name = name
            .as_str()
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                0 => byte.is_ascii_uppercase() || byte == b'_',
                _ => byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_',
            });
        if !valid_name {
            return Err(RunnerRefusal::InvalidText {
                field: "environment_name",
                reason: "must be a portable upper-case environment name",
            });
        }
        Ok(Self { name, value })
    }

    /// Binding name.
    #[must_use]
    pub const fn name(&self) -> &RunnerText {
        &self.name
    }

    /// Binding value.
    #[must_use]
    pub const fn value(&self) -> &RunnerText {
        &self.value
    }
}

/// Identity of every build-relevant input.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BuildInputCapsule {
    authority_head: Commitment,
    source_objects: Vec<SourceObject>,
    dependency_lock: Commitment,
    toolchain: RunnerText,
    environment: Vec<EnvironmentBinding>,
    id: CapsuleId,
}

impl BuildInputCapsule {
    /// Creates an immutable capsule from an exact, deduplicated input closure.
    ///
    /// The constructor sorts sets before identifying the capsule and refuses
    /// duplicate commitments or variable names.  This avoids depending on map
    /// iteration order while retaining all caller-provided data.
    pub fn new(
        authority_head: Commitment,
        mut source_objects: Vec<SourceObject>,
        dependency_lock: Commitment,
        toolchain: RunnerText,
        mut environment: Vec<EnvironmentBinding>,
    ) -> Result<Self, RunnerRefusal> {
        if source_objects.is_empty() {
            return Err(RunnerRefusal::EmptySourceClosure);
        }
        if source_objects.len() > MAX_SOURCE_OBJECTS {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "source_objects",
                limit: MAX_SOURCE_OBJECTS,
            });
        }
        if environment.len() > MAX_ENVIRONMENT_BINDINGS {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "environment",
                limit: MAX_ENVIRONMENT_BINDINGS,
            });
        }

        source_objects.sort_unstable_by_key(|object| object.commitment());
        if source_objects
            .windows(2)
            .any(|pair| pair[0].commitment() == pair[1].commitment())
        {
            return Err(RunnerRefusal::DuplicateSourceObject);
        }
        environment.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        if environment
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(RunnerRefusal::DuplicateEnvironmentName);
        }

        let canonical = capsule_bytes(
            authority_head,
            &source_objects,
            dependency_lock,
            &toolchain,
            &environment,
        );
        Ok(Self {
            authority_head,
            source_objects,
            dependency_lock,
            toolchain,
            environment,
            id: CapsuleId(Commitment::of_bytes(&canonical)),
        })
    }

    /// Identity of this exact immutable capsule.
    #[must_use]
    pub const fn id(&self) -> CapsuleId {
        self.id
    }

    /// Authenticated authority position used to assemble the source closure.
    #[must_use]
    pub const fn authority_head(&self) -> Commitment {
        self.authority_head
    }

    /// Canonically ordered source closure.
    #[must_use]
    pub fn source_objects(&self) -> &[SourceObject] {
        &self.source_objects
    }

    /// Exact dependency lock commitment.
    #[must_use]
    pub const fn dependency_lock(&self) -> Commitment {
        self.dependency_lock
    }

    /// Pinned toolchain identity.
    #[must_use]
    pub const fn toolchain(&self) -> &RunnerText {
        &self.toolchain
    }

    /// Commitment of the pinned toolchain identity for obligation hand-off.
    #[must_use]
    pub fn toolchain_commitment(&self) -> Commitment {
        Commitment::of_bytes(self.toolchain.as_str().as_bytes())
    }

    /// Canonically ordered environment allowlist.
    #[must_use]
    pub fn environment(&self) -> &[EnvironmentBinding] {
        &self.environment
    }
}

/// Opaque identity of a [`BuildInputCapsule`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapsuleId(Commitment);

impl CapsuleId {
    /// The SHA-256 commitment of the canonical capsule preimage.
    #[must_use]
    pub const fn commitment(self) -> Commitment {
        self.0
    }
}

impl fmt::Display for CapsuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// A trust partition for secrets and cache entries.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustDomain(RunnerText);

impl TrustDomain {
    /// Names one policy-selected trust partition.
    #[must_use]
    pub const fn new(value: RunnerText) -> Self {
        Self(value)
    }

    /// The stable policy name.
    #[must_use]
    pub const fn name(&self) -> &RunnerText {
        &self.0
    }
}

/// A deterministic, trust-scoped cache namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheNamespace(Commitment);

impl CacheNamespace {
    /// Derives a cache namespace from a trust domain and one exact capsule.
    #[must_use]
    pub fn for_capsule(domain: &TrustDomain, capsule: &BuildInputCapsule) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CACHE_DOMAIN);
        write_text(&mut bytes, domain.name().as_str());
        write_digest(&mut bytes, capsule.id().commitment().digest());
        Self(Commitment::of_bytes(&bytes))
    }

    /// The immutable namespace commitment.
    #[must_use]
    pub const fn commitment(self) -> Commitment {
        self.0
    }
}

impl fmt::Display for CacheNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// Bounded resource ceilings enforced before a run reaches a substrate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResourceCeilings {
    cpu_micros: u64,
    memory_bytes: u64,
    disk_bytes: u64,
    network_bytes: u64,
    processes: u32,
    wall_clock_millis: u64,
}

impl ResourceCeilings {
    /// Creates one complete pre-admission resource envelope.
    pub fn new(
        cpu_micros: u64,
        memory_bytes: u64,
        disk_bytes: u64,
        network_bytes: u64,
        processes: u32,
        wall_clock_millis: u64,
    ) -> Result<Self, RunnerRefusal> {
        for (field, value) in [
            ("cpu_micros", cpu_micros),
            ("memory_bytes", memory_bytes),
            ("disk_bytes", disk_bytes),
            ("wall_clock_millis", wall_clock_millis),
        ] {
            if value == 0 {
                return Err(RunnerRefusal::ZeroResourceCeiling { field });
            }
        }
        if processes == 0 {
            return Err(RunnerRefusal::ZeroResourceCeiling { field: "processes" });
        }
        Ok(Self {
            cpu_micros,
            memory_bytes,
            disk_bytes,
            network_bytes,
            processes,
            wall_clock_millis,
        })
    }

    /// The first exceeded resource in a stable public ordering.
    #[must_use]
    pub fn first_exceeded(self, usage: ResourceUsage) -> Option<ResourceDimension> {
        [
            (
                ResourceDimension::CpuMicros,
                usage.cpu_micros > self.cpu_micros,
            ),
            (
                ResourceDimension::MemoryBytes,
                usage.memory_bytes > self.memory_bytes,
            ),
            (
                ResourceDimension::DiskBytes,
                usage.disk_bytes > self.disk_bytes,
            ),
            (
                ResourceDimension::NetworkBytes,
                usage.network_bytes > self.network_bytes,
            ),
            (
                ResourceDimension::Processes,
                usage.processes > self.processes,
            ),
            (
                ResourceDimension::WallClockMillis,
                usage.wall_clock_millis > self.wall_clock_millis,
            ),
        ]
        .into_iter()
        .find_map(|(dimension, exceeded)| exceeded.then_some(dimension))
    }

    /// Converts this policy into the existing runner-slot reservation shape.
    pub fn runner_request(
        self,
        profile: SandboxProfile,
        toolchain: Commitment,
        network: NetworkPolicy,
        cache: CacheNamespace,
    ) -> Result<RunnerRequest, RunnerRefusal> {
        let toolchain = OpaqueHandle::new(toolchain.digest().bytes().as_bytes())
            .map_err(|_| RunnerRefusal::OpaqueHandleUnavailable { field: "toolchain" })?;
        let cache_namespace = OpaqueHandle::new(cache.commitment().digest().bytes().as_bytes())
            .map_err(|_| RunnerRefusal::OpaqueHandleUnavailable {
                field: "cache_namespace",
            })?;
        Ok(RunnerRequest {
            sandbox: profile,
            toolchain,
            network,
            cache_namespace,
        })
    }
}

/// Measured resource usage returned by a containment substrate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResourceUsage {
    /// CPU time consumed by all run processes.
    pub cpu_micros: u64,
    /// Peak memory charged to the run.
    pub memory_bytes: u64,
    /// Writable disk bytes charged to the run.
    pub disk_bytes: u64,
    /// Network bytes observed at the substrate boundary.
    pub network_bytes: u64,
    /// Highest concurrent process count observed.
    pub processes: u32,
    /// Elapsed wall-clock time measured by the substrate.
    pub wall_clock_millis: u64,
}

/// A dimension named by a resource termination or refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceDimension {
    /// CPU-time budget.
    CpuMicros,
    /// Memory budget.
    MemoryBytes,
    /// Disk budget.
    DiskBytes,
    /// Network-byte budget.
    NetworkBytes,
    /// Process-count budget.
    Processes,
    /// Wall-clock budget.
    WallClockMillis,
}

impl ResourceDimension {
    const fn token(self) -> &'static str {
        match self {
            Self::CpuMicros => "cpu_micros",
            Self::MemoryBytes => "memory_bytes",
            Self::DiskBytes => "disk_bytes",
            Self::NetworkBytes => "network_bytes",
            Self::Processes => "processes",
            Self::WallClockMillis => "wall_clock_millis",
        }
    }
}

/// The policy-selected runner profile for one admission.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RunnerPolicy {
    trust_domain: TrustDomain,
    profile: SandboxProfile,
    network: NetworkPolicy,
    ceilings: ResourceCeilings,
}

impl RunnerPolicy {
    /// Creates a policy that has no implicit egress or platform downgrade.
    pub fn new(
        trust_domain: TrustDomain,
        profile: SandboxProfile,
        network: NetworkPolicy,
        ceilings: ResourceCeilings,
    ) -> Result<Self, RunnerRefusal> {
        if !cfg!(target_os = "linux") {
            return Err(RunnerRefusal::UnsupportedPlatform);
        }
        if profile != SandboxProfile::ProcessIsolated {
            return Err(RunnerRefusal::UnsupportedSandboxProfile { profile });
        }
        if network != NetworkPolicy::Denied {
            return Err(RunnerRefusal::UnsupportedNetworkPolicy { network });
        }
        Ok(Self {
            trust_domain,
            profile,
            network,
            ceilings,
        })
    }

    /// Trust partition used by secrets and cache entries.
    #[must_use]
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Selected substrate profile.
    #[must_use]
    pub const fn profile(&self) -> SandboxProfile {
        self.profile
    }

    /// Egress policy, currently always denied for the supported profile.
    #[must_use]
    pub const fn network(&self) -> NetworkPolicy {
        self.network
    }

    /// Pre-admission resource envelope.
    #[must_use]
    pub const fn ceilings(&self) -> ResourceCeilings {
        self.ceilings
    }
}

/// Whether a secret may be delivered to a forked job.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ForkPolicy {
    /// A fork never receives this secret.
    TrustedOnly,
    /// The secret is explicitly approved for a forked trust domain.
    ForkAllowed,
}

/// Region-scoped request for a brokered secret handle.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretRequest {
    name: RunnerText,
    trust_domain: TrustDomain,
    fork_policy: ForkPolicy,
    expires_at: u64,
}

impl SecretRequest {
    /// Creates a secret request that carries no secret material.
    #[must_use]
    pub const fn new(
        name: RunnerText,
        trust_domain: TrustDomain,
        fork_policy: ForkPolicy,
        expires_at: u64,
    ) -> Self {
        Self {
            name,
            trust_domain,
            fork_policy,
            expires_at,
        }
    }
}

/// Opaque broker handle.  It never contains secret bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretLease(u64);

/// An ephemeral broker for one runner region.
///
/// This map records ownership only; it is neither canonical state nor durable
/// secret storage.  Actual secret material stays behind the selected
/// substrate's delivery boundary.
#[derive(Debug, Default)]
pub struct SecretBroker {
    next_id: u64,
    records: BTreeMap<SecretLease, SecretRecord>,
}

#[derive(Clone, Debug)]
struct SecretRecord {
    request: SecretRequest,
    state: SecretState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretState {
    Issued,
    Bound,
    Revoked,
}

impl SecretBroker {
    /// Issues one non-material secret handle for a future job.
    pub fn issue(
        &mut self,
        request: SecretRequest,
        logical_now: u64,
    ) -> Result<SecretLease, RunnerRefusal> {
        if request.expires_at <= logical_now {
            return Err(RunnerRefusal::SecretAlreadyExpired);
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RunnerRefusal::SecretLeaseExhausted)?;
        let lease = SecretLease(self.next_id);
        self.records.insert(
            lease,
            SecretRecord {
                request,
                state: SecretState::Issued,
            },
        );
        Ok(lease)
    }

    fn bind_all(
        &mut self,
        leases: &[SecretLease],
        policy: &RunnerPolicy,
        forked: bool,
        logical_now: u64,
    ) -> Result<(), RunnerRefusal> {
        let mut seen = BTreeSet::new();
        let mut secret_classes = BTreeSet::new();
        for lease in leases {
            if !seen.insert(*lease) {
                return Err(RunnerRefusal::DuplicateSecretLease);
            }
            let Some(record) = self.records.get(lease) else {
                return Err(RunnerRefusal::UnknownSecretLease);
            };
            if record.state != SecretState::Issued {
                return Err(RunnerRefusal::SecretLeaseUnavailable);
            }
            if record.request.expires_at <= logical_now {
                return Err(RunnerRefusal::SecretAlreadyExpired);
            }
            if !secret_classes.insert(record.request.name.clone()) {
                return Err(RunnerRefusal::DuplicateSecretClass);
            }
            if record.request.trust_domain != policy.trust_domain {
                return Err(RunnerRefusal::SecretTrustDomainMismatch);
            }
            if forked && record.request.fork_policy != ForkPolicy::ForkAllowed {
                return Err(RunnerRefusal::SecretForbiddenForFork);
            }
        }
        for lease in leases {
            let Some(record) = self.records.get_mut(lease) else {
                return Err(RunnerRefusal::UnknownSecretLease);
            };
            record.state = SecretState::Bound;
        }
        Ok(())
    }

    fn revoke_all(&mut self, leases: &[SecretLease]) -> Result<u16, RunnerRefusal> {
        let mut revoked = 0_u16;
        for lease in leases {
            let Some(record) = self.records.get_mut(lease) else {
                return Err(RunnerRefusal::UnknownSecretLease);
            };
            if record.state != SecretState::Bound {
                return Err(RunnerRefusal::SecretLeaseUnavailable);
            }
            record.state = SecretState::Revoked;
            revoked = revoked
                .checked_add(1)
                .ok_or(RunnerRefusal::SecretLeaseExhausted)?;
        }
        Ok(revoked)
    }

    /// Returns whether a lease has been revoked after terminal handling.
    #[must_use]
    pub fn is_revoked(&self, lease: SecretLease) -> bool {
        self.records
            .get(&lease)
            .is_some_and(|record| record.state == SecretState::Revoked)
    }
}

/// A probe used by the hostile corpus to ask for a forbidden ambient surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ForbiddenProbe {
    /// The link-local cloud metadata service.
    MetadataService,
    /// Credentials inherited from the host process environment.
    AmbientCredential,
}

/// Inputs unique to one admitted job.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct JobRequest {
    forked: bool,
    secret_leases: Vec<SecretLease>,
    logical_order: u64,
}

impl JobRequest {
    /// Builds a job request.  Forbidden-probe fixtures are refused through
    /// this same admission path before any substrate work begins.
    pub fn new(
        forked: bool,
        secret_leases: Vec<SecretLease>,
        hostile_probes: Vec<ForbiddenProbe>,
        logical_order: u64,
    ) -> Result<Self, RunnerRefusal> {
        if secret_leases.len() > MAX_SECRET_LEASES {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "secret_leases",
                limit: MAX_SECRET_LEASES,
            });
        }
        if !hostile_probes.is_empty() {
            return Err(RunnerRefusal::ForbiddenProbeRequested {
                probe: hostile_probes[0],
            });
        }
        Ok(Self {
            forked,
            secret_leases,
            logical_order,
        })
    }
}

/// The plan given to the chosen isolation substrate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SandboxPlan {
    capsule: BuildInputCapsule,
    cache_namespace: CacheNamespace,
    policy: RunnerPolicy,
    secret_leases: Vec<SecretLease>,
    logical_order: u64,
}

impl SandboxPlan {
    /// Exact immutable capsule visible to the substrate.
    #[must_use]
    pub const fn capsule(&self) -> &BuildInputCapsule {
        &self.capsule
    }

    /// Only cache namespace visible to this run.
    #[must_use]
    pub const fn cache_namespace(&self) -> CacheNamespace {
        self.cache_namespace
    }

    /// Non-negotiable policy the substrate must establish before work starts.
    #[must_use]
    pub const fn policy(&self) -> &RunnerPolicy {
        &self.policy
    }

    /// Broker handles, never secret material.
    #[must_use]
    pub fn secret_leases(&self) -> &[SecretLease] {
        &self.secret_leases
    }

    /// Stable coordination order carried into the receipt.
    #[must_use]
    pub const fn logical_order(&self) -> u64 {
        self.logical_order
    }
}

/// A terminal report supplied by a real containment substrate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubstrateObservation {
    /// How the process tree terminated.
    pub exit: ExitClass,
    /// Resource usage measured at the containment boundary.
    pub usage: ResourceUsage,
    /// Evidence that processes were reaped or explicitly contained.
    pub reaped: RunnerReaped,
    /// Commitment of the immutable log object.
    pub log_root: Commitment,
    /// Immutable output artifact commitments in deterministic output order.
    pub artifacts: Vec<Commitment>,
}

/// The one substrate interface every platform must implement and test.
pub trait ContainmentSubstrate {
    /// Establishes `plan` before user work begins and returns its terminal
    /// observation only after reaping or explicit containment.
    fn launch(&mut self, plan: &SandboxPlan) -> Result<SubstrateObservation, SubstrateRefusal>;
}

/// A typed reason that a substrate declined to establish the requested plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubstrateRefusal {
    /// The requested policy is not implemented by this substrate.
    UnsupportedPolicy,
    /// The substrate could not reserve capacity before starting work.
    NoCapacity,
    /// A required isolation primitive was unavailable.
    IsolationUnavailable,
    /// The substrate cannot prove process reaping for this run.
    ReapingUnverifiable,
}

/// A runner capacity controller.
#[derive(Debug)]
pub struct RunnerControlPlane {
    maximum: ResourceCeilings,
    available_slots: u16,
}

impl RunnerControlPlane {
    /// Creates a controller with a finite, predeclared capacity.
    pub const fn new(maximum: ResourceCeilings, slots: u16) -> Result<Self, RunnerRefusal> {
        if slots == 0 {
            return Err(RunnerRefusal::NoRunnerCapacity);
        }
        Ok(Self {
            maximum,
            available_slots: slots,
        })
    }

    /// Admits a complete plan before any substrate is asked to start work.
    pub fn admit(
        &mut self,
        capsule: BuildInputCapsule,
        policy: RunnerPolicy,
        request: JobRequest,
        broker: &mut SecretBroker,
        logical_now: u64,
    ) -> Result<AdmittedRun, RunnerRefusal> {
        if self.available_slots == 0 {
            return Err(RunnerRefusal::NoRunnerCapacity);
        }
        if let Some(dimension) = self.maximum.first_exceeded(ResourceUsage {
            cpu_micros: policy.ceilings.cpu_micros,
            memory_bytes: policy.ceilings.memory_bytes,
            disk_bytes: policy.ceilings.disk_bytes,
            network_bytes: policy.ceilings.network_bytes,
            processes: policy.ceilings.processes,
            wall_clock_millis: policy.ceilings.wall_clock_millis,
        }) {
            return Err(RunnerRefusal::ResourceCeilingAboveRunnerMaximum { dimension });
        }
        broker.bind_all(&request.secret_leases, &policy, request.forked, logical_now)?;
        self.available_slots -= 1;
        let cache_namespace = CacheNamespace::for_capsule(policy.trust_domain(), &capsule);
        let runner_request = policy.ceilings.runner_request(
            policy.profile,
            capsule.toolchain_commitment(),
            policy.network,
            cache_namespace,
        )?;
        Ok(AdmittedRun {
            plan: SandboxPlan {
                capsule,
                cache_namespace,
                policy,
                secret_leases: request.secret_leases,
                logical_order: request.logical_order,
            },
            runner_request,
        })
    }

    /// Invokes a real substrate and always turns a terminal observation into a
    /// revocation-aware receipt.
    pub fn execute<S: ContainmentSubstrate>(
        &mut self,
        admitted: AdmittedRun,
        substrate: &mut S,
        broker: &mut SecretBroker,
    ) -> Result<CheckReceipt, RunnerRefusal> {
        match substrate.launch(admitted.plan()) {
            Ok(observation) => self.finish(admitted, observation, broker),
            Err(refusal) => self.refuse(admitted, refusal, broker),
        }
    }

    fn finish(
        &mut self,
        admitted: AdmittedRun,
        observation: SubstrateObservation,
        broker: &mut SecretBroker,
    ) -> Result<CheckReceipt, RunnerRefusal> {
        let outcome = match (
            admitted
                .plan
                .policy
                .ceilings
                .first_exceeded(observation.usage),
            observation.exit,
        ) {
            (Some(dimension), ExitClass::ResourceCeiling) => {
                CheckOutcome::ResourceCeiling { dimension }
            }
            (Some(dimension), _) => CheckOutcome::ContainmentFailure {
                kind: ContainmentFailureKind::MissingResourceTermination { dimension },
            },
            (None, ExitClass::ResourceCeiling) => CheckOutcome::ContainmentFailure {
                kind: ContainmentFailureKind::UnmeasuredResourceTermination,
            },
            (None, exit) => CheckOutcome::from_non_resource_exit(exit),
        };
        self.finalize(admitted, outcome, observation, broker)
    }

    fn refuse(
        &mut self,
        admitted: AdmittedRun,
        refusal: SubstrateRefusal,
        broker: &mut SecretBroker,
    ) -> Result<CheckReceipt, RunnerRefusal> {
        let observation = SubstrateObservation {
            exit: ExitClass::Cancelled,
            usage: ResourceUsage {
                cpu_micros: 0,
                memory_bytes: 0,
                disk_bytes: 0,
                network_bytes: 0,
                processes: 0,
                wall_clock_millis: 0,
            },
            reaped: RunnerReaped {
                processes_reaped: 0,
                containment: ContainmentClass::Cooperative,
            },
            log_root: Commitment::of_bytes(refusal.token().as_bytes()),
            artifacts: Vec::new(),
        };
        self.finalize(
            admitted,
            CheckOutcome::SubstrateRefused { refusal },
            observation,
            broker,
        )
    }

    fn finalize(
        &mut self,
        admitted: AdmittedRun,
        outcome: CheckOutcome,
        observation: SubstrateObservation,
        broker: &mut SecretBroker,
    ) -> Result<CheckReceipt, RunnerRefusal> {
        if observation.artifacts.len() > MAX_ARTIFACTS {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "artifacts",
                limit: MAX_ARTIFACTS,
            });
        }
        if has_duplicate_commitment(&observation.artifacts) {
            return Err(RunnerRefusal::DuplicateArtifactCommitment);
        }
        let evidence = receipt_evidence(admitted.plan(), outcome, &observation)?;
        let revoked_secrets = broker.revoke_all(&admitted.plan.secret_leases)?;
        self.available_slots = self.available_slots.saturating_add(1);
        let runner_finished = RunnerFinished {
            exit_class: outcome.exit_class(),
            artifacts: u32::try_from(observation.artifacts.len()).map_err(|_| {
                RunnerRefusal::CollectionTooLarge {
                    field: "artifacts",
                    limit: MAX_ARTIFACTS,
                }
            })?,
            log_root: evidence.id(),
        };
        Ok(CheckReceipt {
            capsule_id: admitted.plan.capsule.id(),
            cache_namespace: admitted.plan.cache_namespace,
            runner_request: admitted.runner_request,
            outcome,
            usage: observation.usage,
            artifacts: observation.artifacts,
            runner_finished,
            reaped: observation.reaped,
            revoked_secrets,
            evidence,
        })
    }
}

/// A plan admitted by [`RunnerControlPlane`].
#[must_use = "an admitted run must be executed or settled through the owning region"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRun {
    plan: SandboxPlan,
    runner_request: RunnerRequest,
}

impl AdmittedRun {
    /// Plan that the substrate must establish.
    #[must_use]
    pub const fn plan(&self) -> &SandboxPlan {
        &self.plan
    }
}

/// One terminal check state, including typed refusal and resource outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CheckOutcome {
    /// User work completed successfully.
    Succeeded,
    /// User work failed after containment was established.
    Failed,
    /// The region cancelled the run.
    Cancelled,
    /// A resource ceiling was hit and recorded by its stable dimension.
    ResourceCeiling {
        /// The first exceeded resource in protocol order.
        dimension: ResourceDimension,
    },
    /// The substrate failed to produce a coherent terminal containment report.
    ContainmentFailure {
        /// Exact evidence mismatch that prevents a normal terminal claim.
        kind: ContainmentFailureKind,
    },
    /// The requested substrate refused before user work started.
    SubstrateRefused {
        /// Refusal emitted by the requested containment substrate.
        refusal: SubstrateRefusal,
    },
}

impl CheckOutcome {
    const fn from_non_resource_exit(exit: ExitClass) -> Self {
        match exit {
            ExitClass::Succeeded => Self::Succeeded,
            ExitClass::Failed => Self::Failed,
            ExitClass::Cancelled => Self::Cancelled,
            ExitClass::ResourceCeiling => Self::ContainmentFailure {
                kind: ContainmentFailureKind::UnmeasuredResourceTermination,
            },
        }
    }

    const fn exit_class(self) -> ExitClass {
        match self {
            Self::Succeeded => ExitClass::Succeeded,
            Self::Failed => ExitClass::Failed,
            Self::Cancelled | Self::ContainmentFailure { .. } | Self::SubstrateRefused { .. } => {
                ExitClass::Cancelled
            }
            Self::ResourceCeiling { .. } => ExitClass::ResourceCeiling,
        }
    }

    const fn token(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ResourceCeiling { dimension } => dimension.token(),
            Self::ContainmentFailure { kind } => kind.token(),
            Self::SubstrateRefused { refusal } => refusal.token(),
        }
    }
}

/// A terminal report inconsistency that must be visible as containment failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContainmentFailureKind {
    /// Usage exceeded a limit but the substrate did not report resource termination.
    MissingResourceTermination {
        /// First exceeded resource in protocol order.
        dimension: ResourceDimension,
    },
    /// The substrate claimed resource termination without any measured excess.
    UnmeasuredResourceTermination,
}

impl ContainmentFailureKind {
    const fn token(self) -> &'static str {
        match self {
            Self::MissingResourceTermination { dimension } => dimension.token(),
            Self::UnmeasuredResourceTermination => "unmeasured-resource-termination",
        }
    }
}

impl SubstrateRefusal {
    const fn token(self) -> &'static str {
        match self {
            Self::UnsupportedPolicy => "unsupported_policy",
            Self::NoCapacity => "no_capacity",
            Self::IsolationUnavailable => "isolation_unavailable",
            Self::ReapingUnverifiable => "reaping_unverifiable",
        }
    }
}

/// Immutable terminal receipt for one runner execution attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReceipt {
    capsule_id: CapsuleId,
    cache_namespace: CacheNamespace,
    runner_request: RunnerRequest,
    outcome: CheckOutcome,
    usage: ResourceUsage,
    artifacts: Vec<Commitment>,
    runner_finished: RunnerFinished,
    reaped: RunnerReaped,
    revoked_secrets: u16,
    evidence: EvidenceRecord,
}

impl CheckReceipt {
    /// Exact input capsule that this receipt describes.
    #[must_use]
    pub const fn capsule_id(&self) -> CapsuleId {
        self.capsule_id
    }

    /// Immutable cache namespace used by the job.
    #[must_use]
    pub const fn cache_namespace(&self) -> CacheNamespace {
        self.cache_namespace
    }

    /// Existing obligation vocabulary for the allocated runner slot.
    #[must_use]
    pub const fn runner_request(&self) -> RunnerRequest {
        self.runner_request
    }

    /// Terminal run outcome.
    #[must_use]
    pub const fn outcome(&self) -> CheckOutcome {
        self.outcome
    }

    /// Substrate-measured resource use.
    #[must_use]
    pub const fn usage(&self) -> ResourceUsage {
        self.usage
    }

    /// Every immutable output artifact commitment in substrate output order.
    #[must_use]
    pub fn artifacts(&self) -> &[Commitment] {
        &self.artifacts
    }

    /// Runner-slot commit receipt, rooted at immutable evidence.
    #[must_use]
    pub const fn runner_finished(&self) -> RunnerFinished {
        self.runner_finished
    }

    /// Reaping acknowledgement required at terminal handling.
    #[must_use]
    pub const fn reaped(&self) -> RunnerReaped {
        self.reaped
    }

    /// Number of secret handles revoked while finalizing.
    #[must_use]
    pub const fn revoked_secrets(&self) -> u16 {
        self.revoked_secrets
    }

    /// Immutable codec-framed provenance record for this receipt.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceRecord {
        &self.evidence
    }

    /// Re-verifies the linked canonical provenance frame.
    pub fn verify_evidence(&self) -> Result<(), RunnerRefusal> {
        self.evidence
            .verify(DecodeLimits::default())
            .map_err(|_| RunnerRefusal::EvidenceConstruction)
    }
}

/// Typed refusal returned by runner planning, admission, or finalization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RunnerRefusal {
    /// A fixed protocol field was absent, oversized, or noncanonical.
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A non-SHA-256 digest was offered where the profile fixes SHA-256.
    UnsupportedDigestAlgorithm {
        /// Observed algorithm registry code point.
        observed: u16,
    },
    /// No source object was supplied for an exact source closure.
    EmptySourceClosure,
    /// A bounded collection exceeded its protocol limit.
    CollectionTooLarge {
        /// Collection name.
        field: &'static str,
        /// Maximum supported element count.
        limit: usize,
    },
    /// A source closure named one object more than once.
    DuplicateSourceObject,
    /// A receipt named one immutable output artifact more than once.
    DuplicateArtifactCommitment,
    /// The environment allowlist contains an ambiguous duplicate name.
    DuplicateEnvironmentName,
    /// A required resource ceiling was zero.
    ZeroResourceCeiling {
        /// Resource name.
        field: &'static str,
    },
    /// The current target has no registered containment substrate.
    UnsupportedPlatform,
    /// The requested profile has no implementing substrate in this slice.
    UnsupportedSandboxProfile {
        /// Profile selected by the caller.
        profile: SandboxProfile,
    },
    /// The requested egress policy would weaken the first supported profile.
    UnsupportedNetworkPolicy {
        /// Requested egress policy.
        network: NetworkPolicy,
    },
    /// No runner slot was available before any work began.
    NoRunnerCapacity,
    /// A requested job ceiling exceeds the runner's reserved envelope.
    ResourceCeilingAboveRunnerMaximum {
        /// First dimension that exceeded the runner maximum.
        dimension: ResourceDimension,
    },
    /// A resource identity could not fit the existing obligation handle.
    OpaqueHandleUnavailable {
        /// Handle field that could not be constructed.
        field: &'static str,
    },
    /// A request contained the same broker handle twice.
    DuplicateSecretLease,
    /// A request named the same secret class through two handles.
    DuplicateSecretClass,
    /// A broker handle was not issued by this broker.
    UnknownSecretLease,
    /// A lease is not available for the requested lifecycle transition.
    SecretLeaseUnavailable,
    /// A lease expired before it was admitted to a job.
    SecretAlreadyExpired,
    /// A 64-bit secret-handle sequence exhausted.
    SecretLeaseExhausted,
    /// The requested secret belongs to another trust domain.
    SecretTrustDomainMismatch,
    /// A trusted-only secret was requested by a forked job.
    SecretForbiddenForFork,
    /// A hostile corpus request named an ambient surface that is never granted.
    ForbiddenProbeRequested {
        /// Forbidden ambient surface requested by the fixture.
        probe: ForbiddenProbe,
    },
    /// Canonical provenance could not be constructed from a terminal receipt.
    EvidenceConstruction,
}

impl fmt::Display for RunnerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidText { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::UnsupportedDigestAlgorithm { observed } => {
                write!(formatter, "unsupported digest algorithm {observed}")
            }
            Self::EmptySourceClosure => formatter.write_str("source closure must not be empty"),
            Self::CollectionTooLarge { field, limit } => {
                write!(formatter, "{field} exceeds the limit of {limit}")
            }
            Self::DuplicateSourceObject => {
                formatter.write_str("source closure contains a duplicate")
            }
            Self::DuplicateArtifactCommitment => {
                formatter.write_str("receipt contains a duplicate artifact commitment")
            }
            Self::DuplicateEnvironmentName => {
                formatter.write_str("environment allowlist contains a duplicate name")
            }
            Self::ZeroResourceCeiling { field } => write!(formatter, "{field} must be non-zero"),
            Self::UnsupportedPlatform => {
                formatter.write_str("no containment substrate for platform")
            }
            Self::UnsupportedSandboxProfile { profile } => {
                write!(formatter, "unsupported sandbox profile {profile:?}")
            }
            Self::UnsupportedNetworkPolicy { network } => {
                write!(formatter, "unsupported network policy {network:?}")
            }
            Self::NoRunnerCapacity => formatter.write_str("no runner capacity available"),
            Self::ResourceCeilingAboveRunnerMaximum { dimension } => {
                write!(
                    formatter,
                    "runner maximum exceeded for {}",
                    dimension.token()
                )
            }
            Self::OpaqueHandleUnavailable { field } => {
                write!(formatter, "cannot construct obligation handle for {field}")
            }
            Self::DuplicateSecretLease => formatter.write_str("duplicate secret lease"),
            Self::DuplicateSecretClass => formatter.write_str("duplicate secret class"),
            Self::UnknownSecretLease => formatter.write_str("unknown secret lease"),
            Self::SecretLeaseUnavailable => formatter.write_str("secret lease is unavailable"),
            Self::SecretAlreadyExpired => formatter.write_str("secret lease is already expired"),
            Self::SecretLeaseExhausted => formatter.write_str("secret lease sequence exhausted"),
            Self::SecretTrustDomainMismatch => {
                formatter.write_str("secret belongs to another trust domain")
            }
            Self::SecretForbiddenForFork => formatter.write_str("secret is forbidden for forks"),
            Self::ForbiddenProbeRequested { probe } => {
                write!(formatter, "forbidden ambient probe requested: {probe:?}")
            }
            Self::EvidenceConstruction => {
                formatter.write_str("receipt evidence construction refused")
            }
        }
    }
}

impl std::error::Error for RunnerRefusal {}

fn capsule_bytes(
    authority_head: Commitment,
    source_objects: &[SourceObject],
    dependency_lock: Commitment,
    toolchain: &RunnerText,
    environment: &[EnvironmentBinding],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CAPSULE_DOMAIN);
    write_digest(&mut bytes, authority_head.digest());
    write_count(&mut bytes, source_objects.len());
    for object in source_objects {
        write_digest(&mut bytes, object.commitment.digest());
        bytes.extend_from_slice(&object.byte_len.to_be_bytes());
    }
    write_digest(&mut bytes, dependency_lock.digest());
    write_text(&mut bytes, toolchain.as_str());
    write_count(&mut bytes, environment.len());
    for binding in environment {
        write_text(&mut bytes, binding.name.as_str());
        write_text(&mut bytes, binding.value.as_str());
    }
    bytes
}

fn write_count(bytes: &mut Vec<u8>, count: usize) {
    let count = u32::try_from(count).expect("runner collection limits fit in u32");
    bytes.extend_from_slice(&count.to_be_bytes());
}

fn write_text(bytes: &mut Vec<u8>, text: &str) {
    write_count(bytes, text.len());
    bytes.extend_from_slice(text.as_bytes());
}

fn write_digest(bytes: &mut Vec<u8>, digest: Digest) {
    bytes.extend_from_slice(&digest.algorithm().code_point().to_be_bytes());
    write_count(bytes, digest.bytes().len());
    bytes.extend_from_slice(digest.bytes().as_bytes());
}

fn has_duplicate_commitment(commitments: &[Commitment]) -> bool {
    let mut seen = BTreeSet::new();
    commitments
        .iter()
        .any(|commitment| !seen.insert(*commitment))
}

fn receipt_evidence(
    plan: &SandboxPlan,
    outcome: CheckOutcome,
    observation: &SubstrateObservation,
) -> Result<EvidenceRecord, RunnerRefusal> {
    let sources = vec![
        evidence_text("capsule", format!("capsule-{}", plan.capsule.id()))?,
        evidence_text(
            "authority",
            format!("authority-{}", plan.capsule.authority_head()),
        )?,
        evidence_text(
            "dependency",
            format!("dependency-{}", plan.capsule.dependency_lock()),
        )?,
    ];
    let sources = canonical_evidence_text_set(sources, "source_input")?;
    let assumptions = vec![
        evidence_text("assumption", "ambient-env-cleared".to_owned())?,
        evidence_text("assumption", "metadata-egress-denied".to_owned())?,
        evidence_text("assumption", "secrets-brokered".to_owned())?,
    ];
    let assumptions = canonical_evidence_text_set(assumptions, "assumption")?;
    let mut artifacts = vec![EvidenceArtifact::new(
        evidence_text("log_root", "runner-log-root".to_owned())?,
        observation.log_root.digest(),
    )];
    for (index, artifact) in observation.artifacts.iter().enumerate() {
        artifacts.push(EvidenceArtifact::new(
            evidence_text("artifact", format!("output-{index}"))?,
            artifact.digest(),
        ));
    }
    let artifacts = canonical_evidence_artifact_set(artifacts)?;
    let context = EvidenceContext::new(
        sources,
        evidence_text("implementation", "fgit-runner-v1".to_owned())?,
        evidence_text("toolchain", plan.capsule.toolchain().as_str().to_owned())?,
        evidence_text("selection", "exact-capsule".to_owned())?,
        evidence_text("window", format!("logical-{}", plan.logical_order))?,
        evidence_text("policy", outcome.token().to_owned())?,
        assumptions,
        evidence_text("verifier", "containment-substrate".to_owned())?,
        artifacts,
        evidence_text("fallback", "typed-substrate-refusal".to_owned())?,
        ReplayCompleteness::Structural,
        None,
    )
    .map_err(|_| RunnerRefusal::EvidenceConstruction)?;
    let body = EvidenceRecordBody::new(
        evidence_text("claim_id", "runner-check-receipt".to_owned())?,
        evidence_text(
            "claim_scope",
            "capsule-bound-execution-observation".to_owned(),
        )?,
        ClaimRank::Benchmark,
        ClaimRank::Benchmark,
        context,
    )
    .map_err(|_| RunnerRefusal::EvidenceConstruction)?;
    EvidenceRecord::new(body).map_err(|_| RunnerRefusal::EvidenceConstruction)
}

fn evidence_text(field: &'static str, value: String) -> Result<EvidenceText, RunnerRefusal> {
    EvidenceText::parse(field, &value).map_err(|_| RunnerRefusal::EvidenceConstruction)
}

/// Sorts an evidence set by exactly the same element bytes as its codec frame.
///
/// `EvidenceText`'s Rust ordering is not the protocol ordering: the codec
/// prefixes every element with its length. Keeping the in-memory body in codec
/// order makes decode/encode round-trips structurally identical as well as
/// identity-equivalent.
fn canonical_evidence_text_set(
    values: Vec<EvidenceText>,
    field: &'static str,
) -> Result<Vec<EvidenceText>, RunnerRefusal> {
    let mut encoded = values
        .into_iter()
        .map(|value| {
            let mut encoder = Encoder::new();
            encoder
                .write_text(field, value.as_str())
                .map_err(|_| RunnerRefusal::EvidenceConstruction)?;
            Ok((encoder.into_bytes(), value))
        })
        .collect::<Result<Vec<_>, RunnerRefusal>>()?;
    encoded.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(encoded.into_iter().map(|(_, value)| value).collect())
}

/// Sorts evidence artifacts by the exact bytes the canonical evidence codec
/// uses for one artifact set element.
fn canonical_evidence_artifact_set(
    values: Vec<EvidenceArtifact>,
) -> Result<Vec<EvidenceArtifact>, RunnerRefusal> {
    let mut encoded = values
        .into_iter()
        .map(|value| {
            let mut encoder = Encoder::new();
            encoder
                .write_text("artifact_location", value.location().as_str())
                .and_then(|()| encoder.write_digest(value.commitment()))
                .map_err(|_| RunnerRefusal::EvidenceConstruction)?;
            Ok((encoder.into_bytes(), value))
        })
        .collect::<Result<Vec<_>, RunnerRefusal>>()?;
    encoded.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(encoded.into_iter().map(|(_, value)| value).collect())
}

#[cfg(test)]
mod tests {
    use super::{
        BuildInputCapsule, CheckOutcome, Commitment, ContainmentFailureKind, ContainmentSubstrate,
        EnvironmentBinding, ForbiddenProbe, ForkPolicy, JobRequest, ResourceCeilings,
        ResourceDimension, ResourceUsage, RunnerControlPlane, RunnerPolicy, RunnerRefusal,
        RunnerText, SecretBroker, SecretRequest, SourceObject, SubstrateObservation, TrustDomain,
    };
    use fgit_codec::DecodeLimits;
    use fgit_evidence::EvidenceRecord;
    use fgit_resource::kinds::{
        ContainmentClass, ExitClass, NetworkPolicy, RunnerReaped, SandboxProfile,
    };

    fn text(value: &str) -> RunnerText {
        RunnerText::parse("test", value).expect("test text is canonical")
    }

    fn commitment(label: &str) -> Commitment {
        Commitment::of_bytes(label.as_bytes())
    }

    fn capsule(permuted: bool) -> BuildInputCapsule {
        let first = SourceObject::new(commitment("object-a"), 11);
        let second = SourceObject::new(commitment("object-b"), 12);
        let objects = if permuted {
            vec![second, first]
        } else {
            vec![first, second]
        };
        let first_env = EnvironmentBinding::new(text("LANG"), text("C"))
            .expect("canonical environment binding");
        let second_env = EnvironmentBinding::new(text("PROFILE"), text("release"))
            .expect("canonical environment binding");
        let environment = if permuted {
            vec![second_env, first_env]
        } else {
            vec![first_env, second_env]
        };
        BuildInputCapsule::new(
            commitment("authority-head"),
            objects,
            commitment("dependency-lock"),
            text("rust-nightly-2026-08-20"),
            environment,
        )
        .expect("valid capsule")
    }

    fn ceilings(memory_bytes: u64) -> ResourceCeilings {
        ResourceCeilings::new(10_000, memory_bytes, 4_096, 0, 4, 1_000).expect("valid ceilings")
    }

    fn policy(domain: &str, memory_bytes: u64) -> RunnerPolicy {
        RunnerPolicy::new(
            TrustDomain::new(text(domain)),
            SandboxProfile::ProcessIsolated,
            NetworkPolicy::Denied,
            ceilings(memory_bytes),
        )
        .expect("Linux process-isolated denied-egress policy")
    }

    fn observation(exit: ExitClass, memory_bytes: u64) -> SubstrateObservation {
        SubstrateObservation {
            exit,
            usage: ResourceUsage {
                cpu_micros: 2,
                memory_bytes,
                disk_bytes: 3,
                network_bytes: 0,
                processes: 1,
                wall_clock_millis: 4,
            },
            reaped: RunnerReaped {
                processes_reaped: 1,
                containment: ContainmentClass::Cooperative,
            },
            log_root: commitment("log-root"),
            artifacts: vec![commitment("artifact-root")],
        }
    }

    struct FixedSubstrate(SubstrateObservation);

    impl ContainmentSubstrate for FixedSubstrate {
        fn launch(
            &mut self,
            _plan: &super::SandboxPlan,
        ) -> Result<SubstrateObservation, super::SubstrateRefusal> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn capsule_identity_is_independent_of_source_and_environment_input_order() {
        let first = capsule(false);
        let permuted = capsule(true);
        assert_eq!(first.id(), permuted.id());
        assert_eq!(first.source_objects(), permuted.source_objects());
        assert_eq!(first.environment(), permuted.environment());
    }

    #[test]
    fn duplicate_source_commitment_is_refused_instead_of_ambiguously_collapsing() {
        let object = SourceObject::new(commitment("object"), 1);
        let result = BuildInputCapsule::new(
            commitment("authority"),
            vec![object, object],
            commitment("lock"),
            text("toolchain"),
            Vec::new(),
        );
        assert_eq!(result, Err(RunnerRefusal::DuplicateSourceObject));
    }

    #[test]
    fn ambient_credential_and_metadata_probe_fixtures_are_refused_before_admission() {
        for probe in [
            ForbiddenProbe::MetadataService,
            ForbiddenProbe::AmbientCredential,
        ] {
            let result = JobRequest::new(false, Vec::new(), vec![probe], 7);
            assert_eq!(
                result,
                Err(RunnerRefusal::ForbiddenProbeRequested { probe })
            );
        }
        let permitted = JobRequest::new(false, Vec::new(), Vec::new(), 7);
        assert!(permitted.is_ok());
    }

    #[test]
    fn resource_limit_termination_emits_a_typed_receipt_and_revokes_secret_handles() {
        let mut broker = SecretBroker::default();
        let secret = broker
            .issue(
                SecretRequest::new(
                    text("TOKEN"),
                    TrustDomain::new(text("trusted")),
                    ForkPolicy::TrustedOnly,
                    20,
                ),
                1,
            )
            .expect("live secret lease");
        let request = JobRequest::new(false, vec![secret], Vec::new(), 9).expect("safe request");
        let mut control = RunnerControlPlane::new(ceilings(32), 1).expect("capacity");
        let admitted = control
            .admit(
                capsule(false),
                policy("trusted", 32),
                request,
                &mut broker,
                2,
            )
            .expect("admitted before launch");
        let mut substrate = FixedSubstrate(observation(ExitClass::ResourceCeiling, 33));
        let receipt = control
            .execute(admitted, &mut substrate, &mut broker)
            .expect("resource termination is receipted");
        assert_eq!(
            receipt.outcome(),
            CheckOutcome::ResourceCeiling {
                dimension: ResourceDimension::MemoryBytes,
            }
        );
        assert_eq!(receipt.revoked_secrets(), 1);
        assert!(broker.is_revoked(secret));
    }

    #[test]
    fn resource_overrun_without_matching_termination_is_receipted_as_containment_failure() {
        let request = JobRequest::new(false, Vec::new(), Vec::new(), 2).expect("safe request");
        let mut broker = SecretBroker::default();
        let mut control = RunnerControlPlane::new(ceilings(32), 1).expect("capacity");
        let admitted = control
            .admit(
                capsule(false),
                policy("trusted", 32),
                request,
                &mut broker,
                1,
            )
            .expect("admitted before launch");
        let mut substrate = FixedSubstrate(observation(ExitClass::Succeeded, 33));
        let receipt = control
            .execute(admitted, &mut substrate, &mut broker)
            .expect("containment failure must still settle the admitted run");
        assert_eq!(
            receipt.outcome(),
            CheckOutcome::ContainmentFailure {
                kind: ContainmentFailureKind::MissingResourceTermination {
                    dimension: ResourceDimension::MemoryBytes,
                },
            }
        );
    }

    #[test]
    fn cache_namespaces_and_secrets_do_not_cross_trust_domains() {
        let trusted = policy("trusted", 32);
        let untrusted = policy("untrusted", 32);
        assert_ne!(
            super::CacheNamespace::for_capsule(trusted.trust_domain(), &capsule(false)),
            super::CacheNamespace::for_capsule(untrusted.trust_domain(), &capsule(false)),
        );
        let mut broker = SecretBroker::default();
        let secret = broker
            .issue(
                SecretRequest::new(
                    text("TOKEN"),
                    trusted.trust_domain().clone(),
                    ForkPolicy::TrustedOnly,
                    20,
                ),
                1,
            )
            .expect("issued secret");
        let request = JobRequest::new(false, vec![secret], Vec::new(), 4).expect("safe request");
        let mut control = RunnerControlPlane::new(ceilings(32), 1).expect("capacity");
        assert_eq!(
            control.admit(capsule(false), untrusted, request, &mut broker, 2),
            Err(RunnerRefusal::SecretTrustDomainMismatch)
        );
    }

    #[test]
    fn receipt_provenance_is_codec_framed_and_identity_verified() {
        let request = JobRequest::new(false, Vec::new(), Vec::new(), 5).expect("safe request");
        let mut broker = SecretBroker::default();
        let mut control = RunnerControlPlane::new(ceilings(32), 1).expect("capacity");
        let admitted = control
            .admit(
                capsule(false),
                policy("trusted", 32),
                request,
                &mut broker,
                2,
            )
            .expect("admitted before launch");
        let mut substrate = FixedSubstrate(observation(ExitClass::Succeeded, 16));
        let receipt = control
            .execute(admitted, &mut substrate, &mut broker)
            .expect("successful receipt");
        receipt.verify_evidence().expect("evidence verifies");
        let decoded = EvidenceRecord::decode(
            receipt.evidence().id(),
            receipt.evidence().frame(),
            DecodeLimits::default(),
        )
        .expect("receipt evidence codec roundtrip");
        assert_eq!(&decoded, receipt.evidence());
    }
}
