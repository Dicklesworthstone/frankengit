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
//! The first selected profile is the ADR-0007 Linux process-isolation profile
//! with denied egress. Selecting that policy is not evidence that a concrete
//! namespace/cgroup substrate is registered: a missing or incomplete
//! substrate must return a typed refusal before user work begins. This crate
//! keeps the same capsule, secret, cache, resource, and receipt rules for each
//! future platform substrate.
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
/// Maximum number of argv elements admitted after one command program.
pub const MAX_COMMAND_ARGUMENTS: usize = 128;
/// Maximum number of brokered secret handles a job may receive.
pub const MAX_SECRET_LEASES: usize = 64;
/// Maximum number of artifact commitments recorded in one receipt.
pub const MAX_ARTIFACTS: usize = 1_024;
/// Maximum bytes accepted in one canonical runner text field.
pub const MAX_RUNNER_TEXT_BYTES: usize = 256;
/// Maximum secret byte sequences configured for one log redactor.
pub const MAX_REDACTION_NEEDLES: usize = 64;
/// Maximum bytes retained long enough to produce one redacted log object.
pub const MAX_LOG_BYTES: usize = 4 * 1024 * 1024;

const CAPSULE_DOMAIN: &[u8] = b"frankengit/build-input-capsule/v1\0";
const CACHE_DOMAIN: &[u8] = b"frankengit/runner-cache-key/v1\0";
const COMMAND_DOMAIN: &[u8] = b"frankengit/build-command/v1\0";
const REUSE_SPOT_CHECK_DOMAIN: &[u8] = b"frankengit/runner-reuse-spot-check/v1\0";
const REUSE_ARTIFACTS_DOMAIN: &[u8] = b"frankengit/runner-reuse-artifacts/v1\0";

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

/// One shell-free command bound into a build capsule.
///
/// The runner never reparses this value through a shell.  The program and
/// every argv element are separately canonical runner fields, so changing an
/// argument changes the capsule identity and the terminal receipt evidence.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BuildCommand {
    program: RunnerText,
    arguments: Vec<RunnerText>,
}

impl BuildCommand {
    /// Creates one bounded, shell-free program plus argv vector.
    pub fn new(program: RunnerText, arguments: Vec<RunnerText>) -> Result<Self, RunnerRefusal> {
        if arguments.len() > MAX_COMMAND_ARGUMENTS {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "command_arguments",
                limit: MAX_COMMAND_ARGUMENTS,
            });
        }
        Ok(Self { program, arguments })
    }

    /// Executable selected for this exact build.
    #[must_use]
    pub const fn program(&self) -> &RunnerText {
        &self.program
    }

    /// Exact argv elements, preserving their declared order.
    #[must_use]
    pub fn arguments(&self) -> &[RunnerText] {
        &self.arguments
    }

    /// Stable command commitment used by receipt provenance.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment::of_bytes(&command_bytes(self))
    }
}

/// One opaque byte sequence that must never remain in a persisted runner log.
///
/// This type intentionally omits `Debug` so secret material cannot be exposed
/// by diagnostics. The only public operation is to construct a redactor that
/// replaces this sequence before calculating the log commitment.
#[derive(Clone, Eq, PartialEq)]
pub struct RedactionNeedle(Vec<u8>);

impl RedactionNeedle {
    /// Adopts one bounded nonempty secret byte sequence for log redaction.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RunnerRefusal> {
        if bytes.is_empty() {
            return Err(RunnerRefusal::EmptyRedactionNeedle);
        }
        if bytes.len() > MAX_LOG_BYTES {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "redaction_needle_bytes",
                limit: MAX_LOG_BYTES,
            });
        }
        Ok(Self(bytes))
    }
}

/// Immutable record of the substrate's log-redaction accounting.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogRedactionReceipt {
    log_root: Commitment,
    source_bytes: u64,
    replacements: u16,
}

impl LogRedactionReceipt {
    /// Records a substrate-supplied log root and the redaction accounting that
    /// produced it. Substrates must calculate `log_root` over redacted bytes.
    #[must_use]
    pub const fn new(log_root: Commitment, source_bytes: u64, replacements: u16) -> Self {
        Self {
            log_root,
            source_bytes,
            replacements,
        }
    }

    /// Commitment of the immutable, already-redacted log bytes.
    #[must_use]
    pub const fn log_root(self) -> Commitment {
        self.log_root
    }

    /// Input byte length before redaction.
    #[must_use]
    pub const fn source_bytes(self) -> u64 {
        self.source_bytes
    }

    /// Number of secret-sequence replacements applied before commitment.
    #[must_use]
    pub const fn replacements(self) -> u16 {
        self.replacements
    }
}

/// Redacts configured secret byte sequences before any log bytes are retained.
pub struct LogRedactor {
    needles: Vec<RedactionNeedle>,
}

impl LogRedactor {
    /// Creates a deterministic redactor. Longer matching needles win, so
    /// overlapping secret values cannot produce input-order-dependent output.
    pub fn new(mut needles: Vec<RedactionNeedle>) -> Result<Self, RunnerRefusal> {
        if needles.len() > MAX_REDACTION_NEEDLES {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "redaction_needles",
                limit: MAX_REDACTION_NEEDLES,
            });
        }
        needles.sort_unstable_by(|left, right| {
            right.0.len().cmp(&left.0.len()).then(left.0.cmp(&right.0))
        });
        if needles.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RunnerRefusal::DuplicateRedactionNeedle);
        }
        Ok(Self { needles })
    }

    /// Replaces every configured secret before computing the immutable root.
    pub fn redact(&self, bytes: &[u8]) -> Result<RedactedLog, RunnerRefusal> {
        if bytes.len() > MAX_LOG_BYTES {
            return Err(RunnerRefusal::CollectionTooLarge {
                field: "log_bytes",
                limit: MAX_LOG_BYTES,
            });
        }
        let mut redacted = Vec::with_capacity(bytes.len());
        let mut cursor = 0;
        let mut replacements = 0_u16;
        while cursor < bytes.len() {
            let matched = self
                .needles
                .iter()
                .find(|needle| bytes[cursor..].starts_with(&needle.0));
            if let Some(needle) = matched {
                redacted.extend_from_slice(b"[REDACTED]");
                cursor += needle.0.len();
                replacements = replacements
                    .checked_add(1)
                    .ok_or(RunnerRefusal::RedactionCountExhausted)?;
            } else {
                redacted.push(bytes[cursor]);
                cursor += 1;
            }
        }
        let source_bytes =
            u64::try_from(bytes.len()).map_err(|_| RunnerRefusal::CollectionTooLarge {
                field: "log_bytes",
                limit: MAX_LOG_BYTES,
            })?;
        let receipt =
            LogRedactionReceipt::new(Commitment::of_bytes(&redacted), source_bytes, replacements);
        Ok(RedactedLog {
            bytes: redacted,
            receipt,
        })
    }
}

/// The sole log body that a runner substrate may persist or turn into evidence.
pub struct RedactedLog {
    bytes: Vec<u8>,
    receipt: LogRedactionReceipt,
}

impl RedactedLog {
    /// Bytes safe for log persistence after configured secret replacement.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Immutable redaction accounting and redacted-log commitment.
    #[must_use]
    pub const fn receipt(&self) -> LogRedactionReceipt {
        self.receipt
    }
}

/// Identity of every build-relevant input.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BuildInputCapsule {
    authority_head: Commitment,
    source_objects: Vec<SourceObject>,
    dependency_lock: Commitment,
    toolchain: RunnerText,
    command: BuildCommand,
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
        command: BuildCommand,
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
            &command,
            &environment,
        );
        Ok(Self {
            authority_head,
            source_objects,
            dependency_lock,
            toolchain,
            command,
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

    /// Exact shell-free command bound into this immutable build input.
    #[must_use]
    pub const fn command(&self) -> &BuildCommand {
        &self.command
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
    ///
    /// A policy selects the requested profile; it does not claim that the
    /// caller has registered a concrete containment substrate for it.
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
    /// Redaction accounting and commitment of the immutable log object.
    pub log_redaction: LogRedactionReceipt,
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
            log_redaction: LogRedactionReceipt::new(
                Commitment::of_bytes(refusal.token().as_bytes()),
                0,
                0,
            ),
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
            command: admitted.plan.capsule.command.clone(),
            cache_namespace: admitted.plan.cache_namespace,
            runner_request: admitted.runner_request,
            outcome,
            usage: observation.usage,
            artifacts: observation.artifacts,
            runner_finished,
            reaped: observation.reaped,
            log_redaction: observation.log_redaction,
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
    command: BuildCommand,
    cache_namespace: CacheNamespace,
    runner_request: RunnerRequest,
    outcome: CheckOutcome,
    usage: ResourceUsage,
    artifacts: Vec<Commitment>,
    runner_finished: RunnerFinished,
    reaped: RunnerReaped,
    log_redaction: LogRedactionReceipt,
    revoked_secrets: u16,
    evidence: EvidenceRecord,
}

impl CheckReceipt {
    /// Exact input capsule that this receipt describes.
    #[must_use]
    pub const fn capsule_id(&self) -> CapsuleId {
        self.capsule_id
    }

    /// Exact command bound by the input capsule and this terminal receipt.
    #[must_use]
    pub const fn command(&self) -> &BuildCommand {
        &self.command
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

    /// Redaction accounting for the only log body bound into this receipt.
    #[must_use]
    pub const fn log_redaction(&self) -> LogRedactionReceipt {
        self.log_redaction
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

/// A workflow author's explicit reproducibility declaration.
///
/// Reuse is permitted only for [`Self::DeclaredDeterministic`].  The runner
/// never infers reproducibility from a successful execution or from a cache
/// hit, because that would let an incidental observation become policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DeterminismDeclaration {
    /// The workflow contract declares byte-stable output for this step.
    DeclaredDeterministic,
    /// The workflow contract declares output nondeterministic.
    DeclaredNondeterministic,
}

/// Workflow-level declaration before runner lowering.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkflowStepDeclaration {
    step_id: RunnerText,
    determinism: DeterminismDeclaration,
}

impl WorkflowStepDeclaration {
    /// Creates one declared workflow step.
    #[must_use]
    pub const fn new(step_id: RunnerText, determinism: DeterminismDeclaration) -> Self {
        Self {
            step_id,
            determinism,
        }
    }

    /// Lowers the declaration into the runner's exact reuse input.
    #[must_use]
    pub fn lower(self) -> LoweredWorkflowStep {
        LoweredWorkflowStep {
            step_id: self.step_id,
            determinism: self.determinism,
        }
    }
}

/// Runner-owned immutable lowering of one workflow step declaration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LoweredWorkflowStep {
    step_id: RunnerText,
    determinism: DeterminismDeclaration,
}

impl LoweredWorkflowStep {
    /// Stable workflow step identifier included in every reuse key.
    #[must_use]
    pub const fn step_id(&self) -> &RunnerText {
        &self.step_id
    }

    /// The workflow's explicit reproducibility declaration.
    #[must_use]
    pub const fn determinism(&self) -> DeterminismDeclaration {
        self.determinism
    }
}

/// Stable identity of the original execution that produced a cached output.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionRunId(RunnerText);

impl ExecutionRunId {
    /// Parses one canonical execution-run identity.
    pub fn parse(value: &str) -> Result<Self, RunnerRefusal> {
        RunnerText::parse("execution_run_id", value).map(Self)
    }

    /// Canonical run identity.
    #[must_use]
    pub const fn as_text(&self) -> &RunnerText {
        &self.0
    }
}

/// Exact cache lookup key: trust partition, full input capsule, and step.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReuseKey {
    trust_domain: TrustDomain,
    capsule_id: CapsuleId,
    step_id: RunnerText,
}

impl ReuseKey {
    fn new(trust_domain: TrustDomain, capsule_id: CapsuleId, step_id: RunnerText) -> Self {
        Self {
            trust_domain,
            capsule_id,
            step_id,
        }
    }

    /// Trust partition that scopes this derived entry.
    #[must_use]
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Exact build capsule required for a reuse hit.
    #[must_use]
    pub const fn capsule_id(&self) -> CapsuleId {
        self.capsule_id
    }

    /// Exact lowered workflow step required for a reuse hit.
    #[must_use]
    pub const fn step_id(&self) -> &RunnerText {
        &self.step_id
    }
}

/// A trust-scoped workflow class quarantined after a failed spot check.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReuseClass {
    trust_domain: TrustDomain,
    step_id: RunnerText,
}

impl ReuseClass {
    fn from_key(key: &ReuseKey) -> Self {
        Self {
            trust_domain: key.trust_domain.clone(),
            step_id: key.step_id.clone(),
        }
    }

    /// Trust partition containing this workflow class.
    #[must_use]
    pub const fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Workflow step whose outputs are quarantined from reuse.
    #[must_use]
    pub const fn step_id(&self) -> &RunnerText {
        &self.step_id
    }
}

/// Deterministic schedule for a pseudorandomly distributed spot-check sample.
///
/// The caller supplies a policy seed.  Selection is a deterministic hash of
/// that seed and the exact reuse key, so a verifier can replay which entries
/// were selected without treating cache state as authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpotCheckSchedule {
    numerator: u16,
    denominator: u16,
    selection_seed: Commitment,
}

impl SpotCheckSchedule {
    /// Creates a sample schedule with `numerator / denominator` selection.
    pub fn new(
        numerator: u16,
        denominator: u16,
        selection_seed: Commitment,
    ) -> Result<Self, ReuseRefusal> {
        if denominator == 0 || numerator > denominator {
            return Err(ReuseRefusal::InvalidSpotCheckSchedule);
        }
        Ok(Self {
            numerator,
            denominator,
            selection_seed,
        })
    }

    /// Whether this exact key is selected for reexecution.
    #[must_use]
    pub fn selects(&self, key: &ReuseKey) -> bool {
        if self.numerator == 0 {
            return false;
        }
        if self.numerator == self.denominator {
            return true;
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REUSE_SPOT_CHECK_DOMAIN);
        write_digest(&mut bytes, self.selection_seed.digest());
        write_text(&mut bytes, key.trust_domain.name().as_str());
        write_digest(&mut bytes, key.capsule_id.commitment().digest());
        write_text(&mut bytes, key.step_id.as_str());
        let selection = Commitment::of_bytes(&bytes);
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&selection.digest().bytes().as_bytes()[..8]);
        u64::from_be_bytes(prefix) % u64::from(self.denominator) < u64::from(self.numerator)
    }
}

/// Policy input for cache reuse.  It is consulted on both insert and lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusePolicy {
    permitted_steps: BTreeSet<RunnerText>,
    spot_checks: SpotCheckSchedule,
}

impl ReusePolicy {
    /// Creates a policy that permits reuse only for the named lowered steps.
    pub fn new(
        permitted_steps: Vec<RunnerText>,
        spot_checks: SpotCheckSchedule,
    ) -> Result<Self, ReuseRefusal> {
        let mut canonical = BTreeSet::new();
        for step_id in permitted_steps {
            if !canonical.insert(step_id) {
                return Err(ReuseRefusal::DuplicatePolicyStep);
            }
        }
        Ok(Self {
            permitted_steps: canonical,
            spot_checks,
        })
    }

    fn permits(&self, step: &LoweredWorkflowStep) -> bool {
        self.permitted_steps.contains(step.step_id())
    }

    /// Deterministic schedule used for selected reuse receipts.
    #[must_use]
    pub const fn spot_checks(&self) -> SpotCheckSchedule {
        self.spot_checks
    }
}

/// A reference to the immutable receipt produced by the original execution.
///
/// This is deliberately not a [`CheckReceipt`].  A cache reuse did not launch
/// a process, reserve a slot, or observe reaping; consumers must retain that
/// structural distinction rather than treating reuse as a fresh execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceiptReference {
    run_id: ExecutionRunId,
    capsule_id: CapsuleId,
    cache_namespace: CacheNamespace,
    evidence: EvidenceRecord,
}

impl ExecutionReceiptReference {
    /// Original execution identity.
    #[must_use]
    pub const fn run_id(&self) -> &ExecutionRunId {
        &self.run_id
    }

    /// Capsule that the original receipt bound.
    #[must_use]
    pub const fn capsule_id(&self) -> CapsuleId {
        self.capsule_id
    }

    /// Trust-scoped namespace that the original receipt bound.
    #[must_use]
    pub const fn cache_namespace(&self) -> CacheNamespace {
        self.cache_namespace
    }

    /// Immutable provenance for the original execution receipt.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceRecord {
        &self.evidence
    }
}

/// A cache reuse observation, structurally distinct from an execution receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReuseReceipt {
    key: ReuseKey,
    artifacts: Vec<Commitment>,
    original_execution: ExecutionReceiptReference,
    spot_check_scheduled: bool,
}

impl ReuseReceipt {
    /// Exact derived-cache key that was reused.
    #[must_use]
    pub const fn key(&self) -> &ReuseKey {
        &self.key
    }

    /// Content-addressed artifacts retained in original output order.
    #[must_use]
    pub fn artifacts(&self) -> &[Commitment] {
        &self.artifacts
    }

    /// Immutable reference to the original producing execution.
    #[must_use]
    pub const fn original_execution(&self) -> &ExecutionReceiptReference {
        &self.original_execution
    }

    /// Whether this reuse must be independently reexecuted and compared.
    #[must_use]
    pub const fn spot_check_scheduled(&self) -> bool {
        self.spot_check_scheduled
    }
}

/// A typed reason that an exact cache lookup executes instead of reusing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReuseMiss {
    /// This step is intentionally nondeterministic according to workflow lowering.
    NondeterministicDeclaration,
    /// Policy does not permit this step to reuse output.
    PolicyDenied,
    /// No entry exists for the exact trust-domain, capsule, and step key.
    ExactOutputAbsent {
        /// Exact key that did not resolve to a derived output.
        key: ReuseKey,
    },
    /// A prior sampled mismatch quarantined the whole trust-scoped step class.
    ClassQuarantined {
        /// Class that must be reverified before any later reuse.
        class: ReuseClass,
        /// Immutable evidence for the sampled mismatch.
        evidence: ReuseNegativeEvidence,
    },
}

/// Result of the policy-constrained exact lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReuseDecision {
    /// A real execution is required before producing output.
    Execute(ReuseMiss),
    /// The exact stored output may be reused, with original provenance named.
    Reuse(ReuseReceipt),
}

/// Immutable negative evidence emitted by a failed reuse spot check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReuseNegativeEvidence {
    class: ReuseClass,
    original_execution: ExecutionReceiptReference,
    reexecution_run_id: ExecutionRunId,
    expected_artifacts: Vec<Commitment>,
    observed_artifacts: Vec<Commitment>,
    evidence: EvidenceRecord,
}

impl ReuseNegativeEvidence {
    /// Class removed from reuse eligibility by this observation.
    #[must_use]
    pub const fn class(&self) -> &ReuseClass {
        &self.class
    }

    /// Original run whose output was selected for reuse.
    #[must_use]
    pub const fn original_execution(&self) -> &ExecutionReceiptReference {
        &self.original_execution
    }

    /// Independently executed run that disagreed byte-for-byte.
    #[must_use]
    pub const fn reexecution_run_id(&self) -> &ExecutionRunId {
        &self.reexecution_run_id
    }

    /// Original ordered artifact commitments.
    #[must_use]
    pub fn expected_artifacts(&self) -> &[Commitment] {
        &self.expected_artifacts
    }

    /// Independently observed ordered artifact commitments.
    #[must_use]
    pub fn observed_artifacts(&self) -> &[Commitment] {
        &self.observed_artifacts
    }

    /// Canonical negative-evidence record for the mismatch.
    #[must_use]
    pub const fn evidence(&self) -> &EvidenceRecord {
        &self.evidence
    }
}

/// Terminal result of a scheduled reuse spot check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SpotCheckResult {
    /// Independent execution produced the exact same ordered artifact bytes.
    Matched,
    /// Independent execution disagreed and automatically quarantined the class.
    Mismatch(ReuseNegativeEvidence),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedOutput {
    artifacts: Vec<Commitment>,
    original_execution: ExecutionReceiptReference,
}

/// Discardable, derived cache of completed outputs.
///
/// This store has no authority or durability role.  It can be deleted and
/// rebuilt from immutable execution receipts, and neither its presence nor a
/// reuse decision publishes repository state.  The only accepted lookup is an
/// exact `(trust domain, BuildInputCapsule id, lowered step)` match.
#[derive(Default)]
pub struct OutputStore {
    entries: BTreeMap<ReuseKey, CachedOutput>,
    quarantined_classes: BTreeMap<ReuseClass, ReuseNegativeEvidence>,
}

impl OutputStore {
    /// Creates an empty derived output store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores successful output and the immutable receipt that originally made it.
    ///
    /// An existing exact key is never overwritten with a different producing
    /// run.  That conflict is a refusal, not a race-dependent cache update.
    pub fn record_execution(
        &mut self,
        trust_domain: TrustDomain,
        capsule: &BuildInputCapsule,
        step: &LoweredWorkflowStep,
        policy: &ReusePolicy,
        run_id: ExecutionRunId,
        receipt: &CheckReceipt,
    ) -> Result<(), ReuseRefusal> {
        require_reusable_step(step, policy)?;
        if receipt.outcome() != CheckOutcome::Succeeded {
            return Err(ReuseRefusal::ExecutionDidNotSucceed);
        }
        if receipt.capsule_id() != capsule.id()
            || receipt.cache_namespace() != CacheNamespace::for_capsule(&trust_domain, capsule)
        {
            return Err(ReuseRefusal::ReceiptBindingMismatch);
        }
        let key = ReuseKey::new(trust_domain, capsule.id(), step.step_id().clone());
        let output = CachedOutput {
            artifacts: receipt.artifacts().to_vec(),
            original_execution: ExecutionReceiptReference {
                run_id,
                capsule_id: receipt.capsule_id(),
                cache_namespace: receipt.cache_namespace(),
                evidence: receipt.evidence().clone(),
            },
        };
        if let Some(existing) = self.entries.get(&key) {
            if existing != &output {
                return Err(ReuseRefusal::ConflictingExactOutput);
            }
            return Ok(());
        }
        self.entries.insert(key, output);
        Ok(())
    }

    /// Resolves a derived output only after declaration, policy, quarantine, and
    /// exact-key checks all agree that reuse is allowed.
    #[must_use]
    pub fn decide(
        &self,
        trust_domain: TrustDomain,
        capsule: &BuildInputCapsule,
        step: &LoweredWorkflowStep,
        policy: &ReusePolicy,
    ) -> ReuseDecision {
        if step.determinism() == DeterminismDeclaration::DeclaredNondeterministic {
            return ReuseDecision::Execute(ReuseMiss::NondeterministicDeclaration);
        }
        if !policy.permits(step) {
            return ReuseDecision::Execute(ReuseMiss::PolicyDenied);
        }
        let key = ReuseKey::new(trust_domain, capsule.id(), step.step_id().clone());
        let class = ReuseClass::from_key(&key);
        if let Some(evidence) = self.quarantined_classes.get(&class) {
            return ReuseDecision::Execute(ReuseMiss::ClassQuarantined {
                class,
                evidence: evidence.clone(),
            });
        }
        let Some(output) = self.entries.get(&key) else {
            return ReuseDecision::Execute(ReuseMiss::ExactOutputAbsent { key });
        };
        ReuseDecision::Reuse(ReuseReceipt {
            spot_check_scheduled: policy.spot_checks().selects(&key),
            key,
            artifacts: output.artifacts.clone(),
            original_execution: output.original_execution.clone(),
        })
    }

    /// Compares the scheduled independent reexecution with the reused bytes.
    ///
    /// A disagreement emits immutable evidence and quarantines the complete
    /// trust-scoped step class before a later lookup can return another hit.
    pub fn complete_spot_check(
        &mut self,
        reuse: &ReuseReceipt,
        reexecution_run_id: ExecutionRunId,
        capsule: &BuildInputCapsule,
        reexecution: &CheckReceipt,
    ) -> Result<SpotCheckResult, ReuseRefusal> {
        if !reuse.spot_check_scheduled() {
            return Err(ReuseRefusal::SpotCheckNotScheduled);
        }
        if reuse.original_execution.run_id() == &reexecution_run_id {
            return Err(ReuseRefusal::ReexecutionUsesOriginalRun);
        }
        if reexecution.outcome() != CheckOutcome::Succeeded
            || reexecution.capsule_id() != reuse.key.capsule_id()
            || reexecution.capsule_id() != capsule.id()
            || reexecution.cache_namespace()
                != CacheNamespace::for_capsule(reuse.key.trust_domain(), capsule)
        {
            return Err(ReuseRefusal::ReceiptBindingMismatch);
        }
        if reuse.artifacts == reexecution.artifacts() {
            return Ok(SpotCheckResult::Matched);
        }
        let negative = ReuseNegativeEvidence {
            class: ReuseClass::from_key(&reuse.key),
            original_execution: reuse.original_execution.clone(),
            reexecution_run_id,
            expected_artifacts: reuse.artifacts.clone(),
            observed_artifacts: reexecution.artifacts().to_vec(),
            evidence: reuse_negative_evidence(reuse, reexecution)?,
        };
        self.quarantined_classes
            .insert(negative.class.clone(), negative.clone());
        Ok(SpotCheckResult::Mismatch(negative))
    }
}

/// Typed refusal for output reuse and sampled reexecution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReuseRefusal {
    /// A sample fraction had zero denominator or exceeded one whole.
    InvalidSpotCheckSchedule,
    /// Policy named one workflow step more than once.
    DuplicatePolicyStep,
    /// A workflow declaration prohibits reuse.
    NondeterministicStep,
    /// Policy prohibits reuse for this declared deterministic step.
    StepNotPermitted,
    /// Only successful execution receipts may become cached outputs.
    ExecutionDidNotSucceed,
    /// Receipt capsule or cache namespace did not bind the expected identity.
    ReceiptBindingMismatch,
    /// A different original run attempted to replace an exact cached output.
    ConflictingExactOutput,
    /// A caller attempted to complete an unscheduled spot check.
    SpotCheckNotScheduled,
    /// A reexecution must use a distinct execution-run identity.
    ReexecutionUsesOriginalRun,
    /// Canonical negative evidence could not be constructed.
    EvidenceConstruction,
}

impl fmt::Display for ReuseRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSpotCheckSchedule => "invalid reuse spot-check schedule",
            Self::DuplicatePolicyStep => "reuse policy contains a duplicate step",
            Self::NondeterministicStep => "workflow declaration prohibits output reuse",
            Self::StepNotPermitted => "reuse policy does not permit this step",
            Self::ExecutionDidNotSucceed => "only successful execution receipts may be reused",
            Self::ReceiptBindingMismatch => "receipt does not bind the exact reuse identity",
            Self::ConflictingExactOutput => "exact reuse key already names another producing run",
            Self::SpotCheckNotScheduled => "reuse receipt was not selected for a spot check",
            Self::ReexecutionUsesOriginalRun => "spot check must use a distinct execution run",
            Self::EvidenceConstruction => "reuse negative evidence construction refused",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReuseRefusal {}

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
    /// A redaction input must contain at least one byte.
    EmptyRedactionNeedle,
    /// One redactor named the same secret sequence twice.
    DuplicateRedactionNeedle,
    /// More redaction replacements occurred than the receipt can represent.
    RedactionCountExhausted,
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
            Self::EmptyRedactionNeedle => formatter.write_str("redaction needle must not be empty"),
            Self::DuplicateRedactionNeedle => {
                formatter.write_str("redactor contains a duplicate secret sequence")
            }
            Self::RedactionCountExhausted => {
                formatter.write_str("redaction replacement count exhausted")
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
    command: &BuildCommand,
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
    bytes.extend_from_slice(&command_bytes(command));
    write_count(&mut bytes, environment.len());
    for binding in environment {
        write_text(&mut bytes, binding.name.as_str());
        write_text(&mut bytes, binding.value.as_str());
    }
    bytes
}

fn command_bytes(command: &BuildCommand) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(COMMAND_DOMAIN);
    write_text(&mut bytes, command.program.as_str());
    write_count(&mut bytes, command.arguments.len());
    for argument in &command.arguments {
        write_text(&mut bytes, argument.as_str());
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

fn require_reusable_step(
    step: &LoweredWorkflowStep,
    policy: &ReusePolicy,
) -> Result<(), ReuseRefusal> {
    if step.determinism() == DeterminismDeclaration::DeclaredNondeterministic {
        return Err(ReuseRefusal::NondeterministicStep);
    }
    if !policy.permits(step) {
        return Err(ReuseRefusal::StepNotPermitted);
    }
    Ok(())
}

fn artifact_sequence_commitment(artifacts: &[Commitment]) -> Commitment {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(REUSE_ARTIFACTS_DOMAIN);
    write_count(&mut bytes, artifacts.len());
    for artifact in artifacts {
        write_digest(&mut bytes, artifact.digest());
    }
    Commitment::of_bytes(&bytes)
}

fn reuse_negative_evidence(
    reuse: &ReuseReceipt,
    reexecution: &CheckReceipt,
) -> Result<EvidenceRecord, ReuseRefusal> {
    let sources = canonical_evidence_text_set(
        vec![
            reuse_evidence_text("source_input", format!("capsule-{}", reuse.key.capsule_id))?,
            reuse_evidence_text(
                "source_input",
                format!(
                    "original-run-{}",
                    reuse.original_execution.run_id().as_text()
                ),
            )?,
            reuse_evidence_text(
                "source_input",
                format!("reexecution-evidence-{}", reexecution.evidence().id()),
            )?,
        ],
        "source_input",
    )
    .map_err(|_| ReuseRefusal::EvidenceConstruction)?;
    let assumptions = canonical_evidence_text_set(
        vec![
            reuse_evidence_text("assumption", "exact-key-required".to_owned())?,
            reuse_evidence_text("assumption", "ordered-artifacts-compared".to_owned())?,
        ],
        "assumption",
    )
    .map_err(|_| ReuseRefusal::EvidenceConstruction)?;
    let artifacts = canonical_evidence_artifact_set(vec![
        EvidenceArtifact::new(
            reuse_evidence_text("artifact_location", "expected-artifacts".to_owned())?,
            artifact_sequence_commitment(reuse.artifacts()).digest(),
        ),
        EvidenceArtifact::new(
            reuse_evidence_text("artifact_location", "observed-artifacts".to_owned())?,
            artifact_sequence_commitment(reexecution.artifacts()).digest(),
        ),
    ])
    .map_err(|_| ReuseRefusal::EvidenceConstruction)?;
    let context = EvidenceContext::new(
        sources,
        reuse_evidence_text("implementation", "fgit-runner-reuse-v1".to_owned())?,
        reuse_evidence_text("toolchain", "receipt-bound-toolchain".to_owned())?,
        reuse_evidence_text("selection", "policy-scheduled-spot-check".to_owned())?,
        reuse_evidence_text(
            "window",
            format!(
                "trust-{}-step-{}",
                reuse.key.trust_domain.name(),
                reuse.key.step_id
            ),
        )?,
        reuse_evidence_text("policy", "quarantine-on-byte-mismatch".to_owned())?,
        assumptions,
        reuse_evidence_text("verifier", "independent-runner-reexecution".to_owned())?,
        artifacts,
        reuse_evidence_text("fallback", "execute-without-reuse".to_owned())?,
        ReplayCompleteness::Structural,
        Some(reuse.original_execution.evidence().id()),
    )
    .map_err(|_| ReuseRefusal::EvidenceConstruction)?;
    let body = EvidenceRecordBody::new(
        reuse_evidence_text("claim_id", "runner-reuse-spot-check-mismatch".to_owned())?,
        reuse_evidence_text("claim_scope", "trust-scoped-output-reuse-class".to_owned())?,
        ClaimRank::Benchmark,
        ClaimRank::Benchmark,
        context,
    )
    .map_err(|_| ReuseRefusal::EvidenceConstruction)?;
    EvidenceRecord::new(body).map_err(|_| ReuseRefusal::EvidenceConstruction)
}

fn reuse_evidence_text(field: &'static str, value: String) -> Result<EvidenceText, ReuseRefusal> {
    EvidenceText::parse(field, &value).map_err(|_| ReuseRefusal::EvidenceConstruction)
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
        evidence_text(
            "command",
            format!("command-{}", plan.capsule.command().commitment()),
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
        observation.log_redaction.log_root().digest(),
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
        BuildCommand, BuildInputCapsule, CheckOutcome, Commitment, ContainmentFailureKind,
        ContainmentSubstrate, EnvironmentBinding, ForbiddenProbe, ForkPolicy, JobRequest,
        LogRedactor, RedactionNeedle, ResourceCeilings, ResourceDimension, ResourceUsage,
        RunnerControlPlane, RunnerPolicy, RunnerRefusal, RunnerText, SecretBroker, SecretRequest,
        SourceObject, SubstrateObservation, TrustDomain,
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
            BuildCommand::new(text("cargo"), vec![text("check"), text("--locked")])
                .expect("canonical command"),
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
            log_redaction: super::LogRedactionReceipt::new(commitment("log-root"), 0, 0),
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
    fn capsule_identity_and_receipt_bind_the_exact_command() {
        let capsule = capsule(false);
        let changed_command = BuildInputCapsule::new(
            commitment("authority-head"),
            capsule.source_objects().to_vec(),
            commitment("dependency-lock"),
            text("rust-nightly-2026-08-20"),
            BuildCommand::new(text("cargo"), vec![text("test"), text("--locked")])
                .expect("changed canonical command"),
            capsule.environment().to_vec(),
        )
        .expect("changed command capsule");
        assert_ne!(capsule.id(), changed_command.id());

        let request = JobRequest::new(false, Vec::new(), Vec::new(), 5).expect("safe request");
        let mut broker = SecretBroker::default();
        let mut control = RunnerControlPlane::new(ceilings(32), 1).expect("capacity");
        let admitted = control
            .admit(
                capsule.clone(),
                policy("trusted", 32),
                request,
                &mut broker,
                2,
            )
            .expect("admitted before launch");
        let mut substrate = FixedSubstrate(observation(ExitClass::Succeeded, 16));
        let receipt = control
            .execute(admitted, &mut substrate, &mut broker)
            .expect("successful command-bound receipt");
        assert_eq!(receipt.command(), capsule.command());
    }

    #[test]
    fn log_redaction_commits_only_replaced_log_bytes_with_explicit_accounting() {
        let redactor = LogRedactor::new(vec![
            RedactionNeedle::new(b"secret-value".to_vec()).expect("nonempty secret"),
            RedactionNeedle::new(b"secret".to_vec()).expect("overlapping secret"),
        ])
        .expect("canonical redactor");
        let log = redactor
            .redact(b"token=secret-value\n")
            .expect("bounded log redaction");
        assert_eq!(log.bytes(), b"token=[REDACTED]\n");
        assert!(
            !log.bytes()
                .windows(b"secret".len())
                .any(|part| part == b"secret")
        );
        assert_eq!(log.receipt().replacements(), 1);
        assert_eq!(log.receipt().source_bytes(), 19);
        assert_eq!(
            log.receipt().log_root(),
            Commitment::of_bytes(b"token=[REDACTED]\n")
        );
    }

    #[test]
    fn duplicate_source_commitment_is_refused_instead_of_ambiguously_collapsing() {
        let object = SourceObject::new(commitment("object"), 1);
        let result = BuildInputCapsule::new(
            commitment("authority"),
            vec![object, object],
            commitment("lock"),
            text("toolchain"),
            BuildCommand::new(text("cargo"), Vec::new()).expect("canonical command"),
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
