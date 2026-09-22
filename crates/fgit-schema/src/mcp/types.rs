#![forbid(unsafe_code)]
//! Canonical MCP surface types, classifications, and boundaries.
//!
//! Every tool, resource, and prompt exposed over the Model Context Protocol
//! has a single authoritative definition here. Text and model outputs cannot
//! widen capabilities or bypass resource budgets.

use core::fmt;

/// The protocol kind of an MCP surface entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum McpEntityKind {
    /// A callable operation taking structured parameters and returning a result.
    Tool,
    /// A readable data URI (e.g. `repo://info`).
    Resource,
    /// A templated prompt for agent interaction within strict capability bounds.
    Prompt,
}

impl McpEntityKind {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Resource => "resource",
            Self::Prompt => "prompt",
        }
    }
}

impl fmt::Display for McpEntityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The support lifecycle of an MCP entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SupportProfile {
    /// Production active, supported, and fully functional.
    Active,
    /// Known and discoverable construct that returns an authoritative typed refusal.
    /// Never silently falls through or disappears.
    Unsupported,
    /// Deprecated construct with a designated migration path.
    Deprecated,
    /// Gated experimental surface not yet promoted to active production.
    Experimental,
}

impl SupportProfile {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Unsupported => "unsupported",
            Self::Deprecated => "deprecated",
            Self::Experimental => "experimental",
        }
    }

    /// Whether this entity refuses invocation.
    #[must_use]
    pub const fn refuses(self) -> bool {
        matches!(self, Self::Unsupported | Self::Deprecated)
    }
}

impl fmt::Display for SupportProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The mutation class of an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReadMutationClass {
    /// Pure read-only operation. Does not alter canonical state or move refs.
    ReadOnly,
    /// State-mutating operation committed through a two-phase transaction decision.
    Mutation,
    /// Idempotent query of a historical transaction decision outcome.
    Recovery,
}

impl ReadMutationClass {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Mutation => "mutation",
            Self::Recovery => "recovery",
        }
    }
}

impl fmt::Display for ReadMutationClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The capability required to invoke an operation.
///
/// Must match one of the 13 foundational operation classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityRequirement(pub &'static str);

impl CapabilityRequirement {
    pub const READ_CANONICAL_OBJECT: Self = Self("read_canonical_object");
    pub const READ_DERIVED_GENERATION: Self = Self("read_derived_generation");
    pub const TREEFS_WORKSPACE: Self = Self("treefs_workspace");
    pub const EXECUTE_SANDBOXED_PROCESS: Self = Self("execute_sandboxed_process");
    pub const NETWORK_DESTINATION: Self = Self("network_destination");
    pub const SECRET_HANDLE: Self = Self("secret_handle");
    pub const EXTERNAL_INTEGRATION: Self = Self("external_integration");
    pub const CREATE_CANDIDATE_OBJECT: Self = Self("create_candidate_object");
    pub const PREPARE_PUBLICATION: Self = Self("prepare_publication");
    pub const SUBMIT_EVIDENCE: Self = Self("submit_evidence");
    pub const MUTATE_FORGE_ENTITY: Self = Self("mutate_forge_entity");
    pub const DELEGATE_SUB_INTENT: Self = Self("delegate_sub_intent");
    pub const CONSUME_BUDGET: Self = Self("consume_budget");

    /// All valid capability strings.
    pub const ALL_VALID: [&'static str; 13] = [
        "read_canonical_object",
        "read_derived_generation",
        "treefs_workspace",
        "execute_sandboxed_process",
        "network_destination",
        "secret_handle",
        "external_integration",
        "create_candidate_object",
        "prepare_publication",
        "submit_evidence",
        "mutate_forge_entity",
        "delegate_sub_intent",
        "consume_budget",
    ];

    /// Whether this capability requirement is a recognized narrow class.
    #[must_use]
    pub fn is_valid(self) -> bool {
        Self::ALL_VALID.contains(&self.0)
    }

    /// The string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for CapabilityRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Principal and sponsor requirements for operation execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrincipalRequirement {
    /// No authenticated principal required (e.g. public anonymous read).
    None,
    /// Requires an explicit operator-bound principal at launch (not client-supplied).
    OperatorBound,
    /// Requires a verified delegated agent token.
    DelegatedAgent,
}

impl PrincipalRequirement {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OperatorBound => "operator_bound",
            Self::DelegatedAgent => "delegated_agent",
        }
    }
}

impl fmt::Display for PrincipalRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Idempotency requirements for safe execution and retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdempotencyRequirement {
    /// Read-only operation; idempotency key is not applicable.
    NotApplicable,
    /// Mutation requiring a durable 1..256 byte ASCII idempotency key.
    RequiredDurableKey,
}

impl IdempotencyRequirement {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::RequiredDurableKey => "required_durable_key",
        }
    }
}

impl fmt::Display for IdempotencyRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Input authority root or predecessor pin requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InputAuthorityRootRequirement {
    /// No snapshot pin required.
    None,
    /// Read requires an exact `expected_head` snapshot token.
    ExactSnapshotToken,
    /// Mutation requires an exact predecessor aggregate version (`expected_version`).
    ExactPredecessorVersion,
    /// Mutation requires an exact predecessor commit ID (`expected_commit`).
    ExactPredecessorCommit,
}

impl InputAuthorityRootRequirement {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ExactSnapshotToken => "exact_snapshot_token",
            Self::ExactPredecessorVersion => "exact_predecessor_version",
            Self::ExactPredecessorCommit => "exact_predecessor_commit",
        }
    }
}

impl fmt::Display for InputAuthorityRootRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded resource dimensions for an MCP operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BudgetDimensions {
    /// Maximum allowed input size in bytes.
    pub max_input_bytes: u32,
    /// Maximum allowed output size in bytes.
    pub max_output_bytes: u32,
    /// Maximum allowed JSON nesting depth.
    pub max_depth: u16,
    /// Maximum allowed item count in request or response collections.
    pub max_items: u32,
    /// Maximum allowed fan-out factor.
    pub max_fan_out: u32,
    /// Maximum wall-clock execution budget in milliseconds.
    pub max_duration_ms: u32,
}

impl BudgetDimensions {
    /// Default bounds for standard read tools.
    pub const READ_STANDARD: Self = Self {
        max_input_bytes: 16_384,
        max_output_bytes: 65_536,
        max_depth: 16,
        max_items: 100,
        max_fan_out: 8,
        max_duration_ms: 30_000,
    };

    /// Default bounds for standard mutation tools.
    pub const MUTATION_STANDARD: Self = Self {
        max_input_bytes: 65_536,
        max_output_bytes: 32_768,
        max_depth: 16,
        max_items: 64,
        max_fan_out: 4,
        max_duration_ms: 60_000,
    };

    /// Default bounds for outcome recovery queries.
    pub const RECOVERY_STANDARD: Self = Self {
        max_input_bytes: 4_096,
        max_output_bytes: 16_384,
        max_depth: 8,
        max_items: 16,
        max_fan_out: 1,
        max_duration_ms: 15_000,
    };

    /// Default bounds for prompt/resource introspection.
    pub const INTROSPECTION_STANDARD: Self = Self {
        max_input_bytes: 4_096,
        max_output_bytes: 16_384,
        max_depth: 8,
        max_items: 32,
        max_fan_out: 1,
        max_duration_ms: 10_000,
    };

    /// Sentinel bounds for unsupported/refusal tools.
    pub const UNSUPPORTED_SENTINEL: Self = Self {
        max_input_bytes: 4_096,
        max_output_bytes: 4_096,
        max_depth: 4,
        max_items: 1,
        max_fan_out: 1,
        max_duration_ms: 5_000,
    };
}

/// Pagination and streaming cursor rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PaginationRules {
    /// Single entity or unpaginated bounded result.
    Unpaginated,
    /// Paginated with `after` cursor and mandatory `expected_head` snapshot pin.
    SnapshotBoundCursor,
    /// Paginated with monotone sequence number `after_version`.
    MonotoneVersionSequence,
    /// Byte offset pagination with `offset` and `max_bytes`.
    OffsetBytes,
}

impl PaginationRules {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unpaginated => "unpaginated",
            Self::SnapshotBoundCursor => "snapshot_bound_cursor",
            Self::MonotoneVersionSequence => "monotone_version_sequence",
            Self::OffsetBytes => "offset_bytes",
        }
    }
}

impl fmt::Display for PaginationRules {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Disclosure sensitivity and security boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DisclosureClass {
    /// Public repository data visible to authorized readers.
    PublicRepositoryData,
    /// Untrusted user-generated content (e.g. issues, comments, patches).
    /// Must never be interpreted as executable instructions.
    UntrustedContentData,
    /// Operator internal diagnostic or audit logs.
    OperatorInternal,
}

impl DisclosureClass {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicRepositoryData => "public_repository_data",
            Self::UntrustedContentData => "untrusted_content_data",
            Self::OperatorInternal => "operator_internal",
        }
    }
}

impl fmt::Display for DisclosureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Evidence and cryptographic receipt class returned by the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceReceiptClass {
    /// Pure read operation returning no durable mutation receipt.
    None,
    /// Canonical decision digest (RCR digest or forge event digest).
    CanonicalDecisionDigest,
    /// Historical transaction outcome record.
    HistoricalOutcomeRecord,
    /// Attested merge verification receipt.
    AttestedMergeReceipt,
}

impl EvidenceReceiptClass {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CanonicalDecisionDigest => "canonical_decision_digest",
            Self::HistoricalOutcomeRecord => "historical_outcome_record",
            Self::AttestedMergeReceipt => "attested_merge_receipt",
        }
    }
}

impl fmt::Display for EvidenceReceiptClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Cancellation lifecycle behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CancellationBehavior {
    /// Operation is read-only and enters immediate quiescence on cancellation.
    ImmediateQuiescent,
    /// Operation commits atomically; once admitted, completion or terminal
    /// refusal must be recorded; cancellation cannot infer rollback.
    NonPreemptiveTerminalCommit,
    /// Long read operation drains serially to the next safe page boundary.
    SerialGracefulDrain,
}

impl CancellationBehavior {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateQuiescent => "immediate_quiescent",
            Self::NonPreemptiveTerminalCommit => "non_preemptive_terminal_commit",
            Self::SerialGracefulDrain => "serial_graceful_drain",
        }
    }
}

impl fmt::Display for CancellationBehavior {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Security classification of a schema field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FieldClassification {
    /// User-supplied content (e.g. title, body, comment text, patch, code).
    /// Always treated as untrusted data.
    UntrustedContent,
    /// System and protocol metadata (e.g. snapshot tokens, timestamps, hashes).
    SystemMetadata,
    /// Explicit capability or permission flag.
    CapabilityGrant,
    /// Exact selector position or identity (e.g. ref name, issue number, commit ID).
    SelectorPosition,
}

impl FieldClassification {
    /// Stable lowercase string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedContent => "untrusted_content",
            Self::SystemMetadata => "system_metadata",
            Self::CapabilityGrant => "capability_grant",
            Self::SelectorPosition => "selector_position",
        }
    }
}

impl fmt::Display for FieldClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One schema field in an MCP parameter or return object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct McpField {
    /// Field property name.
    pub name: &'static str,
    /// JSON schema data type (`string`, `integer`, `boolean`, `array`, `object`).
    pub field_type: &'static str,
    /// Security classification.
    pub classification: FieldClassification,
    /// Human-readable description.
    pub description: &'static str,
    /// Whether the field is mandatory.
    pub required: bool,
    /// Maximum byte length for string fields.
    pub max_bytes: Option<u32>,
    /// Regular expression pattern for validation.
    pub pattern: Option<&'static str>,
}

/// Single-source MCP surface registry entry for one tool, resource, or prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct McpToolEntry {
    /// Stable unique tool name.
    pub name: &'static str,
    /// Monotone interface version number (starts at 1).
    pub version: u32,
    /// Protocol entity kind.
    pub entity_kind: McpEntityKind,
    /// Owner subsystem.
    pub owner_subsystem: &'static str,
    /// Support and lifecycle profile.
    pub support_profile: SupportProfile,
    /// Tool description exposed in MCP discovery.
    pub description: &'static str,
    /// Read/mutation class.
    pub read_mutation: ReadMutationClass,
    /// Capability requirement.
    pub capability: CapabilityRequirement,
    /// Principal requirement.
    pub principal: PrincipalRequirement,
    /// Idempotency requirement.
    pub idempotency: IdempotencyRequirement,
    /// Authority root / snapshot pin requirement.
    pub authority_root: InputAuthorityRootRequirement,
    /// Enforced resource budget dimensions.
    pub budget: BudgetDimensions,
    /// Pagination rules.
    pub pagination: PaginationRules,
    /// Disclosure sensitivity class.
    pub disclosure: DisclosureClass,
    /// Evidence receipt class.
    pub receipt: EvidenceReceiptClass,
    /// Cancellation behavior.
    pub cancellation: CancellationBehavior,
    /// Input parameters schema fields.
    pub input_fields: &'static [McpField],
    /// Output result schema fields.
    pub output_fields: &'static [McpField],
    /// Closed machine refusal codes.
    pub refusal_codes: &'static [&'static str],
    /// Parity CLI command.
    pub cli_command: &'static str,
    /// Parity REST API path.
    pub rest_api_path: &'static str,
}
