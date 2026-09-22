#![forbid(unsafe_code)]
//! Single-source MCP surface registry, capability contract, and typed refusals.
//!
//! # Deliverables (FG-096a)
//!
//! - Single-source MCP surface registry ([`registry::REGISTRY`]) with 28 tool,
//!   resource, and prompt definitions.
//! - Canonical capability, budget, authority root, and principal contracts ([`types`]).
//! - Strict constitutional anti-admin validation ([`validate`]).
//! - Discoverable typed refusals for unsupported operations ([`refusal`] and [`dispatch`]).
//! - Artifact generation for JSON Schema, JSON tool registry, and parity manifest.

pub mod dispatch;
pub mod refusal;
pub mod registry;
pub mod types;
pub mod validate;

pub use dispatch::{admit_call, discover_tools};
pub use refusal::McpRefusal;
pub use registry::{REGISTRY, find_tool, find_tool_version};
pub use types::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpToolEntry, PaginationRules,
    PrincipalRequirement, ReadMutationClass, SupportProfile,
};
pub use validate::{McpValidationError, validate_registry, validate_tool_entry};
