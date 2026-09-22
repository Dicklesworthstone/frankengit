#![forbid(unsafe_code)]
//! Constitutional validation for MCP registry entries.
//!
//! Enforces:
//! - No generic admin pass-through or arbitrary command execution.
//! - Strict capability scoping (no wildcards or overbroad tokens).
//! - Bounded resource dimensions on all axes.
//! - Snapshot/predecessor binding on paginated reads and mutations.
//! - Content fields classified as untrusted data.
//! - Machine-readable refusal codes (never prose-only error strings).
//! - Deterministic alphabetical ordering.

use super::types::{FieldClassification, McpToolEntry, ReadMutationClass, SupportProfile};
use core::fmt;

/// Validation errors for an MCP registry entry or entire registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpValidationError {
    /// Tool attempts generic admin pass-through or arbitrary execution.
    GenericAdminPassThrough {
        tool: &'static str,
        matched_pattern: &'static str,
    },
    /// Capability is overbroad, a wildcard, or outside admitted classes.
    OverbroadCapability {
        tool: &'static str,
        capability: &'static str,
    },
    /// A required budget dimension is missing or zero.
    MissingBudgetDimension {
        tool: &'static str,
        dimension: &'static str,
    },
    /// Budget exceeds constitutional hard ceilings.
    BudgetCeilingExceeded {
        tool: &'static str,
        dimension: &'static str,
        actual: u32,
        ceiling: u32,
    },
    /// Read cursor or mutation lacks mandatory predecessor authority root.
    MissingAuthorityPosition {
        tool: &'static str,
        requirement: &'static str,
    },
    /// Refusal code is prose-like rather than a typed machine identifier.
    ProseOnlyError {
        tool: &'static str,
        code: &'static str,
    },
    /// Refusal codes collection is empty.
    EmptyRefusalCodes { tool: &'static str },
    /// User content field was not classified as untrusted content data.
    ContentFieldMisclassified {
        tool: &'static str,
        field: &'static str,
    },
    /// Duplicate tool name and version in registry.
    DuplicateToolNameVersion { tool: &'static str, version: u32 },
    /// Registry entries are not in strict deterministic sort order.
    UnsortedRegistry {
        current: &'static str,
        previous: &'static str,
    },
    /// Active tool is missing CLI or REST API parity mapping.
    MissingParityMapping {
        tool: &'static str,
        missing: &'static str,
    },
    /// Input field string lacks maximum byte bound.
    UnboundedStringField {
        tool: &'static str,
        field: &'static str,
    },
}

impl fmt::Display for McpValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericAdminPassThrough {
                tool,
                matched_pattern,
            } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: prohibited generic admin pattern '{matched_pattern}'"
                )
            }
            Self::OverbroadCapability { tool, capability } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: capability '{capability}' is overbroad or unrecognized"
                )
            }
            Self::MissingBudgetDimension { tool, dimension } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: budget dimension '{dimension}' must be greater than zero"
                )
            }
            Self::BudgetCeilingExceeded {
                tool,
                dimension,
                actual,
                ceiling,
            } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: budget dimension '{dimension}' value {actual} exceeds ceiling {ceiling}"
                )
            }
            Self::MissingAuthorityPosition { tool, requirement } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: missing required authority root '{requirement}'"
                )
            }
            Self::ProseOnlyError { tool, code } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: refusal code '{code}' is prose-like, must be snake_case identifier"
                )
            }
            Self::EmptyRefusalCodes { tool } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: refusal_codes list must not be empty"
                )
            }
            Self::ContentFieldMisclassified { tool, field } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: field '{field}' must be classified as UntrustedContent"
                )
            }
            Self::DuplicateToolNameVersion { tool, version } => {
                write!(
                    formatter,
                    "duplicate registry entry: tool '{tool}' version {version}"
                )
            }
            Self::UnsortedRegistry { current, previous } => {
                write!(
                    formatter,
                    "registry sorting violation: '{current}' must sort after '{previous}'"
                )
            }
            Self::MissingParityMapping { tool, missing } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: missing public parity mapping '{missing}'"
                )
            }
            Self::UnboundedStringField { tool, field } => {
                write!(
                    formatter,
                    "tool '{tool}' refuses: string field '{field}' must declare max_bytes bound"
                )
            }
        }
    }
}

/// Hard ceilings for resource bounds.
const MAX_INPUT_CEILING_BYTES: u32 = 1_048_576; // 1 MiB
const MAX_OUTPUT_CEILING_BYTES: u32 = 1_048_576; // 1 MiB
const MAX_DEPTH_CEILING: u16 = 32;
const MAX_ITEMS_CEILING: u32 = 10_000;
const MAX_FAN_OUT_CEILING: u32 = 256;
const MAX_DURATION_CEILING_MS: u32 = 300_000; // 5 minutes

/// Forbidden substrings that indicate generic admin or arbitrary execution.
const FORBIDDEN_ADMIN_PATTERNS: &[&str] = &[
    "admin_exec",
    "arbitrary_command",
    "raw_sql",
    "raw_storage",
    "hidden_repair",
    "model_says_allow",
    "shell_exec",
    "sudo",
    "eval",
];

/// Validates a single tool entry against all constitutional constraints.
pub fn validate_tool_entry(entry: &McpToolEntry) -> Result<(), McpValidationError> {
    // 1. Generic admin pass-through check.
    // Active or experimental tools must NEVER match forbidden admin patterns.
    // Unsupported sentinel tools are allowed to name the forbidden pattern only
    // because they exist explicitly to document and typed-refuse that pattern.
    if entry.support_profile != SupportProfile::Unsupported {
        for pattern in FORBIDDEN_ADMIN_PATTERNS {
            if entry.name.contains(pattern) || entry.description.to_lowercase().contains(pattern) {
                return Err(McpValidationError::GenericAdminPassThrough {
                    tool: entry.name,
                    matched_pattern: pattern,
                });
            }
        }
    }

    // 2. Capability check: must be a recognized narrow capability class.
    if !entry.capability.is_valid() {
        return Err(McpValidationError::OverbroadCapability {
            tool: entry.name,
            capability: entry.capability.as_str(),
        });
    }

    // 3. Budget dimensions check: non-zero and within hard ceilings.
    if entry.budget.max_input_bytes == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_input_bytes",
        });
    }
    if entry.budget.max_input_bytes > MAX_INPUT_CEILING_BYTES {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_input_bytes",
            actual: entry.budget.max_input_bytes,
            ceiling: MAX_INPUT_CEILING_BYTES,
        });
    }
    if entry.budget.max_output_bytes == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_output_bytes",
        });
    }
    if entry.budget.max_output_bytes > MAX_OUTPUT_CEILING_BYTES {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_output_bytes",
            actual: entry.budget.max_output_bytes,
            ceiling: MAX_OUTPUT_CEILING_BYTES,
        });
    }
    if entry.budget.max_depth == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_depth",
        });
    }
    if entry.budget.max_depth > MAX_DEPTH_CEILING {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_depth",
            actual: entry.budget.max_depth as u32,
            ceiling: MAX_DEPTH_CEILING as u32,
        });
    }
    if entry.budget.max_items == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_items",
        });
    }
    if entry.budget.max_items > MAX_ITEMS_CEILING {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_items",
            actual: entry.budget.max_items,
            ceiling: MAX_ITEMS_CEILING,
        });
    }
    if entry.budget.max_fan_out == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_fan_out",
        });
    }
    if entry.budget.max_fan_out > MAX_FAN_OUT_CEILING {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_fan_out",
            actual: entry.budget.max_fan_out,
            ceiling: MAX_FAN_OUT_CEILING,
        });
    }
    if entry.budget.max_duration_ms == 0 {
        return Err(McpValidationError::MissingBudgetDimension {
            tool: entry.name,
            dimension: "max_duration_ms",
        });
    }
    if entry.budget.max_duration_ms > MAX_DURATION_CEILING_MS {
        return Err(McpValidationError::BudgetCeilingExceeded {
            tool: entry.name,
            dimension: "max_duration_ms",
            actual: entry.budget.max_duration_ms,
            ceiling: MAX_DURATION_CEILING_MS,
        });
    }

    // 4. Authority position enforcement:
    // - Paginated reads must bind exact snapshot tokens or version sequence.
    // - Mutations must require exact predecessor version or commit and durable key.
    match entry.read_mutation {
        ReadMutationClass::ReadOnly => {
            if entry.pagination != super::types::PaginationRules::Unpaginated
                && entry.authority_root == super::types::InputAuthorityRootRequirement::None
            {
                return Err(McpValidationError::MissingAuthorityPosition {
                    tool: entry.name,
                    requirement: "paginated reads must specify an authority root requirement",
                });
            }
        }
        ReadMutationClass::Mutation => {
            if entry.idempotency != super::types::IdempotencyRequirement::RequiredDurableKey {
                return Err(McpValidationError::MissingAuthorityPosition {
                    tool: entry.name,
                    requirement: "mutations must require an idempotency key",
                });
            }
            if entry.authority_root == super::types::InputAuthorityRootRequirement::None {
                return Err(McpValidationError::MissingAuthorityPosition {
                    tool: entry.name,
                    requirement: "mutations must require an exact predecessor authority root",
                });
            }
        }
        ReadMutationClass::Recovery => {
            // Outcome recovery uses durable transaction key
            if entry
                .input_fields
                .iter()
                .all(|f| f.name != "idempotency_key")
            {
                return Err(McpValidationError::MissingAuthorityPosition {
                    tool: entry.name,
                    requirement: "recovery operations must take an idempotency_key parameter",
                });
            }
        }
    }

    // 5. Content field classification check:
    // Any field containing user text or payload must be classified as UntrustedContent.
    for field in entry.input_fields.iter().chain(entry.output_fields.iter()) {
        let is_content_name = field.name == "body"
            || field.name == "title"
            || field.name == "comment"
            || field.name == "explanation"
            || field.name == "text_utf8"
            || field.name == "bytes_hex"
            || field.name == "bundle_hex"
            || field.name == "patch";

        if is_content_name && field.classification != FieldClassification::UntrustedContent {
            return Err(McpValidationError::ContentFieldMisclassified {
                tool: entry.name,
                field: field.name,
            });
        }

        // String fields must declare max_bytes bound
        if field.field_type == "string" && field.max_bytes.is_none() {
            return Err(McpValidationError::UnboundedStringField {
                tool: entry.name,
                field: field.name,
            });
        }
    }

    // 6. Refusal codes check: must be non-empty and snake_case machine identifiers.
    if entry.refusal_codes.is_empty() {
        return Err(McpValidationError::EmptyRefusalCodes { tool: entry.name });
    }
    for &code in entry.refusal_codes {
        if !is_machine_refusal_code(code) {
            return Err(McpValidationError::ProseOnlyError {
                tool: entry.name,
                code,
            });
        }
    }

    // 7. Parity mapping check: active tools must have non-empty CLI and REST API mappings.
    if entry.support_profile == SupportProfile::Active {
        if entry.cli_command.is_empty() {
            return Err(McpValidationError::MissingParityMapping {
                tool: entry.name,
                missing: "cli_command",
            });
        }
        if entry.rest_api_path.is_empty() {
            return Err(McpValidationError::MissingParityMapping {
                tool: entry.name,
                missing: "rest_api_path",
            });
        }
    }

    Ok(())
}

/// Validates that an entire registry is sorted, unique, and every entry is valid.
pub fn validate_registry(tools: &[McpToolEntry]) -> Result<(), McpValidationError> {
    let mut prev: Option<&McpToolEntry> = None;
    for entry in tools {
        validate_tool_entry(entry)?;

        if let Some(p) = prev {
            if entry.name == p.name && entry.version == p.version {
                return Err(McpValidationError::DuplicateToolNameVersion {
                    tool: entry.name,
                    version: entry.version,
                });
            }
            if (entry.name, entry.version) <= (p.name, p.version) {
                return Err(McpValidationError::UnsortedRegistry {
                    current: entry.name,
                    previous: p.name,
                });
            }
        }
        prev = Some(entry);
    }
    Ok(())
}

/// Checks whether a string is a valid machine identifier (snake_case, no spaces, no uppercase).
fn is_machine_refusal_code(code: &str) -> bool {
    if code.is_empty() || code.len() > 64 {
        return false;
    }
    let bytes = code.as_bytes();
    // Must start with lowercase ASCII letter
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    // All characters must be lowercase ASCII letters, digits, or underscores
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::types::*;

    fn valid_mock_entry() -> McpToolEntry {
        McpToolEntry {
            name: "frankengit_test_tool",
            version: 1,
            entity_kind: McpEntityKind::Tool,
            owner_subsystem: "forge",
            support_profile: SupportProfile::Active,
            description: "Test tool description",
            read_mutation: ReadMutationClass::ReadOnly,
            capability: CapabilityRequirement::READ_CANONICAL_OBJECT,
            principal: PrincipalRequirement::None,
            idempotency: IdempotencyRequirement::NotApplicable,
            authority_root: InputAuthorityRootRequirement::None,
            budget: BudgetDimensions::READ_STANDARD,
            pagination: PaginationRules::Unpaginated,
            disclosure: DisclosureClass::PublicRepositoryData,
            receipt: EvidenceReceiptClass::None,
            cancellation: CancellationBehavior::ImmediateQuiescent,
            input_fields: &[McpField {
                name: "param1",
                field_type: "string",
                classification: FieldClassification::SelectorPosition,
                description: "Test param",
                required: true,
                max_bytes: Some(64),
                pattern: None,
            }],
            output_fields: &[McpField {
                name: "result",
                field_type: "string",
                classification: FieldClassification::SystemMetadata,
                description: "Test result",
                required: true,
                max_bytes: Some(128),
                pattern: None,
            }],
            refusal_codes: &["test_not_found", "test_invalid_argument"],
            cli_command: "fg test tool",
            rest_api_path: "GET /test/tool",
        }
    }

    #[test]
    fn valid_entry_passes_validation() {
        let entry = valid_mock_entry();
        assert!(validate_tool_entry(&entry).is_ok());
    }

    #[test]
    fn generic_admin_is_rejected() {
        let mut entry = valid_mock_entry();
        entry.name = "frankengit_shell_exec";
        assert!(matches!(
            validate_tool_entry(&entry),
            Err(McpValidationError::GenericAdminPassThrough { .. })
        ));
    }

    #[test]
    fn overbroad_capability_is_rejected() {
        let mut entry = valid_mock_entry();
        entry.capability = CapabilityRequirement("admin_all");
        assert!(matches!(
            validate_tool_entry(&entry),
            Err(McpValidationError::OverbroadCapability { .. })
        ));
    }

    #[test]
    fn missing_budget_is_rejected() {
        let mut entry = valid_mock_entry();
        entry.budget.max_input_bytes = 0;
        assert!(matches!(
            validate_tool_entry(&entry),
            Err(McpValidationError::MissingBudgetDimension { .. })
        ));
    }

    #[test]
    fn prose_only_error_is_rejected() {
        let mut entry = valid_mock_entry();
        entry.refusal_codes = &["An error occurred while processing"];
        assert!(matches!(
            validate_tool_entry(&entry),
            Err(McpValidationError::ProseOnlyError { .. })
        ));
    }

    #[test]
    fn misclassified_content_field_is_rejected() {
        let mut entry = valid_mock_entry();
        entry.input_fields = &[McpField {
            name: "body",
            field_type: "string",
            classification: FieldClassification::SystemMetadata, // Should be UntrustedContent!
            description: "Issue body",
            required: true,
            max_bytes: Some(16384),
            pattern: None,
        }];
        assert!(matches!(
            validate_tool_entry(&entry),
            Err(McpValidationError::ContentFieldMisclassified { .. })
        ));
    }
}
