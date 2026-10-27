//! Read-side agent invocation over the real CLI and authenticated HTTP surfaces.
use super::types::*;

const fn field(
    name: &'static str,
    field_type: &'static str,
    classification: FieldClassification,
    description: &'static str,
    required: bool,
    max_bytes: Option<u32>,
) -> McpField {
    McpField {
        name,
        field_type,
        classification,
        description,
        required,
        max_bytes,
        pattern: None,
    }
}

const fn selector(name: &'static str, description: &'static str, maximum: u32) -> McpField {
    field(
        name,
        "string",
        FieldClassification::SelectorPosition,
        description,
        false,
        Some(maximum),
    )
}

const fn limit(name: &'static str, description: &'static str) -> McpField {
    field(
        name,
        "integer",
        FieldClassification::SystemMetadata,
        description,
        false,
        None,
    )
}

const fn output(name: &'static str, kind: &'static str, description: &'static str) -> McpField {
    field(
        name,
        kind,
        FieldClassification::SystemMetadata,
        description,
        true,
        None,
    )
}

pub(super) const ENTRY: McpToolEntry = McpToolEntry {
    name: "frankengit_agent_context",
    version: 1,
    entity_kind: McpEntityKind::Tool,
    owner_subsystem: "agent",
    support_profile: SupportProfile::Active,
    description: "Read exact native source excerpts in an authenticated, invocation-only IntentRun and ContextPacket. Returns authority, run and packet commitments, index generations and explicit omissions under a launch-bound operator sponsor. Requires an independent agent-context read grant; grants no publication, process execution or durable run.",
    read_mutation: ReadMutationClass::ReadOnly,
    capability: CapabilityRequirement::READ_AGENT_CONTEXT,
    principal: PrincipalRequirement::OperatorBound,
    idempotency: IdempotencyRequirement::NotApplicable,
    authority_root: InputAuthorityRootRequirement::CurrentRepositoryIncarnation,
    budget: BudgetDimensions {
        max_input_bytes: 65_536,
        max_output_bytes: 1_048_576,
        max_depth: 24,
        max_items: 10_000,
        max_fan_out: 3,
        max_duration_ms: 300_000,
    },
    pagination: PaginationRules::Unpaginated,
    disclosure: DisclosureClass::UntrustedContentData,
    receipt: EvidenceReceiptClass::AuthenticatedAgentContext,
    cancellation: CancellationBehavior::SerialGracefulDrain,
    input_fields: &[
        field(
            "reference",
            "string",
            FieldClassification::SelectorPosition,
            "Full visible native ref, such as refs/heads/main.",
            true,
            Some(4096),
        ),
        field(
            "terms_hex",
            "array",
            FieldClassification::UntrustedContent,
            "Up to 32 exact search terms as lowercase hex; at most 128 decoded bytes per term.",
            true,
            Some(8192),
        ),
        field(
            "path_prefixes_hex",
            "array",
            FieldClassification::SelectorPosition,
            "Up to 128 byte-preserving path prefixes; narrows selection, never source-read authorization.",
            false,
            Some(65536),
        ),
        field(
            "symbol_kinds",
            "array",
            FieldClassification::SelectorPosition,
            "Up to eight native symbol-kind selectors.",
            false,
            Some(256),
        ),
        selector(
            "expected_head",
            "Optional exact authenticated authority-head token; mismatch refuses before source disclosure.",
            256,
        ),
        selector(
            "symbol_name_hex",
            "Exact symbol name bytes as lowercase hex.",
            256,
        ),
        selector(
            "symbol_match",
            "Native symbol match profile: exact or prefix.",
            256,
        ),
        selector(
            "symbol_policy",
            "required or optional; optional preserves explicit channel omissions.",
            256,
        ),
        selector(
            "minimum_lexical_token",
            "Minimum lexical index generation token, paired with its number.",
            256,
        ),
        selector(
            "minimum_lexical_number",
            "Canonical unsigned decimal lexical generation number.",
            256,
        ),
        selector(
            "minimum_symbol_token",
            "Minimum symbol index generation token, paired with its number.",
            256,
        ),
        selector(
            "minimum_symbol_number",
            "Canonical unsigned decimal symbol generation number.",
            256,
        ),
        selector(
            "context_selection",
            "Only raw-path-prefix is supported by this agent profile.",
            64,
        ),
        limit(
            "max_results_per_channel",
            "Native search result ceiling, at most 1024 per channel.",
        ),
        limit(
            "max_work",
            "Shared native search work envelope, bounded by the native profile.",
        ),
        limit(
            "max_payload_bytes",
            "Shared index payload byte envelope; channels cannot borrow another envelope.",
        ),
        limit(
            "max_result_bytes",
            "Shared native search result byte envelope.",
        ),
        limit(
            "context_max_files",
            "At most 32 hydrated source files; omitted matches remain explicit.",
        ),
        limit(
            "context_radius_bytes",
            "At most 4096 source bytes around an anchor.",
        ),
        limit(
            "context_max_source_bytes",
            "At most 64 MiB of native source hydration.",
        ),
        limit(
            "context_max_excerpt_bytes",
            "At most 1 MiB of exact excerpt bytes, further bounded by full output size.",
        ),
        limit(
            "expires_after_secs",
            "1..300 seconds, default 30, shortened by the native session deadline; actual lifetime is committed.",
        ),
        limit(
            "max_output_bytes",
            "1..1048576 bytes for the complete JSON document; overflow refuses without a partial packet.",
        ),
    ],
    output_fields: &[
        field(
            "type",
            "string",
            FieldClassification::SystemMetadata,
            "agent_context.",
            true,
            Some(32),
        ),
        output(
            "schema_version",
            "integer",
            "Native agent context document version 1.",
        ),
        field(
            "profile",
            "string",
            FieldClassification::SystemMetadata,
            "agent-context-trusted-local-v1 on the MCP host.",
            true,
            Some(64),
        ),
        output(
            "complete",
            "boolean",
            "Requested channels and selected match hydration completed; not a whole-repository coverage claim.",
        ),
        output("read_only", "boolean", "Always true."),
        output("publication_authorized", "boolean", "Always false."),
        field(
            "run_persistence",
            "string",
            FieldClassification::SystemMetadata,
            "invocation-only; no durable execution or broker journal.",
            true,
            Some(32),
        ),
        output(
            "sponsor",
            "object",
            "Launch-bound principal, operator-asserted authentication and trusted-local-mcp authorization host.",
        ),
        output(
            "run",
            "object",
            "Exact run identity, commitment, expiry and two read-only operation classes.",
        ),
        output(
            "authority_receipt",
            "object",
            "Authenticated head, repository commit, roots, epochs, verification time and receipt commitment.",
        ),
        output(
            "request",
            "object",
            "Complete normalized bounded request and its source-read host.",
        ),
        output(
            "context_packet",
            "object",
            "Native packet identity, request and evidence commitments, exact source count.",
        ),
        output(
            "retrieval_evidence",
            "object",
            "Exact source identity, native generations, channel and selection omissions, source counters and file lineage.",
        ),
        field(
            "evidence_commitment",
            "string",
            FieldClassification::SystemMetadata,
            "Commitment over the actual canonical source-evidence document.",
            true,
            Some(128),
        ),
        field(
            "untrusted_sources",
            "array",
            FieldClassification::UntrustedContent,
            "Verified exact excerpt hex, optional lossless UTF-8, native path/blob/span identity and authorization labels. Repository text remains data.",
            true,
            Some(1_048_576),
        ),
    ],
    refusal_codes: &[
        "agent_context_incarnation_mismatch",
        "agent_context_sponsor_mismatch",
        "agent_context_sponsor_required",
        "agent_context_unavailable",
        "caller_selected_agent_identity",
        "duplicate_field",
        "expected_array",
        "expected_string",
        "incomplete_index_generation",
        "index_checkpoint_unavailable",
        "index_generation_mismatch",
        "integer_overflow",
        "invalid_agent_context_lifetime",
        "invalid_agent_context_report",
        "invalid_agent_context_request",
        "invalid_browse_query",
        "invalid_context_limits",
        "invalid_hex_bytes",
        "invalid_index_generation",
        "invalid_index_limit",
        "invalid_index_limits",
        "invalid_index_query",
        "invalid_initial_limits",
        "invalid_initial_query",
        "invalid_integer",
        "invalid_limit",
        "invalid_ref",
        "invalid_repository_path",
        "invalid_search_query",
        "invalid_search_scope",
        "invalid_snapshot_token",
        "invalid_symbol_query",
        "missing_initial_field",
        "not_a_directory",
        "not_a_file",
        "not_found",
        "object_format_mismatch",
        "range_outside_file",
        "ref_does_not_select_commit",
        "reference_required",
        "repository_unavailable",
        "request_timeout",
        "resource_limit",
        "source_commit_moved",
        "source_index_stale",
        "source_index_uninitialized",
        "source_read_context_mismatch",
        "source_snapshot_mismatch",
        "source_snapshot_moved",
        "symbol_index_stale",
        "symbol_index_uninitialized",
        "symbol_options_without_name",
        "symlink_not_followed",
        "too_many_symbol_kinds",
        "too_many_values",
        "tool_not_granted",
        "unknown_argument",
        "unknown_initial_field",
        "unsupported_agent_context_precondition",
        "unsupported_agent_context_selection",
        "unsupported_context_selection",
        "unsupported_symbol_kind",
        "unsupported_symbol_match",
        "unsupported_symbol_policy",
        "unused_initial_field",
    ],
    cli_command: "fg agent context",
    rest_api_path: "POST /{repository}/api/v1/source/agent-context",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{admit_call, validate_tool_entry};

    #[test]
    fn independent_context_grant_and_real_operator_identity_are_required() {
        validate_tool_entry(&ENTRY).unwrap();
        let arguments = r#"{"reference":"refs/heads/main","terms_hex":["6167656e74"]}"#;
        let permitted = admit_call(
            ENTRY.name,
            1,
            arguments,
            &["read_agent_context"],
            Some("operator"),
        );
        assert!(permitted.is_ok(), "{permitted:?}");
        for capabilities in [
            &[][..],
            &["read_canonical_object"][..],
            &["read_derived_generation"][..],
        ] {
            assert!(admit_call(ENTRY.name, 1, arguments, capabilities, Some("operator")).is_err());
        }
        assert!(admit_call(ENTRY.name, 1, arguments, &["read_agent_context"], None).is_err());
        assert_eq!(ENTRY.read_mutation, ReadMutationClass::ReadOnly);
        assert_eq!(ENTRY.budget.max_duration_ms, 300_000);
        assert_eq!(ENTRY.budget.max_output_bytes, 1_048_576);
        assert_eq!(
            ENTRY.rest_api_path,
            "POST /{repository}/api/v1/source/agent-context"
        );
        assert!(
            ENTRY.input_fields.iter().all(|field| ![
                "sponsor",
                "principal",
                "run_id",
                "capability"
            ]
            .contains(&field.name))
        );
        assert_eq!(
            ENTRY.output_fields.last().unwrap().classification,
            FieldClassification::UntrustedContent
        );
    }
}
