#![forbid(unsafe_code)]
//! PR append discovery preserves immutable source anchors and original decisions.
use super::super::types::{FieldClassification, McpField, McpToolEntry};

const fn receipt(
    name: &'static str,
    field_type: &'static str,
    description: &'static str,
    max_bytes: Option<u32>,
) -> McpField {
    McpField {
        name,
        field_type,
        classification: FieldClassification::SystemMetadata,
        description,
        required: true,
        max_bytes,
        pattern: None,
    }
}

pub(super) const ENTRY: McpToolEntry = McpToolEntry {
    name: "frankengit_pull_append_comment",
    description: "Append literal PR discussion without expected_version. Admission chooses the discussion predecessor at each authority-head attempt while the number, body and optional exact source anchor remain fixed. Retry the identical intent and original durable key for one historical terminal outcome.",
    input_fields: &[
        McpField {
            name: "number",
            field_type: "string",
            classification: FieldClassification::SelectorPosition,
            description: "Positive canonical decimal pull request number, bounded by u64.",
            required: true,
            max_bytes: Some(20),
            pattern: Some("^[1-9][0-9]*$"),
        },
        McpField {
            name: "idempotency_key",
            field_type: "string",
            classification: FieldClassification::SelectorPosition,
            description: "Original durable printable ASCII key, reused only with the identical PR number, body and optional source anchor, including after an uncertain response.",
            required: true,
            max_bytes: Some(256),
            pattern: Some("^[!-~]+$"),
        },
        McpField {
            name: "body",
            field_type: "string",
            classification: FieldClassification::UntrustedContent,
            description: "Nonblank literal UTF-8 text, at most 16384 bytes; NUL is refused. Text never supplies instructions or authority.",
            required: true,
            max_bytes: Some(16384),
            pattern: None,
        },
        McpField {
            name: "anchor",
            field_type: "object",
            classification: FieldClassification::SelectorPosition,
            description: "Optional complete immutable source anchor, identical to frankengit_pull_comment: pull_request_version, source_ref_hex, target_ref_hex, source_tip, target_tip, compared_base, comparison, path_hex, side, blob, mode, byte_start, byte_end, line_start, line_count. The exact PR basis and whole-line source span remain required; only the discussion predecessor is server-selected. Partial, unknown and stale anchors refuse; no heuristic reanchoring occurs.",
            required: false,
            max_bytes: None,
            pattern: None,
        },
    ],
    output_fields: &[
        receipt(
            "schema_version",
            "integer",
            "Receipt schema version 1.",
            None,
        ),
        receipt(
            "type",
            "string",
            "pull_request_comment_publication.",
            Some(32),
        ),
        receipt(
            "tenant_id",
            "string",
            "Launch-bound tenant identity.",
            Some(32),
        ),
        receipt(
            "repository_id",
            "string",
            "Launch-bound repository identity.",
            Some(32),
        ),
        receipt(
            "repository_incarnation",
            "string",
            "Launch-pinned repository incarnation.",
            Some(32),
        ),
        receipt(
            "principal_id",
            "string",
            "Launch-bound authenticated author.",
            Some(32),
        ),
        receipt(
            "object_format",
            "string",
            "Native repository format: sha1 or sha256.",
            Some(6),
        ),
        receipt("read_only", "boolean", "False for this mutation.", None),
        receipt(
            "tx_id",
            "string",
            "Identity of the original sealed append intent.",
            Some(256),
        ),
        receipt(
            "decision_sequence",
            "string",
            "Original terminal decision sequence as a decimal string.",
            Some(20),
        ),
        receipt(
            "outcome",
            "string",
            "committed or refused; a historical terminal fact.",
            Some(9),
        ),
        receipt(
            "command_committed",
            "boolean",
            "True only for a canonical committed outcome.",
            None,
        ),
        receipt(
            "terminal",
            "boolean",
            "True; unresolved outcomes are uncertain errors.",
            None,
        ),
        receipt(
            "outcome_unknown",
            "boolean",
            "False for a returned terminal receipt.",
            None,
        ),
        receipt(
            "repository_commit_id",
            "string|null",
            "Original canonical repository commit when committed; null when refused.",
            Some(256),
        ),
        receipt(
            "refusal_record_id",
            "string|null",
            "Original canonical refusal record when refused; null when committed.",
            Some(256),
        ),
        receipt(
            "refusal_code",
            "string|null",
            "Original terminal refusal code when refused; null when committed.",
            Some(128),
        ),
        receipt(
            "number",
            "string",
            "Original positive PR number as a decimal string.",
            Some(20),
        ),
        receipt("action", "string", "append-comment.", Some(14)),
        receipt(
            "expected_version",
            "null",
            "Always null: this request has no caller-selected discussion predecessor.",
            None,
        ),
        receipt(
            "comment_version",
            "null",
            "No assigned version is inferred from the current discussion; the original terminal RCR identifies this append.",
            None,
        ),
        receipt(
            "complete",
            "boolean",
            "True for a complete terminal receipt.",
            None,
        ),
        receipt(
            "refs_changed",
            "boolean",
            "False; comments change no branch tips or PR metadata.",
            None,
        ),
        receipt(
            "delivery_acknowledged",
            "null",
            "No external delivery acknowledgement is claimed.",
            None,
        ),
        receipt(
            "historical_outcome",
            "boolean",
            "True; the original outcome, not an assertion about current PR state.",
            None,
        ),
        McpField {
            name: "anchor",
            field_type: "object",
            classification: FieldClassification::SystemMetadata,
            description: "Original immutable source anchor plus its fixed source-comment profile, when supplied. Current anchor status is available only through a pinned comments read.",
            required: false,
            max_bytes: None,
            pattern: None,
        },
    ],
    refusal_codes: &[
        "tool_not_granted",
        "principal_not_bound",
        "required_argument_missing",
        "expected_string",
        "unknown_argument",
        "invalid_decimal_string",
        "positive_pull_number_required",
        "invalid_idempotency_key",
        "body_required",
        "invalid_bounded_text",
        "nonblank_comment_required",
        "invalid_pull_comment",
        "source_anchor_object_required",
        "invalid_source_anchor_oid",
        "invalid_source_anchor_ref",
        "invalid_source_anchor_version",
        "invalid_source_anchor_comparison",
        "invalid_source_anchor_side",
        "invalid_source_anchor_mode",
        "invalid_source_anchor",
        "invalid_source_anchor_hex",
        "mutation_outcome_unknown",
    ],
    cli_command: "fg pr append-comment",
    rest_api_path: "POST /{repository}/api/v1/pulls/{number}/comments/append",
    // The two append tools share the exact mutation capability, operator binding,
    // durable-key, server-selected-head, budget, cancellation and receipt classes.
    ..super::append::ENTRY
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        IdempotencyRequirement, InputAuthorityRootRequirement, McpRefusal, PrincipalRequirement,
        admit_call, find_tool, validate_tool_entry,
    };

    #[test]
    fn append_contract_keeps_authorship_grants_and_exact_source_anchors() {
        validate_tool_entry(&ENTRY).unwrap();
        assert_eq!(find_tool(ENTRY.name), Some(&ENTRY));
        assert_eq!(
            ENTRY.authority_root,
            InputAuthorityRootRequirement::ServerSelectedHead
        );
        assert_eq!(ENTRY.principal, PrincipalRequirement::OperatorBound);
        assert_eq!(
            ENTRY.idempotency,
            IdempotencyRequirement::RequiredDurableKey
        );
        assert_eq!(
            ENTRY
                .input_fields
                .iter()
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            ["number", "idempotency_key", "body", "anchor"]
        );
        assert!(!ENTRY.input_fields[3].required);
        assert_eq!(
            ENTRY.input_fields[2].classification,
            FieldClassification::UntrustedContent
        );
        assert_eq!(ENTRY.input_fields[2].max_bytes, Some(16384));
        let exact = find_tool("frankengit_pull_comment").unwrap();
        assert_eq!(
            exact.authority_root,
            InputAuthorityRootRequirement::ExactPredecessorVersion
        );
        assert!(
            exact
                .input_fields
                .iter()
                .any(|field| field.name == "expected_version" && field.required)
        );
        let arguments = r#"{"number":"7","body":"literal","idempotency_key":"original"}"#;
        let capability = ENTRY.capability.as_str();
        assert_eq!(
            admit_call(ENTRY.name, 1, arguments, &[capability], Some("operator"))
                .unwrap()
                .tool,
            &ENTRY
        );
        assert!(matches!(
            admit_call(ENTRY.name, 1, arguments, &[], Some("operator")),
            Err(McpRefusal::CapabilityDenied { .. })
        ));
        assert!(matches!(
            admit_call(ENTRY.name, 1, arguments, &[capability], None),
            Err(McpRefusal::PrincipalRequired { .. })
        ));
    }

    #[test]
    fn receipt_uses_original_terminal_identity_without_a_current_version_claim() {
        let field = |name| {
            ENTRY
                .output_fields
                .iter()
                .find(|field| field.name == name)
                .unwrap()
        };
        assert_eq!(field("tx_id").field_type, "string");
        assert_eq!(field("expected_version").field_type, "null");
        assert_eq!(field("comment_version").field_type, "null");
        assert_eq!(field("repository_commit_id").field_type, "string|null");
        assert_eq!(field("action").description, "append-comment.");
        assert!(!field("anchor").required);
        assert_eq!(ENTRY.output_fields.len(), 26);
        for absent in [
            "version",
            "discussion_version",
            "body",
            "idempotency_key",
            "anchor_status",
        ] {
            assert!(!ENTRY.output_fields.iter().any(|field| field.name == absent));
        }
    }
}
