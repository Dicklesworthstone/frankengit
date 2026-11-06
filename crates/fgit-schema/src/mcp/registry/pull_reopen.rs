#![forbid(unsafe_code)]
//! Reopening uses the existing exact-version PR command and canonical receipt.
use super::super::types::{
    FieldClassification, InputAuthorityRootRequirement, McpField, McpToolEntry,
};

const fn input(
    name: &'static str,
    description: &'static str,
    required: bool,
    max_bytes: u32,
    pattern: Option<&'static str>,
) -> McpField {
    McpField {
        name,
        field_type: "string",
        classification: FieldClassification::SelectorPosition,
        description,
        required,
        max_bytes: Some(max_bytes),
        pattern,
    }
}

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
    name: "frankengit_pull_reopen",
    description: "Reopen a closed, unmerged native PR at an exact positive predecessor version. Complete metadata may refresh current tips on the same branches. Retry the identical command and original durable key; no branch restoration, code publication, review or merge is authorized.",
    authority_root: InputAuthorityRootRequirement::ExactPredecessorVersion,
    input_fields: &[
        input(
            "number",
            "Positive canonical decimal PR number, bounded by u64.",
            true,
            20,
            Some("^[1-9][0-9]*$"),
        ),
        input(
            "expected_version",
            "Exact positive predecessor PR version; never refreshed automatically.",
            true,
            20,
            Some("^[1-9][0-9]*$"),
        ),
        input(
            "idempotency_key",
            "Original durable printable ASCII key, reused only with the identical complete command.",
            true,
            256,
            Some("^[!-~]+$"),
        ),
        input(
            "source_reference",
            "Full source branch name. Supply this or source_reference_hex, never both. Cannot retarget the PR.",
            false,
            4096,
            None,
        ),
        input(
            "source_reference_hex",
            "Lossless source branch bytes. Alternative to source_reference; full refs/heads/ name required.",
            false,
            8192,
            Some("^(?:[0-9a-f]{2})+$"),
        ),
        input(
            "target_reference",
            "Full target branch name. Supply this or target_reference_hex, never both. Cannot retarget the PR.",
            false,
            4096,
            None,
        ),
        input(
            "target_reference_hex",
            "Lossless target branch bytes. Alternative to target_reference; full refs/heads/ name required.",
            false,
            8192,
            Some("^(?:[0-9a-f]{2})+$"),
        ),
        input(
            "expected_source",
            "Explicit nonzero current source commit in the repository SHA-1 or SHA-256 format.",
            true,
            64,
            Some("^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),
        ),
        input(
            "expected_target",
            "Explicit nonzero current target commit in the repository SHA-1 or SHA-256 format.",
            true,
            64,
            Some("^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),
        ),
        McpField {
            classification: FieldClassification::UntrustedContent,
            ..input(
                "title",
                "Complete literal UTF-8 title; nonblank and NUL-free. Text grants no authority.",
                true,
                256,
                None,
            )
        },
        McpField {
            classification: FieldClassification::UntrustedContent,
            ..input(
                "body",
                "Complete literal NUL-free UTF-8 body, including an explicit empty string. No text normalization.",
                true,
                16384,
                None,
            )
        },
    ],
    output_fields: &[
        receipt(
            "schema_version",
            "integer",
            "Receipt schema version 1.",
            None,
        ),
        receipt("type", "string", "pull_request_publication.", Some(24)),
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
            "Authenticated operator or canonical sponsored agent principal.",
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
            "Identity of the original sealed PR command.",
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
        receipt(
            "expected_version",
            "string",
            "Original submitted predecessor version, not the current PR version.",
            Some(20),
        ),
        receipt("action", "string", "reopen.", Some(6)),
        receipt(
            "complete",
            "boolean",
            "True for a complete terminal receipt.",
            None,
        ),
        receipt(
            "refs_changed",
            "boolean",
            "False; reopening changes no branch tips.",
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
        "exactly_one_branch_encoding_required",
        "full_branch_required",
        "invalid_branch",
        "invalid_native_oid",
        "invalid_pull_request_data",
        "invalid_pull_request_command",
        "mutation_outcome_unknown",
    ],
    cli_command: "fg pr reopen",
    rest_api_path: "POST /{repository}/api/v1/pulls/{number}/reopen",
    // Reopen retains the native metadata mutation, principal, durable-key,
    // disclosure, cancellation, budget and canonical receipt classes.
    ..super::append::ENTRY
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{find_tool, validate_tool_entry};

    #[test]
    fn reopen_contract_has_complete_inputs_and_an_original_terminal_receipt() {
        validate_tool_entry(&ENTRY).unwrap();
        assert_eq!(find_tool(ENTRY.name), Some(&ENTRY));
        assert_eq!(ENTRY.input_fields.len(), 11);
        assert_eq!(ENTRY.output_fields.len(), 24);
        assert_eq!(
            ENTRY.authority_root,
            InputAuthorityRootRequirement::ExactPredecessorVersion
        );
        for name in [
            "title",
            "body",
            "expected_version",
            "expected_source",
            "expected_target",
        ] {
            assert!(
                ENTRY
                    .input_fields
                    .iter()
                    .find(|field| field.name == name)
                    .unwrap()
                    .required
            );
        }
        for name in [
            "source_reference",
            "source_reference_hex",
            "target_reference",
            "target_reference_hex",
        ] {
            assert!(
                !ENTRY
                    .input_fields
                    .iter()
                    .find(|field| field.name == name)
                    .unwrap()
                    .required
            );
        }
        for absent in [
            "version",
            "body",
            "idempotency_key",
            "approval",
            "merge_permission",
        ] {
            assert!(!ENTRY.output_fields.iter().any(|field| field.name == absent));
        }
    }
}
