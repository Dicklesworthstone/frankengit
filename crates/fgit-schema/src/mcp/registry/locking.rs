#![forbid(unsafe_code)]
//! Exact-version discussion moderation shares the existing issue-write authority.
use super::super::types::{
    FieldClassification, InputAuthorityRootRequirement, McpField, McpToolEntry,
};

const INPUT: &[McpField] = &[
    McpField {
        name: "number",
        field_type: "string",
        classification: FieldClassification::SelectorPosition,
        description: "Positive canonical decimal issue number, bounded by u64.",
        required: true,
        max_bytes: Some(20),
        pattern: Some("^[1-9][0-9]*$"),
    },
    McpField {
        name: "expected_version",
        field_type: "string",
        classification: FieldClassification::SelectorPosition,
        description: "Exact positive predecessor issue version. Never refresh this value when retrying the original command.",
        required: true,
        max_bytes: Some(20),
        pattern: Some("^[1-9][0-9]*$"),
    },
    McpField {
        name: "idempotency_key",
        field_type: "string",
        classification: FieldClassification::SelectorPosition,
        description: "Original durable printable ASCII key, reused only with the identical action, issue number and expected version.",
        required: true,
        max_bytes: Some(256),
        pattern: Some("^[!-~]+$"),
    },
];

// The native exact-version and append surfaces return the same terminal receipt
// fields. Only the action and original expected-version descriptions differ;
// no current aggregate version is inferred from a later read.
const fn receipt(lock: bool) -> [McpField; 24] {
    let source = super::append::ENTRY.output_fields;
    assert!(source.len() == 24);
    let mut fields = [source[0]; 24];
    let mut index = 0;
    while index < source.len() {
        fields[index] = source[index];
        index += 1;
    }
    fields[8].description = "Canonical identity of the original sealed exact-version command.";
    fields[18].description = if lock { "lock." } else { "unlock." };
    fields[18].max_bytes = Some(6);
    fields[19].field_type = "string";
    fields[19].description =
        "Original exact positive predecessor version, not a current issue version.";
    fields[19].max_bytes = Some(20);
    fields[21].description = "False; issue discussion moderation does not change Git refs.";
    fields
}
const LOCK_RECEIPT: [McpField; 24] = receipt(true);
const UNLOCK_RECEIPT: [McpField; 24] = receipt(false);

const fn entry(lock: bool) -> McpToolEntry {
    let mut row = super::append::ENTRY;
    row.name = if lock {
        "frankengit_issue_lock"
    } else {
        "frankengit_issue_unlock"
    };
    row.description = if lock {
        "Lock discussion on an open or closed issue at an exact positive version. Both exact-version and append comments refuse while locked; edits, assignment and close/reopen preserve the lock. Requires the existing issue-write grant."
    } else {
        "Unlock discussion on an open or closed issue at an exact positive version. Retry the identical action, number, version and original durable key; unlocking never reinterprets a previously refused comment. Requires the existing issue-write grant."
    };
    row.authority_root = InputAuthorityRootRequirement::ExactPredecessorVersion;
    row.input_fields = INPUT;
    row.output_fields = if lock { &LOCK_RECEIPT } else { &UNLOCK_RECEIPT };
    row.refusal_codes = &[
        "tool_not_granted",
        "principal_not_bound",
        "required_argument_missing",
        "expected_string",
        "unknown_argument",
        "invalid_decimal_string",
        "positive_issue_number_required",
        "positive_version_required",
        "version_exhausted",
        "invalid_idempotency_key",
        "mutation_outcome_unknown",
    ];
    row.cli_command = if lock {
        "fg issue lock"
    } else {
        "fg issue unlock"
    };
    row.rest_api_path = if lock {
        "POST /{repository}/api/v1/issues/{number}/lock"
    } else {
        "POST /{repository}/api/v1/issues/{number}/unlock"
    };
    row
}

pub(super) const LOCK: McpToolEntry = entry(true);
pub(super) const UNLOCK: McpToolEntry = entry(false);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        CapabilityRequirement, IdempotencyRequirement, McpRefusal, PrincipalRequirement,
        admit_call, find_tool, validate_tool_entry,
    };

    #[test]
    fn moderation_contracts_bind_exact_versions_without_extra_authority_or_payload() {
        for entry in [LOCK, UNLOCK] {
            validate_tool_entry(&entry).unwrap();
            assert_eq!(find_tool(entry.name), Some(&entry));
            assert_eq!(entry.capability, CapabilityRequirement::MUTATE_FORGE_ENTITY);
            assert_eq!(entry.principal, PrincipalRequirement::OperatorBound);
            assert_eq!(
                entry.idempotency,
                IdempotencyRequirement::RequiredDurableKey
            );
            assert_eq!(
                entry.authority_root,
                InputAuthorityRootRequirement::ExactPredecessorVersion
            );
            assert_eq!(
                entry
                    .input_fields
                    .iter()
                    .map(|field| field.name)
                    .collect::<Vec<_>>(),
                ["number", "expected_version", "idempotency_key"]
            );
            assert!(entry.input_fields.iter().all(|field| field.required));
            assert_eq!(entry.input_fields[1].pattern, Some("^[1-9][0-9]*$"));
            let arguments = r#"{"number":"7","expected_version":"3","idempotency_key":"original"}"#;
            let capabilities = [entry.capability.as_str()];
            assert!(admit_call(entry.name, 1, arguments, &capabilities, Some("operator")).is_ok());
            assert!(matches!(
                admit_call(entry.name, 1, arguments, &[], Some("operator")),
                Err(McpRefusal::CapabilityDenied { .. })
            ));
            assert!(matches!(
                admit_call(entry.name, 1, arguments, &capabilities, None),
                Err(McpRefusal::PrincipalRequired { .. })
            ));
        }
    }

    #[test]
    fn moderation_receipts_describe_the_original_terminal_fact() {
        for (entry, action) in [(LOCK, "lock."), (UNLOCK, "unlock.")] {
            let field = |name| {
                entry
                    .output_fields
                    .iter()
                    .find(|field| field.name == name)
                    .unwrap()
            };
            assert_eq!(field("tx_id").field_type, "string");
            assert!(field("tx_id").description.contains("exact-version"));
            assert_eq!(field("action").description, action);
            assert_eq!(field("expected_version").field_type, "string");
            assert_eq!(field("expected_version").max_bytes, Some(20));
            assert_eq!(field("historical_outcome").field_type, "boolean");
            assert!(field("refs_changed").description.contains("moderation"));
            for absent in ["transaction_id", "version", "body", "idempotency_key"] {
                assert!(!entry.output_fields.iter().any(|field| field.name == absent));
            }
        }
    }
}
