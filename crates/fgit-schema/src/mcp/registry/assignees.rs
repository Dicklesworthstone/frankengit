#![forbid(unsafe_code)]
//! Explicit additive assignment requests retain the ordinary terminal receipt.

use super::append;
use super::types::{DisclosureClass, FieldClassification, McpField, McpToolEntry};

const fn named(left: &str, right: &str) -> bool {
    !super::less(left, right) && !super::less(right, left)
}

const fn receipt_fields() -> [McpField; append::ENTRY.output_fields.len() + 1] {
    let mut fields = [append::ENTRY.output_fields[0]; append::ENTRY.output_fields.len() + 1];
    let mut index = 0;
    while index < append::ENTRY.output_fields.len() {
        fields[index] = append::ENTRY.output_fields[index];
        if named(fields[index].name, "action") {
            fields[index].description = "add-assignees.";
            fields[index].max_bytes = Some(13);
        } else if named(fields[index].name, "tx_id") {
            fields[index].description =
                "Canonical identity of the original sealed assignee-addition intent.";
        } else if named(fields[index].name, "expected_version") {
            fields[index].description =
                "Always null: admission selects the assignment's current predecessor.";
        } else if named(fields[index].name, "refs_changed") {
            fields[index].description =
                "False; issue assignments do not change Git refs or access grants.";
        }
        index += 1;
    }
    fields[index] = McpField {
        name: "command_profile",
        field_type: "string",
        classification: FieldClassification::SystemMetadata,
        description: "issue.add-assignees.v1: the exact sealed addition request profile.",
        required: true,
        max_bytes: Some(22),
        pattern: None,
    };
    fields
}

pub(super) const ENTRY: McpToolEntry = McpToolEntry {
    name: "frankengit_issue_add_assignees",
    description: "Add 1..16 distinct principal IDs to an existing issue without expected_version. Concurrent additions preserve each other's assignments; the current union stays bounded. Retry the identical issue, assignee set and original durable key to recover the original terminal outcome. Assignment grants no access or membership.",
    disclosure: DisclosureClass::PublicRepositoryData,
    input_fields: &[
        append::ENTRY.input_fields[0],
        McpField {
            description: "Original durable printable ASCII key, reused only with the identical issue number and assignee set, including after an uncertain response.",
            ..append::ENTRY.input_fields[1]
        },
        McpField {
            name: "assignees",
            field_type: "array",
            classification: FieldClassification::SelectorPosition,
            description: "1..16 unique lowercase 32-hex principal IDs to add; input order is canonicalized before sealing.",
            required: true,
            max_bytes: None,
            pattern: None,
        },
    ],
    output_fields: &receipt_fields(),
    refusal_codes: &[
        "tool_not_granted",
        "principal_not_bound",
        "required_argument_missing",
        "expected_string",
        "unknown_argument",
        "invalid_decimal_string",
        "positive_issue_number_required",
        "invalid_idempotency_key",
        "assignees_array_required",
        "invalid_assignee",
        "invalid_assignee_count",
        "duplicate_assignee",
        "mutation_outcome_unknown",
    ],
    cli_command: "fg issue add-assignees",
    rest_api_path: "POST /{repository}/api/v1/issues/{number}/add-assignees",
    ..append::ENTRY
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        InputAuthorityRootRequirement, McpRefusal, admit_call, find_tool, validate_tool_entry,
    };

    #[test]
    fn additive_assignment_contract_is_distinct_from_strict_assignment() {
        validate_tool_entry(&ENTRY).unwrap();
        assert_eq!(find_tool(ENTRY.name), Some(&ENTRY));
        assert_eq!(
            ENTRY.authority_root,
            InputAuthorityRootRequirement::ServerSelectedHead
        );
        assert_eq!(
            ENTRY
                .input_fields
                .iter()
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            ["number", "idempotency_key", "assignees"]
        );
        let exact = find_tool("frankengit_issue_assign").unwrap();
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
        let field = |name| {
            ENTRY
                .output_fields
                .iter()
                .find(|field| field.name == name)
                .unwrap()
        };
        assert_eq!(field("action").description, "add-assignees.");
        assert_eq!(field("expected_version").field_type, "null");
        assert_eq!(field("tx_id").field_type, "string");
        assert_eq!(field("decision_sequence").field_type, "string");
        assert_eq!(field("command_profile").field_type, "string");
    }

    #[test]
    fn additive_assignment_requires_the_normal_mutation_grant_and_principal() {
        let arguments = r#"{"number":"7","assignees":["11111111111111111111111111111111"],"idempotency_key":"original"}"#;
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
}
