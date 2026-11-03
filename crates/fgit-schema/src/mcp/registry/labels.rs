#![forbid(unsafe_code)]
//! Label union intents keep ordinary principal, retry and terminal boundaries.

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
            fields[index].description = "add-labels.";
            fields[index].max_bytes = Some(10);
        } else if named(fields[index].name, "tx_id") {
            fields[index].description =
                "Canonical identity of the original sealed label-addition intent.";
        } else if named(fields[index].name, "expected_version") {
            fields[index].description =
                "Always null: admission selects the label union's current predecessor.";
        } else if named(fields[index].name, "refs_changed") {
            fields[index].description =
                "False; issue labels do not change Git refs or access grants.";
        }
        index += 1;
    }
    fields[index] = McpField {
        name: "command_profile",
        field_type: "string",
        classification: FieldClassification::SystemMetadata,
        description: "issue.add-labels.v1: the exact sealed label-addition request profile.",
        required: true,
        max_bytes: Some(19),
        pattern: None,
    };
    fields
}

pub(super) const ENTRY: McpToolEntry = McpToolEntry {
    name: "frankengit_issue_add_labels",
    description: "Add 1..32 distinct labels to an existing issue without expected_version. Concurrent additions preserve each other's labels within the 32-label union bound. Retry the identical issue, label set and original durable key to recover the original terminal outcome without undoing later replacements. Labels grant no authority.",
    disclosure: DisclosureClass::PublicRepositoryData,
    input_fields: &[
        append::ENTRY.input_fields[0],
        McpField {
            description: "Original durable printable ASCII key, reused only with the identical issue number and label set, including after an uncertain response.",
            ..append::ENTRY.input_fields[1]
        },
        McpField {
            name: "labels",
            field_type: "array",
            classification: FieldClassification::UntrustedContent,
            description: "1..32 unique nonblank labels of at most 64 UTF-8 bytes each, without control characters; input order is canonicalized before sealing.",
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
        "labels_required",
        "labels_must_be_array",
        "too_many_labels",
        "invalid_label",
        "duplicate_label",
        "invalid_issue_labels",
        "mutation_outcome_unknown",
    ],
    cli_command: "fg issue add-labels",
    rest_api_path: "POST /{repository}/api/v1/issues/{number}/add-labels",
    ..append::ENTRY
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{
        InputAuthorityRootRequirement, McpRefusal, admit_call, find_tool, validate_tool_entry,
    };

    #[test]
    fn label_addition_is_distinct_from_replacement_and_requires_normal_write_authority() {
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
            ["number", "idempotency_key", "labels"]
        );
        assert_eq!(
            ENTRY.input_fields[2].classification,
            FieldClassification::UntrustedContent
        );
        let exact = find_tool("frankengit_issue_edit").unwrap();
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
        assert_eq!(field("expected_version").field_type, "null");
        assert_eq!(field("command_profile").field_type, "string");
        let arguments = r#"{"number":"7","labels":["bug"],"idempotency_key":"original"}"#;
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
