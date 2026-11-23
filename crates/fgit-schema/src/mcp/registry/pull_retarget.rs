#![forbid(unsafe_code)]
//! Retarget shares the exact-version metadata envelope and original receipt.
use super::super::types::{McpField, McpToolEntry};

const fn inputs() -> [McpField; 11] {
    let source = super::pull_reopen::ENTRY.input_fields;
    let mut fields = [source[0]; 11];
    let mut i = 0;
    while i < fields.len() {
        fields[i] = source[i];
        i += 1;
    }
    fields[3].description =
        "The PR's unchanged full source branch. Supply this or source_reference_hex, never both.";
    fields[5].description = "Different full target branch. Supply this or target_reference_hex, never both; its current tip must match expected_target.";
    fields
}
const fn outputs() -> [McpField; 24] {
    let source = super::pull_reopen::ENTRY.output_fields;
    let mut fields = [source[0]; 24];
    let mut i = 0;
    while i < fields.len() {
        fields[i] = source[i];
        i += 1;
    }
    fields[19].description = "retarget.";
    fields[19].max_bytes = Some(8);
    fields[21].description = "False; retargeting changes PR metadata and no branch tips.";
    fields
}

pub(super) const ENTRY: McpToolEntry = McpToolEntry {
    name: "frankengit_pull_retarget",
    description: "Retarget an open native PR to a different target branch at an exact positive predecessor version. The source branch stays fixed; full metadata and explicit current source/new-target tips are required. Keeps PR identity and conversation, invalidates old review subjects, and changes no refs. Retry only the identical command and original durable key.",
    input_fields: &inputs(),
    output_fields: &outputs(),
    cli_command: "fg pr retarget",
    rest_api_path: "POST /{repository}/api/v1/pulls/{number}/retarget",
    ..super::pull_reopen::ENTRY
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{find_tool, validate_tool_entry};

    #[test]
    fn retarget_preserves_the_complete_metadata_contract_and_names_its_distinct_action() {
        validate_tool_entry(&ENTRY).unwrap();
        assert_eq!(find_tool(ENTRY.name), Some(&ENTRY));
        assert_eq!(ENTRY.input_fields.len(), 11);
        assert_eq!(ENTRY.output_fields.len(), 24);
        assert!(
            ENTRY.input_fields[5]
                .description
                .starts_with("Different full target")
        );
        assert_eq!(ENTRY.output_fields[19].name, "action");
        assert_eq!(ENTRY.output_fields[19].description, "retarget.");
        assert_eq!(ENTRY.output_fields[21].name, "refs_changed");
    }
}
