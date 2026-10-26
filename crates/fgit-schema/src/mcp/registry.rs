#![forbid(unsafe_code)]
//! Complete immutable MCP registry. Existing definitions remain byte-identical
//! in core; explicit additional tools join them at compile time in canonical order.
mod append;
mod artifacts;
mod core;
use super::types;
use types::{FieldClassification, McpField, McpToolEntry};

const fn less(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
        i += 1;
    }
    a.len() < b.len()
}
const fn entry() -> McpToolEntry {
    let mut i = 0;
    while i < core::REGISTRY.len() {
        let name = core::REGISTRY[i].name;
        if !less(name, "frankengit_branch_rename") && !less("frankengit_branch_rename", name) {
            let mut row = core::REGISTRY[i];
            row.name = "frankengit_branch_transaction";
            row.description = "Atomically create, advance or delete 1..64 distinct branches under one durable key and canonical decision.";
            row.input_fields = &[
                McpField {
                    name: "commands",
                    field_type: "array",
                    classification: FieldClassification::SelectorPosition,
                    description: "1..64 distinct create/update/delete objects with exact branch names and native old/new OIDs; no nested keys, force or identity overrides.",
                    required: true,
                    max_bytes: Some(65536),
                    pattern: None,
                },
                McpField {
                    name: "idempotency_key",
                    field_type: "string",
                    classification: FieldClassification::SelectorPosition,
                    description: "One durable printable ASCII key for the entire canonical transaction.",
                    required: true,
                    max_bytes: Some(256),
                    pattern: Some("^[!-~]+$"),
                },
            ];
            row.cli_command = "fg branch transaction";
            row.rest_api_path = "/api/v1/source/branches/transaction";
            row.refusal_codes = &[
                "tool_not_granted",
                "commands_required",
                "branch_transaction_limit",
                "command_must_be_object",
                "invalid_branch_action",
                "duplicate_branch_target",
                "source_mutation_outcome_unknown",
                "inconsistent_atomic_outcome",
            ];
            return row;
        }
        i += 1;
    }
    panic!("native branch registry contract missing")
}
const TRANSACTION: McpToolEntry = entry();
const ADDITIONS: [McpToolEntry; 4] = [
    artifacts::INSPECT,
    artifacts::READ,
    TRANSACTION,
    append::ENTRY,
];
const fn assemble() -> [McpToolEntry; core::REGISTRY.len() + ADDITIONS.len()] {
    let mut result = [TRANSACTION; core::REGISTRY.len() + ADDITIONS.len()];
    let mut source = 0;
    let mut extra = 0;
    let mut target = 0;
    while source < core::REGISTRY.len() || extra < ADDITIONS.len() {
        if extra < ADDITIONS.len()
            && (source == core::REGISTRY.len()
                || less(ADDITIONS[extra].name, core::REGISTRY[source].name))
        {
            result[target] = ADDITIONS[extra];
            extra += 1;
        } else {
            result[target] = core::REGISTRY[source];
            source += 1;
        }
        target += 1;
    }
    result
}
/// The single public registry consumed by discovery, validation and generators.
pub static REGISTRY: &[McpToolEntry] = &assemble();
pub fn find_tool(name: &str) -> Option<&'static McpToolEntry> {
    ADDITIONS
        .iter()
        .find(|entry| entry.name == name)
        .or_else(|| core::find_tool(name))
}
pub fn find_tool_version(name: &str, version: u32) -> Option<&'static McpToolEntry> {
    ADDITIONS
        .iter()
        .find(|entry| entry.name == name && entry.version == version)
        .or_else(|| core::find_tool_version(name, version))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn composed_registry_preserves_every_existing_contract_and_inserts_each_addition_once() {
        crate::mcp::validate_registry(REGISTRY).unwrap();
        assert_eq!(REGISTRY.len(), core::REGISTRY.len() + ADDITIONS.len());
        for old in core::REGISTRY {
            assert_eq!(find_tool(old.name), core::find_tool(old.name));
            assert_eq!(
                find_tool_version(old.name, old.version),
                core::find_tool_version(old.name, old.version)
            );
            assert_eq!(find_tool_version(old.name, old.version), Some(old));
            assert!(REGISTRY.contains(old));
        }
        for addition in ADDITIONS {
            assert_eq!(
                REGISTRY
                    .iter()
                    .filter(|row| row.name == addition.name)
                    .count(),
                1
            );
            assert_eq!(find_tool(addition.name), Some(&addition));
            assert_eq!(
                find_tool_version(addition.name, addition.version),
                Some(&addition)
            );
            assert!(find_tool_version(addition.name, 0).is_none());
            assert!(find_tool_version(addition.name, addition.version + 1).is_none());
        }
        assert!(find_tool("frankengit_unknown_tool").is_none());
        assert!(find_tool_version("frankengit_unknown_tool", 1).is_none());
        assert!(
            REGISTRY
                .windows(2)
                .all(|pair| (pair[0].name, pair[0].version) < (pair[1].name, pair[1].version))
        );
        assert!(find_tool_version(TRANSACTION.name, 2).is_none());
        assert_eq!(
            find_tool(TRANSACTION.name).unwrap().rest_api_path,
            "/api/v1/source/branches/transaction"
        );
    }
}
