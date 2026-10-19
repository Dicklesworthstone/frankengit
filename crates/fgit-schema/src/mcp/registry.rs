#![forbid(unsafe_code)]
//! Complete immutable MCP registry. Existing definitions remain byte-identical
//! in core; the transaction entry joins them at compile time in canonical order.
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
const fn assemble() -> [McpToolEntry; core::REGISTRY.len() + 1] {
    let mut result = [TRANSACTION; core::REGISTRY.len() + 1];
    let mut source = 0;
    let mut target = 0;
    let mut inserted = false;
    while source < core::REGISTRY.len() {
        if !inserted && less(TRANSACTION.name, core::REGISTRY[source].name) {
            result[target] = TRANSACTION;
            target += 1;
            inserted = true;
        }
        result[target] = core::REGISTRY[source];
        target += 1;
        source += 1;
    }
    if !inserted {
        result[target] = TRANSACTION;
    }
    result
}
/// The single public registry consumed by discovery, validation and generators.
pub static REGISTRY: &[McpToolEntry] = &assemble();
pub fn find_tool(name: &str) -> Option<&'static McpToolEntry> {
    if name == TRANSACTION.name {
        Some(&TRANSACTION)
    } else {
        core::find_tool(name)
    }
}
pub fn find_tool_version(name: &str, version: u32) -> Option<&'static McpToolEntry> {
    if name == TRANSACTION.name {
        if version == TRANSACTION.version {
            Some(&TRANSACTION)
        } else {
            None
        }
    } else {
        core::find_tool_version(name, version)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn composed_registry_preserves_every_existing_contract_and_inserts_exactly_one_tool() {
        crate::mcp::validate_registry(REGISTRY).unwrap();
        assert_eq!(REGISTRY.len(), core::REGISTRY.len() + 1);
        for old in core::REGISTRY {
            assert_eq!(find_tool_version(old.name, old.version), Some(old));
            assert!(REGISTRY.contains(old));
        }
        assert_eq!(
            REGISTRY
                .iter()
                .filter(|row| row.name == TRANSACTION.name)
                .count(),
            1
        );
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
