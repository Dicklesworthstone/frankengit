#![forbid(unsafe_code)]
//! Independent label replacement does not advance PR content or review subjects.
use super::super::types::{FieldClassification, McpField, McpToolEntry};

const fn base(name: &str) -> McpToolEntry {
    let mut index = 0;
    while index < super::core::REGISTRY.len() {
        let entry = super::core::REGISTRY[index];
        if !super::less(entry.name, name) && !super::less(name, entry.name) { return entry; }
        index += 1;
    }
    panic!("PR registry base is missing")
}
const fn field(name: &'static str, field_type: &'static str, description: &'static str, required: bool, max_bytes: Option<u32>, classification: FieldClassification) -> McpField {
    McpField { name, field_type, description, required, max_bytes, classification, pattern: None }
}
const fn selector(name: &'static str, description: &'static str, required: bool, bytes: u32) -> McpField {
    field(name, "string", description, required, Some(bytes), FieldClassification::SelectorPosition)
}
const fn output(name: &'static str, field_type: &'static str, description: &'static str, bytes: Option<u32>) -> McpField {
    field(name, field_type, description, true, bytes, FieldClassification::SystemMetadata)
}

pub(super) const READ: McpToolEntry = McpToolEntry {
    name: "frankengit_pull_labels",
    description: "Read the complete literal label set of a visible native PR at one authenticated snapshot. Missing and hidden PRs are indistinguishable. Label version zero means never written; an explicitly cleared stream retains its positive version. Labels carry no approval or authority.",
    input_fields: &[
        selector("number", "Positive canonical decimal PR number bounded by u64.", true, 20),
        selector("expected_head", "Optional exact retained snapshot_token; current disclosure still applies.", false, 140),
    ],
    output_fields: &[
        output("schema_version", "integer", "Label report schema version 1.", None),
        output("type", "string", "pull_request_labels.", Some(19)),
        output("tenant_id", "string", "Launch-bound tenant.", Some(32)),
        output("repository_id", "string", "Launch-bound repository.", Some(32)),
        output("repository_incarnation", "string", "Launch-bound repository incarnation.", Some(32)),
        output("object_format", "string", "Native sha1 or sha256 format.", Some(6)),
        output("snapshot_token", "string", "Exact authenticated snapshot token.", Some(140)),
        output("source_head", "string", "Authenticated repository authority head.", Some(256)),
        output("number", "string", "Requested PR number as a decimal string.", Some(20)),
        output("found", "boolean", "True only for a visible native metadata PR.", None),
        output("pull_request_version", "string|null", "Independent PR content version; null when not found.", Some(20)),
        output("labels_version", "string|null", "Exact label version as decimal: zero if unset, null if PR not found.", Some(20)),
        output("labels_actor", "string|null", "Last authenticated label author; null if unset or not found.", Some(32)),
        field("labels", "array|null", "Complete sorted distinct literal set, empty if unset or cleared; null when not found.", true, None, FieldClassification::UntrustedContent),
        output("complete", "boolean", "True; label sets are bounded and unpaginated.", None),
        output("read_only", "boolean", "True.", None),
        output("transaction_created", "boolean", "False; reading creates no command.", None),
    ],
    refusal_codes: &["tool_not_granted", "required_argument_missing", "expected_string", "unknown_argument", "invalid_decimal_string", "positive_pull_number_required", "snapshot_unavailable", "pull_labels_read_failed", "invalid_pull_page", "invalid_pull_labels_state"],
    cli_command: "fg pr labels",
    rest_api_path: "GET /{repository}/api/v1/pulls/{number}/labels",
    ..base("frankengit_pull_show")
};

pub(super) const WRITE: McpToolEntry = McpToolEntry {
    name: "frankengit_pull_set_labels",
    description: "Replace an existing visible PR's complete labels using the exact independent label version, including closed and merged PRs. Empty labels explicitly clears. No PR content version, refs or review freshness changes. Retry the identical complete command and original durable key; receipts describe original outcomes, not today's state.",
    input_fields: &[
        selector("number", "Positive canonical decimal PR number bounded by u64.", true, 20),
        selector("expected_version", "Exact independent label version: zero only for a never-written label stream. Never refreshed during retry.", true, 20),
        selector("idempotency_key", "Original durable printable ASCII key, reused only with the identical complete command.", true, 256),
        field("labels", "array", "Complete desired set: 0..32 unique nonblank literal labels, each at most 64 UTF-8 bytes without controls. Order is canonicalized; spelling is preserved.", true, None, FieldClassification::UntrustedContent),
    ],
    output_fields: &[
        output("schema_version", "integer", "Receipt schema version 1.", None),
        output("type", "string", "pull_request_labels_publication.", Some(31)),
        output("tenant_id", "string", "Launch-bound tenant.", Some(32)),
        output("repository_id", "string", "Launch-bound repository.", Some(32)),
        output("repository_incarnation", "string", "Launch-bound repository incarnation.", Some(32)),
        output("principal_id", "string", "Authenticated operator or sponsored agent principal.", Some(32)),
        output("object_format", "string", "Native sha1 or sha256 format.", Some(6)),
        output("read_only", "boolean", "False.", None),
        output("tx_id", "string", "Original sealed label command identity.", Some(256)),
        output("decision_sequence", "string", "Original terminal decision sequence as a decimal string.", Some(20)),
        output("outcome", "string", "committed or refused.", Some(9)),
        output("command_committed", "boolean", "True only for canonical commit.", None),
        output("terminal", "boolean", "True; uncertain outcomes are reported as errors.", None),
        output("outcome_unknown", "boolean", "False for a returned receipt.", None),
        output("repository_commit_id", "string|null", "Original committed RCR; null on refusal.", Some(256)),
        output("refusal_record_id", "string|null", "Original refusal record; null on commit.", Some(256)),
        output("refusal_code", "string|null", "Original canonical refusal code; null on commit.", Some(128)),
        output("number", "string", "Original PR number as decimal string.", Some(20)),
        output("expected_version", "string", "Original predecessor label version as decimal string.", Some(20)),
        field("labels", "array", "Original complete canonical desired label set; historical command content, not current state.", true, None, FieldClassification::UntrustedContent),
        output("labels_version", "string|null", "Original committed label version, expected plus one; null on refusal, never today's state.", Some(20)),
        output("action", "string", "set-labels.", Some(10)),
        output("refs_changed", "boolean", "False.", None),
        output("pull_request_version_changed", "boolean", "False; labels use an independent stream.", None),
        output("historical_outcome", "boolean", "True; this is an original terminal outcome.", None),
        output("delivery_acknowledged", "null", "External acknowledgement is not claimed.", None),
    ],
    refusal_codes: &["tool_not_granted", "principal_not_bound", "required_argument_missing", "expected_string", "unknown_argument", "invalid_decimal_string", "positive_pull_number_required", "invalid_idempotency_key", "version_exhausted", "labels_required", "labels_must_be_array", "too_many_labels", "label_must_be_string", "invalid_pull_labels", "mutation_outcome_unknown"],
    cli_command: "fg pr set-labels",
    rest_api_path: "POST /{repository}/api/v1/pulls/{number}/labels",
    ..base("frankengit_pull_update")
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{InputAuthorityRootRequirement, ReadMutationClass, find_tool, validate_tool_entry};
    #[test]
    fn labels_keep_independent_read_and_exact_version_write_contracts() {
        for entry in [READ, WRITE] {
            validate_tool_entry(&entry).unwrap();
            assert_eq!(find_tool(entry.name), Some(&entry));
        }
        assert_eq!(READ.read_mutation, ReadMutationClass::ReadOnly);
        assert_eq!(WRITE.read_mutation, ReadMutationClass::Mutation);
        assert_eq!(WRITE.authority_root, InputAuthorityRootRequirement::ExactPredecessorVersion);
        assert_eq!(WRITE.input_fields.iter().map(|field| field.name).collect::<Vec<_>>(), ["number", "expected_version", "idempotency_key", "labels"]);
        assert!(WRITE.input_fields.iter().all(|field| field.required));
        for entry in [READ, WRITE] {
            assert!(!entry.output_fields.iter().any(|field| field.name == "idempotency_key"));
        }
        assert_eq!(WRITE.input_fields[3].classification, FieldClassification::UntrustedContent);
    }
}
