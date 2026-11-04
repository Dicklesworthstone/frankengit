#![forbid(unsafe_code)]
//! Reviewed linear-series publication uses the existing source-write authority.
use super::super::types::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpToolEntry, PaginationRules,
    PrincipalRequirement, ReadMutationClass, SupportProfile,
};

const NATIVE_OID: Option<&str> = Some("^(?:[0-9a-f]{40}|[0-9a-f]{64})$");
const fn input(
    name: &'static str,
    field_type: &'static str,
    description: &'static str,
    required: bool,
    max_bytes: Option<u32>,
    pattern: Option<&'static str>,
) -> McpField {
    McpField {
        name,
        field_type,
        classification: FieldClassification::SelectorPosition,
        description,
        required,
        max_bytes,
        pattern,
    }
}
const fn output(
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
const fn untrusted(mut field: McpField) -> McpField {
    field.classification = FieldClassification::UntrustedContent;
    field
}
const INPUT: &[McpField] = &[
    input("reference", "string", "Exact SOURCE refs/heads/* branch, at most 1024 UTF-8 bytes. Supply exactly one of reference/reference_hex.", false, Some(1024), None),
    input("reference_hex", "string", "Exact raw SOURCE branch, at most 1024 decoded bytes; mutually exclusive with reference.", false, Some(2048), Some("^(?:[0-9a-f]{2})+$")),
    input("expected_source", "string", "Exact old SOURCE branch tip: the publication lease, independent of onto.", true, Some(64), NATIVE_OID),
    input("onto", "string", "Exact nonzero sole bundle prerequisite in the launch hash domain. Not the old-source lease or a current-tip selector.", true, Some(64), NATIVE_OID),
    input("expected_candidate", "string", "Exact independently inspected final candidate. May equal onto for a zero-commit series.", true, Some(64), NATIVE_OID),
    untrusted(input("bundle_hex_chunks", "array", "One complete native Git bundle: 1..3 ordered lowercase-hex chunks of at most 8192 decoded bytes each, at most 24576 decoded bytes total. Native quarantine and dedicated complete-series validation own acceptance.", true, Some(49164), None)),
    input("idempotency_key", "string", "Original 1..256-byte printable ASCII durable key for the exact old-source/new-candidate ref transaction. Retry identical submitted inputs; JSON-RPC IDs are independent.", true, Some(256), Some("^[!-~]+$")),
];
const OUTPUT: &[McpField] = &[
    output("schema_version", "integer", "Result schema version 1.", None),
    output("type", "string", "source_publication.", Some(32)),
    output("action", "string", "publish_rebase.", Some(32)),
    output("publication_profile", "string", "linear-rebase-v1, using the dedicated native bounded-series validator.", Some(32)),
    output("tenant_id", "string", "Launch-bound tenant.", Some(32)),
    output("repository_id", "string", "Launch-bound repository.", Some(32)),
    output("repository_incarnation", "string", "Launch-verified repository incarnation.", Some(32)),
    output("principal_id", "string", "Operator-bound principal; caller metadata cannot choose it.", Some(32)),
    output("object_format", "string", "Launch-bound sha1 or sha256 domain.", Some(6)),
    output("read_only", "boolean", "Always false: this is canonical publication.", None),
    output("tx_id", "string", "Verified canonical transaction identity.", Some(256)),
    output("decision_sequence", "string", "Exact canonical positive decimal decision position.", Some(20)),
    output("outcome", "string", "Historical committed or refused terminal fact.", Some(16)),
    output("command_committed", "boolean", "Whether the submitted canonical ref transaction committed.", None),
    output("terminal", "boolean", "Always true for this successful result envelope.", None),
    output("outcome_unknown", "boolean", "Always false after a verified terminal result; uncertain execution is a typed failure.", None),
    output("repository_commit_id", "string|null", "Canonical RCR on commit, null on refusal.", Some(256)),
    output("refusal_record_id", "string|null", "Canonical refusal identity on refusal, null on commit.", Some(256)),
    output("refusal_code", "string|null", "Native terminal refusal code, null on commit.", Some(128)),
    output("atomic", "boolean", "The native result is one atomic ref transaction.", None),
    output("complete", "boolean", "The complete verified terminal result is present.", None),
    output("historical_outcome", "boolean", "Always true: original-key recovery can return an older decision.", None),
    output("current_refs_asserted", "boolean", "Always false: terminal history does not assert today's refs.", None),
    output("ref_transaction_committed", "boolean", "Whether the one source ref transaction committed.", None),
    untrusted(output("submitted_commands", "array", "One submitted source branch command: raw reference_hex, exact expected_old/new candidate, and force:false. These are submitted coordinates, not current-ref assertions.", Some(4096))),
    output("submitted_onto", "string", "The caller's bundle prerequisite. This is not sealed ref semantics or a historical pack-validation attestation.", Some(64)),
    output("bundle_validation_receipt", "null", "Always null: a recovered terminal does not attest a newly submitted pack encoding.", None),
    output("replay_equivalence_verified", "boolean", "Always false: bounded chain validation and admission do not prove semantic equivalence to original commits.", None),
];

pub(super) const PUBLISH: McpToolEntry = McpToolEntry {
    name: "frankengit_source_publish_rebase",
    version: 1,
    entity_kind: McpEntityKind::Tool,
    owner_subsystem: "git-core",
    support_profile: SupportProfile::Active,
    description: "Publish an independently inspected native linear-rebase bundle with the exact old source lease, onto prerequisite, final candidate and original durable key. Ordinary source-write grant only; sponsored profiles exclude this operator adapter. Native quarantine, bounded series validation and ordinary atomic admission retain policy and historical retry semantics.",
    read_mutation: ReadMutationClass::Mutation,
    capability: CapabilityRequirement::PREPARE_PUBLICATION,
    principal: PrincipalRequirement::OperatorBound,
    idempotency: IdempotencyRequirement::RequiredDurableKey,
    authority_root: InputAuthorityRootRequirement::ExactPredecessorCommit,
    budget: BudgetDimensions::MUTATION_STANDARD,
    pagination: PaginationRules::Unpaginated,
    disclosure: DisclosureClass::UntrustedContentData,
    receipt: EvidenceReceiptClass::CanonicalDecisionDigest,
    cancellation: CancellationBehavior::NonPreemptiveTerminalCommit,
    input_fields: INPUT,
    output_fields: OUTPUT,
    refusal_codes: &[
        "tool_not_granted",
        "principal_not_bound",
        "unknown_argument",
        "required_argument_missing",
        "expected_string",
        "invalid_idempotency_key",
        "exactly_one_branch_encoding_required",
        "full_branch_required",
        "invalid_branch",
        "invalid_native_oid",
        "invalid_hex_bytes",
        "bundle_chunks_required",
        "bundle_chunk_limit",
        "bundle_chunk_must_be_hex",
        "invalid_bundle_chunk",
        "bundle_byte_limit",
        "allocation_refused",
        "source_mutation_outcome_unknown",
        "inconsistent_atomic_outcome",
    ],
    cli_command: "fg rebase apply",
    rest_api_path: "/api/v1/source/rebase/apply",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebase_publication_preserves_native_authority_and_retry_classification() {
        assert_eq!(PUBLISH.read_mutation, ReadMutationClass::Mutation);
        assert_eq!(PUBLISH.capability, CapabilityRequirement::PREPARE_PUBLICATION);
        assert_eq!(PUBLISH.principal, PrincipalRequirement::OperatorBound);
        assert_eq!(PUBLISH.idempotency, IdempotencyRequirement::RequiredDurableKey);
        assert_eq!(PUBLISH.cancellation, CancellationBehavior::NonPreemptiveTerminalCommit);
        for name in ["expected_source", "onto", "expected_candidate", "bundle_hex_chunks", "idempotency_key"] {
            assert!(INPUT.iter().any(|field| field.name == name && field.required));
        }
        for name in ["expected_head", "force", "principal", "initial"] {
            assert!(INPUT.iter().all(|field| field.name != name));
        }
        assert_eq!(OUTPUT.iter().find(|field| field.name == "bundle_validation_receipt").unwrap().field_type, "null");
        assert_eq!(OUTPUT.iter().find(|field| field.name == "submitted_commands").unwrap().classification, FieldClassification::UntrustedContent);
    }
}
