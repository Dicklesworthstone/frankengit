#![forbid(unsafe_code)]
//! Native tag reads and sealed ref publication under existing source grants.
//! Authored tagger/message/signature bytes never authenticate a principal.
use super::super::types::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpToolEntry, PaginationRules,
    PrincipalRequirement, ReadMutationClass, SupportProfile,
};

const NATIVE_OID: Option<&str> = Some("^(?:[0-9a-f]{40}|[0-9a-f]{64})$");

const fn selector(
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

const fn metadata(
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

const REFERENCE: McpField = selector(
    "reference",
    "string",
    "Full UTF-8 refs/tags/* name, at most 1024 bytes. Supply exactly one of reference and reference_hex.",
    false,
    Some(1024),
    None,
);
const REFERENCE_HEX: McpField = selector(
    "reference_hex",
    "string",
    "Exact raw full refs/tags/* name in lowercase hex, at most 1024 decoded bytes. Mutually exclusive with reference.",
    false,
    Some(2048),
    Some("^(?:[0-9a-f]{2})+$"),
);
const KEY: McpField = selector(
    "idempotency_key",
    "string",
    "Original durable key: 1..256 printable ASCII bytes. Retry only the identical operation and all original tag operands; JSON-RPC IDs are independent.",
    true,
    Some(256),
    Some("^[!-~]+$"),
);
const TARGET: McpField = selector(
    "target",
    "string",
    "Exact nonzero native target OID in the launch-bound SHA-1 or SHA-256 domain. Current visible reachability is checked by native admission.",
    true,
    Some(64),
    NATIVE_OID,
);
const fn expected_object(required: bool) -> McpField {
    selector(
        "expected_object",
        "string",
        "Exact nonzero OUTER tag-ref object ID, not its peeled commit. A comparison or deletion lease; never an arbitrary-object read capability.",
        required,
        Some(64),
        NATIVE_OID,
    )
}

const INSPECT_INPUT: &[McpField] = &[
    REFERENCE,
    REFERENCE_HEX,
    selector(
        "expected_head",
        "string",
        "Optional exact current algorithm-qualified snapshot token. Authority movement refuses; this does not select a retained historical snapshot.",
        false,
        Some(140),
        None,
    ),
    expected_object(false),
    selector(
        "max_tags",
        "integer",
        "Narrow the recursively peeled annotation count from 1 through 64; default 64.",
        false,
        None,
        None,
    ),
    selector(
        "max_object_bytes",
        "integer",
        "Narrow the native per-object read bound from 1 through 262144 bytes; default 262144. Includes the terminal non-tag object.",
        false,
        None,
        None,
    ),
    selector(
        "max_total_bytes",
        "integer",
        "Narrow total original object bytes from 1 through 524288; default 524288. Includes the terminal object, whose body is not returned. Encoded output has an independent 1 MiB limit.",
        false,
        None,
        None,
    ),
];
const CREATE_INPUT: &[McpField] = &[REFERENCE, REFERENCE_HEX, TARGET, KEY];
const ANNOTATE_INPUT: &[McpField] = &[
    REFERENCE,
    REFERENCE_HEX,
    TARGET,
    selector(
        "target_kind",
        "string",
        "Declared target kind: commit, tree, blob or tag. Native quarantine checks the actual kind before publication.",
        true,
        Some(6),
        Some("^(commit|tree|blob|tag)$"),
    ),
    untrusted(selector(
        "tagger",
        "string",
        "Explicit native Name <email> metadata, at most 1024 UTF-8 bytes. Content only, never the launch-bound authenticated principal.",
        true,
        Some(1024),
        None,
    )),
    untrusted(selector(
        "timestamp",
        "string",
        "Explicit UTC Unix seconds as canonical decimal, 0..9223372036854775807. No ambient clock or authenticated authorship is inferred.",
        true,
        Some(19),
        Some("^(0|[1-9][0-9]*)$"),
    )),
    untrusted(selector(
        "message_hex",
        "string",
        "Exact message bytes as lowercase hex, at most 8192 decoded bytes. Empty is valid; NUL refuses. No trimming, newline insertion or signature trust.",
        true,
        Some(16384),
        Some("^(?:[0-9a-f]{2})*$"),
    )),
    KEY,
];
const DELETE_INPUT: &[McpField] = &[REFERENCE, REFERENCE_HEX, expected_object(true), KEY];

const SCHEMA_VERSION: McpField = metadata(
    "schema_version",
    "integer",
    "Result schema version 1.",
    None,
);
const TENANT: McpField = metadata(
    "tenant_id",
    "string",
    "Launch-selected tenant identity.",
    Some(32),
);
const REPOSITORY: McpField = metadata(
    "repository_id",
    "string",
    "Launch-selected repository identity.",
    Some(32),
);
const INCARNATION: McpField = metadata(
    "repository_incarnation",
    "string",
    "Authenticated repository incarnation bound by this launch.",
    Some(32),
);
const FORMAT: McpField = metadata(
    "object_format",
    "string",
    "Launch-bound native hash domain: sha1 or sha256.",
    Some(6),
);
const REFERENCE_OUTPUT: McpField = metadata(
    "reference_hex",
    "string",
    "Exact raw selected tag name encoded as lowercase hexadecimal.",
    Some(2048),
);
const COMPLETE: McpField = metadata(
    "complete",
    "boolean",
    "True; a complete bounded result was constructed. Failures never return a truncated successful result.",
    None,
);
const SIGNATURE: McpField = metadata(
    "signature_verified",
    "boolean",
    "False; signature presence or tag-object identity does not establish cryptographic signature trust.",
    None,
);
const TAGGER: McpField = metadata(
    "tagger_is_authenticated_principal",
    "boolean",
    "False; tagger metadata is independent of the launch-bound principal.",
    None,
);

const INSPECT_OUTPUT: &[McpField] = &[
    metadata("type", "string", "source_tag.", Some(10)),
    SCHEMA_VERSION,
    TENANT,
    REPOSITORY,
    INCARNATION,
    FORMAT,
    metadata(
        "snapshot_token",
        "string",
        "Exact algorithm-qualified authority snapshot selected by the native read.",
        Some(140),
    ),
    metadata(
        "source_head",
        "string",
        "Exact native authority-head identity for this read.",
        Some(256),
    ),
    REFERENCE_OUTPUT,
    metadata(
        "object_id",
        "string",
        "Exact outer ref value in the launch hash domain.",
        Some(64),
    ),
    metadata(
        "peeled_object",
        "string",
        "Verified terminal non-tag object identity; its body is not disclosed by this result.",
        Some(64),
    ),
    metadata(
        "peeled_kind",
        "string",
        "Verified terminal native kind: commit, tree or blob.",
        Some(6),
    ),
    metadata(
        "annotation_count",
        "string",
        "Complete annotation-chain count from zero through 64 as canonical decimal.",
        Some(2),
    ),
    untrusted(metadata(
        "annotations",
        "array",
        "Outer-to-inner original annotation objects: object_id, target, target_kind, signature (absent or opaque_unverifiable), signature_verified:false, decimal body_bytes and exact body_hex. Native tag hashes and chain links are checked; authored content remains untrusted.",
        None,
    )),
    COMPLETE,
    metadata(
        "read_only",
        "boolean",
        "True; inspection creates no mutation.",
        None,
    ),
    metadata(
        "repository_changed",
        "boolean",
        "False; tag inspection does not change repository authority.",
        None,
    ),
    metadata(
        "transaction_created",
        "boolean",
        "False; no durable inspection transaction is created.",
        None,
    ),
    metadata(
        "published",
        "boolean",
        "False; inspection publishes nothing.",
        None,
    ),
    SIGNATURE,
    TAGGER,
];
const WRITE_OUTPUT: &[McpField] = &[
    metadata("type", "string", "tag_publication.", Some(15)),
    SCHEMA_VERSION,
    TENANT,
    REPOSITORY,
    INCARNATION,
    FORMAT,
    metadata(
        "principal_id",
        "string",
        "Original launch-bound principal owning the durable command; never supplied by tagger metadata.",
        Some(32),
    ),
    metadata(
        "read_only",
        "boolean",
        "False; this is a canonical publication or refusal receipt.",
        None,
    ),
    metadata(
        "tx_id",
        "string",
        "Canonical transaction identity of the original sealed tag command.",
        Some(256),
    ),
    metadata(
        "decision_sequence",
        "string",
        "Original terminal decision sequence as canonical decimal.",
        Some(20),
    ),
    metadata(
        "outcome",
        "string",
        "committed or refused, for the original transaction.",
        Some(9),
    ),
    metadata(
        "command_committed",
        "boolean",
        "Whether that original command committed.",
        None,
    ),
    metadata(
        "terminal",
        "boolean",
        "True; this receipt contains a canonical terminal fact.",
        None,
    ),
    metadata(
        "outcome_unknown",
        "boolean",
        "False on a terminal receipt. Admission or response failures retain uncertainty separately.",
        None,
    ),
    metadata(
        "repository_commit_id",
        "string|null",
        "Original committed RCR identity, or null for a canonical refusal.",
        Some(256),
    ),
    metadata(
        "refusal_record_id",
        "string|null",
        "Original canonical refusal-record identity, or null for a commit.",
        Some(256),
    ),
    metadata(
        "refusal_code",
        "string|null",
        "Canonical refusal code, or null for a commit.",
        Some(256),
    ),
    metadata(
        "operation",
        "string",
        "lightweight, annotated or delete.",
        Some(11),
    ),
    REFERENCE_OUTPUT,
    metadata(
        "expected_object",
        "string|null",
        "Original exact outer deletion lease; null denotes the absent-ref creation precondition.",
        Some(64),
    ),
    metadata(
        "new_object",
        "string|null",
        "Original proposed ref OID; null for deletion. Never a fresh current-ref observation.",
        Some(64),
    ),
    metadata(
        "force",
        "boolean",
        "False; no replacement or protection bypass is supported.",
        None,
    ),
    metadata(
        "atomic",
        "boolean",
        "True; one exact ref command has one canonical terminal decision.",
        None,
    ),
    COMPLETE,
    metadata(
        "historical_outcome",
        "boolean",
        "True; identical retries recover the original decision even after later tag deletion.",
        None,
    ),
    metadata(
        "current_refs_asserted",
        "boolean",
        "False; this receipt does not assert present ref freshness.",
        None,
    ),
    metadata(
        "ref_transaction_committed",
        "boolean",
        "Whether the original exact ref transaction committed.",
        None,
    ),
    metadata(
        "forge_transition",
        "boolean",
        "False; these tag commands do not synthesize forge metadata events.",
        None,
    ),
    SIGNATURE,
    TAGGER,
];

const READ_ERRORS: &[&str] = &[
    "tool_not_granted",
    "expected_string",
    "unknown_argument",
    "exactly_one_reference_required",
    "invalid_tag_reference",
    "invalid_hex_bytes",
    "invalid_object_id",
    "invalid_tag_limits",
    "invalid_snapshot_token",
    "tag_unavailable",
    "snapshot_moved",
    "resource_limit",
    "invalid_tag_query",
    "tag_read_cancelled",
    "tag_read_failed",
    "tag_object_moved",
    "invalid_tag_report",
    "allocation_refused",
    "tag_result_limit",
];
const WRITE_ERRORS: &[&str] = &[
    "tool_not_granted",
    "principal_not_bound",
    "required_argument_missing",
    "expected_string",
    "unknown_argument",
    "exactly_one_reference_required",
    "invalid_tag_reference",
    "invalid_hex_bytes",
    "invalid_object_id",
    "invalid_idempotency_key",
    "invalid_decimal_string",
    "invalid_target_kind",
    "invalid_tag_command",
    "invalid_tag_operation",
    "tag_mutation_outcome_unknown",
    "inconsistent_tag_outcome",
    "tag_receipt_output_limit",
];

pub(super) const INSPECT: McpToolEntry = McpToolEntry {
    name: "frankengit_tag_inspect",
    version: 1,
    entity_kind: McpEntityKind::Tool,
    owner_subsystem: "git-core",
    support_profile: SupportProfile::Active,
    description: "Inspect one visible tag and its verified bounded native annotation chain under the ordinary source-read grant. Optional pins compare the current authority head and outer ref value. Tagger and signature content grant no identity or trust; sponsored-agent profiles exclude this tool.",
    read_mutation: ReadMutationClass::ReadOnly,
    capability: CapabilityRequirement::READ_CANONICAL_OBJECT,
    principal: PrincipalRequirement::None,
    idempotency: IdempotencyRequirement::NotApplicable,
    authority_root: InputAuthorityRootRequirement::ExactSnapshotToken,
    budget: BudgetDimensions {
        max_input_bytes: 65_536,
        // The adapter enforces this complete encoded-result limit separately
        // from its 512 KiB original-object budget and the protocol's 2 MiB cap.
        max_output_bytes: 1_048_576,
        max_depth: 16,
        max_items: 1024,
        max_fan_out: 1,
        max_duration_ms: 300_000,
    },
    pagination: PaginationRules::Unpaginated,
    disclosure: DisclosureClass::UntrustedContentData,
    receipt: EvidenceReceiptClass::None,
    cancellation: CancellationBehavior::SerialGracefulDrain,
    input_fields: INSPECT_INPUT,
    output_fields: INSPECT_OUTPUT,
    refusal_codes: READ_ERRORS,
    cli_command: "fg tag show",
    rest_api_path: "POST /{repository}/api/v1/source/tags/inspect",
};

const fn write(
    name: &'static str,
    description: &'static str,
    cli: &'static str,
    path: &'static str,
    inputs: &'static [McpField],
) -> McpToolEntry {
    McpToolEntry {
        name,
        description,
        read_mutation: ReadMutationClass::Mutation,
        capability: CapabilityRequirement::PREPARE_PUBLICATION,
        principal: PrincipalRequirement::OperatorBound,
        idempotency: IdempotencyRequirement::RequiredDurableKey,
        authority_root: InputAuthorityRootRequirement::ServerSelectedHead,
        receipt: EvidenceReceiptClass::CanonicalDecisionDigest,
        cancellation: CancellationBehavior::NonPreemptiveTerminalCommit,
        input_fields: inputs,
        output_fields: WRITE_OUTPUT,
        refusal_codes: WRITE_ERRORS,
        cli_command: cli,
        rest_api_path: path,
        ..INSPECT
    }
}

pub(super) const CREATE: McpToolEntry = write(
    "frankengit_tag_create",
    "Create an absent lightweight tag at an explicit visible native object through ordinary sealed source publication. Requires source-write and the launch-bound principal; grants no reads or outcome lookup. Exact-key retries return historical decisions without replacing or recreating tags.",
    "fg tag create",
    "POST /{repository}/api/v1/source/tags/lightweight",
    CREATE_INPUT,
);
pub(super) const ANNOTATE: McpToolEntry = write(
    "frankengit_tag_annotate",
    "Create an absent annotated tag from explicit native target kind, tagger, timestamp and exact bounded message bytes. Quarantine verifies the native target and authored tag object before ordinary source-write admission. Metadata and signature-looking text grant no authority; sponsored-agent profiles exclude this tool.",
    "fg tag annotate",
    "POST /{repository}/api/v1/source/tags/annotated",
    ANNOTATE_INPUT,
);
pub(super) const DELETE: McpToolEntry = write(
    "frankengit_tag_delete",
    "Delete one tag at its exact original unpeeled expected_object under the source-write grant and launch-bound principal. No implicit latest tip, force or protection bypass. Retain the original key and lease for retries; the receipt does not assert current ref state.",
    "fg tag delete",
    "POST /{repository}/api/v1/source/tags/delete",
    DELETE_INPUT,
);
