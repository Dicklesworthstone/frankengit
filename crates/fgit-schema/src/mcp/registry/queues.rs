#![forbid(unsafe_code)]
//! Independent queue discovery and exact canonical management/landing contracts.
//! Capability classes describe effects; each tool also requires its own explicit
//! queue launch ceiling. Source, PR and ordinary merge grants do not imply it.
use super::super::types::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpToolEntry, PaginationRules,
    PrincipalRequirement, ReadMutationClass, SupportProfile,
};

const fn selector(
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

const POSITIVE: Option<&str> = Some("^[1-9][0-9]*$");
const DECIMAL: Option<&str> = Some("^(0|[1-9][0-9]*)$");
const NATIVE_OID: Option<&str> = Some("^(?:[0-9a-f]{40}|[0-9a-f]{64})$");
const NUMBER: McpField = selector(
    "number",
    "Positive canonical decimal queue number bounded by u64.",
    true,
    20,
    POSITIVE,
);
const VERSION: McpField = selector(
    "expected_version",
    "Exact positive queue predecessor version; landing requires two available successor versions. Never refresh this guard while retrying the original key.",
    true,
    20,
    POSITIVE,
);
const FIRST_VERSION: McpField = selector(
    "expected_version",
    "Exact queue predecessor as canonical decimal; 0 creates a queue on its first enqueue, otherwise use its current positive version.",
    true,
    20,
    DECIMAL,
);
const KEY: McpField = selector(
    "idempotency_key",
    "Original durable printable ASCII key. Retry identical operation, versions, policy and candidate coordinates after an uncertain response.",
    true,
    256,
    Some("^[!-~]+$"),
);
const INCARNATION: McpField = selector(
    "expected_incarnation",
    "Exact 32-lowercase-hex repository incarnation. Must equal both the operator launch binding and the current node configuration; cannot select another repository.",
    true,
    32,
    Some("^[0-9a-f]{32}$"),
);
const FORMAT: McpField = selector(
    "object_format",
    "Exact launch-bound native object format: sha1 or sha256.",
    true,
    6,
    Some("^(sha1|sha256)$"),
);
const TARGET: McpField = selector(
    "target_reference",
    "Literal full refs/heads/ target, at most 1024 UTF-8 bytes. Supply exactly one of target_reference and target_reference_hex.",
    false,
    1024,
    None,
);
const TARGET_HEX: McpField = selector(
    "target_reference_hex",
    "Exact full refs/heads/ target bytes encoded as lowercase hexadecimal, at most 1024 decoded bytes. Supply exactly one target-reference representation.",
    false,
    2048,
    Some("^(?:[0-9a-f]{2})+$"),
);
const SOURCE: McpField = selector(
    "source_reference",
    "Literal full refs/heads/ source, distinct from target, at most 1024 UTF-8 bytes. Supply exactly one of source_reference and source_reference_hex.",
    false,
    1024,
    None,
);
const SOURCE_HEX: McpField = selector(
    "source_reference_hex",
    "Exact full refs/heads/ source bytes encoded as lowercase hexadecimal, at most 1024 decoded bytes. Supply exactly one source-reference representation.",
    false,
    2048,
    Some("^(?:[0-9a-f]{2})+$"),
);
const PULL: McpField = selector(
    "pull_request",
    "Positive canonical decimal native pull request number bounded by u64.",
    true,
    20,
    POSITIVE,
);
const PULL_VERSION: McpField = selector(
    "expected_pull_request_version",
    "Exact positive canonical PR version, checked against the current open PR on every publication attempt; landing also requires its successor to exist.",
    true,
    20,
    POSITIVE,
);
const SOURCE_TIP: McpField = selector(
    "expected_source",
    "Exact nonzero native source commit OID in lowercase hexadecimal for the launch object format. Landing requires a different OID from expected_target.",
    true,
    64,
    NATIVE_OID,
);
const TARGET_TIP: McpField = selector(
    "expected_target",
    "Exact nonzero native target commit OID in lowercase hexadecimal for the launch object format.",
    true,
    64,
    NATIVE_OID,
);
const POLICY_EPOCH: McpField = selector(
    "expected_policy_epoch",
    "Exact positive canonical decimal policy epoch. The current protected-ref, review and required-check rules remain mandatory; the epoch is not permission to bypass them.",
    true,
    20,
    POSITIVE,
);
const HEAD: McpField = selector(
    "expected_head",
    "Exact algorithm-qualified snapshot token returned by the first read. Required on list continuation after a nonzero queue number; retained snapshots still obey current visibility.",
    false,
    140,
    None,
);

const READ_BUDGET: BudgetDimensions = BudgetDimensions {
    max_input_bytes: 65_536,
    max_output_bytes: 1_048_576,
    max_depth: 16,
    max_items: 1024,
    max_fan_out: 20,
    max_duration_ms: 300_000,
};
const WRITE_BUDGET: BudgetDimensions = BudgetDimensions {
    max_input_bytes: 65_536,
    max_output_bytes: 1_048_576,
    max_depth: 16,
    max_items: 256,
    max_fan_out: 1,
    max_duration_ms: 300_000,
};

const READ_ERRORS: &[&str] = &[
    "tool_not_granted",
    "required_argument_missing",
    "expected_string",
    "unknown_argument",
    "invalid_decimal_string",
    "positive_queue_number_required",
    "invalid_limit",
    "snapshot_required",
    "invalid_snapshot_token",
    "snapshot_unavailable",
    "queue_read_failed",
    "invalid_queue_page",
    "invalid_queue_state",
    "queue_response_limit",
];
const WRITE_ERRORS: &[&str] = &[
    "tool_not_granted",
    "principal_not_bound",
    "incarnation_not_bound",
    "required_argument_missing",
    "expected_string",
    "unknown_argument",
    "invalid_decimal_string",
    "invalid_idempotency_key",
    "invalid_repository_incarnation",
    "repository_incarnation_mismatch",
    "object_format_mismatch",
    "positive_queue_number_required",
    "positive_version_required",
    "version_exhausted",
    "positive_pull_number_required",
    "positive_pull_version_required",
    "pr_version_exhausted",
    "positive_policy_epoch_required",
    "exactly_one_branch_encoding_required",
    "branch_name_limit",
    "full_branch_required",
    "invalid_branch",
    "invalid_hex_bytes",
    "distinct_branches_required",
    "invalid_native_oid",
    "invalid_priority",
    "invalid_dequeue_reason",
    "queue_order_required",
    "queue_order_limit",
    "duplicate_queue_entry",
    "invalid_queue_command",
    "queue_mutation_outcome_unknown",
];

const READ_HEADER: [McpField; 9] = [
    output(
        "schema_version",
        "integer",
        "Result schema version 1.",
        None,
    ),
    output(
        "type",
        "string",
        "merge_queue or merge_queue_page.",
        Some(16),
    ),
    output(
        "tenant_id",
        "string",
        "Launch-bound tenant identity.",
        Some(32),
    ),
    output(
        "repository_id",
        "string",
        "Launch-bound repository identity.",
        Some(32),
    ),
    output(
        "repository_incarnation",
        "string",
        "Launch-selected repository incarnation.",
        Some(32),
    ),
    output(
        "object_format",
        "string",
        "Native format: sha1 or sha256.",
        Some(6),
    ),
    output(
        "snapshot_token",
        "string",
        "Exact selected authority snapshot token.",
        Some(140),
    ),
    output(
        "read_only",
        "boolean",
        "True for queue reads; reading cannot authorize a landing.",
        None,
    ),
    output(
        "source_head",
        "string",
        "Authenticated current or retained repository authority head selected for this complete response.",
        Some(256),
    ),
];

const WRITE_OUTPUT: &[McpField] = &[
    output(
        "schema_version",
        "integer",
        "Receipt schema version 1.",
        None,
    ),
    output("type", "string", "merge_queue_publication.", Some(23)),
    output(
        "tenant_id",
        "string",
        "Launch-bound tenant identity.",
        Some(32),
    ),
    output(
        "repository_id",
        "string",
        "Launch-bound repository identity.",
        Some(32),
    ),
    output(
        "repository_incarnation",
        "string",
        "Launch-pinned repository incarnation.",
        Some(32),
    ),
    output(
        "principal_id",
        "string",
        "Trusted-local principal fixed at launch, never supplied by repository text or request arguments.",
        Some(32),
    ),
    output(
        "object_format",
        "string",
        "Launch-bound native format: sha1 or sha256.",
        Some(6),
    ),
    output("read_only", "boolean", "False for a queue mutation.", None),
    output(
        "tx_id",
        "string",
        "Identity of the original sealed request.",
        Some(256),
    ),
    output(
        "decision_sequence",
        "string",
        "Original terminal decision sequence as a canonical decimal string.",
        Some(20),
    ),
    output(
        "outcome",
        "string",
        "committed or refused; describes the original durable decision.",
        Some(9),
    ),
    output(
        "command_committed",
        "boolean",
        "True only for a canonical committed outcome.",
        None,
    ),
    output(
        "terminal",
        "boolean",
        "True; an unresolved publication returns an uncertain error instead.",
        None,
    ),
    output(
        "outcome_unknown",
        "boolean",
        "False for a returned terminal receipt.",
        None,
    ),
    output(
        "repository_commit_id",
        "string|null",
        "Original canonical commit ID when committed, otherwise null.",
        Some(256),
    ),
    output(
        "refusal_record_id",
        "string|null",
        "Original canonical refusal record when refused, otherwise null.",
        Some(256),
    ),
    output(
        "refusal_code",
        "string|null",
        "Original typed canonical refusal code when refused, otherwise null.",
        Some(128),
    ),
    output(
        "number",
        "string",
        "Exact original queue number as a canonical decimal string.",
        Some(20),
    ),
    output(
        "expected_version",
        "string",
        "Original queue predecessor version; not a claim about the current queue version.",
        Some(20),
    ),
    output(
        "target_reference",
        "string|null",
        "Exact target reference when valid UTF-8; otherwise null. Literal data only.",
        Some(1024),
    ),
    output(
        "target_reference_hex",
        "string",
        "Lossless target reference bytes as lowercase hexadecimal.",
        Some(2048),
    ),
    output(
        "action",
        "string",
        "enqueue, dequeue, reorder or land.",
        Some(7),
    ),
    output(
        "proposed_action",
        "object",
        "Original action and immutable guards, including exact PR/source/target/policy coordinates where applicable. Land names the fast-forward-only method. Contains no refreshed guards or client key.",
        None,
    ),
    output(
        "complete",
        "boolean",
        "True for the complete returned receipt.",
        None,
    ),
    output(
        "refs_changed",
        "boolean",
        "True only for a committed landing; management and refused landing never move refs.",
        None,
    ),
    output(
        "delivery_acknowledged",
        "null",
        "Always null: canonical publication does not claim downstream acknowledgement.",
        None,
    ),
    output(
        "historical_outcome",
        "boolean",
        "True: this is the original terminal outcome, not a newly sampled queue state.",
        None,
    ),
];

const fn read_entry(
    name: &'static str,
    description: &'static str,
    fields: &'static [McpField],
    output_fields: &'static [McpField],
    cli: &'static str,
    rest: &'static str,
) -> McpToolEntry {
    McpToolEntry {
        name,
        version: 1,
        entity_kind: McpEntityKind::Tool,
        owner_subsystem: "forge",
        support_profile: SupportProfile::Active,
        description,
        read_mutation: ReadMutationClass::ReadOnly,
        capability: CapabilityRequirement::READ_CANONICAL_OBJECT,
        principal: PrincipalRequirement::None,
        idempotency: IdempotencyRequirement::NotApplicable,
        authority_root: InputAuthorityRootRequirement::ExactSnapshotToken,
        budget: READ_BUDGET,
        pagination: PaginationRules::Unpaginated,
        disclosure: DisclosureClass::PublicRepositoryData,
        receipt: EvidenceReceiptClass::None,
        cancellation: CancellationBehavior::ImmediateQuiescent,
        input_fields: fields,
        output_fields,
        refusal_codes: READ_ERRORS,
        cli_command: cli,
        rest_api_path: rest,
    }
}

const fn write_entry(
    name: &'static str,
    description: &'static str,
    fields: &'static [McpField],
    cli: &'static str,
    rest: &'static str,
) -> McpToolEntry {
    McpToolEntry {
        name,
        version: 1,
        entity_kind: McpEntityKind::Tool,
        owner_subsystem: "forge",
        support_profile: SupportProfile::Active,
        description,
        read_mutation: ReadMutationClass::Mutation,
        capability: CapabilityRequirement::MUTATE_FORGE_ENTITY,
        principal: PrincipalRequirement::OperatorBound,
        idempotency: IdempotencyRequirement::RequiredDurableKey,
        authority_root: InputAuthorityRootRequirement::ExactPredecessorVersion,
        budget: WRITE_BUDGET,
        pagination: PaginationRules::Unpaginated,
        disclosure: DisclosureClass::PublicRepositoryData,
        receipt: EvidenceReceiptClass::CanonicalDecisionDigest,
        cancellation: CancellationBehavior::NonPreemptiveTerminalCommit,
        input_fields: fields,
        output_fields: WRITE_OUTPUT,
        refusal_codes: WRITE_ERRORS,
        cli_command: cli,
        rest_api_path: rest,
    }
}

pub(super) const LIST: McpToolEntry = McpToolEntry {
    pagination: PaginationRules::SnapshotBoundCursor,
    ..read_entry(
        "frankengit_queue_list",
        "Read complete visible queues in numeric order from one authenticated snapshot. Requires the independent --allow-queues launch grant; source/PR grants and queue writes or landings do not imply it. Page limit 1..20 defaults to 5; continuation pins expected_head. Hidden target or queued source hides the whole queue. A page above 1 MiB refuses instead of returning partial queues.",
        &[
            selector(
                "after",
                "Canonical decimal queue cursor, default 0; a nonzero cursor requires expected_head.",
                false,
                20,
                DECIMAL,
            ),
            McpField {
                field_type: "integer",
                max_bytes: None,
                ..selector(
                    "limit",
                    "Number of queues, 1..20, default 5.",
                    false,
                    0,
                    None,
                )
            },
            HEAD,
        ],
        &[
            READ_HEADER[0],
            READ_HEADER[1],
            READ_HEADER[2],
            READ_HEADER[3],
            READ_HEADER[4],
            READ_HEADER[5],
            READ_HEADER[6],
            READ_HEADER[7],
            READ_HEADER[8],
            output(
                "after",
                "string",
                "Requested canonical decimal queue cursor.",
                Some(20),
            ),
            output("limit", "integer", "Requested page limit, 1..20.", None),
            output(
                "next_after",
                "string|null",
                "Last returned queue number when another visible queue remains, otherwise null.",
                Some(20),
            ),
            output(
                "queues",
                "array",
                "Complete visible queue snapshots: decimal-string number/version, exact target references, ordered entries with PR/source/tip/actor/priority/enqueued version, explicit order, and active_batch. Each queue holds at most 1024 entries.",
                None,
            ),
            output(
                "complete",
                "boolean",
                "True only when next_after is null; every individual returned queue is complete.",
                None,
            ),
        ],
        "fg queue list",
        "GET /{repository}/api/v1/queues",
    )
};

pub(super) const SHOW: McpToolEntry = read_entry(
    "frankengit_queue_show",
    "Read one complete canonical queue at the current or an exact retained snapshot. Requires the independent --allow-queues launch grant. Hidden and absent queues return found=false without disclosing entries. Current visibility also applies to retained snapshots. A read provides no merge permission.",
    &[NUMBER, HEAD],
    &[
        READ_HEADER[0],
        READ_HEADER[1],
        READ_HEADER[2],
        READ_HEADER[3],
        READ_HEADER[4],
        READ_HEADER[5],
        READ_HEADER[6],
        READ_HEADER[7],
        READ_HEADER[8],
        output(
            "number",
            "string",
            "Requested positive canonical decimal queue number.",
            Some(20),
        ),
        output(
            "found",
            "boolean",
            "True only for a visible selected queue.",
            None,
        ),
        output(
            "version",
            "string",
            "Canonical decimal queue version; 0 when absent or hidden.",
            Some(20),
        ),
        output(
            "queue",
            "object|null",
            "Complete queue snapshot including exact target, ordered PR/source/tip entries, priorities, enqueued actors/versions, explicit order and active_batch; null when absent or hidden.",
            None,
        ),
        output(
            "complete",
            "boolean",
            "True; partial queue snapshots are never returned.",
            None,
        ),
    ],
    "fg queue show",
    "GET /{repository}/api/v1/queues/{number}",
);

pub(super) const ENQUEUE: McpToolEntry = write_entry(
    "frankengit_queue_enqueue",
    "Enqueue or replace one exact open PR under the queue predecessor, PR version and live source/target tips. Requires independent --allow-queue-writes plus the trusted-local launch principal and incarnation; this grants neither reads nor landing. Higher priority enters first and equal priority enters FIFO. Publishes queue metadata only and never satisfies reviews or checks.",
    &[
        NUMBER,
        FIRST_VERSION,
        KEY,
        INCARNATION,
        FORMAT,
        TARGET,
        TARGET_HEX,
        PULL,
        PULL_VERSION,
        SOURCE,
        SOURCE_HEX,
        SOURCE_TIP,
        TARGET_TIP,
        selector(
            "priority",
            "Canonical decimal u32 priority, default 0; larger values enter first.",
            false,
            10,
            DECIMAL,
        ),
    ],
    "fg queue enqueue",
    "POST /{repository}/api/v1/queues/{number}/enqueue",
);

pub(super) const DEQUEUE: McpToolEntry = write_entry(
    "frankengit_queue_dequeue",
    "Remove one queued PR with an explicit reason and exact queue predecessor. Requires independent --allow-queue-writes plus the trusted-local launch principal and incarnation; it grants neither reads nor landing. Publishes queue metadata without moving Git refs or changing PR lifecycle.",
    &[
        NUMBER,
        VERSION,
        KEY,
        INCARNATION,
        FORMAT,
        TARGET,
        TARGET_HEX,
        PULL,
        selector(
            "reason",
            "Explicit removal reason: withdrawn, conflict, check-failed, base-moved, evicted or admin-override. The reason does not grant authority.",
            true,
            14,
            Some("^(withdrawn|conflict|check-failed|base-moved|evicted|admin-override)$"),
        ),
    ],
    "fg queue dequeue",
    "POST /{repository}/api/v1/queues/{number}/dequeue",
);

pub(super) const REORDER: McpToolEntry = write_entry(
    "frankengit_queue_reorder",
    "Replace the execution order with an explicit complete permutation under the exact queue predecessor. Requires independent --allow-queue-writes plus the trusted-local launch principal and incarnation. This MCP profile accepts 1..256 distinct PR numbers; use CLI or HTTP for larger queues. Unknown, duplicate or omitted entries refuse. Reordering grants no landing permission.",
    &[
        NUMBER,
        VERSION,
        KEY,
        INCARNATION,
        FORMAT,
        TARGET,
        TARGET_HEX,
        McpField {
            name: "order",
            field_type: "array",
            classification: FieldClassification::SelectorPosition,
            description: "Complete desired permutation: 1..256 distinct positive canonical decimal PR strings. Order is preserved exactly; partial permutations refuse.",
            required: true,
            max_bytes: None,
            pattern: None,
        },
    ],
    "fg queue reorder",
    "POST /{repository}/api/v1/queues/{number}/reorder",
);

pub(super) const LAND: McpToolEntry = McpToolEntry {
    capability: CapabilityRequirement::PREPARE_PUBLICATION,
    ..write_entry(
        "frankengit_queue_land",
        "Land exactly the current queue-head PR using native FastForwardOnly admission. Requires independent --allow-queue-landings plus the trusted-local launch principal and incarnation; queue management, source and ordinary merge grants do not imply it. Exact queue/PR/policy versions and both live branch tips remain immutable guards. Existing ancestry, review, required-check and protected-ref rules apply on every attempt. One decision atomically moves the target, merges the PR and advances the queue twice; no checks run or merge objects are synthesized. The MCP adapter remains trusted-local. The authenticated HTTP counterpart independently requires --allow-queue-landings, queues-land, and a target-permitting reference-write ceiling; remote requests cannot assert an actor.",
        &[
            NUMBER,
            VERSION,
            KEY,
            INCARNATION,
            FORMAT,
            TARGET,
            TARGET_HEX,
            PULL,
            PULL_VERSION,
            SOURCE,
            SOURCE_HEX,
            SOURCE_TIP,
            TARGET_TIP,
            POLICY_EPOCH,
        ],
        "fg queue land",
        "POST /{repository}/api/v1/queues/{number}/land",
    )
};
