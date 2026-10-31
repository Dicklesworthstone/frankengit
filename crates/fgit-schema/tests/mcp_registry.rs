#![forbid(unsafe_code)]
//! Comprehensive test suite for the MCP surface registry and capability contracts (FG-096a).

use fgit_schema::mcp::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpRefusal, McpToolEntry,
    McpValidationError, PaginationRules, PrincipalRequirement, REGISTRY, ReadMutationClass,
    SupportProfile, admit_call, discover_tools, find_tool, validate_registry,
    validate_server_parity, validate_tool_entry,
};

const fn valid_prototype() -> McpToolEntry {
    McpToolEntry {
        name: "frankengit_prototype_tool",
        version: 1,
        entity_kind: McpEntityKind::Tool,
        owner_subsystem: "forge",
        support_profile: SupportProfile::Active,
        description: "Valid prototype tool for testing.",
        read_mutation: ReadMutationClass::ReadOnly,
        capability: CapabilityRequirement::READ_CANONICAL_OBJECT,
        principal: PrincipalRequirement::None,
        idempotency: IdempotencyRequirement::NotApplicable,
        authority_root: InputAuthorityRootRequirement::None,
        budget: BudgetDimensions::READ_STANDARD,
        pagination: PaginationRules::Unpaginated,
        disclosure: DisclosureClass::PublicRepositoryData,
        receipt: EvidenceReceiptClass::None,
        cancellation: CancellationBehavior::ImmediateQuiescent,
        input_fields: &[McpField {
            name: "id",
            field_type: "string",
            classification: FieldClassification::SelectorPosition,
            description: "Target identifier.",
            required: true,
            max_bytes: Some(64),
            pattern: None,
        }],
        output_fields: &[McpField {
            name: "status",
            field_type: "string",
            classification: FieldClassification::SystemMetadata,
            description: "Operation status.",
            required: true,
            max_bytes: Some(32),
            pattern: None,
        }],
        refusal_codes: &["id_not_found", "invalid_id"],
        cli_command: "fg prototype show",
        rest_api_path: "GET /prototype/{id}",
    }
}

#[test]
fn protection_registry_describes_optional_queue_requirement_without_new_authority() {
    let tool = find_tool("frankengit_protection_set").unwrap();
    let branches = tool
        .input_fields
        .iter()
        .find(|field| field.name == "branches")
        .unwrap();
    assert!(
        branches
            .description
            .contains("boolean require_merge_queue (default false)")
    );
    assert!(branches.description.contains("queue-only"));
    assert!(
        branches
            .description
            .contains("ordinary merges and direct writes do not qualify")
    );
    assert_eq!(tool.principal, PrincipalRequirement::OperatorBound);
    assert_eq!(tool.capability, CapabilityRequirement::MUTATE_FORGE_ENTITY);
    assert_eq!(tool.idempotency, IdempotencyRequirement::RequiredDurableKey);
}

#[test]
fn test_registry_is_valid_and_sorted() {
    assert!(validate_registry(REGISTRY).is_ok());
    assert_eq!(REGISTRY.len(), 59);
    assert!(find_tool("frankengit_pull_append_comment").is_some());

    // Verify strict alphabetical ASCII sort order
    for pair in REGISTRY.windows(2) {
        assert!(
            (pair[0].name, pair[0].version) < (pair[1].name, pair[1].version),
            "Sort order violation: '{}' must precede '{}'",
            pair[0].name,
            pair[1].name
        );
    }
}

#[test]
fn test_planted_generic_admin_pass_through() {
    let mut planted = valid_prototype();
    planted.name = "frankengit_admin_exec_probe";
    assert_eq!(
        validate_tool_entry(&planted),
        Err(McpValidationError::GenericAdminPassThrough {
            tool: "frankengit_admin_exec_probe",
            matched_pattern: "admin_exec",
        })
    );

    let mut planted2 = valid_prototype();
    planted2.description = "Executes arbitrary_command in the worker";
    assert_eq!(
        validate_tool_entry(&planted2),
        Err(McpValidationError::GenericAdminPassThrough {
            tool: "frankengit_prototype_tool",
            matched_pattern: "arbitrary_command",
        })
    );
}

#[test]
fn test_planted_overbroad_capability() {
    let mut planted = valid_prototype();
    planted.capability = CapabilityRequirement("*");
    assert_eq!(
        validate_tool_entry(&planted),
        Err(McpValidationError::OverbroadCapability {
            tool: "frankengit_prototype_tool",
            capability: "*",
        })
    );

    let mut planted2 = valid_prototype();
    planted2.capability = CapabilityRequirement("repo_write");
    assert_eq!(
        validate_tool_entry(&planted2),
        Err(McpValidationError::OverbroadCapability {
            tool: "frankengit_prototype_tool",
            capability: "repo_write",
        })
    );
}

#[test]
fn test_planted_missing_budget_dimensions() {
    let mut planted = valid_prototype();
    planted.budget.max_input_bytes = 0;
    assert_eq!(
        validate_tool_entry(&planted),
        Err(McpValidationError::MissingBudgetDimension {
            tool: "frankengit_prototype_tool",
            dimension: "max_input_bytes",
        })
    );

    let mut planted2 = valid_prototype();
    planted2.budget.max_output_bytes = 10_000_000; // Exceeds 1 MiB
    assert_eq!(
        validate_tool_entry(&planted2),
        Err(McpValidationError::BudgetCeilingExceeded {
            tool: "frankengit_prototype_tool",
            dimension: "max_output_bytes",
            actual: 10_000_000,
            ceiling: 1_048_576,
        })
    );
}

#[test]
fn test_planted_missing_authority_position() {
    // 1. Paginated read without snapshot pin
    let mut planted_read = valid_prototype();
    planted_read.pagination = PaginationRules::SnapshotBoundCursor;
    planted_read.authority_root = InputAuthorityRootRequirement::None;
    assert_eq!(
        validate_tool_entry(&planted_read),
        Err(McpValidationError::MissingAuthorityPosition {
            tool: "frankengit_prototype_tool",
            requirement: "paginated reads must specify an authority root requirement",
        })
    );

    // 2. Mutation without idempotency key
    let mut planted_mutation = valid_prototype();
    planted_mutation.read_mutation = ReadMutationClass::Mutation;
    planted_mutation.idempotency = IdempotencyRequirement::NotApplicable;
    planted_mutation.authority_root = InputAuthorityRootRequirement::ExactPredecessorVersion;
    assert_eq!(
        validate_tool_entry(&planted_mutation),
        Err(McpValidationError::MissingAuthorityPosition {
            tool: "frankengit_prototype_tool",
            requirement: "mutations must require an idempotency key",
        })
    );

    // 3. Mutation without predecessor authority root
    let mut planted_mutation2 = valid_prototype();
    planted_mutation2.read_mutation = ReadMutationClass::Mutation;
    planted_mutation2.idempotency = IdempotencyRequirement::RequiredDurableKey;
    planted_mutation2.authority_root = InputAuthorityRootRequirement::None;
    assert_eq!(
        validate_tool_entry(&planted_mutation2),
        Err(McpValidationError::MissingAuthorityPosition {
            tool: "frankengit_prototype_tool",
            requirement: "mutations must require an exact predecessor authority root",
        })
    );
}

#[test]
fn test_planted_prose_only_errors() {
    let mut planted = valid_prototype();
    planted.refusal_codes = &["An unexpected internal error occurred"];
    assert_eq!(
        validate_tool_entry(&planted),
        Err(McpValidationError::ProseOnlyError {
            tool: "frankengit_prototype_tool",
            code: "An unexpected internal error occurred",
        })
    );

    let mut planted2 = valid_prototype();
    planted2.refusal_codes = &[];
    assert_eq!(
        validate_tool_entry(&planted2),
        Err(McpValidationError::EmptyRefusalCodes {
            tool: "frankengit_prototype_tool",
        })
    );
}

#[test]
fn test_planted_content_field_misclassification() {
    let mut planted = valid_prototype();
    planted.input_fields = &[McpField {
        name: "body",
        field_type: "string",
        classification: FieldClassification::SystemMetadata, // Must be UntrustedContent!
        description: "Body text",
        required: true,
        max_bytes: Some(1024),
        pattern: None,
    }];
    assert_eq!(
        validate_tool_entry(&planted),
        Err(McpValidationError::ContentFieldMisclassified {
            tool: "frankengit_prototype_tool",
            field: "body",
        })
    );
}

#[test]
fn test_every_tool_mapped_exactly_once_to_owner_and_public_operation() {
    let mut cli_commands = std::collections::BTreeSet::new();
    let mut rest_paths = std::collections::BTreeSet::new();

    for tool in REGISTRY {
        if tool.support_profile == SupportProfile::Active {
            assert!(
                !tool.owner_subsystem.is_empty(),
                "Tool {} must have non-empty owner",
                tool.name
            );
            assert!(
                !tool.cli_command.is_empty(),
                "Tool {} must have non-empty CLI command",
                tool.name
            );
            assert!(
                !tool.rest_api_path.is_empty(),
                "Tool {} must have non-empty REST API path",
                tool.name
            );

            assert!(
                cli_commands.insert(tool.cli_command),
                "Duplicate CLI command mapping: {}",
                tool.cli_command
            );
            assert!(
                rest_paths.insert(tool.rest_api_path),
                "Duplicate REST API path mapping: {}",
                tool.rest_api_path
            );
        }
    }
}

#[test]
fn test_unsupported_tools_discoverable_and_typed_refusal() {
    let tools = discover_tools();
    let unsupported_tools: Vec<_> = tools
        .iter()
        .filter(|t| t.support_profile == SupportProfile::Unsupported)
        .collect();

    assert_eq!(unsupported_tools.len(), 4);

    let names: Vec<_> = unsupported_tools.iter().map(|t| t.name).collect();
    assert!(names.contains(&"frankengit_admin_exec"));
    assert!(names.contains(&"frankengit_ambient_fs_read"));
    assert!(names.contains(&"frankengit_hidden_repair"));
    assert!(names.contains(&"frankengit_raw_sql_query"));

    // Verify typed refusal on admission
    for tool in unsupported_tools {
        let result = admit_call(
            tool.name,
            tool.version,
            "{}",
            &[tool.capability.as_str()],
            Some("operator"),
        );
        match result {
            Err(McpRefusal::UnsupportedTool {
                tool: refused_name,
                version,
                refusal_code,
                ..
            }) => {
                assert_eq!(refused_name, tool.name);
                assert_eq!(version, tool.version);
                assert_eq!(refusal_code, *tool.refusal_codes.first().unwrap());
            }
            other => panic!(
                "Expected typed refusal for unsupported tool {}, got {:?}",
                tool.name, other
            ),
        }
    }
}

#[test]
fn test_capability_lattice_and_attenuation() {
    // Calling a read tool with only mutation capability granted must be refused
    let result = admit_call(
        "frankengit_issue_list",
        1,
        "{}",
        &["mutate_forge_entity"],
        None,
    );
    assert_eq!(
        result,
        Err(McpRefusal::CapabilityDenied {
            tool: "frankengit_issue_list".into(),
            required: "read_canonical_object",
            provided: Some("mutate_forge_entity".into()),
        })
    );

    // Calling a read tool with the exact required capability succeeds
    let result2 = admit_call(
        "frankengit_issue_list",
        1,
        "{}",
        &["read_canonical_object"],
        None,
    );
    assert!(result2.is_ok());
}

#[test]
fn test_hostile_input_handling_and_bounds() {
    let tool = find_tool("frankengit_issue_list").expect("issue_list must exist");

    // Input exceeding max_input_bytes
    let oversized = "a".repeat(tool.budget.max_input_bytes as usize + 1);
    let result = admit_call(
        "frankengit_issue_list",
        1,
        &oversized,
        &["read_canonical_object"],
        None,
    );
    assert!(matches!(
        result,
        Err(McpRefusal::InputBudgetExceeded { .. })
    ));
}

#[test]
fn test_generated_artifacts_byte_stability() {
    let artifacts = fgit_schema::emit::artifacts();
    assert_eq!(artifacts.len(), 7);

    let mcp_schema = artifacts
        .iter()
        .find(|a| a.name == "mcp-surface.schema.json")
        .unwrap();
    assert!(
        mcp_schema
            .contents
            .contains("FrankenGit Model Context Protocol (MCP) surface schema")
    );

    let mcp_tools = artifacts
        .iter()
        .find(|a| a.name == "mcp_tools.json")
        .unwrap();
    assert!(mcp_tools.contents.contains("\"total_count\": 59"));
    assert!(mcp_tools.contents.contains("\"active_count\": 55"));
    assert!(
        mcp_tools
            .contents
            .contains("frankengit_pull_append_comment")
    );
    assert!(mcp_tools.contents.contains("\"unsupported_count\": 4"));

    let mcp_parity = artifacts
        .iter()
        .find(|a| a.name == "mcp_parity_manifest.json")
        .unwrap();
    assert!(mcp_parity.contents.contains("\"total_tools\": 59"));
}

#[test]
fn test_server_parity_and_planted_drift() {
    let active_names: Vec<&'static str> = REGISTRY
        .iter()
        .filter(|entry| entry.support_profile == SupportProfile::Active)
        .map(|entry| entry.name)
        .collect();
    assert_eq!(active_names.len(), 55);
    assert!(active_names.contains(&"frankengit_pull_append_comment"));

    // 1. Consistent twin passes.
    assert_eq!(validate_server_parity(&active_names, REGISTRY), Ok(()));

    // 2. Planted server tool missing from registry fails.
    let mut with_extra_server_tool = active_names.clone();
    with_extra_server_tool.push("frankengit_unregistered_server_tool");
    assert_eq!(
        validate_server_parity(&with_extra_server_tool, REGISTRY),
        Err(McpValidationError::ServerToolMissingFromRegistry {
            tool: "frankengit_unregistered_server_tool",
        })
    );

    // 3. Planted active registry tool missing from server fails.
    let missing_one_server_tool: Vec<&'static str> = active_names
        .iter()
        .copied()
        .filter(|&name| name != "frankengit_events")
        .collect();
    assert_eq!(
        validate_server_parity(&missing_one_server_tool, REGISTRY),
        Err(McpValidationError::RegistryToolMissingFromServer {
            tool: "frankengit_events",
        })
    );
}

#[test]
fn queue_registry_separates_read_management_and_landing_authority() {
    let queue_tools: Vec<_> = REGISTRY
        .iter()
        .filter(|tool| tool.name.starts_with("frankengit_queue_"))
        .collect();
    assert_eq!(queue_tools.len(), 6);
    for tool in queue_tools {
        assert_eq!(tool.support_profile, SupportProfile::Active);
        assert_eq!(tool.owner_subsystem, "forge");
        assert_eq!(tool.budget.max_input_bytes, 65_536);
        assert_eq!(tool.budget.max_output_bytes, 1_048_576);
        assert!(!tool.input_fields.iter().any(|field| matches!(
            field.name,
            "principal" | "principal_id" | "tenant_id" | "repository_id" | "storage_root"
        )));
        match tool.name {
            "frankengit_queue_list" | "frankengit_queue_show" => {
                assert_eq!(tool.read_mutation, ReadMutationClass::ReadOnly);
                assert_eq!(
                    tool.capability,
                    CapabilityRequirement::READ_CANONICAL_OBJECT
                );
                assert_eq!(tool.principal, PrincipalRequirement::None);
                assert_eq!(tool.idempotency, IdempotencyRequirement::NotApplicable);
                assert!(tool.description.contains("--allow-queues"));
                assert!(admit_call(tool.name, 1, "{}", &["read_canonical_object"], None).is_ok());
            }
            _ => {
                assert_eq!(tool.read_mutation, ReadMutationClass::Mutation);
                assert_eq!(tool.principal, PrincipalRequirement::OperatorBound);
                assert_eq!(tool.idempotency, IdempotencyRequirement::RequiredDurableKey);
                assert_eq!(
                    tool.authority_root,
                    InputAuthorityRootRequirement::ExactPredecessorVersion
                );
                for field in [
                    "number",
                    "expected_version",
                    "idempotency_key",
                    "expected_incarnation",
                    "object_format",
                ] {
                    assert!(
                        tool.input_fields
                            .iter()
                            .any(|entry| entry.name == field && entry.required)
                    );
                }
                let is_landing = tool.name == "frankengit_queue_land";
                let capability = if is_landing {
                    "prepare_publication"
                } else {
                    "mutate_forge_entity"
                };
                let opposite = if is_landing {
                    "mutate_forge_entity"
                } else {
                    "prepare_publication"
                };
                assert_eq!(tool.capability.as_str(), capability);
                assert!(tool.description.contains(if is_landing {
                    "--allow-queue-landings"
                } else {
                    "--allow-queue-writes"
                }));
                assert!(matches!(
                    admit_call(tool.name, 1, "{}", &[opposite], Some("operator")),
                    Err(McpRefusal::CapabilityDenied { .. })
                ));
                assert!(matches!(
                    admit_call(tool.name, 1, "{}", &[capability], None),
                    Err(McpRefusal::PrincipalRequired { .. })
                ));
            }
        }
    }
}

#[test]
fn queue_schemas_preserve_exact_versions_reference_aliases_and_complete_bounded_reorder() {
    let enqueue = find_tool("frankengit_queue_enqueue").unwrap();
    let landing = find_tool("frankengit_queue_land").unwrap();
    for tool in [enqueue, landing] {
        for name in [
            "pull_request",
            "expected_pull_request_version",
            "expected_source",
            "expected_target",
        ] {
            assert!(
                tool.input_fields
                    .iter()
                    .any(|field| field.name == name && field.required)
            );
        }
        for name in [
            "source_reference",
            "source_reference_hex",
            "target_reference",
            "target_reference_hex",
        ] {
            let field = tool
                .input_fields
                .iter()
                .find(|field| field.name == name)
                .unwrap();
            assert!(
                !field.required,
                "reference representations are an exclusive pair"
            );
            assert_eq!(field.classification, FieldClassification::SelectorPosition);
        }
    }
    assert!(
        landing
            .input_fields
            .iter()
            .any(|field| field.name == "expected_policy_epoch" && field.required)
    );
    assert!(
        !enqueue
            .input_fields
            .iter()
            .any(|field| field.name == "expected_policy_epoch")
    );
    assert_eq!(
        enqueue
            .input_fields
            .iter()
            .find(|field| field.name == "expected_version")
            .unwrap()
            .pattern,
        Some("^(0|[1-9][0-9]*)$")
    );
    assert_eq!(
        landing
            .input_fields
            .iter()
            .find(|field| field.name == "expected_version")
            .unwrap()
            .pattern,
        Some("^[1-9][0-9]*$")
    );
    let reorder = find_tool("frankengit_queue_reorder").unwrap();
    let order = reorder
        .input_fields
        .iter()
        .find(|field| field.name == "order")
        .unwrap();
    assert_eq!(order.field_type, "array");
    assert!(order.required);
    assert!(order.description.contains("1..256"));
    assert!(order.description.contains("Complete desired permutation"));
    assert_eq!(reorder.budget.max_items, 256);
    assert_eq!(
        find_tool("frankengit_queue_list").unwrap().pagination,
        PaginationRules::SnapshotBoundCursor
    );
}

#[test]
fn queue_landing_catalog_names_the_authenticated_http_counterpart_without_changing_mcp_authority() {
    let landing = find_tool("frankengit_queue_land").unwrap();
    assert_eq!(landing.cli_command, "fg queue land");
    assert_eq!(
        landing.rest_api_path,
        "POST /{repository}/api/v1/queues/{number}/land"
    );
    assert_eq!(landing.principal, PrincipalRequirement::OperatorBound);
    assert_eq!(
        landing.capability,
        CapabilityRequirement::PREPARE_PUBLICATION
    );
    assert_eq!(
        landing.idempotency,
        IdempotencyRequirement::RequiredDurableKey
    );
    assert!(
        landing
            .description
            .contains("MCP adapter remains trusted-local")
    );
    assert!(
        landing
            .description
            .contains("--allow-queue-landings, queues-land")
    );
    assert!(
        landing
            .description
            .contains("target-permitting reference-write ceiling")
    );
    assert!(
        landing
            .description
            .contains("remote requests cannot assert an actor")
    );
    let manifest = fgit_schema::emit::mcp_parity_manifest();
    assert!(
        manifest.contains("\"rest_api_path\": \"POST /{repository}/api/v1/queues/{number}/land\"")
    );
    assert!(!manifest.contains("local-only: fg queue land"));
}
