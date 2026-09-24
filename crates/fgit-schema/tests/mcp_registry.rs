#![forbid(unsafe_code)]
//! Comprehensive test suite for the MCP surface registry and capability contracts (FG-096a).

use fgit_schema::mcp::{
    BudgetDimensions, CancellationBehavior, CapabilityRequirement, DisclosureClass,
    EvidenceReceiptClass, FieldClassification, IdempotencyRequirement,
    InputAuthorityRootRequirement, McpEntityKind, McpField, McpRefusal, McpToolEntry,
    McpValidationError, PaginationRules, PrincipalRequirement, REGISTRY, ReadMutationClass,
    SupportProfile, admit_call, discover_tools, find_tool, validate_registry, validate_tool_entry,
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
fn test_registry_is_valid_and_sorted() {
    assert!(validate_registry(REGISTRY).is_ok());
    assert_eq!(REGISTRY.len(), 28);

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
    assert!(mcp_tools.contents.contains("\"total_count\": 28"));
    assert!(mcp_tools.contents.contains("\"active_count\": 24"));
    assert!(mcp_tools.contents.contains("\"unsupported_count\": 4"));

    let mcp_parity = artifacts
        .iter()
        .find(|a| a.name == "mcp_parity_manifest.json")
        .unwrap();
    assert!(mcp_parity.contents.contains("\"total_tools\": 28"));
}
