#![forbid(unsafe_code)]
//! MCP call dispatch, discovery, and capability admission.
//!
//! An unsupported tool is discoverable in `tools/list` but returns a typed refusal
//! at invocation. It never disappears or falls through to another operation.

use super::refusal::McpRefusal;
use super::registry::{REGISTRY, find_tool_version};
use super::types::{McpToolEntry, PrincipalRequirement, SupportProfile};

/// Result of a successful capability admission and input parameter check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedCall<'a> {
    /// The resolved tool entry.
    pub tool: &'a McpToolEntry,
    /// The validated parameters.
    pub arguments: &'a str,
    /// Verified operator principal, if required.
    pub principal: Option<&'a str>,
}

/// Lists all tools in the registry for MCP `tools/list` discovery.
/// Even unsupported sentinels are discoverable so clients receive typed refusals.
#[must_use]
pub fn discover_tools() -> &'static [McpToolEntry] {
    REGISTRY
}

/// Admits or typed-refuses an incoming MCP tool call.
///
/// Steps:
/// 1. Resolution: looks up tool by name and version. If missing, returns `UnknownTool`.
/// 2. Support profile check: if `Unsupported`, immediately returns typed refusal.
/// 3. Deprecation check: if `Deprecated`, returns typed refusal with migration.
/// 4. Capability check: ensures the caller holds the exact narrow capability class.
/// 5. Principal check: ensures operator-bound principal is attached if required.
/// 6. Budget check: enforces max input byte length.
pub fn admit_call<'a>(
    name: &str,
    version: u32,
    arguments: &'a str,
    granted_capabilities: &[&str],
    principal: Option<&'a str>,
) -> Result<AdmittedCall<'a>, McpRefusal> {
    // 1. Resolution
    let tool = find_tool_version(name, version).ok_or_else(|| McpRefusal::UnknownTool {
        tool: name.to_string(),
        version: Some(version),
    })?;

    // 2. Support profile check
    match tool.support_profile {
        SupportProfile::Unsupported => {
            let refusal_code = tool
                .refusal_codes
                .first()
                .copied()
                .unwrap_or("unsupported_tool");
            return Err(McpRefusal::UnsupportedTool {
                tool: tool.name.to_string(),
                version: tool.version,
                reason: tool.description.to_string(),
                refusal_code,
            });
        }
        SupportProfile::Deprecated => {
            return Err(McpRefusal::DeprecatedTool {
                tool: tool.name.to_string(),
                version: tool.version,
                migration_target: tool.cli_command.to_string(),
            });
        }
        SupportProfile::Active | SupportProfile::Experimental => {}
    }

    // 3. Capability authorization
    let required_cap = tool.capability.as_str();
    if !granted_capabilities.contains(&required_cap) {
        return Err(McpRefusal::CapabilityDenied {
            tool: tool.name.to_string(),
            required: required_cap,
            provided: granted_capabilities.first().map(|s| s.to_string()),
        });
    }

    // 4. Principal check
    if tool.principal == PrincipalRequirement::OperatorBound && principal.is_none() {
        return Err(McpRefusal::PrincipalRequired { tool: tool.name });
    }

    // 5. Budget dimension check: max input bytes
    let input_bytes = arguments.len();
    if input_bytes > tool.budget.max_input_bytes as usize {
        return Err(McpRefusal::InputBudgetExceeded {
            max_bytes: tool.budget.max_input_bytes,
            actual_bytes: input_bytes,
        });
    }

    Ok(AdmittedCall {
        tool,
        arguments,
        principal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_tool_is_discoverable_and_returns_typed_refusal() {
        let tools = discover_tools();
        let admin_tool = tools
            .iter()
            .find(|t| t.name == "frankengit_admin_exec")
            .expect("admin_exec must be discoverable");
        assert_eq!(admin_tool.support_profile, SupportProfile::Unsupported);

        let result = admit_call(
            "frankengit_admin_exec",
            1,
            "{}",
            &["execute_sandboxed_process"],
            Some("operator"),
        );

        assert!(matches!(
            result,
            Err(McpRefusal::UnsupportedTool {
                refusal_code: "generic_admin_prohibited",
                ..
            })
        ));
    }

    #[test]
    fn missing_capability_is_refused() {
        let result = admit_call(
            "frankengit_issue_list",
            1,
            "{}",
            &["mutate_forge_entity"], // Missing read_canonical_object!
            None,
        );
        assert!(matches!(result, Err(McpRefusal::CapabilityDenied { .. })));
    }

    #[test]
    fn missing_principal_on_mutation_is_refused() {
        let result = admit_call(
            "frankengit_issue_open",
            1,
            "{}",
            &["mutate_forge_entity"],
            None, // Missing principal!
        );
        assert!(matches!(result, Err(McpRefusal::PrincipalRequired { .. })));
    }

    #[test]
    fn oversized_input_is_refused() {
        let oversized = "x".repeat(70_000);
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
    fn valid_call_is_admitted() {
        let result = admit_call(
            "frankengit_issue_list",
            1,
            "{}",
            &["read_canonical_object"],
            None,
        );
        assert!(result.is_ok());
    }
}
