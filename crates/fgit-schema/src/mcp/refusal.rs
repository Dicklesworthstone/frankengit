#![forbid(unsafe_code)]
//! Typed MCP refusals and machine error contracts.
//!
//! An unsupported or denied operation returns a typed refusal with an exact
//! machine-readable refusal code and parameter spans. It never silently fails,
//! panics, or falls through to an alternative operation.

use core::fmt::{self, Write as _};

/// Typed refusal returned when an MCP call cannot be dispatched or admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpRefusal {
    /// The requested tool or version is recognized in the registry but unsupported.
    /// Discoverable by design, never disappearing or falling through.
    UnsupportedTool {
        tool: String,
        version: u32,
        reason: String,
        refusal_code: &'static str,
    },
    /// The requested tool is deprecated and has a recommended migration target.
    DeprecatedTool {
        tool: String,
        version: u32,
        migration_target: String,
    },
    /// Caller lacks the narrow capability required for the tool.
    CapabilityDenied {
        tool: String,
        required: &'static str,
        provided: Option<String>,
    },
    /// Operation requires an explicit operator-bound principal at launch.
    PrincipalRequired { tool: &'static str },
    /// Mutation requires a durable idempotency key.
    IdempotencyKeyRequired { tool: &'static str },
    /// Paginated read or mutation lacks the required predecessor authority root.
    AuthorityRootRequired {
        tool: &'static str,
        requirement: &'static str,
    },
    /// Input payload byte size exceeds the enforced budget dimension.
    InputBudgetExceeded { max_bytes: u32, actual_bytes: usize },
    /// JSON nesting depth exceeds the enforced budget dimension.
    DepthBudgetExceeded { max_depth: u16, actual_depth: usize },
    /// Parameter validation error with optional source span.
    ValidationError {
        field: String,
        reason: String,
        span: Option<(usize, usize)>,
    },
    /// Unknown tool name or unregistered version.
    UnknownTool { tool: String, version: Option<u32> },
}

impl McpRefusal {
    /// Exact machine-readable refusal code.
    #[must_use]
    pub const fn refusal_code(&self) -> &'static str {
        match self {
            Self::UnsupportedTool { refusal_code, .. } => refusal_code,
            Self::DeprecatedTool { .. } => "deprecated_tool",
            Self::CapabilityDenied { .. } => "capability_denied",
            Self::PrincipalRequired { .. } => "principal_required",
            Self::IdempotencyKeyRequired { .. } => "idempotency_key_required",
            Self::AuthorityRootRequired { .. } => "authority_root_required",
            Self::InputBudgetExceeded { .. } => "input_budget_exceeded",
            Self::DepthBudgetExceeded { .. } => "depth_budget_exceeded",
            Self::ValidationError { .. } => "argument_validation_failed",
            Self::UnknownTool { .. } => "unknown_tool",
        }
    }

    /// Renders the refusal into canonical JSON for the MCP protocol.
    /// Always sets `isError: true`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let code = self.refusal_code();
        let message = self.to_string();
        let escaped_msg = escape_json(&message);

        match self {
            Self::UnsupportedTool {
                tool,
                version,
                reason,
                ..
            } => {
                let escaped_reason = escape_json(reason);
                format!(
                    r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","tool":"{tool}","version":{version},"reason":"{escaped_reason}","message":"{escaped_msg}"}}"#
                )
            }
            Self::DeprecatedTool {
                tool,
                version,
                migration_target,
            } => {
                format!(
                    r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","tool":"{tool}","version":{version},"migration_target":"{migration_target}","message":"{escaped_msg}"}}"#
                )
            }
            Self::CapabilityDenied {
                tool,
                required,
                provided,
            } => {
                let prov_str = provided.as_deref().unwrap_or("none");
                format!(
                    r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","tool":"{tool}","required_capability":"{required}","provided_capability":"{prov_str}","message":"{escaped_msg}"}}"#
                )
            }
            Self::ValidationError {
                field,
                reason,
                span,
            } => {
                let escaped_reason = escape_json(reason);
                if let Some((start, end)) = span {
                    format!(
                        r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","field":"{field}","reason":"{escaped_reason}","span":[{start},{end}],"message":"{escaped_msg}"}}"#
                    )
                } else {
                    format!(
                        r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","field":"{field}","reason":"{escaped_reason}","message":"{escaped_msg}"}}"#
                    )
                }
            }
            _ => {
                format!(
                    r#"{{"isError":true,"outcome":"refused","refusal_code":"{code}","message":"{escaped_msg}"}}"#
                )
            }
        }
    }
}

impl fmt::Display for McpRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTool {
                tool,
                version,
                reason,
                refusal_code,
            } => {
                write!(
                    formatter,
                    "tool '{tool}' v{version} is unsupported ({refusal_code}): {reason}"
                )
            }
            Self::DeprecatedTool {
                tool,
                version,
                migration_target,
            } => {
                write!(
                    formatter,
                    "tool '{tool}' v{version} is deprecated; migrate to '{migration_target}'"
                )
            }
            Self::CapabilityDenied {
                tool,
                required,
                provided,
            } => {
                write!(
                    formatter,
                    "capability '{required}' denied for tool '{tool}' (caller provided: {})",
                    provided.as_deref().unwrap_or("none")
                )
            }
            Self::PrincipalRequired { tool } => {
                write!(
                    formatter,
                    "tool '{tool}' requires an explicit launch principal (--principal)"
                )
            }
            Self::IdempotencyKeyRequired { tool } => {
                write!(
                    formatter,
                    "tool '{tool}' requires an idempotency_key parameter"
                )
            }
            Self::AuthorityRootRequired { tool, requirement } => {
                write!(
                    formatter,
                    "tool '{tool}' requires authority position: {requirement}"
                )
            }
            Self::InputBudgetExceeded {
                max_bytes,
                actual_bytes,
            } => {
                write!(
                    formatter,
                    "input size {actual_bytes} bytes exceeds budget of {max_bytes} bytes"
                )
            }
            Self::DepthBudgetExceeded {
                max_depth,
                actual_depth,
            } => {
                write!(
                    formatter,
                    "input nesting depth {actual_depth} exceeds budget of {max_depth}"
                )
            }
            Self::ValidationError {
                field,
                reason,
                span,
            } => {
                if let Some((start, end)) = span {
                    write!(
                        formatter,
                        "validation failed for field '{field}' [{start}..{end}]: {reason}"
                    )
                } else {
                    write!(formatter, "validation failed for field '{field}': {reason}")
                }
            }
            Self::UnknownTool { tool, version } => {
                if let Some(v) = version {
                    write!(formatter, "unknown tool '{tool}' version {v}")
                } else {
                    write!(formatter, "unknown tool '{tool}'")
                }
            }
        }
    }
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_codes_and_json_rendering() {
        let refusal = McpRefusal::UnsupportedTool {
            tool: "frankengit_raw_sql_query".into(),
            version: 1,
            reason: "Raw database queries are constitutionally forbidden".into(),
            refusal_code: "raw_query_prohibited",
        };
        assert_eq!(refusal.refusal_code(), "raw_query_prohibited");
        let json = refusal.to_json();
        assert!(json.contains(r#""isError":true"#));
        assert!(json.contains(r#""refusal_code":"raw_query_prohibited""#));
        assert!(json.contains(r#""tool":"frankengit_raw_sql_query""#));
    }

    #[test]
    fn validation_error_span_rendering() {
        let refusal = McpRefusal::ValidationError {
            field: "number".into(),
            reason: "positive integer required".into(),
            span: Some((12, 16)),
        };
        assert_eq!(refusal.refusal_code(), "argument_validation_failed");
        let json = refusal.to_json();
        assert!(json.contains(r#""span":[12,16]"#));
    }
}
