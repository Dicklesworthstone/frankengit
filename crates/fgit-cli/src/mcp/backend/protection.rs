//! Separate operator policy profile, not an additional grant on a code agent.
//! The same MCP codec/transport and native authority reader remain the owners.
use std::collections::BTreeMap;

use fgit_forge::event::protection::ReviewProtection;
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};

use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{self, ReadTools, Tool, ToolError};
use super::{NodeTools, Options, head, hex, mutations, require_fields};

const SHOW: &str = "frankengit_protection_show";
const USAGE: &str = "usage: fg-mcp --protection-admin <storage-root> <tenant-id> <repository-id>
  --trusted-local --expected-incarnation <id> --allow-read
  [--object-format sha1|sha256] [--max-messages <1..100000>]

Read the exact authority-selected required-review policy of an existing node.
This profile exposes no code, issue, PR, review, mutation or recovery tools.
It is explicitly operator-authorized local access, not remote IAM. Never proxy
this process to untrusted clients. Policy text cannot expand its launch grant.
MCP framing, serial execution, native request budgets and explicit node shutdown
are identical to the existing fg-mcp profile. No separate listener or runtime.";

#[derive(Clone, Debug)]
struct Launch {
    options: Options,
}

fn parse(arguments: &[String]) -> Result<Launch, String> {
    if arguments.len() < 3
        || arguments.len() > 12
        || arguments[0].is_empty()
        || arguments.iter().any(|arg| arg.len() > 4096)
    {
        return Err(USAGE.into());
    }
    let mut flags = BTreeMap::new();
    let mut cursor = 3;
    while cursor < arguments.len() {
        let flag = arguments[cursor].as_str();
        cursor += 1;
        let value = match flag {
            "--trusted-local" | "--allow-read" => "",
            "--expected-incarnation" | "--object-format" | "--max-messages" => {
                let value = arguments
                    .get(cursor)
                    .ok_or("missing protection option value")?;
                cursor += 1;
                value.as_str()
            }
            _ => return Err("unknown protection option".into()),
        };
        if flags.insert(flag, value).is_some() {
            return Err("duplicate protection option".into());
        }
    }
    if !flags.contains_key("--trusted-local") || !flags.contains_key("--allow-read") {
        return Err("policy inspection requires --trusted-local and --allow-read".into());
    }
    let incarnation = flags
        .get("--expected-incarnation")
        .ok_or("--expected-incarnation is required")?;
    let incarnation =
        RepositoryIncarnationId::from_hex(incarnation).map_err(|_| "invalid incarnation ID")?;
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported object format".into()),
    };
    let maximum = flags
        .get("--max-messages")
        .map(|value| json::decimal(value))
        .transpose()?
        .unwrap_or(1024);
    if !(1..=100_000).contains(&maximum) {
        return Err("message bound must be 1..100000".into());
    }
    Ok(Launch {
        options: Options {
            storage: arguments[0].clone().into(),
            tenant: TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?,
            repository: RepositoryId::from_hex(&arguments[2])
                .map_err(|_| "invalid repository ID")?,
            format,
            incarnation: Some(incarnation),
            max_messages: maximum as usize,
            issues: false,
            pulls: false,
            source: false,
            writes: Default::default(),
            outcomes: false,
            principal: None,
        },
    })
}

// No Deref, generic dispatch, or exposed NodeTools handle: the separate profile
// never inherits the ordinary backend's tool catalogue or capability ceilings.
struct ProtectionTools {
    backend: NodeTools,
}
impl ProtectionTools {
    fn open(launch: Launch) -> Result<Self, String> {
        Ok(Self {
            backend: NodeTools::open_authorized(launch.options, false)?,
        })
    }
    fn close(self) -> Result<(), String> {
        self.backend.close()
    }
    fn show(&self, args: &Object) -> Result<Value, ToolError> {
        require_fields(args, &["expected_head"])?;
        let expected = head(args, 0)?;
        let node = &self.backend.node;
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.read_review_protection_in(&request))
            .map_err(|_| ToolError::failed("protection_read_failed"))?;
        if expected.is_some_and(|expected| expected != selected.source_head) {
            return Err(ToolError::failed("snapshot_moved"));
        }
        let policy = selected.protection();
        if selected.event.is_some() != policy.is_some() {
            return Err(ToolError::failed("invalid_protection_state"));
        }
        let mut result = self.backend.header(selected.source_head);
        result.insert("schema_version".into(), json::number(1));
        result.insert("type".into(), text("repository_review_protection"));
        result.insert("source_head".into(), text(selected.source_head.to_string()));
        result.insert(
            "policy_epoch".into(),
            text(selected.policy_epoch.get().to_string()),
        );
        result.insert(
            "version".into(),
            text(selected.version().map_or(0, |v| v.get()).to_string()),
        );
        result.insert("installed".into(), Value::Bool(policy.is_some()));
        result.insert(
            "enabled".into(),
            Value::Bool(policy.is_some_and(|p| !p.branches.is_empty())),
        );
        result.insert("policy".into(), policy.map_or(Value::Null, policy_value));
        result.insert("complete".into(), Value::Bool(true));
        result.insert("transaction_created".into(), Value::Bool(false));
        result.insert("published".into(), Value::Bool(false));
        Ok(Value::Object(result))
    }
}

fn policy_value(policy: &ReviewProtection) -> Value {
    object([
        (
            "administrators",
            Value::Array(
                policy
                    .administrators
                    .iter()
                    .map(|id| text(id.to_string()))
                    .collect(),
            ),
        ),
        (
            "branches",
            Value::Array(
                policy
                    .branches
                    .iter()
                    .map(|branch| {
                        object([
                            ("reference_hex", text(hex(branch.name.as_bytes()))),
                            (
                                "reference_utf8",
                                std::str::from_utf8(branch.name.as_bytes())
                                    .map_or(Value::Null, text),
                            ),
                            (
                                "required_reviewers",
                                Value::Array(
                                    branch
                                        .reviewers
                                        .iter()
                                        .map(|id| text(id.to_string()))
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

impl ReadTools for ProtectionTools {
    fn tools(&self) -> Vec<Tool> {
        let mut properties = Object::new();
        properties.insert("expected_head".into(), object([
            ("type", text("string")), ("maxLength", json::number(140)),
            ("description", text("Optional exact snapshot_token. A moved head refuses, never silently repins.")),
        ]));
        vec![Tool {
            name: SHOW,
            description: "Read complete required-review protection, administrators, version and policy epoch at one authenticated head. Absent policy differs from an installed policy with no protected branches. Read-only; does not grant administration or code access.",
            schema: mutations::input_schema(properties, &[]),
        }]
    }
    fn call(&mut self, name: &str, args: &Object) -> Result<Value, ToolError> {
        if name != SHOW {
            return Err(ToolError::invalid("tool_not_granted"));
        }
        self.show(args)
    }
}

pub(in crate::mcp) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments == ["--help"] {
        eprintln!("{USAGE}");
        return Ok(());
    }
    let launch = parse(arguments)?;
    let maximum = launch.options.max_messages;
    let mut tools = ProtectionTools::open(launch)?;
    let served = protocol::serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut tools,
        maximum,
    );
    let closed = tools.close();
    match (served, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

#[cfg(test)]
mod tests;
