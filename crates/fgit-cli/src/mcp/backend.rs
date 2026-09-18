//! Real node reads, not fixtures or a CLI subprocess. Scope is fixed at launch.
mod issues;
use fgit_node::{IssueReadRefusal, NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RepositoryAuthorityHeadId};
use super::Options;
use super::json::{self, Object, Value, object, text};
use super::protocol::{ReadTools, Tool, ToolError, fields};

pub(super) struct NodeTools { node: OneNode, options: Options }
impl NodeTools {
    pub(super) fn open(options: Options) -> Result<Self, String> {
        let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format).with_worker_threads(2)).map_err(|_| "MCP repository could not be opened")?;
        let startup = (|| -> Result<(), String> {
            if options.incarnation.is_some_and(|id| id != node.repository_incarnation_id()) {
                return Err("MCP repository incarnation does not match launch binding".into());
            }
            let head = node.runtime().block_on(node.authenticate_authority_head())
                .map_err(|_| "MCP authority authentication failed")?;
            node.bring_into_service(head.receipt().generation()).map_err(|_| "MCP repository read service unavailable")?;
            Ok(())
        })();
        if let Err(error) = startup {
            return match node.shutdown() {
                Ok(()) => Err(error),
                Err(_) => Err(format!("{error}; MCP node shutdown also failed")),
            };
        }
        Ok(Self { node, options })
    }
    pub(super) fn close(self) -> Result<(), String> {
        self.node.shutdown().map_err(|_| "MCP node shutdown failed".into())
    }
    fn header(&self, head: RepositoryAuthorityHeadId) -> Object {
        let Value::Object(fields) = object([
            ("tenant_id", text(self.options.tenant.to_string())),
            ("repository_id", text(self.options.repository.to_string())),
            ("repository_incarnation", text(self.node.repository_incarnation_id().to_string())),
            ("object_format", text(self.options.format.as_str())),
            ("snapshot_token", text(head_token(head))),
            ("read_only", Value::Bool(true)),
        ]) else { unreachable!() };
        fields
    }
}
impl ReadTools for NodeTools {
    fn tools(&self) -> Vec<Tool> {
        let mut tools = Vec::new();
        if self.options.issues { tools.extend(issues::tools()); }
        tools
    }
    fn call(&mut self, name: &str, args: &Object) -> Result<Value, ToolError> {
        if self.options.issues && matches!(name, "frankengit_issue_list" | "frankengit_issue_show") {
            return issues::call(self, name, args);
        }
        Err(ToolError::invalid("tool_not_granted"))
    }
}
fn require_fields(args: &Object, allowed: &[&str]) -> Result<(), ToolError> {
    if !fields(args, allowed) { return Err(ToolError::invalid("unknown_argument")); }
    Ok(())
}
fn string<'a>(args: &'a Object, name: &str) -> Result<Option<&'a str>, ToolError> {
    args.get(name).map(|value| value.text().ok_or(ToolError::invalid("expected_string"))).transpose()
}
fn decimal(args: &Object, name: &str, default: u64) -> Result<u64, ToolError> {
    string(args, name)?.map(json::decimal).transpose().map(|n| n.unwrap_or(default))
        .map_err(|_| ToolError::invalid("invalid_decimal_string"))
}
fn limit(args: &Object) -> Result<u16, ToolError> {
    let n = args.get("limit").map(|v| v.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?.unwrap_or(5);
    if !(1..=20).contains(&n) { return Err(ToolError::invalid("invalid_limit")); }
    Ok(n as u16)
}
fn head(args: &Object, after: u64) -> Result<Option<RepositoryAuthorityHeadId>, ToolError> {
    let value = string(args, "expected_head")?.map(parse_head).transpose()?;
    if after != 0 && value.is_none() { return Err(ToolError::invalid("snapshot_required")); }
    Ok(value)
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes { out.push(char::from(HEX[usize::from(byte >> 4)])); out.push(char::from(HEX[usize::from(byte & 15)])); }
    out
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, ToolError> {
    if value.len() > maximum * 2 || value.len() % 2 != 0
        || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(ToolError::invalid("invalid_hex_bytes"));
    }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(value.as_bytes().chunks_exact(2).map(|p| digit(p[0]) * 16 + digit(p[1])).collect())
}
fn parse_head(value: &str) -> Result<RepositoryAuthorityHeadId, ToolError> {
    let bad = || ToolError::invalid("invalid_snapshot_token");
    let (algorithm, bytes) = value.strip_prefix("alg:").and_then(|v| v.split_once(':')).ok_or_else(bad)?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(json::decimal(algorithm).map_err(|_| bad())?)
        .map_err(|_| bad())?).map_err(|_| bad())?;
    let bytes = unhex(bytes, 64)?;
    if bytes.is_empty() { return Err(bad()); }
    let digest = DigestBytes::try_new(&bytes).map_err(|_| bad())?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
fn issue_error(error: IssueReadRefusal) -> ToolError {
    match error {
        IssueReadRefusal::SnapshotMoved => ToolError::failed("snapshot_unavailable"),
        IssueReadRefusal::SnapshotRequired => ToolError::invalid("snapshot_required"),
        IssueReadRefusal::InvalidLimit => ToolError::invalid("invalid_limit"),
        _ => ToolError::failed("repository_read_failed"),
    }
}
fn schema(show: bool) -> Value {
    let mut properties = BTreeMapForSchema::new();
    properties.insert("limit".to_owned(), object([("type", text("integer")), ("minimum", json::number(1)),
        ("maximum", json::number(20)), ("default", json::number(5))]));
    properties.insert(if show { "after_version" } else { "after" }.to_owned(), decimal_schema());
    properties.insert("expected_head".to_owned(), object([("type", text("string")), ("maxLength", json::number(140)),
        ("description", text("Exact snapshot_token from the first page; mandatory with a nonzero cursor."))]));
    if show { properties.insert("number".to_owned(), decimal_schema()); }
    object([("type", text("object")), ("properties", Value::Object(properties)),
        ("required", Value::Array(if show { vec![text("number")] } else { Vec::new() })),
        ("additionalProperties", Value::Bool(false))])
}
type BTreeMapForSchema = std::collections::BTreeMap<String, Value>;
fn decimal_schema() -> Value {
    object([("type", text("string")), ("pattern", text("^(0|[1-9][0-9]{0,19})$")),
        ("description", text("Exact unsigned decimal string; never a floating-point JSON number."))])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_integer_and_snapshot_arguments_cannot_be_lossily_coerced() {
        for bad in [json::number(1), text("01"), text("-1"), text("18446744073709551616")] {
            let Value::Object(args) = object([("after", bad)]) else { unreachable!() };
            assert!(decimal(&args, "after", 0).is_err());
        }
        let Value::Object(args) = object([("after", text(u64::MAX.to_string()))]) else { unreachable!() };
        assert_eq!(decimal(&args, "after", 0).unwrap(), u64::MAX);
        assert!(head(&args, 1).is_err());
        assert!(parse_head("alg:01:aa").is_err());
        assert!(parse_head("alg:1:GG").is_err());
        assert!(unhex("../secret", 4096).is_err());
    }
}

#[cfg(test)]
mod integration_tests;
