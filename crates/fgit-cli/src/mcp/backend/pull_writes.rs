//! Explicitly sponsored PR lifecycle through the existing canonical admission.
//! Full client metadata is immutable across retries; no latest-version lookup.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::mutations as common;
use super::{NodeTools, require_fields, string, unhex};
use fgit_forge::{
    PullRequestNumber,
    event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData},
};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

pub(super) const OPEN: &str = "frankengit_pull_open";
pub(super) const UPDATE: &str = "frankengit_pull_update";
pub(super) const CLOSE: &str = "frankengit_pull_close";
const FIELDS: &[&str] = &[
    "number",
    "expected_version",
    "idempotency_key",
    "source_reference",
    "source_reference_hex",
    "target_reference",
    "target_reference_hex",
    "expected_source",
    "expected_target",
    "title",
    "body",
];

pub(super) fn is_tool(name: &str) -> bool {
    matches!(name, OPEN | UPDATE | CLOSE)
}
pub(super) fn tools() -> Vec<Tool> {
    [
        (OPEN, "Open a native PR at version zero from explicit source and target branches/tips. Canonical metadata mutation only; does not move refs, approve or merge code."),
        (UPDATE, "Replace complete PR metadata at an exact positive version and explicit branch tips. Cannot retarget branches or reopen a closed/merged PR. No latest-tip lookup."),
        (CLOSE, "Close a PR using its exact positive version and unchanged full recorded metadata. Remains possible after branch deletion. Retry the identical command and durable key."),
    ].into_iter().map(|(name, description)| Tool { name, description, schema: schema() }).collect()
}
fn schema() -> Value {
    let mut properties = common::base_properties();
    for name in ["source_reference", "target_reference"] {
        properties.insert(name.into(), object([("type", text("string")), ("maxLength", json::number(4096)),
            ("description", text("Full branch name, such as refs/heads/topic. Supply this OR its _hex alternative, never both."))]));
    }
    for name in ["source_reference_hex", "target_reference_hex"] {
        properties.insert(name.into(), object([("type", text("string")), ("maxLength", json::number(8192)),
            ("pattern", text("^(?:[0-9a-f]{2})+$")), ("description", text("Lossless full branch-name bytes; alternative to the UTF-8 reference field."))]));
    }
    for name in ["expected_source", "expected_target"] {
        properties.insert(name.into(), object([("type", text("string")), ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
            ("description", text("Explicit nonzero native commit OID in the repository object format. Never a latest-tip selector."))]));
    }
    properties.insert("title".into(), common::text_schema(256));
    properties.insert(
        "body".into(),
        common::text_schema(common::MAX_TEXT_BYTES as u64),
    );
    let mut schema = common::input_schema(
        properties,
        &[
            "number",
            "expected_version",
            "idempotency_key",
            "expected_source",
            "expected_target",
            "title",
            "body",
        ],
    );
    // Preserve the mutually exclusive raw-byte and UTF-8 alternatives in discovery.
    if let Value::Object(fields) = &mut schema {
        fields.insert(
            "allOf".into(),
            Value::Array(
                [
                    ("source_reference", "source_reference_hex"),
                    ("target_reference", "target_reference_hex"),
                ]
                .into_iter()
                .map(|(plain, hex)| {
                    object([(
                        "oneOf",
                        Value::Array(vec![
                            object([("required", Value::Array(vec![text(plain)]))]),
                            object([("required", Value::Array(vec![text(hex)]))]),
                        ]),
                    )])
                })
                .collect(),
            ),
        );
    }
    schema
}

/// Bounded native input primitives, also used by the source publication adapter.
pub(super) fn branch(args: &Object, plain: &str, encoded: &str) -> Result<RefName, ToolError> {
    let bytes = match (string(args, plain)?, string(args, encoded)?) {
        (Some(name), None) if name.len() <= 4096 => name.as_bytes().to_vec(),
        (None, Some(name)) => unhex(name, 4096)?,
        _ => return Err(ToolError::invalid("exactly_one_branch_encoding_required")),
    };
    if !bytes.starts_with(b"refs/heads/") {
        return Err(ToolError::invalid("full_branch_required"));
    }
    RefName::try_new(&bytes).map_err(|_| ToolError::invalid("invalid_branch"))
}
pub(super) fn oid(
    args: &Object,
    name: &str,
    format: GitHashAlgorithm,
) -> Result<GitOid, ToolError> {
    let value = common::required(args, name)?;
    if value.len() != format.digest_len() * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolError::invalid("invalid_native_oid"));
    }
    GitOid::from_hex(format, value)
        .ok()
        .filter(|oid| !oid.is_zero())
        .ok_or(ToolError::invalid("invalid_native_oid"))
}
pub(super) fn parse(
    name: &str,
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<PullRequestCommand, ToolError> {
    if !is_tool(name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    require_fields(args, FIELDS)?;
    let number = PullRequestNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_pull_number_required"))?;
    let expected_version = common::version(args, name == OPEN)?;
    let data = PullRequestData {
        source_ref: branch(args, "source_reference", "source_reference_hex")?,
        target_ref: branch(args, "target_reference", "target_reference_hex")?,
        source_tip: oid(args, "expected_source", format)?,
        target_tip: oid(args, "expected_target", format)?,
        title: common::required(args, "title")?.to_owned(),
        body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
    };
    data.validate()
        .map_err(|_| ToolError::invalid("invalid_pull_request_data"))?;
    let action = match name {
        OPEN => PullRequestAction::Open,
        UPDATE => PullRequestAction::Update,
        CLOSE => PullRequestAction::Close,
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    Ok(PullRequestCommand {
        number,
        expected_version,
        action,
        data,
    })
}
pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.pulls {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let command = parse(name, args, backend.options.format)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal, backend.options.format)
        .map_err(|_| ToolError::invalid("invalid_pull_request_command"))?;
    let context = backend.node.request_context();
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_pull_request_durable_in(
            &context,
            &session,
            &command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    // Only verified canonical terminal facts enter a success/refusal receipt.
    // No follow-up latest-state read may turn an accepted command into an error.
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.insert("type".into(), text("pull_request_publication"));
    result.insert("number".into(), text(command.number.get().to_string()));
    result.insert(
        "expected_version".into(),
        text(
            match command.expected_version {
                fgit_forge::ExpectedVersion::NewStream => 0,
                fgit_forge::ExpectedVersion::Exactly(version) => version.get(),
            }
            .to_string(),
        ),
    );
    result.insert(
        "action".into(),
        text(match command.action {
            PullRequestAction::Open => "open",
            PullRequestAction::Update => "update",
            PullRequestAction::Close => "close",
        }),
    );
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod tests;
