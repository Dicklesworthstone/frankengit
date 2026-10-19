//! Read-only reference inventory: the exact native tips an agent pins as
//! `expected_old` before a branch write. Names are exact bytes; a page is never
//! a write capability and never refreshes a failed write expectation.
#[cfg(test)]
mod tests;

use super::*;
use fgit_node::NodeWorkspaceRefusal;
use fgit_types::RefName;

pub(super) const NAME: &str = "frankengit_ref_list";
const DEFAULT_LIMIT: u64 = 50;
const MAX_LIMIT: u64 = 100;
const MAX_REFERENCE_BYTES: usize = 4096;

pub(super) fn tool() -> Tool {
    Tool {
        name: NAME,
        description: "List currently visible refs (all, or only refs/tags/) with exact names as hex and native tips, from one authenticated snapshot. Use a tip as expected_old for a branch write. Continue with next_after_hex and the same snapshot_token; if authority moved, restart. Read-only.",
        schema: input_schema(),
    }
}

/// Which namespace a page enumerates; both use the node's snapshot-bound pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Namespace {
    All,
    Tags,
}

#[derive(Debug)]
struct Query {
    namespace: Namespace,
    after: Option<RefName>,
    limit: u16,
    expected_head: Option<RepositoryAuthorityHeadId>,
}

fn parse(args: &Object) -> Result<Query, ToolError> {
    require_fields(args, &["namespace", "after_hex", "limit", "expected_head"])?;
    let namespace = match string(args, "namespace")? {
        None | Some("refs") => Namespace::All,
        Some("tags") => Namespace::Tags,
        Some(_) => return Err(ToolError::invalid("invalid_namespace")),
    };
    let after = string(args, "after_hex")?
        .map(|value| {
            let bytes = unhex(value, MAX_REFERENCE_BYTES)?;
            RefName::try_new(&bytes).map_err(|_| ToolError::invalid("invalid_reference_cursor"))
        })
        .transpose()?;
    if after.as_ref().is_some_and(|name| {
        !name.as_bytes().starts_with(match namespace {
            Namespace::All => b"refs/".as_slice(),
            Namespace::Tags => b"refs/tags/".as_slice(),
        })
    }) {
        return Err(ToolError::invalid("invalid_reference_cursor"));
    }
    let limit = args
        .get("limit")
        .map(|value| value.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?
        .unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ToolError::invalid("invalid_limit"));
    }
    let expected_head = string(args, "expected_head")?.map(parse_head).transpose()?;
    if after.is_some() && expected_head.is_none() {
        return Err(ToolError::invalid("snapshot_required"));
    }
    Ok(Query {
        namespace,
        after,
        limit: u16::try_from(limit).map_err(|_| ToolError::invalid("invalid_limit"))?,
        expected_head,
    })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let query = parse(args)?;
    let request = fgit_cli::command_request_context(&backend.node);
    let visibility = Default::default();
    let node = &backend.node;
    let (head, rows, next) = node
        .runtime()
        .block_on(async {
            match query.namespace {
                Namespace::All => {
                    node.list_refs_in(
                        &request,
                        &visibility,
                        query.after.as_ref(),
                        query.limit,
                        query.expected_head,
                    )
                    .await
                }
                Namespace::Tags => {
                    node.list_tag_refs_in(
                        &request,
                        &visibility,
                        query.after.as_ref(),
                        query.limit,
                        query.expected_head,
                    )
                    .await
                }
            }
        })
        .map_err(read_error)?;
    // The node owns pagination; still refuse a page that breaks its contract
    // rather than hand an agent a tip from the wrong snapshot or order.
    if query.expected_head.is_some_and(|expected| expected != head)
        || rows.len() > usize::from(query.limit)
        || rows.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || query
            .after
            .as_ref()
            .is_some_and(|cursor| rows.first().is_some_and(|(name, _)| name <= cursor))
        || rows
            .iter()
            .any(|(_, tip)| tip.algorithm() != backend.options.format || tip.is_zero())
    {
        return Err(ToolError::failed("invalid_reference_page"));
    }
    let mut result = backend.header(head);
    result.insert(
        "namespace".into(),
        text(match query.namespace {
            Namespace::All => "refs/",
            Namespace::Tags => "refs/tags/",
        }),
    );
    result.insert(
        "references".into(),
        Value::Array(
            rows.iter()
                .map(|(name, tip)| {
                    object([
                        ("reference_hex", text(hex(name.as_bytes()))),
                        (
                            "reference",
                            std::str::from_utf8(name.as_bytes()).map_or(Value::Null, text),
                        ),
                        ("tip", text(tip.to_string())),
                    ])
                })
                .collect(),
        ),
    );
    result.insert(
        "next_after_hex".into(),
        next.as_ref()
            .map_or(Value::Null, |name| text(hex(name.as_bytes()))),
    );
    result.insert("complete".into(), Value::Bool(next.is_none()));
    Ok(Value::Object(result))
}

fn read_error(error: NodeWorkspaceRefusal) -> ToolError {
    match error {
        NodeWorkspaceRefusal::BranchOperation("reference snapshot moved") => {
            ToolError::failed("snapshot_moved")
        }
        NodeWorkspaceRefusal::BranchOperation(_) => ToolError::invalid("invalid_reference_query"),
        NodeWorkspaceRefusal::Cancelled { exhaustion: None } => ToolError::failed("read_cancelled"),
        NodeWorkspaceRefusal::Cancelled {
            exhaustion: Some(_),
        } => ToolError::failed("resource_limit"),
        _ => ToolError::failed("reference_read_failed"),
    }
}

fn input_schema() -> Value {
    let mut properties = Object::new();
    properties.insert(
        "namespace".into(),
        object([
            ("type", text("string")),
            (
                "enum",
                Value::Array(vec![text("refs"), text("tags")]),
            ),
            ("default", text("refs")),
            (
                "description",
                text("refs lists every visible ref (branches, tags, remote-tracking); tags lists only refs/tags/."),
            ),
        ]),
    );
    properties.insert(
        "after_hex".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number(8192)),
            ("pattern", text("^(?:[0-9a-f]{2})+$")),
            (
                "description",
                text("Exact next_after_hex from the previous page; requires expected_head."),
            ),
        ]),
    );
    properties.insert(
        "limit".into(),
        object([
            ("type", text("integer")),
            ("minimum", json::number(1)),
            ("maximum", json::number(MAX_LIMIT)),
            ("default", json::number(DEFAULT_LIMIT)),
        ]),
    );
    properties.insert(
        "expected_head".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number(140)),
            (
                "description",
                text("Exact snapshot_token from the first page; mandatory with after_hex."),
            ),
        ]),
    );
    object([
        ("type", text("object")),
        ("properties", Value::Object(properties)),
        ("required", Value::Array(Vec::new())),
        ("additionalProperties", Value::Bool(false)),
    ])
}
