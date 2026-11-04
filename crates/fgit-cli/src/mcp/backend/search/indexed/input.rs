//! Closed MCP arguments; native query and route parsers retain semantic ownership.
use super::*;
use fgit_node::source_retrieval::current_index::{LexicalChannel, LexicalQuery};
use fgit_types::{GitHashAlgorithm, GitOid, MAX_REF_NAME_LEN, RefName};

pub(super) const FIELDS: &[&str] = &[
    "reference",
    "terms_hex",
    "path_prefixes_hex",
    "source_mode",
    "channel",
    "expected_head",
    "expected_commit",
    "index_token",
    "index_number",
    "minimum_index_token",
    "minimum_index_number",
    "after",
    "limit",
    "max_work",
    "max_payload_bytes",
];
const MAX_PREFIX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Exact,
    Revalidated,
}
impl Mode {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Revalidated => "revalidated",
        }
    }
    pub(super) const fn result_type(self) -> &'static str {
        match self {
            Self::Exact => "source_search_index",
            Self::Revalidated => "source_search_index_current",
        }
    }
    pub(super) const fn profile(self) -> &'static str {
        match self {
            Self::Exact => "ascii-word-postings-v1",
            Self::Revalidated => "source-lexical-revalidated-v1",
        }
    }
}

#[derive(Debug)]
pub(super) struct Query {
    pub fields: Vec<(String, String)>,
    pub reference: String,
    pub mode: Mode,
    pub query: LexicalQuery,
    pub head: Option<String>,
    pub commit: Option<GitOid>,
    pub generation: Option<(String, u64)>,
    pub minimum: Option<(String, u64)>,
    pub after: Option<u64>,
    pub limit: u64,
    pub max_work: u64,
    pub max_payload_bytes: u64,
}

fn bounded_text<'a>(
    args: &'a Object,
    name: &str,
    maximum: usize,
) -> Result<Option<&'a str>, ToolError> {
    let value = string(args, name)?;
    if value.is_some_and(|text| text.is_empty() || text.len() > maximum) {
        return Err(ToolError::invalid("invalid_index_argument"));
    }
    Ok(value)
}
fn decimal(args: &Object, name: &str) -> Result<Option<u64>, ToolError> {
    bounded_text(args, name, 20)?
        .map(|value| {
            json::decimal(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or(ToolError::invalid("invalid_decimal_string"))
        })
        .transpose()
}
fn pair(
    args: &Object,
    token: &str,
    number: &str,
) -> Result<Option<(String, u64)>, ToolError> {
    match (bounded_text(args, token, 140)?, decimal(args, number)?) {
        (None, None) => Ok(None),
        (Some(token), Some(number)) => Ok(Some((token.to_owned(), number))),
        _ => Err(ToolError::invalid("incomplete_index_generation")),
    }
}
fn limit(args: &Object, name: &str, default: u64, maximum: u64) -> Result<u64, ToolError> {
    args.get(name)
        .map(|value| {
            value
                .unsigned()
                .filter(|value| (1..=maximum).contains(value))
                .ok_or(ToolError::invalid("invalid_index_limit"))
        })
        .unwrap_or(Ok(default))
}
fn bytes_list(
    args: &Object,
    name: &str,
    required: bool,
    count: usize,
    each: usize,
    total: usize,
) -> Result<Vec<Vec<u8>>, ToolError> {
    let Some(value) = args.get(name) else {
        return if required {
            Err(ToolError::invalid("terms_required"))
        } else {
            Ok(Vec::new())
        };
    };
    let Value::Array(values) = value else {
        return Err(ToolError::invalid("expected_array"));
    };
    if values.len() > count || (required && values.is_empty()) {
        return Err(ToolError::invalid("invalid_index_query"));
    }
    let mut bytes = 0_usize;
    values
        .iter()
        .map(|value| {
            let encoded = value.text().ok_or(ToolError::invalid("expected_string"))?;
            let decoded = unhex(encoded, each)?;
            if decoded.is_empty() {
                return Err(ToolError::invalid("invalid_index_query"));
            }
            bytes = bytes
                .checked_add(decoded.len())
                .filter(|value| *value <= total)
                .ok_or(ToolError::invalid("invalid_search_scope"))?;
            Ok(decoded)
        })
        .collect()
}

pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Query, ToolError> {
    require_fields(args, FIELDS)?;
    let reference = bounded_text(args, "reference", MAX_REF_NAME_LEN)?
        .ok_or(ToolError::invalid("reference_required"))?;
    if !reference.starts_with("refs/") || RefName::try_new(reference.as_bytes()).is_err() {
        return Err(ToolError::invalid("invalid_ref"));
    }
    let mode = match string(args, "source_mode")? {
        None | Some("revalidated") => Mode::Revalidated,
        Some("exact") => Mode::Exact,
        _ => return Err(ToolError::invalid("invalid_index_source_mode")),
    };
    let channel = match string(args, "channel")? {
        None | Some("content") => LexicalChannel::Content,
        Some("path") => LexicalChannel::Path,
        _ => return Err(ToolError::invalid("unsupported_index_channel")),
    };
    let terms = bytes_list(args, "terms_hex", true, 32, 128, 4096)?;
    let prefixes = bytes_list(
        args,
        "path_prefixes_hex",
        false,
        128,
        4096,
        MAX_PREFIX_BYTES,
    )?;
    let query = LexicalQuery::new(channel, &terms, &prefixes)
        .map_err(|_| ToolError::invalid("invalid_index_query"))?;
    let expected_head = bounded_text(args, "expected_head", 140)?.map(str::to_owned);
    // Use the shared canonical snapshot parser before any node work.
    head(args, 0)?;
    let commit = bounded_text(args, "expected_commit", 64)?
        .map(|value| {
            if value.len() != format.digest_len() * 2
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ToolError::invalid("invalid_expected_commit"));
            }
            GitOid::from_hex(format, value)
                .ok()
                .filter(|id| !id.is_zero())
                .ok_or(ToolError::invalid("invalid_expected_commit"))
        })
        .transpose()?;
    let generation = pair(args, "index_token", "index_number")?;
    let minimum = pair(args, "minimum_index_token", "minimum_index_number")?;
    let after = decimal(args, "after")?;
    if after.is_some() && (expected_head.is_none() || commit.is_none() || generation.is_none()) {
        return Err(ToolError::invalid("index_continuation_requires_pins"));
    }
    let page_limit = limit(args, "limit", 20, MAX_PAGE)?;
    let max_work = limit(args, "max_work", MAX_WORK, MAX_WORK)?;
    let max_payload_bytes = limit(args, "max_payload_bytes", DEFAULT_PAYLOAD, MAX_PAYLOAD)?;
    let mut fields = vec![
        ("ref".into(), reference.to_owned()),
        ("source_mode".into(), mode.label().into()),
        (
            "channel".into(),
            match channel {
                LexicalChannel::Content => "content",
                LexicalChannel::Path => "path",
            }
            .into(),
        ),
        ("limit".into(), page_limit.to_string()),
        ("max_work".into(), max_work.to_string()),
        ("max_payload_bytes".into(), max_payload_bytes.to_string()),
    ];
    for value in terms {
        fields.push(("term_hex".into(), hex(&value)));
    }
    for value in prefixes {
        fields.push(("path_prefix_hex".into(), hex(&value)));
    }
    for name in [
        "expected_head",
        "expected_commit",
        "index_token",
        "index_number",
        "minimum_index_token",
        "minimum_index_number",
        "after",
    ] {
        if let Some(value) = string(args, name)? {
            fields.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok(Query {
        fields,
        reference: reference.to_owned(),
        mode,
        query,
        head: expected_head,
        commit,
        generation,
        minimum,
        after,
        limit: page_limit,
        max_work,
        max_payload_bytes,
    })
}

fn string_field(maximum: u64, description: &str, pattern: Option<&str>) -> Value {
    let mut fields = Object::from([
        ("type".into(), text("string")),
        ("maxLength".into(), json::number(maximum)),
        ("description".into(), text(description)),
    ]);
    if let Some(pattern) = pattern {
        fields.insert("pattern".into(), text(pattern));
    }
    Value::Object(fields)
}
fn strings(maximum: u64, count: u64, minimum: u64, description: &str) -> Value {
    object([
        ("type", text("array")),
        ("minItems", json::number(minimum)),
        ("maxItems", json::number(count)),
        (
            "items",
            string_field(maximum, description, Some("^(?:[0-9a-f]{2})+$")),
        ),
        ("description", text(description)),
    ])
}
pub(super) fn schema() -> Value {
    let mut properties = Object::new();
    properties.insert(
        "reference".into(),
        string_field(1024, "Full visible UTF-8 refs/* name, at most 1024 native bytes.", None),
    );
    properties.insert(
        "terms_hex".into(),
        strings(256, 32, 1, "1..32 nonempty ASCII word tokens in lowercase hex; 128 decoded bytes each. Tokens are case-folded, sorted and deduplicated; conjunction, not regex or substrings."),
    );
    properties.insert(
        "path_prefixes_hex".into(),
        strings(8192, 128, 0, "Optional native raw path prefixes, 4096 decoded bytes each and 8192 decoded bytes combined. Slash-component scope only; no host paths."),
    );
    for (name, choices, default) in [
        ("source_mode", ["revalidated", "exact"], "revalidated"),
        ("channel", ["content", "path"], "content"),
    ] {
        properties.insert(
            name.into(),
            object([
                ("type", text("string")),
                ("enum", Value::Array(choices.map(text).into())),
                ("default", text(default)),
            ]),
        );
    }
    for (name, maximum, description) in [
        ("expected_head", 140, "Optional exact current source snapshot token; mandatory for continuation."),
        ("expected_commit", 64, "Exact nonzero bare native commit hex in the launch hash domain; mandatory for continuation."),
        ("index_token", 140, "Exact index identity paired with index_number; mandatory for continuation."),
        ("minimum_index_token", 140, "Independent retained anti-rollback floor, paired with minimum_index_number."),
    ] {
        properties.insert(name.into(), string_field(maximum, description, None));
    }
    for name in ["index_number", "minimum_index_number", "after"] {
        properties.insert(
            name.into(),
            string_field(20, "Positive canonical decimal u64 string. after additionally requires original expected_head, expected_commit and exact index pair.", Some("^[1-9][0-9]*$")),
        );
    }
    for (name, default, maximum) in [
        ("limit", 20, MAX_PAGE),
        ("max_work", MAX_WORK, MAX_WORK),
        ("max_payload_bytes", DEFAULT_PAYLOAD, MAX_PAYLOAD),
    ] {
        properties.insert(
            name.into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(maximum)),
                ("default", json::number(default)),
            ]),
        );
    }
    mutations::input_schema(properties, &["reference", "terms_hex"])
}
