use super::*;
use fgit_authority::{IdempotencyKey, RefCommand};
use fgit_crypto::GitObjectKind;
use fgit_forge::tags::{MAX_TAG_IDENTITY_BYTES, TagCommand, TagMetadata, validate_tag_name};
use fgit_types::{GitHashAlgorithm, GitOid, MAX_REF_NAME_LEN, RefName};

pub(super) struct Inspection {
    pub reference: RefName,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_object: Option<GitOid>,
    pub limits: TagReadLimits,
}

pub(super) struct Mutation {
    pub key: IdempotencyKey,
    pub command: TagCommand,
    pub reference_command: RefCommand,
}

fn reference(args: &Object) -> Result<RefName, ToolError> {
    let bytes = match (string(args, "reference")?, string(args, "reference_hex")?) {
        (Some(value), None) if value.len() <= MAX_REF_NAME_LEN => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, MAX_REF_NAME_LEN)?,
        (Some(_), None) => return Err(ToolError::invalid("invalid_tag_reference")),
        _ => return Err(ToolError::invalid("exactly_one_reference_required")),
    };
    let name = RefName::try_new(&bytes).map_err(|_| ToolError::invalid("invalid_tag_reference"))?;
    validate_tag_name(&name).map_err(|_| ToolError::invalid("invalid_tag_reference"))?;
    Ok(name)
}

fn oid(value: &str, format: GitHashAlgorithm) -> Result<GitOid, ToolError> {
    if value.len() != format.digest_len() * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolError::invalid("invalid_object_id"));
    }
    let id =
        GitOid::from_hex(format, value).map_err(|_| ToolError::invalid("invalid_object_id"))?;
    if id.is_zero() {
        return Err(ToolError::invalid("invalid_object_id"));
    }
    Ok(id)
}

fn bound(args: &Object, name: &str, maximum: usize) -> Result<usize, ToolError> {
    let Some(value) = args.get(name) else {
        return Ok(maximum);
    };
    value
        .unsigned()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=maximum).contains(value))
        .ok_or(ToolError::invalid("invalid_tag_limits"))
}

pub(super) fn inspection(args: &Object, format: GitHashAlgorithm) -> Result<Inspection, ToolError> {
    require_fields(
        args,
        &[
            "reference",
            "reference_hex",
            "expected_head",
            "expected_object",
            "max_tags",
            "max_object_bytes",
            "max_total_bytes",
        ],
    )?;
    let defaults = default_limits();
    let limits = TagReadLimits {
        max_tags: bound(args, "max_tags", defaults.max_tags)?,
        max_object_bytes: bound(args, "max_object_bytes", defaults.max_object_bytes)?,
        max_total_bytes: bound(args, "max_total_bytes", defaults.max_total_bytes)?,
    };
    limits
        .validate()
        .map_err(|_| ToolError::invalid("invalid_tag_limits"))?;
    Ok(Inspection {
        reference: reference(args)?,
        expected_head: head(args, 0)?,
        expected_object: string(args, "expected_object")?
            .map(|value| oid(value, format))
            .transpose()?,
        limits,
    })
}

pub(super) fn mutation(
    name: &str,
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<Mutation, ToolError> {
    require_fields(
        args,
        match name {
            CREATE => &["reference", "reference_hex", "target", "idempotency_key"],
            ANNOTATE => &[
                "reference",
                "reference_hex",
                "target",
                "target_kind",
                "tagger",
                "timestamp",
                "message_hex",
                "idempotency_key",
            ],
            DELETE => &[
                "reference",
                "reference_hex",
                "expected_object",
                "idempotency_key",
            ],
            _ => return Err(ToolError::invalid("invalid_tag_operation")),
        },
    )?;
    let key = mutations::key(args)?;
    let reference = reference(args)?;
    let command = match name {
        CREATE => TagCommand::Lightweight {
            name: reference,
            target: oid(mutations::required(args, "target")?, format)?,
        },
        DELETE => TagCommand::Delete {
            name: reference,
            expected: oid(mutations::required(args, "expected_object")?, format)?,
        },
        ANNOTATE => TagCommand::Annotated {
            name: reference,
            target: oid(mutations::required(args, "target")?, format)?,
            target_kind: match mutations::required(args, "target_kind")? {
                "commit" => GitObjectKind::Commit,
                "tree" => GitObjectKind::Tree,
                "blob" => GitObjectKind::Blob,
                "tag" => GitObjectKind::Tag,
                _ => return Err(ToolError::invalid("invalid_target_kind")),
            },
            metadata: TagMetadata {
                tagger: {
                    let value = mutations::required(args, "tagger")?;
                    if value.len() > MAX_TAG_IDENTITY_BYTES {
                        return Err(ToolError::invalid("invalid_tag_command"));
                    }
                    value.to_owned()
                },
                timestamp: mutations::number(args, "timestamp")?,
                message: unhex(mutations::required(args, "message_hex")?, MAX_MESSAGE_BYTES)?,
            },
        },
        _ => return Err(ToolError::invalid("invalid_tag_operation")),
    };
    let prepared = command
        .prepare(format)
        .map_err(|_| ToolError::invalid("invalid_tag_command"))?;
    Ok(Mutation {
        key,
        command,
        reference_command: prepared.command,
    })
}

fn string_schema(maximum: usize, description: &str) -> Value {
    object([
        ("type", text("string")),
        ("maxLength", json::number(maximum as u64)),
        ("description", text(description)),
    ])
}

fn oid_schema() -> Value {
    object([
        ("type", text("string")),
        ("maxLength", json::number(64)),
        ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
        (
            "description",
            text("Exact nonzero native object ID in the launch-bound hash domain."),
        ),
    ])
}

pub(super) fn schema(name: &str) -> Value {
    let mut properties = Object::new();
    properties.insert("reference".into(), string_schema(MAX_REF_NAME_LEN,
        "Full UTF-8 refs/tags/* name. Supply exactly one of reference and reference_hex; native byte limits apply."));
    properties.insert("reference_hex".into(), object([
        ("type", text("string")),
        ("maxLength", json::number((MAX_REF_NAME_LEN * 2) as u64)),
        ("pattern", text("^(?:[0-9a-f]{2})+$")),
        ("description", text("Exact raw refs/tags/* bytes in lowercase hex; mutually exclusive with reference.")),
    ]));
    let mut required = Vec::new();
    if name == INSPECT {
        properties.insert(
            "expected_head".into(),
            string_schema(
                140,
                "Optional exact current snapshot token; refuse a moved authority head.",
            ),
        );
        properties.insert("expected_object".into(), oid_schema());
        let limits = default_limits();
        for (field, maximum) in [
            ("max_tags", limits.max_tags),
            ("max_object_bytes", limits.max_object_bytes),
            ("max_total_bytes", limits.max_total_bytes),
        ] {
            properties.insert(field.into(), object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(maximum as u64)),
                ("default", json::number(maximum as u64)),
                ("description", text("May only narrow this interface's native read ceiling; the terminal non-tag object also consumes bytes.")),
            ]));
        }
    } else {
        let mut key = mutations::key_schema();
        if let Value::Object(fields) = &mut key {
            fields.insert("description".into(), text("Original client-selected printable ASCII key. Retry only the identical operation and all original tag operands, including exact target or deletion tip and metadata. JSON-RPC IDs do not change this durable key."));
        }
        properties.insert("idempotency_key".into(), key);
        let pin = if name == DELETE {
            "expected_object"
        } else {
            "target"
        };
        properties.insert(pin.into(), oid_schema());
        required.extend(["idempotency_key", pin]);
        if name == ANNOTATE {
            properties.insert(
                "target_kind".into(),
                object([
                    ("type", text("string")),
                    (
                        "enum",
                        Value::Array(["commit", "tree", "blob", "tag"].map(text).into()),
                    ),
                ]),
            );
            properties.insert("tagger".into(), string_schema(MAX_TAG_IDENTITY_BYTES,
                "Explicit native Name <email> metadata; never an authenticated principal. UTF-8 byte limit is enforced."));
            properties.insert("timestamp".into(), object([
                ("type", text("string")),
                ("pattern", text("^(0|[1-9][0-9]*)$")),
                ("maxLength", json::number(19)),
                ("description", text("Explicit UTC Unix seconds from 0 through 9223372036854775807; no ambient clock.")),
            ]));
            properties.insert("message_hex".into(), object([
                ("type", text("string")),
                ("maxLength", json::number((MAX_MESSAGE_BYTES * 2) as u64)),
                ("pattern", text("^(?:[0-9a-f]{2})*$")),
                ("description", text("Exact message bytes, at most 8192 decoded bytes; empty is valid, NUL refuses. No trimming or newline insertion.")),
            ]));
            required.extend(["target_kind", "tagger", "timestamp", "message_hex"]);
        }
    }
    let mut result = mutations::input_schema(properties, &required);
    if let Value::Object(fields) = &mut result {
        fields.insert(
            "oneOf".into(),
            Value::Array(
                [
                    object([("required", Value::Array(vec![text("reference")]))]),
                    object([("required", Value::Array(vec![text("reference_hex")]))]),
                ]
                .into(),
            ),
        );
    }
    result
}
