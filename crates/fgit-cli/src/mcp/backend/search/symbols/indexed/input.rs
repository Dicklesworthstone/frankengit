//! Mode-specific closed arguments. A minimum generation is only an ancestry
//! floor; the native symbol owner does not offer exact selection or cursors.
use super::*;
use fgit_types::DigestBytes;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    Exact,
    Current,
}
impl Mode {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Exact => "indexed-exact",
            Self::Current => "indexed-current",
        }
    }
}

pub(super) struct Input {
    pub selected: Selection,
    pub query: SymbolQuery,
    pub mode: Mode,
    pub minimum: Option<GenerationActivation>,
    pub maximum_payload_bytes: usize,
}

pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(
        args,
        &[
            "reference",
            "name",
            "match",
            "kinds",
            "path_prefixes_hex",
            "expected_head",
            "expected_commit",
            "max_matches",
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_work",
            "source_mode",
            "max_payload_bytes",
            "minimum_index_token",
            "minimum_index_number",
        ],
    )?;
    let mode = match string(args, "source_mode")? {
        Some("indexed-exact") => Mode::Exact,
        Some("indexed-current") => Mode::Current,
        _ => return Err(ToolError::invalid("invalid_symbol_source_mode")),
    };
    let (selected, query) = parse_query(args, format)?;
    let maximum_payload_bytes = args
        .get("max_payload_bytes")
        .map(|value| value.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?
        .unwrap_or(DEFAULT_PAYLOAD_BYTES as u64);
    if !(1..=data::MAX_INDEX_BYTES as u64).contains(&maximum_payload_bytes) {
        return Err(ToolError::invalid("invalid_limit"));
    }
    let minimum = minimum(args)?;
    Ok(Input {
        selected,
        query,
        mode,
        minimum,
        maximum_payload_bytes: maximum_payload_bytes as usize,
    })
}

fn minimum(args: &Object) -> Result<Option<GenerationActivation>, ToolError> {
    let (Some(token), Some(number)) = (
        string(args, "minimum_index_token")?,
        string(args, "minimum_index_number")?,
    ) else {
        return if args.contains_key("minimum_index_token")
            || args.contains_key("minimum_index_number")
        {
            Err(ToolError::invalid("incomplete_index_generation"))
        } else {
            Ok(None)
        };
    };
    let bad = || ToolError::invalid("invalid_index_generation");
    let algorithm = fgit_crypto::internal_algorithm_id(fgit_crypto::IdentityDomain::Generation);
    let prefix = format!("alg:{}:", algorithm.code_point());
    if token.len() > 140 || number.len() > 20 {
        return Err(bad());
    }
    let bytes = unhex(token.strip_prefix(&prefix).ok_or_else(bad)?, 64).map_err(|_| bad())?;
    let id = GenerationId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&bytes).map_err(|_| bad())?,
    );
    if !valid_generation(id.as_internal_object_id()) {
        return Err(bad());
    }
    let number = json::decimal(number).map_err(|_| bad())?;
    let authority_generation = HeadGeneration::try_new(number).map_err(|_| bad())?;
    Ok(Some(GenerationActivation {
        generation_id: id,
        authority_generation,
    }))
}

pub(super) fn schema(mut properties: Object) -> Value {
    properties.insert("source_mode".into(), object([
        ("type", text("string")), ("const", text("scan")), ("default", text("scan")),
        ("description", text("Direct source scan; omitted mode preserves the original behavior. Indexed-only arguments are refused.")),
    ]));
    let scan = object_schema(properties.clone(), &["reference", "name"]);
    properties.insert("source_mode".into(), object([
        ("type", text("string")),
        ("enum", Value::Array(vec![text("indexed-exact"), text("indexed-current")])),
        ("description", text("Explicit persisted read under an ordinary source grant. Exact requires the original source authority; current independently revalidates the visible native commit/tree while retaining indexed provenance. No refresh or scan fallback.")),
    ]));
    properties.insert("max_payload_bytes".into(), object([
        ("type", text("integer")), ("minimum", json::number(1)),
        ("maximum", json::number(data::MAX_INDEX_BYTES as u64)),
        ("default", json::number(DEFAULT_PAYLOAD_BYTES as u64)),
        ("description", text("Aggregate persisted manifest, name-directory and declaration-table bytes; independent of referenced source-byte and work limits.")),
    ]));
    properties.insert("minimum_index_token".into(), object([
        ("type", text("string")), ("minLength", json::number(1)), ("maxLength", json::number(140)),
        ("description", text("Retained algorithm-qualified generation identity, paired with minimum_index_number. An ancestry floor, not an exact generation selector, retention pin or cursor.")),
    ]));
    properties.insert(
        "minimum_index_number".into(),
        object([
            ("type", text("string")),
            ("minLength", json::number(1)),
            ("maxLength", json::number(20)),
            ("pattern", text("^[1-9][0-9]*$")),
            (
                "description",
                text("Positive decimal u64 generation number paired with minimum_index_token."),
            ),
        ]),
    );
    let Value::Object(mut indexed) =
        object_schema(properties.clone(), &["reference", "name", "source_mode"])
    else {
        unreachable!()
    };
    indexed.insert(
        "dependentRequired".into(),
        object([
            (
                "minimum_index_token",
                Value::Array(vec![text("minimum_index_number")]),
            ),
            (
                "minimum_index_number",
                Value::Array(vec![text("minimum_index_token")]),
            ),
        ]),
    );
    properties.insert(
        "source_mode".into(),
        object([
            ("type", text("string")),
            (
                "enum",
                Value::Array(vec![
                    text("scan"),
                    text("indexed-exact"),
                    text("indexed-current"),
                ]),
            ),
            ("default", text("scan")),
        ]),
    );
    let Value::Object(mut combined) = object_schema(properties, &["reference", "name"]) else {
        unreachable!()
    };
    combined.insert(
        "oneOf".into(),
        Value::Array(vec![scan, Value::Object(indexed)]),
    );
    Value::Object(combined)
}
