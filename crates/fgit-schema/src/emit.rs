//! Deterministic emitters for the generated artifacts.
//!
//! Three languages, one descriptor set, and no input other than
//! [`crate::registry::DESCRIBED`]. Nothing here reads the clock, the
//! filesystem, the environment, or a hash map, so the same descriptors always
//! produce the same bytes — which is the property the staleness gate checks.
//!
//! Each emitter builds a `Vec<String>` of lines and joins them. That keeps the
//! line structure of the output visible in the source that produces it, and it
//! means an emitter cannot accidentally depend on partial state.
//!
//! # The `u64` decision, which is the one that matters
//!
//! Every monotone counter in the canonical vocabulary is a `u64`. JavaScript's
//! `Number` is an IEEE-754 double, so it represents integers exactly only up to
//! 2^53 - 1. Emitting `number` for a `u64` would silently round a large
//! sequence number in the `TypeScript` client and in any JSON parsed by one.
//!
//! So `u64` is emitted as a **decimal string** in JSON Schema and
//! `TypeScript`, and as `int` in Python, whose integers are arbitrary
//! precision. The narrower widths (`u16`, `u32`) fit in a double exactly and
//! stay numeric. This is a correctness choice, not a style one: a client that
//! receives `repository_sequence` as a `number` cannot round-trip it.

use crate::descriptor::{
    Cardinality, FieldDescriptor, FieldType, ScalarWidth, SchemaDescriptor, StructureDescriptor,
    UnionDescriptor,
};
use crate::registry::{DESCRIBED, STRUCTURES, UNIONS};

/// Header stamped on every generated artifact.
///
/// Deliberately carries no timestamp, no hostname and no tool version: any of
/// those would make byte-identical regeneration impossible and turn the
/// staleness gate into a clock comparison.
const BANNER_LINES: &[&str] = &[
    "GENERATED FILE - DO NOT EDIT.",
    "",
    "Produced by `cargo run -p fgit-schema --bin fgit-schema-gen -- generate`.",
    "The generator is a repository-owned command: no build script, no proc",
    "macro, no network. `... -- check` refuses if this file differs from what",
    "the current descriptors produce, so an edit here fails the fast lane",
    "instead of drifting.",
];

/// `PascalCase` name for a schema's generated type.
fn type_name(schema: &SchemaDescriptor) -> String {
    let mut out = String::new();
    let mut upper_next = true;
    for character in schema.artifact_stem().chars() {
        if character == '-' {
            upper_next = true;
        } else if upper_next {
            out.extend(character.to_uppercase());
            upper_next = false;
        } else {
            out.push(character);
        }
    }
    out
}

/// The generated type name a `Structure` or `Union` reference resolves to.
///
/// A reference to a canonical body uses that body's VERSIONED name (`RcrV1`),
/// because a v2 would generate a second type beside it and a reference has to
/// say which one it means. A nested structure has no version, so it is just
/// `PascalCase`.
fn reference_type_name(name: &str) -> String {
    if let Some(body) = DESCRIBED.iter().find(|entry| entry.family == name) {
        return type_name(body);
    }
    let mut out = String::new();
    let mut upper_next = true;
    for character in name.chars() {
        if character == '-' {
            upper_next = true;
        } else if upper_next {
            out.extend(character.to_uppercase());
            upper_next = false;
        } else {
            out.push(character);
        }
    }
    out
}

/// Where a `Structure` or `Union` reference resolves inside the document.
///
/// The two kinds live in different containers, so a single hardcoded prefix is
/// wrong for one of them: canonical bodies are emitted as top-level
/// `properties`, while nested structures and unions are emitted into `$defs`. A
/// `$ref` naming the wrong container points at nothing, and no amount of
/// byte-level staleness checking can detect that.
fn json_pointer(name: &str) -> String {
    let rendered = reference_type_name(name);
    if DESCRIBED.iter().any(|entry| entry.family == name) {
        format!("#/properties/{rendered}")
    } else {
        format!("#/$defs/{rendered}")
    }
}

/// Minimal JSON string escaping, sufficient for the ASCII docs and names here.
///
/// Every input is a `&'static str` from a descriptor, so this is a formatter
/// rather than a parser boundary and has nothing to refuse.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let escaped = format!("\\u{:04x}", control as u32);
                out.push_str(&escaped);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

// ------------------------------------------------------------------ JSON Schema

/// JSON Schema lines for one field's value, each already indented by `pad`.
fn json_type_lines(ty: FieldType, pad: &str) -> Vec<String> {
    let inner = format!("{pad}  ");
    match ty {
        FieldType::Scalar(ScalarWidth::U64) => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"string\","),
            format!("{inner}\"pattern\": \"^(0|[1-9][0-9]*)$\","),
            format!(
                "{inner}\"description\": \"u64 as a decimal string; outside the exact range of an IEEE-754 double\""
            ),
            format!("{pad}}}"),
        ],
        FieldType::Scalar(width) => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"integer\","),
            format!("{inner}\"minimum\": 0,"),
            format!("{inner}\"maximum\": {}", width.max_value()),
            format!("{pad}}}"),
        ],
        FieldType::OpaqueId => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"string\","),
            format!("{inner}\"pattern\": \"^[0-9a-f]{{32}}$\","),
            format!("{inner}\"description\": \"16 raw bytes, lowercase hex\""),
            format!("{pad}}}"),
        ],
        FieldType::Digest => vec!["{ \"$ref\": \"#/$defs/Digest\" }".to_owned()],
        FieldType::DerivedId { domain } => vec![
            "{".to_owned(),
            format!("{inner}\"allOf\": [{{ \"$ref\": \"#/$defs/DerivedId\" }}],"),
            format!("{inner}\"description\": \"domain-bound derived identity: {domain}\""),
            format!("{pad}}}"),
        ],
        FieldType::SchemaId => vec!["{ \"$ref\": \"#/$defs/SchemaId\" }".to_owned()],
        FieldType::Text { max_len } => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"string\","),
            format!("{inner}\"maxLength\": {max_len}"),
            format!("{pad}}}"),
        ],
        FieldType::Bytes { min_len, max_len } => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"string\","),
            format!("{inner}\"pattern\": \"^[0-9a-f]*$\","),
            format!("{inner}\"minLength\": {},", min_len.saturating_mul(2)),
            format!("{inner}\"maxLength\": {}", max_len.saturating_mul(2)),
            format!("{pad}}}"),
        ],
        FieldType::GitOid => vec!["{ \"$ref\": \"#/$defs/GitOid\" }".to_owned()],
        FieldType::CodePoint { vocabulary } => vec![
            "{".to_owned(),
            format!("{inner}\"type\": \"integer\","),
            format!("{inner}\"minimum\": 0,"),
            format!("{inner}\"maximum\": 65535,"),
            format!(
                "{inner}\"description\": \"code point from the closed {vocabulary} vocabulary\""
            ),
            format!("{pad}}}"),
        ],
        FieldType::Structure { name } | FieldType::Union { name } => {
            vec![format!("{{ \"$ref\": \"{}\" }}", json_pointer(name))]
        }
    }
}

/// The `type`/`required`/`properties` block shared by bodies and structures.
///
/// Extracted from `json_schema` verbatim so a nested structure is described
/// exactly the way a top-level body is. If the two ever diverge, a consumer
/// validating a nested object would apply different rules to the same bytes.
fn json_object_lines(fields: &[FieldDescriptor]) -> Vec<String> {
    let mut lines = vec![
        "      \"type\": \"object\",".to_owned(),
        "      \"additionalProperties\": false,".to_owned(),
    ];
    let required: Vec<String> = fields
        .iter()
        .filter(|field| field.cardinality == Cardinality::Required)
        .map(|field| json_string(field.name))
        .collect();
    lines.push(format!("      \"required\": [{}],", required.join(", ")));
    lines.push("      \"properties\": {".to_owned());
    for (field_index, field) in fields.iter().enumerate() {
        let field_last = field_index + 1 == fields.len();
        let field_comma = if field_last { "" } else { "," };
        let mut body = json_type_lines(field.ty, "        ");
        if field.cardinality.is_sequence() {
            // A counted repetition on the wire is an array in JSON Schema.
            // The count prefix itself is not represented: it is framing,
            // and a client reconstructs it from the array length.
            let inner: Vec<String> = body.iter().map(|line| format!("  {line}")).collect();
            let mut wrapped = vec!["{".to_owned(), "          \"type\": \"array\",".to_owned()];
            wrapped.push(format!("          \"items\": {}", inner[0].trim_start()));
            for line in &inner[1..] {
                wrapped.push(line.clone());
            }
            wrapped.push("        }".to_owned());
            body = wrapped;
        }
        let head = format!("        {}: {}", json_string(field.name), body[0]);
        if body.len() == 1 {
            lines.push(format!("{head}{field_comma}"));
        } else {
            lines.push(head);
            for tail in &body[1..body.len() - 1] {
                lines.push(tail.clone());
            }
            lines.push(format!("{}{field_comma}", body[body.len() - 1]));
        }
    }
    lines.push("      }".to_owned());
    lines
}

/// Shifts a rendered block right, for nesting a variant inside `oneOf`.
fn shifted(lines: &[String], by: usize) -> Vec<String> {
    let pad = " ".repeat(by);
    lines.iter().map(|line| format!("{pad}{line}")).collect()
}

/// One `$defs` entry for a nested structure.
fn json_structure_def(structure: &StructureDescriptor) -> Vec<String> {
    let mut lines = vec![
        format!(
            "    {}: {{",
            json_string(&reference_type_name(structure.name))
        ),
        format!("      \"description\": {},", json_string(structure.doc)),
    ];
    lines.extend(json_object_lines(structure.fields));
    lines.push("    }".to_owned());
    lines
}

/// One `$defs` entry for a tagged union, as a `oneOf` over its variants.
///
/// The discriminant is emitted as a `const`, so the schema pins the exact wire
/// byte rather than merely noting that a tag exists. A consumer that validates
/// against this cannot accept a variant whose tag does not match its shape.
fn json_union_def(union: &UnionDescriptor) -> Vec<String> {
    let mut lines = vec![
        format!("    {}: {{", json_string(&reference_type_name(union.name))),
        format!("      \"description\": {},", json_string(union.doc)),
        "      \"oneOf\": [".to_owned(),
    ];
    for (index, variant) in union.variants.iter().enumerate() {
        let comma = if index + 1 == union.variants.len() {
            ""
        } else {
            ","
        };
        let mut block = vec![
            "    {".to_owned(),
            format!("      \"description\": {},", json_string(variant.doc)),
            "      \"type\": \"object\",".to_owned(),
            "      \"additionalProperties\": false,".to_owned(),
        ];
        let mut required = vec![json_string("variant"), json_string("discriminant")];
        required.extend(
            variant
                .fields
                .iter()
                .filter(|field| field.cardinality == Cardinality::Required)
                .map(|field| json_string(field.name)),
        );
        block.push(format!("      \"required\": [{}],", required.join(", ")));
        block.push("      \"properties\": {".to_owned());
        block.push(format!(
            "        \"variant\": {{ \"const\": {} }},",
            json_string(variant.name)
        ));
        let tail_comma = if variant.fields.is_empty() { "" } else { "," };
        block.push(format!(
            "        \"discriminant\": {{ \"const\": {} }}{tail_comma}",
            variant.discriminant
        ));
        if !variant.fields.is_empty() {
            let rendered = json_object_lines(variant.fields);
            // Skip the type/additionalProperties/required/properties header the
            // helper emits and take only the property lines it produced.
            let start = rendered
                .iter()
                .position(|line| line.trim() == "\"properties\": {")
                .expect("the helper always emits a properties block")
                + 1;
            for line in &rendered[start..rendered.len() - 1] {
                block.push(line.clone());
            }
        }
        block.push("      }".to_owned());
        block.push(format!("    }}{comma}"));
        lines.extend(shifted(&block, 4));
    }
    lines.push("      ]".to_owned());
    lines.push("    }".to_owned());
    lines
}

/// The shared definitions every schema references.
fn json_defs_lines() -> Vec<String> {
    let mut shared = vec![
        "  \"$defs\": {".to_owned(),
        "    \"Digest\": {".to_owned(),
        "      \"type\": \"object\",".to_owned(),
        "      \"additionalProperties\": false,".to_owned(),
        "      \"required\": [\"algorithm\", \"bytes\"],".to_owned(),
        "      \"properties\": {".to_owned(),
        "        \"algorithm\": { \"type\": \"integer\", \"minimum\": 1, \"maximum\": 65535 },"
            .to_owned(),
        "        \"bytes\": { \"type\": \"string\", \"pattern\": \"^[0-9a-f]{32,128}$\" }"
            .to_owned(),
        "      }".to_owned(),
        "    },".to_owned(),
        "    \"GitOid\": {".to_owned(),
        "      \"type\": \"object\",".to_owned(),
        "      \"additionalProperties\": false,".to_owned(),
        "      \"required\": [\"algorithm\", \"bytes\"],".to_owned(),
        "      \"properties\": {".to_owned(),
        "        \"algorithm\": { \"type\": \"integer\", \"minimum\": 1, \"maximum\": 2 },"
            .to_owned(),
        "        \"bytes\": { \"type\": \"string\", \"pattern\": \"^([0-9a-f]{40}|[0-9a-f]{64})$\" }"
            .to_owned(),
        "      }".to_owned(),
        "    },".to_owned(),
        "    \"SchemaId\": {".to_owned(),
        "      \"type\": \"object\",".to_owned(),
        "      \"additionalProperties\": false,".to_owned(),
        "      \"required\": [\"family\", \"major\", \"minor\"],".to_owned(),
        "      \"properties\": {".to_owned(),
        "        \"family\": { \"type\": \"string\" },".to_owned(),
        "        \"major\": { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 65535 },"
            .to_owned(),
        "        \"minor\": { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 65535 }"
            .to_owned(),
        "      }".to_owned(),
        "    },".to_owned(),
        "    \"DerivedId\": {".to_owned(),
        "      \"type\": \"object\",".to_owned(),
        "      \"additionalProperties\": false,".to_owned(),
        "      \"required\": [\"algorithm\", \"domain\", \"codec_major\", \"codec_minor\", \"digest\"],"
            .to_owned(),
        "      \"properties\": {".to_owned(),
        "        \"algorithm\": { \"type\": \"integer\", \"minimum\": 1, \"maximum\": 65535 },"
            .to_owned(),
        "        \"domain\": { \"type\": \"string\" },".to_owned(),
        "        \"codec_major\": { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 65535 },"
            .to_owned(),
        "        \"codec_minor\": { \"type\": \"integer\", \"minimum\": 0, \"maximum\": 65535 },"
            .to_owned(),
        "        \"digest\": { \"type\": \"string\", \"pattern\": \"^[0-9a-f]{32,128}$\" }"
            .to_owned(),
        "      }".to_owned(),
        "    }".to_owned(),
    ];

    // Nested structures and unions are DEFINED here, not merely referenced.
    // A `$ref` to a name with no definition makes the document unusable, and
    // the staleness gate cannot see that: it compares bytes to bytes.
    let mut blocks: Vec<Vec<String>> = STRUCTURES.iter().copied().map(json_structure_def).collect();
    blocks.extend(UNIONS.iter().copied().map(json_union_def));
    for block in blocks {
        // The previous entry now has a sibling, so it needs its comma.
        let last = shared.len() - 1;
        shared[last] = format!("{},", shared[last]);
        shared.extend(block);
    }

    shared.push("  },".to_owned());
    shared
}

/// The complete JSON Schema document.
#[must_use]
pub fn json_schema() -> String {
    let mut lines = vec![
        "{".to_owned(),
        "  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",".to_owned(),
        "  \"$id\": \"https://frankengit.invalid/schemas/canonical-bodies.json\",".to_owned(),
        "  \"title\": \"FrankenGit canonical bodies\",".to_owned(),
        format!(
            "  \"description\": {},",
            json_string(&BANNER_LINES.join(" "))
        ),
    ];
    lines.extend(json_defs_lines());
    lines.push("  \"properties\": {".to_owned());
    for (index, schema) in DESCRIBED.iter().enumerate() {
        let last = index + 1 == DESCRIBED.len();
        let comma = if last { "" } else { "," };
        lines.push(format!("    {}: {{", json_string(&type_name(schema))));
        lines.push(format!(
            "      \"description\": {},",
            json_string(schema.doc)
        ));
        lines.push(format!(
            "      \"x-schema\": {{ \"family\": {}, \"major\": {}, \"minor\": {}, \"domain\": {} }},",
            json_string(schema.family),
            schema.major,
            schema.minor,
            json_string(schema.domain)
        ));
        lines.extend(json_object_lines(schema.fields));
        lines.push(format!("    }}{comma}"));
    }
    lines.push("  }".to_owned());
    lines.push("}".to_owned());
    lines.join("\n") + "\n"
}

// ------------------------------------------------------------------ TypeScript

/// Whether a scalar of this width survives a round trip through a JavaScript
/// `Number`.
///
/// A named predicate rather than a match arm on purpose. Merging the `u64`
/// case into the other string-typed fields produces identical output and
/// destroys the reason: those are strings because they ARE text, and a `u64`
/// is a string because an IEEE-754 double cannot hold it. One is a mapping,
/// the other is a correctness constraint, and only this one is worth a test.
#[must_use]
pub const fn fits_js_number(width: ScalarWidth) -> bool {
    // 2^53 - 1 is the largest integer a double represents exactly, so the
    // admissible maxima are strictly below 2^53.
    width.max_value() < (1_u64 << 53)
}

/// `TypeScript` type for one field.
const fn ts_type(ty: FieldType) -> &'static str {
    match ty {
        FieldType::Scalar(width) => {
            if fits_js_number(width) {
                "number"
            } else {
                "string"
            }
        }
        FieldType::CodePoint { .. } => "number",
        FieldType::OpaqueId | FieldType::Text { .. } | FieldType::Bytes { .. } => "string",
        FieldType::Digest => "Digest",
        FieldType::GitOid => "GitOid",
        FieldType::DerivedId { .. } => "DerivedId",
        FieldType::SchemaId => "SchemaId",
        // References carry a name, so they need an allocation the caller owns.
        FieldType::Structure { .. } | FieldType::Union { .. } => "",
    }
}

/// `TypeScript` type for one field, resolving references by name.
fn ts_field_type(ty: FieldType) -> String {
    match ty {
        FieldType::Structure { name } | FieldType::Union { name } => reference_type_name(name),
        other => ts_type(other).to_owned(),
    }
}

/// The `TypeScript` field list for a structure or union variant.
fn ts_fields(fields: &[FieldDescriptor]) -> Vec<String> {
    let mut lines = Vec::new();
    for field in fields {
        lines.push(format!("  /** {} */", field.doc));
        let optional = if field.cardinality.is_optional() {
            "?"
        } else {
            ""
        };
        let mut rendered = ts_field_type(field.ty);
        if field.cardinality.is_sequence() {
            rendered = format!("{rendered}[]");
        }
        lines.push(format!("  {}{optional}: {rendered};", field.name));
    }
    lines
}

/// Interfaces for the nested structures, and discriminated unions for the
/// tagged ones.
///
/// These are DEFINITIONS. A field rendered as `decisions: RepositoryDecision[]`
/// is a dangling reference until this runs, and a `.d.ts` with a dangling
/// reference does not compile -- a failure the staleness gate cannot detect
/// because the committed bytes and the generated bytes agree perfectly.
fn ts_nested() -> Vec<String> {
    let mut lines = Vec::new();
    for structure in STRUCTURES {
        lines.push(String::new());
        lines.push(format!("/** {} */", structure.doc));
        lines.push(format!(
            "export interface {} {{",
            reference_type_name(structure.name)
        ));
        lines.extend(ts_fields(structure.fields));
        lines.push("}".to_owned());
    }
    for union in UNIONS {
        let union_name = reference_type_name(union.name);
        lines.push(String::new());
        lines.push(format!("/** {} */", union.doc));
        lines.push(format!("export type {union_name} ="));
        for (index, variant) in union.variants.iter().enumerate() {
            let terminator = if index + 1 == union.variants.len() {
                ";"
            } else {
                ""
            };
            lines.push(format!("  | {union_name}{}{terminator}", variant.name));
        }
        for variant in union.variants {
            lines.push(String::new());
            lines.push(format!("/** {} */", variant.doc));
            lines.push(format!("export interface {union_name}{} {{", variant.name));
            lines.push("  /** The raw wire byte that selects this variant. */".to_owned());
            lines.push(format!("  discriminant: {};", variant.discriminant));
            lines.extend(ts_fields(variant.fields));
            lines.push("}".to_owned());
        }
    }
    lines
}

/// The complete `TypeScript` module.
#[must_use]
pub fn typescript() -> String {
    let mut lines: Vec<String> = BANNER_LINES
        .iter()
        .map(|line| {
            if line.is_empty() {
                "//".to_owned()
            } else {
                format!("// {line}")
            }
        })
        .collect();
    lines.push(String::new());
    lines.push("/** An algorithm-tagged digest. `bytes` is lowercase hex. */".to_owned());
    lines.push("export interface Digest {".to_owned());
    lines.push("  algorithm: number;".to_owned());
    lines.push("  bytes: string;".to_owned());
    lines.push("}".to_owned());
    lines.push(String::new());
    lines.push("/** A native Git object identity. `bytes` is lowercase hex. */".to_owned());
    lines.push("export interface GitOid {".to_owned());
    lines.push("  algorithm: number;".to_owned());
    lines.push("  bytes: string;".to_owned());
    lines.push("}".to_owned());
    lines.push(String::new());
    lines.push("/** A schema identifier. */".to_owned());
    lines.push("export interface SchemaId {".to_owned());
    lines.push("  family: string;".to_owned());
    lines.push("  major: number;".to_owned());
    lines.push("  minor: number;".to_owned());
    lines.push("}".to_owned());
    lines.push(String::new());
    lines.push("/** A domain-bound derived identity. */".to_owned());
    lines.push("export interface DerivedId {".to_owned());
    lines.push("  algorithm: number;".to_owned());
    lines.push("  domain: string;".to_owned());
    lines.push("  codec_major: number;".to_owned());
    lines.push("  codec_minor: number;".to_owned());
    lines.push("  digest: string;".to_owned());
    lines.push("}".to_owned());
    lines.extend(ts_nested());

    for schema in DESCRIBED {
        lines.push(String::new());
        lines.push("/**".to_owned());
        lines.push(format!(" * {}", schema.doc));
        lines.push(" *".to_owned());
        lines.push(format!(
            " * schema {} v{}.{}, domain {}",
            schema.family, schema.major, schema.minor, schema.domain
        ));
        lines.push(" */".to_owned());
        lines.push(format!("export interface {} {{", type_name(schema)));
        lines.extend(ts_fields(schema.fields));
        lines.push("}".to_owned());
    }
    lines.join("\n") + "\n"
}

// ---------------------------------------------------------------------- Python

/// Python annotation for one field.
const fn py_type(ty: FieldType) -> &'static str {
    match ty {
        // Python integers are arbitrary precision, so a u64 stays an int.
        FieldType::Scalar(_) | FieldType::CodePoint { .. } => "int",
        FieldType::OpaqueId | FieldType::Text { .. } | FieldType::Bytes { .. } => "str",
        FieldType::Digest => "Digest",
        FieldType::GitOid => "GitOid",
        FieldType::DerivedId { .. } => "DerivedId",
        FieldType::SchemaId => "SchemaId",
        // References carry a name, so they need an allocation the caller owns.
        FieldType::Structure { .. } | FieldType::Union { .. } => "",
    }
}

/// Python annotation for one field, resolving references by name.
fn py_field_type(ty: FieldType) -> String {
    match ty {
        FieldType::Structure { name } | FieldType::Union { name } => reference_type_name(name),
        other => py_type(other).to_owned(),
    }
}

/// A frozen dataclass header plus its docstring.
fn py_dataclass(name: &str, doc: &str) -> Vec<String> {
    vec![
        "@dataclass(frozen=True, slots=True)".to_owned(),
        format!("class {name}:"),
        format!("    \"\"\"{doc}\"\"\""),
        String::new(),
    ]
}

/// Python annotations for a structure or variant field list.
fn py_fields(fields: &[FieldDescriptor]) -> Vec<String> {
    let mut lines = Vec::new();
    // Required before optional: a dataclass may not place a field without a
    // default after one with a default.
    for group in [
        Cardinality::Required,
        Cardinality::Sequence,
        Cardinality::Optional,
    ] {
        for field in fields.iter().filter(|f| f.cardinality == group) {
            lines.push(format!("    # {}", field.doc));
            let mut annotation = py_field_type(field.ty);
            if group.is_sequence() {
                annotation = format!("tuple[{annotation}, ...]");
            }
            if group.is_optional() {
                lines.push(format!("    {}: {annotation} | None = None", field.name));
            } else {
                lines.push(format!("    {}: {annotation}", field.name));
            }
        }
    }
    lines
}

/// Dataclasses for the nested structures and for each union variant, plus the
/// union alias.
///
/// Emitted BEFORE the bodies: the alias `A | B` is evaluated at import time, so
/// its members must already exist. The field annotations are lazy under
/// `from __future__ import annotations`, but the alias is not.
fn py_nested() -> Vec<String> {
    let mut lines = Vec::new();
    for structure in STRUCTURES {
        lines.push(String::new());
        lines.push(String::new());
        lines.extend(py_dataclass(
            &reference_type_name(structure.name),
            structure.doc,
        ));
        lines.extend(py_fields(structure.fields));
    }
    for union in UNIONS {
        let union_name = reference_type_name(union.name);
        for variant in union.variants {
            lines.push(String::new());
            lines.push(String::new());
            lines.extend(py_dataclass(
                &format!("{union_name}{}", variant.name),
                variant.doc,
            ));
            // A CONSTANT, not a field: an annotated attribute with a default
            // becomes a dataclass field, and a defaulted field may not precede
            // a non-default one. Unannotated, the dataclass machinery ignores
            // it and it stays the per-variant class attribute it actually is.
            lines.push("    # The raw wire byte that selects this variant.".to_owned());
            lines.push(format!("    DISCRIMINANT = {}", variant.discriminant));
            lines.extend(py_fields(variant.fields));
        }
        lines.push(String::new());
        lines.push(String::new());
        lines.push(format!("# {}", union.doc));
        let members: Vec<String> = union
            .variants
            .iter()
            .map(|variant| format!("{union_name}{}", variant.name))
            .collect();
        lines.push(format!("{union_name} = {}", members.join(" | ")));
    }
    lines
}

/// The complete Python module.
#[must_use]
pub fn python() -> String {
    let mut lines: Vec<String> = BANNER_LINES
        .iter()
        .map(|line| {
            if line.is_empty() {
                "#".to_owned()
            } else {
                format!("# {line}")
            }
        })
        .collect();
    lines.push(String::new());
    lines.push("from __future__ import annotations".to_owned());
    lines.push(String::new());
    lines.push("from dataclasses import dataclass".to_owned());
    lines.push(String::new());
    lines.push(String::new());

    lines.extend(py_dataclass(
        "Digest",
        "An algorithm-tagged digest. bytes_hex is lowercase hex.",
    ));
    lines.push("    algorithm: int".to_owned());
    lines.push("    bytes_hex: str".to_owned());
    lines.push(String::new());
    lines.push(String::new());

    lines.extend(py_dataclass(
        "GitOid",
        "A native Git object identity. bytes_hex is lowercase hex.",
    ));
    lines.push("    algorithm: int".to_owned());
    lines.push("    bytes_hex: str".to_owned());
    lines.push(String::new());
    lines.push(String::new());

    lines.extend(py_dataclass("SchemaId", "A schema identifier."));
    lines.push("    family: str".to_owned());
    lines.push("    major: int".to_owned());
    lines.push("    minor: int".to_owned());
    lines.push(String::new());
    lines.push(String::new());

    lines.extend(py_dataclass(
        "DerivedId",
        "A domain-bound derived identity.",
    ));
    lines.push("    algorithm: int".to_owned());
    lines.push("    domain: str".to_owned());
    lines.push("    codec_major: int".to_owned());
    lines.push("    codec_minor: int".to_owned());
    lines.push("    digest: str".to_owned());
    lines.extend(py_nested());

    for schema in DESCRIBED {
        lines.push(String::new());
        lines.push(String::new());
        lines.push("@dataclass(frozen=True, slots=True)".to_owned());
        lines.push(format!("class {}:", type_name(schema)));
        lines.push(format!("    \"\"\"{}", schema.doc));
        lines.push(String::new());
        lines.push(format!(
            "    schema {} v{}.{}, domain {}",
            schema.family, schema.major, schema.minor, schema.domain
        ));
        lines.push("    \"\"\"".to_owned());
        lines.push(String::new());
        // Required fields first: a Python dataclass may not place a field
        // without a default after one with a default. Wire order is preserved
        // inside each group and recorded verbatim in WIRE_ORDER below, so the
        // encoding order is never lost.
        lines.extend(py_fields(schema.fields));
    }

    lines.push(String::new());
    lines.push(String::new());
    lines.push("# Wire order per schema. The dataclasses above group required fields".to_owned());
    lines.push("# before optional ones because Python requires it; the canonical".to_owned());
    lines.push("# encoding does not, and THIS is the order the bytes are in.".to_owned());
    lines.push("WIRE_ORDER: dict[str, tuple[str, ...]] = {".to_owned());
    for schema in DESCRIBED {
        let names: Vec<String> = schema
            .fields
            .iter()
            .map(|field| format!("\"{}\"", field.name))
            .collect();
        lines.push(format!(
            "    \"{}\": ({},),",
            type_name(schema),
            names.join(", ")
        ));
    }
    lines.push("}".to_owned());
    lines.join("\n") + "\n"
}

/// The workflow construct registry as a JSON document.
///
/// ADR-0008 D12 requires a measured per-construct table rather than a blanket
/// compatibility claim, and requires it to be readable by something other than
/// a human scrolling source. Emitting it here puts it under the same staleness
/// gate as everything else: a construct whose status changes without the
/// artifact changing is a failed fast lane, not a stale doc.
#[must_use]
pub fn workflow_registry() -> String {
    use crate::workflow::registry::{CONSTRUCTS, tally};

    let mut lines = vec![
        "{".to_owned(),
        "  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",".to_owned(),
        "  \"$id\": \"https://frankengit.invalid/schemas/workflow-constructs.json\",".to_owned(),
        "  \"title\": \"FrankenGit workflow construct registry\",".to_owned(),
        format!(
            "  \"description\": {},",
            json_string(
                "Per-construct status for the GitHub-Actions subset. ADR-0008 D12: a measured registry, not a blanket compatibility claim. A construct marked unsupported or ambiguous is REFUSED at validation, never ignored."
            )
        ),
    ];
    for (status, count) in tally() {
        lines.push(format!("  \"count_{}\": {count},", status.as_str()));
    }
    lines.push("  \"constructs\": [".to_owned());
    for (index, entry) in CONSTRUCTS.iter().enumerate() {
        let comma = if index + 1 == CONSTRUCTS.len() {
            ""
        } else {
            ","
        };
        lines.push("    {".to_owned());
        lines.push(format!("      \"key\": {},", json_string(entry.key)));
        lines.push(format!(
            "      \"status\": {},",
            json_string(entry.status.as_str())
        ));
        lines.push(format!("      \"refuses\": {},", entry.status.refuses()));
        lines.push(format!("      \"reason\": {}", json_string(entry.reason)));
        lines.push(format!("    }}{comma}"));
    }
    lines.push("  ]".to_owned());
    lines.push("}".to_owned());
    lines.join("\n") + "\n"
}

/// One generated artifact: its file name and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    /// File name inside the generated directory.
    pub name: &'static str,
    /// Complete file contents.
    pub contents: String,
}

/// Every artifact the generator produces, in a fixed order.
#[must_use]
pub fn artifacts() -> Vec<Artifact> {
    vec![
        Artifact {
            name: "canonical-bodies.schema.json",
            contents: json_schema(),
        },
        Artifact {
            name: "canonical_bodies.ts",
            contents: typescript(),
        },
        Artifact {
            name: "canonical_bodies.py",
            contents: python(),
        },
        Artifact {
            name: "workflow-constructs.json",
            contents: workflow_registry(),
        },
    ]
}

/// A field's one-line summary, used by diagnostics and by the conformance test.
#[must_use]
pub fn field_summary(field: &FieldDescriptor) -> String {
    format!(
        "{} ({}, {}): {}",
        field.name,
        field.ty.as_str(),
        field.cardinality.as_str(),
        field.ty.wire_encoding()
    )
}
