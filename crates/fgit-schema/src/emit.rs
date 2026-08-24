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

use crate::descriptor::{Cardinality, FieldDescriptor, FieldType, ScalarWidth, SchemaDescriptor};
use crate::registry::DESCRIBED;

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
    }
}

/// The shared definitions every schema references.
fn json_defs_lines() -> Vec<String> {
    vec![
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
        "  },".to_owned(),
    ]
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
        lines.push("      \"type\": \"object\",".to_owned());
        lines.push("      \"additionalProperties\": false,".to_owned());
        let required: Vec<String> = schema
            .fields
            .iter()
            .filter(|field| field.cardinality == Cardinality::Required)
            .map(|field| json_string(field.name))
            .collect();
        lines.push(format!("      \"required\": [{}],", required.join(", ")));
        lines.push("      \"properties\": {".to_owned());
        for (field_index, field) in schema.fields.iter().enumerate() {
            let field_last = field_index + 1 == schema.fields.len();
            let field_comma = if field_last { "" } else { "," };
            let body = json_type_lines(field.ty, "        ");
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
        FieldType::OpaqueId | FieldType::Text { .. } => "string",
        FieldType::Digest => "Digest",
        FieldType::DerivedId { .. } => "DerivedId",
        FieldType::SchemaId => "SchemaId",
    }
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
        for field in schema.fields {
            lines.push(format!("  /** {} */", field.doc));
            let optional = if field.cardinality.is_optional() {
                "?"
            } else {
                ""
            };
            lines.push(format!(
                "  {}{optional}: {};",
                field.name,
                ts_type(field.ty)
            ));
        }
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
        FieldType::OpaqueId | FieldType::Text { .. } => "str",
        FieldType::Digest => "Digest",
        FieldType::DerivedId { .. } => "DerivedId",
        FieldType::SchemaId => "SchemaId",
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
        for group in [Cardinality::Required, Cardinality::Optional] {
            for field in schema.fields.iter().filter(|f| f.cardinality == group) {
                lines.push(format!("    # {}", field.doc));
                let annotation = py_type(field.ty);
                if group.is_optional() {
                    lines.push(format!("    {}: {annotation} | None = None", field.name));
                } else {
                    lines.push(format!("    {}: {annotation}", field.name));
                }
            }
        }
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
