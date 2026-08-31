//! Workspace-wide canonical-body description coverage.
//!
//! `fgit-schema` is L2 and must not import L3/L4 body owners merely to learn
//! their schemas.  Instead each owning workspace crate commits a small
//! `canonical-bodies.tsv` manifest beside its `Cargo.toml`.  This module uses
//! `cargo metadata` only to enumerate those owners, then compares each
//! manifest with the `CanonicalBody` implementations in that same crate.
//!
//! The manifests are deliberately *descriptions*, not another encoder or a
//! generated Rust type.  The owning implementation remains the only source
//! of canonical bytes; this check makes an undocumented schema-family literal
//! a refusal rather than a silent hole in the schema-generation lane.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::SchemaRefusal;

/// File every canonical-body-owning crate commits beside its manifest.
pub const DESCRIPTION_MANIFEST: &str = "canonical-bodies.tsv";

/// The repository root inferred from this crate's fixed workspace position.
#[must_use]
pub fn default_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fgit-schema sits directly under the workspace crates directory")
        .to_path_buf()
}

/// Refuses unless every workspace `CanonicalBody` family has the owning
/// crate's non-empty, committed byte description.
///
/// `workspace_root` is explicit so the negative test can use a detached
/// probe workspace.  The production binary supplies [`default_workspace_root`].
pub fn check_workspace_descriptions(workspace_root: &Path) -> Result<(), SchemaRefusal> {
    let mut descriptions_by_family = BTreeMap::<String, (String, PathBuf)>::new();

    for crate_root in workspace_crates(workspace_root)? {
        let crate_name = crate_root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("cargo metadata emitted a UTF-8 fgit crate directory")
            .to_owned();
        let source_families = source_families(&crate_root)?;
        if source_families.is_empty() {
            continue;
        }

        let manifest = crate_root.join(DESCRIPTION_MANIFEST);
        if !manifest.is_file() {
            return Err(SchemaRefusal::CanonicalBodyDescriptionManifestMissing {
                crate_name: crate_name.into(),
                manifest: display_path(&manifest).into(),
            });
        }
        let descriptions = read_manifest(&manifest)?;

        for (family, source) in &source_families {
            if !descriptions.contains_key(family) {
                return Err(SchemaRefusal::CanonicalBodyDescriptionMissing {
                    crate_name: crate_name.into(),
                    source: display_path(source).into(),
                    family: family.clone().into(),
                });
            }
        }
        for family in descriptions.keys() {
            if !source_families.contains_key(family) {
                return Err(SchemaRefusal::CanonicalBodyDescriptionPhantom {
                    crate_name: crate_name.into(),
                    manifest: display_path(&manifest).into(),
                    family: family.clone().into(),
                });
            }
        }
        for (family, description) in descriptions {
            if let Some((known, known_manifest)) = descriptions_by_family.get(&family) {
                if known != &description {
                    return Err(SchemaRefusal::CanonicalBodyDescriptionConflicting {
                        family: family.into(),
                        first_manifest: display_path(known_manifest).into(),
                        second_manifest: display_path(&manifest).into(),
                    });
                }
            } else {
                descriptions_by_family.insert(family, (description, manifest.clone()));
            }
        }
    }

    Ok(())
}

fn workspace_crates(workspace_root: &Path) -> Result<Vec<PathBuf>, SchemaRefusal> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .current_dir(workspace_root)
        .output()
        .map_err(|error| SchemaRefusal::WorkspaceMetadataFailed {
            root: display_path(workspace_root).into(),
            detail: error.to_string().into(),
        })?;
    if !output.status.success() {
        return Err(SchemaRefusal::WorkspaceMetadataFailed {
            root: display_path(workspace_root).into(),
            detail: String::from_utf8_lossy(&output.stderr).trim().into(),
        });
    }

    let metadata = String::from_utf8_lossy(&output.stdout);
    let mut manifests = Vec::new();
    let mut remaining = metadata.as_ref();
    const MANIFEST_PATH: &str = "\"manifest_path\":\"";
    while let Some(offset) = remaining.find(MANIFEST_PATH) {
        remaining = &remaining[offset + MANIFEST_PATH.len()..];
        let Some(end) = remaining.find('"') else {
            return Err(SchemaRefusal::WorkspaceMetadataFailed {
                root: display_path(workspace_root).into(),
                detail: "cargo metadata returned an unterminated manifest path".into(),
            });
        };
        manifests.push(PathBuf::from(&remaining[..end]));
        remaining = &remaining[end + 1..];
    }
    if manifests.is_empty() {
        return Err(SchemaRefusal::WorkspaceMetadataFailed {
            root: display_path(workspace_root).into(),
            detail: "cargo metadata returned no workspace manifest paths".into(),
        });
    }

    manifests.sort();
    manifests.dedup();
    Ok(manifests
        .into_iter()
        .filter_map(|manifest| manifest.parent().map(Path::to_path_buf))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("fgit-"))
        })
        .collect())
}

fn read_manifest(manifest: &Path) -> Result<BTreeMap<String, String>, SchemaRefusal> {
    let content =
        fs::read_to_string(manifest).map_err(|error| SchemaRefusal::WorkspaceMetadataFailed {
            root: display_path(manifest).into(),
            detail: error.to_string().into(),
        })?;
    let mut descriptions = BTreeMap::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((family, description)) = raw_line.split_once('\t') else {
            return Err(manifest_malformed(
                manifest,
                line,
                "expected family, tab, description",
            ));
        };
        if description.contains('\t') {
            return Err(manifest_malformed(
                manifest,
                line,
                "a description is one TSV field and cannot contain another tab",
            ));
        }
        let family = family.trim();
        let description = description.trim();
        if family.is_empty() || description.is_empty() {
            return Err(manifest_malformed(
                manifest,
                line,
                "family and description must both be non-empty",
            ));
        }
        if descriptions
            .insert(family.to_owned(), description.to_owned())
            .is_some()
        {
            return Err(SchemaRefusal::CanonicalBodyDescriptionDuplicated {
                manifest: display_path(manifest).into(),
                family: family.into(),
            });
        }
    }
    Ok(descriptions)
}

fn manifest_malformed(manifest: &Path, line: usize, detail: &str) -> SchemaRefusal {
    SchemaRefusal::CanonicalBodyDescriptionManifestMalformed {
        manifest: display_path(manifest).into(),
        line,
        detail: detail.into(),
    }
}

fn source_families(crate_root: &Path) -> Result<BTreeMap<String, PathBuf>, SchemaRefusal> {
    let mut files = Vec::new();
    rust_sources(&crate_root.join("src"), &mut files);
    rust_sources(&crate_root.join("tests"), &mut files);
    files.sort();

    let mut families = BTreeMap::new();
    for source in files {
        let text = fs::read_to_string(&source).map_err(|error| {
            SchemaRefusal::WorkspaceMetadataFailed {
                root: display_path(&source).into(),
                detail: error.to_string().into(),
            }
        })?;
        for family in source_families_in(&text, &source)? {
            families.entry(family).or_insert_with(|| source.clone());
        }
    }
    Ok(families)
}

fn rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn source_families_in(source: &str, path: &Path) -> Result<BTreeSet<String>, SchemaRefusal> {
    let mut families = BTreeSet::new();
    let macro_definition = !code_pattern_offsets(source, "macro_rules! bytes_body").is_empty();

    for start in code_pattern_offsets(source, "impl CanonicalBody for") {
        let implementation = &source[start..];
        if macro_definition
            && implementation
                .split_once('{')
                .is_some_and(|(header, _)| header.contains("$body"))
        {
            continue;
        }
        let Some(end) = implementation.find("fn write_payload") else {
            return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                source: display_path(path).into(),
                expression: "implementation has no write_payload method".into(),
            });
        };
        let associated_constants = &implementation[..end];
        let Some(declaration) = associated_constants.find("const SCHEMA_FAMILY") else {
            return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                source: display_path(path).into(),
                expression: "implementation has no SCHEMA_FAMILY constant".into(),
            });
        };
        let after_declaration = &associated_constants[declaration..];
        let Some(equals) = after_declaration.find('=') else {
            return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                source: display_path(path).into(),
                expression: after_declaration.into(),
            });
        };
        let expression = after_declaration[equals + 1..]
            .split_once(';')
            .map_or(after_declaration[equals + 1..].trim(), |(found, _)| {
                found.trim()
            });

        if expression.contains("$family") && macro_definition {
            continue;
        }
        if let Some(family) = resolve_family(expression, source) {
            families.insert(family);
        } else if !expression.ends_with("::SCHEMA_FAMILY") {
            return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                source: display_path(path).into(),
                expression: expression.into(),
            });
        }
    }

    if macro_definition {
        for offset in code_pattern_offsets(source, "bytes_body!(") {
            let remaining = &source[offset + "bytes_body!(".len()..];
            let Some(end) = remaining.find(");") else {
                return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                    source: display_path(path).into(),
                    expression: "unterminated bytes_body invocation".into(),
                });
            };
            let arguments = string_literals(&remaining[..end]);
            let Some(family) = arguments.get(1) else {
                return Err(SchemaRefusal::CanonicalBodyFamilyUnresolvable {
                    source: display_path(path).into(),
                    expression: "bytes_body invocation has no family literal".into(),
                });
            };
            families.insert(family.clone());
        }
    }

    Ok(families)
}

fn code_pattern_offsets(source: &str, pattern: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut offsets = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1_usize;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else if let Some(end) = char_literal_end(source, index) {
            index = end;
        } else if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
        } else if let Some((hashes, body_start)) = raw_string_start(bytes, index) {
            index = body_start;
            while index < bytes.len() {
                if bytes[index] == b'"'
                    && bytes[index + 1..]
                        .get(..hashes)
                        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                {
                    index += hashes + 1;
                    break;
                }
                index += 1;
            }
        } else if source
            .get(index..)
            .is_some_and(|remaining| remaining.starts_with(pattern))
        {
            offsets.push(index);
            index += pattern.len();
        } else {
            index += source
                .get(index..)
                .and_then(|remaining| remaining.chars().next())
                .map_or(1, char::len_utf8);
        }
    }
    offsets
}

fn char_literal_end(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(index) != Some(&b'\'') {
        return None;
    }
    let mut cursor = index + 1;
    if bytes.get(cursor) == Some(&b'\\') {
        cursor += 2;
    } else {
        cursor += source.get(cursor..)?.chars().next()?.len_utf8();
    }
    (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor - hashes_start, cursor + 1))
}

fn resolve_family(expression: &str, flat_source: &str) -> Option<String> {
    if let Some(argument) = expression
        .split_once("SchemaFamily::from_static(")
        .and_then(|(_, rest)| rest.split_once(')').map(|(argument, _)| argument.trim()))
    {
        return string_literal(argument).or_else(|| constant_string(argument, flat_source));
    }
    constant_string(expression, flat_source)
}

fn constant_string(name: &str, flat_source: &str) -> Option<String> {
    let declaration = format!("const {name}");
    let (_, after) = flat_source.split_once(&declaration)?;
    let (_, value) = after.split_once('=')?;
    let value = value.trim();
    if let Some((argument, _)) = value
        .split_once("SchemaFamily::from_static(")
        .and_then(|(_, rest)| rest.split_once(')'))
    {
        string_literal(argument.trim())
    } else {
        string_literal(value)
    }
}

fn string_literal(value: &str) -> Option<String> {
    let rest = value.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn string_literals(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut remaining = source;
    while let Some(offset) = remaining.find('"') {
        remaining = &remaining[offset + 1..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        found.push(remaining[..end].to_owned());
        remaining = &remaining[end + 1..];
    }
    found
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{code_pattern_offsets, source_families_in};

    #[test]
    fn scanner_does_not_recognize_its_own_pattern_literals_as_code() {
        let source = include_str!("workspace_bodies.rs");
        let offsets = code_pattern_offsets(source, "impl CanonicalBody for");
        assert!(
            offsets.is_empty(),
            "scanner matched lines {:?}",
            offsets
                .iter()
                .map(|offset| source[..*offset].lines().count())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scanner_ignores_body_syntax_inside_comments_and_strings() {
        let source = r####"
            // impl CanonicalBody for LineComment { const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("line"); fn write_payload() {} }
            /* outer /* impl CanonicalBody for Nested { const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("nested"); fn write_payload() {} } */ */
            const ORDINARY: &str = "impl CanonicalBody for Ordinary { const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(\"ordinary\"); fn write_payload() {} }";
            const RAW: &str = r###"impl CanonicalBody for Raw { const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("raw"); fn write_payload() {} }"###;
            const CHARACTER: char = 'i';
        "####;
        assert!(
            source_families_in(source, Path::new("non-code.rs"))
                .expect("source scans")
                .is_empty()
        );
    }

    #[test]
    fn scanner_retains_a_real_body_and_macro_invocation() {
        let source = r#"
            impl CanonicalBody for Real {
                const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("real");
                fn write_payload(&self) {}
            }
            macro_rules! bytes_body {
                ($body:ident, $domain:literal, $family:literal, $field:literal) => {
                    impl CanonicalBody for $body {
                        const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static($family);
                        fn write_payload(&self) {}
                    }
                };
            }
            bytes_body!(MacroBody, "domain", "macro-real", "field");
        "#;
        assert_eq!(
            source_families_in(source, Path::new("code.rs")).expect("source scans"),
            ["macro-real".to_owned(), "real".to_owned()].into()
        );
    }
}
