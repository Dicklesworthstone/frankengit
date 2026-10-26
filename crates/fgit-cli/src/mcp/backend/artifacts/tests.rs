use super::*;
use std::collections::BTreeSet;

fn args<const N: usize>(values: [(&str, Value); N]) -> Object {
    object(values).object().unwrap().clone()
}

#[test]
fn artifact_registry_runtime_shapes_and_read_only_catalog_agree() {
    let names = all_registered_tool_names();
    for tool in tools() {
        assert_eq!(names.iter().filter(|name| **name == tool.name).count(), 1);
        let contract = fgit_schema::mcp::find_tool(tool.name).unwrap();
        let declared: BTreeSet<_> = contract
            .input_fields
            .iter()
            .map(|field| field.name)
            .collect();
        let schema = tool.schema.object().unwrap();
        let served: BTreeSet<_> = schema["properties"]
            .object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(declared, served);
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert_eq!(schema["required"], Value::Array(vec![text("artifact_id")]));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn artifact_arguments_cannot_select_paths_scope_identity_or_unbounded_ranges() {
    let valid = args([("artifact_id", text("ab".repeat(32)))]);
    let query = parse(&valid, true).unwrap();
    assert_eq!(query.offset, 0);
    assert_eq!(query.limit, 65536);
    assert!(parse(&valid, false).is_ok());
    for extra in [
        "path",
        "root",
        "artifact_root",
        "tenant_id",
        "repository_id",
        "incarnation",
        "trust_domain",
        "principal",
        "content_hex",
    ] {
        let mut invalid = valid.clone();
        invalid.insert(extra.into(), text("caller-controlled"));
        assert_eq!(parse(&invalid, true).unwrap_err().code, "unknown_argument");
    }
    for id in [
        "../secret".into(),
        "AA".repeat(32),
        "ab".repeat(31),
        format!("sha256:{}", "ab".repeat(32)),
    ] {
        let invalid = args([("artifact_id", text(id))]);
        assert_eq!(
            parse(&invalid, true).unwrap_err().code,
            "invalid_artifact_id"
        );
    }
    for value in [
        json::number(1),
        text("01"),
        text("-1"),
        text("18446744073709551616"),
    ] {
        let mut invalid = valid.clone();
        invalid.insert("offset".into(), value);
        assert!(parse(&invalid, true).is_err());
    }
    for value in [json::number(0), json::number(65537), text("1"), Value::Null] {
        let mut invalid = valid.clone();
        invalid.insert("limit".into(), value);
        assert_eq!(
            parse(&invalid, true).unwrap_err().code,
            "invalid_artifact_read_limit"
        );
    }
    let mut boundary = valid.clone();
    boundary.insert("offset".into(), text(u64::MAX.to_string()));
    boundary.insert("limit".into(), json::number(1));
    assert!(parse(&boundary, true).is_ok());
    assert_eq!(
        parse(&boundary, false).unwrap_err().code,
        "unknown_argument"
    );
    assert_eq!(
        parse(&Object::new(), true).unwrap_err().code,
        "artifact_id_required"
    );
}

#[cfg(target_os = "linux")]
mod persisted;
