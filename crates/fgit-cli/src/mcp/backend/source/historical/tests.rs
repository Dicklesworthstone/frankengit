use super::*;
use fgit_types::{DigestAlgorithmId, DigestBytes};

fn args(format: GitHashAlgorithm, file: bool) -> Object {
    let head = RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    );
    let mut args = object([
        ("reference", text("refs/heads/main")),
        ("expected_head", text(head_token(head))),
        (
            "expected_ref_tip",
            text("a".repeat(format.digest_len() * 2)),
        ),
        ("at_commit", text("b".repeat(format.digest_len() * 2))),
    ])
    .object()
    .unwrap()
    .clone();
    if file {
        args.insert("path_hex".into(), text("ff"));
    }
    args
}

#[test]
fn historical_queries_require_all_three_pins_and_keep_current_browse_bounds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for file in [false, true] {
            let valid = args(format, file);
            let query = parse(&valid, file, format).unwrap();
            assert!(query.browse.expected_head.is_some());
            assert_eq!(query.browse.expected_commit, Some(query.at_commit));
            assert_ne!(query.expected_ref_tip, query.at_commit);
            for name in [
                "reference",
                "expected_head",
                "expected_ref_tip",
                "at_commit",
            ] {
                let mut missing = valid.clone();
                missing.remove(name);
                assert!(parse(&missing, file, format).is_err(), "{name}");
            }
            for (name, value) in [
                ("expected_commit", text("a".repeat(format.digest_len() * 2))),
                ("oid", text("a".repeat(format.digest_len() * 2))),
                ("storage", text("/etc/passwd")),
                ("principal", text("administrator")),
                ("path_hex", text("2e2e2f736563726574")),
                ("reference", text("/etc/passwd")),
                (
                    "expected_ref_tip",
                    text("0".repeat(format.digest_len() * 2)),
                ),
                ("at_commit", text("B".repeat(format.digest_len() * 2))),
                ("at_commit", text("latest")),
                ("at_commit", json::number(1)),
                (
                    if file { "max_bytes" } else { "limit" },
                    json::number(if file { 65_537 } else { 101 }),
                ),
            ] {
                let mut bad = valid.clone();
                bad.insert(name.into(), value);
                assert!(parse(&bad, file, format).is_err(), "{name}");
            }
            let other = if format == GitHashAlgorithm::Sha1 {
                GitHashAlgorithm::Sha256
            } else {
                GitHashAlgorithm::Sha1
            };
            assert!(parse(&valid, file, other).is_err());
        }
    }
}

#[test]
fn historical_discovery_matches_registered_fields_and_required_pins() {
    use fgit_schema::mcp::{
        InputAuthorityRootRequirement, ReadMutationClass, SupportProfile, find_tool,
    };
    use std::collections::BTreeSet;

    for tool in tools() {
        let registered = find_tool(tool.name).expect("historical tool must pass startup parity");
        assert_eq!(registered.support_profile, SupportProfile::Active);
        assert_eq!(registered.read_mutation, ReadMutationClass::ReadOnly);
        assert_eq!(
            registered.authority_root,
            InputAuthorityRootRequirement::ExactSnapshotToken
        );
        let schema = tool.schema.object().unwrap();
        let properties = schema["properties"].object().unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            registered
                .input_fields
                .iter()
                .map(|field| field.name)
                .collect()
        );
        let Value::Array(required) = &schema["required"] else {
            panic!("historical discovery requires exact pins");
        };
        assert_eq!(
            required
                .iter()
                .map(|value| value.text().unwrap())
                .collect::<BTreeSet<_>>(),
            registered
                .input_fields
                .iter()
                .filter(|field| field.required)
                .map(|field| field.name)
                .collect()
        );
        for field in registered.input_fields {
            let property = properties[field.name].object().unwrap();
            assert_eq!(property["type"].text(), Some(field.field_type));
            if let Some(maximum) = property.get("maxLength") {
                assert_eq!(maximum.unsigned(), field.max_bytes.map(u64::from));
            }
            if let Some(pattern) = field.pattern {
                assert_eq!(property["pattern"].text(), Some(pattern));
            }
        }
    }
}
