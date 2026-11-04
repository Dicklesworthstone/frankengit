use super::*;

fn path_rule(path: &[u8], scope: &str, count: u64) -> Value {
    object([
        ("path_hex", text(hex(path))),
        ("scope", text(scope)),
        ("required_reviewers", people(&[0x33, 0x44])),
        ("required_approvals", json::number(count)),
    ])
}

#[test]
fn omitted_rules_preserve_history_and_path_only_rules_round_trip_exact_bytes() {
    let mut args = arguments();
    let old = write::parse(&args).unwrap();
    fields(&mut args).insert("path_reviews".into(), Value::Array(Vec::new()));
    assert_eq!(write::parse(&args).unwrap(), old);
    fields(&mut args).insert(
        "path_reviews".into(),
        Value::Array(vec![path_rule(b"src/\xff", "subtree", 1)]),
    );
    fields(&mut args).insert("required_reviewers".into(), people(&[]));
    let selected = write::parse(&args).unwrap();
    let branch = &selected.protection.branches[0];
    assert_eq!(branch.required_approvals, 0);
    assert_eq!(branch.path_reviews[0].path, b"src/\xff");
    let Value::Object(mut shown) = policy_value(&selected.protection).unwrap() else {
        panic!()
    };
    let Value::Array(branches) = shown.get_mut("branches").unwrap() else {
        panic!()
    };
    assert_eq!(
        branches[0].object().unwrap()["path_reviews"],
        fields(&mut args)["path_reviews"]
    );
    for branch in branches {
        let Value::Object(branch) = branch else {
            panic!()
        };
        branch.remove("reference_utf8");
    }
    args.insert("branches".into(), shown.remove("branches").unwrap());
    assert_eq!(write::parse(&args).unwrap(), selected);
}

#[test]
fn path_rules_require_canonical_selectors_and_strict_closed_fields() {
    for rules in [
        vec![path_rule(b"src", "glob", 1)],
        vec![path_rule(b"src", "exact", 0)],
        vec![path_rule(b"src", "exact", 3)],
        vec![path_rule(b"src/..", "exact", 1)],
        vec![path_rule(b"src", "exact", 1), path_rule(b"src", "exact", 2)],
        vec![
            path_rule(b"src", "subtree", 1),
            path_rule(b"src", "exact", 1),
        ],
        vec![path_rule(b"z", "exact", 1), path_rule(b"a", "exact", 1)],
    ] {
        let mut args = arguments();
        fields(&mut args).insert("path_reviews".into(), Value::Array(rules));
        assert!(write::parse(&args).is_err());
    }
    for (name, value) in [
        ("required_approvals", text("1")),
        ("unrecognized", text("ignored")),
        ("required_reviewers", people(&[0x44, 0x33])),
        ("required_reviewers", people(&[0x33, 0x33])),
    ] {
        let mut args = arguments();
        let Value::Object(mut rule) = path_rule(b"src", "exact", 1) else {
            panic!()
        };
        rule.insert(name.into(), value);
        fields(&mut args).insert(
            "path_reviews".into(),
            Value::Array(vec![Value::Object(rule)]),
        );
        assert!(write::parse(&args).is_err());
    }
    let mut args = arguments();
    fields(&mut args).insert(
        "path_reviews".into(),
        Value::Array(vec![
            path_rule(b"src", "exact", 1),
            path_rule(b"src", "subtree", 2),
        ]),
    );
    assert!(write::parse(&args).is_ok());
}
