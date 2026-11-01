use super::*;

fn candidate(job: &str) -> Value {
    object([
        (
            "publisher",
            text(PrincipalId::from_bytes([0x66; 16]).to_string()),
        ),
        ("graph_root", text("77".repeat(32))),
        ("job", text(job)),
    ])
}

#[test]
fn absent_and_empty_candidate_arrays_preserve_old_command_but_reads_are_explicit() {
    let mut args = arguments();
    let old = write::parse(&args).unwrap();
    fields(&mut args).insert("required_candidate_checks".into(), Value::Array(Vec::new()));
    assert_eq!(write::parse(&args).unwrap(), old);
    let shown = policy_value(&old.protection).unwrap();
    let Value::Array(branches) = &shown.object().unwrap()["branches"] else {
        panic!()
    };
    assert_eq!(
        branches[0].object().unwrap()["required_candidate_checks"],
        Value::Array(Vec::new())
    );
    fields(&mut args).insert(
        "required_candidate_checks".into(),
        Value::Array(vec![candidate("test:日本語")]),
    );
    fields(&mut args).insert("required_reviewers".into(), people(&[]));
    let command = write::parse(&args).unwrap();
    let rule = &command.protection.branches[0];
    assert_eq!(rule.required_approvals, 0);
    assert!(rule.required_checks.is_empty() && rule.reviewers.is_empty());
    assert_eq!(rule.required_candidate_checks[0].job, "test:日本語");
    fields(&mut args).remove("required_candidate_checks");
    assert!(write::parse(&args).is_err());
}

#[test]
fn candidate_array_requires_exact_closed_sorted_validated_selectors() {
    for bad in [
        Value::Null,
        Value::Bool(false),
        text("[]"),
        Value::Array(vec![Value::Null]),
        Value::Array(vec![candidate("z"), candidate("a")]),
        Value::Array(vec![candidate("same"), candidate("same")]),
        Value::Array(vec![candidate("")]),
        Value::Array(vec![candidate("bad\njob")]),
    ] {
        let mut args = arguments();
        fields(&mut args).insert("required_candidate_checks".into(), bad);
        assert!(write::parse(&args).is_err());
    }
    for (name, value) in [
        ("source_ref_hex", text(hex(b"refs/heads/ci"))),
        ("actor", text("66".repeat(16))),
        ("publisher", text("not-a-principal")),
        ("graph_root", text("77".repeat(31))),
        ("job", Value::Null),
    ] {
        let mut check = candidate("test");
        let Value::Object(ref mut check_fields) = check else {
            panic!()
        };
        check_fields.insert(name.into(), value);
        let mut args = arguments();
        fields(&mut args).insert(
            "required_candidate_checks".into(),
            Value::Array(vec![check]),
        );
        assert!(write::parse(&args).is_err(), "{name}");
    }
}

#[test]
fn candidate_and_ordinary_arrays_share_the_policy_check_limit() {
    let mut args = arguments();
    fields(&mut args).insert(
        "required_candidate_checks".into(),
        Value::Array((0..31).map(|i| candidate(&format!("job-{i:02}"))).collect()),
    );
    let ordinary = object([
        ("source_ref_hex", text(hex(b"refs/heads/ci"))),
        ("publisher", text("66".repeat(16))),
        ("graph_root", text("77".repeat(32))),
        ("job", text("ordinary")),
    ]);
    fields(&mut args).insert("required_checks".into(), Value::Array(vec![ordinary]));
    assert!(write::parse(&args).is_ok());
    let Value::Array(checks) = fields(&mut args)
        .get_mut("required_candidate_checks")
        .unwrap()
    else {
        panic!()
    };
    checks.push(candidate("overflow"));
    assert_eq!(
        write::parse(&args).unwrap_err().code,
        "policy_check_count_limit"
    );
}
