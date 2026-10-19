use super::*;

const TOKEN: &str = "alg:2:0505050505050505050505050505050505050505050505050505050505050505";

fn args<const N: usize>(fields: [(&str, Value); N]) -> Object {
    object_fields(fields)
}
fn refused(args: &Object) -> &'static str {
    query(args)
        .err()
        .expect("the arguments must be refused")
        .code
}

#[test]
fn numbers_cursors_and_pins_have_permitted_and_refused_twins() {
    let first = query(&args([("number", text("7"))])).unwrap();
    assert_eq!(first.number.get(), 7);
    assert!(first.after.is_none() && first.expected.is_none());
    assert_eq!(first.limit, 5);
    let reviewer = "61".repeat(16);
    let next = query(&args([
        ("number", text("7")),
        ("after", text(reviewer.clone())),
        ("expected_head", text(TOKEN)),
        ("limit", json::number(20)),
    ]))
    .unwrap();
    assert_eq!(next.after.unwrap().to_string(), reviewer);
    assert_eq!(next.limit, 20);
    assert_eq!(
        refused(&args([("number", text("7")), ("after", text(reviewer))])),
        "snapshot_required"
    );
    for bad in ["0", "07", "-1", "x"] {
        assert!(query(&args([("number", text(bad))])).is_err(), "{bad}");
    }
    assert_eq!(refused(&args([])), "positive_pull_number_required");
    for cursor in ["61", "ZZ".repeat(16).as_str(), ""] {
        assert_eq!(
            refused(&args([
                ("number", text("7")),
                ("after", text(cursor)),
                ("expected_head", text(TOKEN)),
            ])),
            "invalid_reviewer_cursor",
            "{cursor:?}"
        );
    }
    for limit in [0, 21] {
        assert_eq!(
            refused(&args([
                ("number", text("7")),
                ("limit", json::number(limit))
            ])),
            "invalid_limit"
        );
    }
    for field in ["decision", "idempotency_key", "reviewer", "approve"] {
        assert_eq!(
            refused(&args([("number", text("7")), (field, text("x"))])),
            "unknown_argument"
        );
    }
}
