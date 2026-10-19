use super::*;

const TOKEN: &str = "alg:2:0505050505050505050505050505050505050505050505050505050505050505";

fn args<const N: usize>(fields: [(&str, Value); N]) -> Object {
    let Value::Object(args) = object(fields) else {
        unreachable!()
    };
    args
}

#[test]
fn defaults_and_bounds_have_permitted_twins() {
    let query = parse(&args([])).unwrap();
    assert_eq!(query.namespace, Namespace::All);
    assert_eq!(query.limit, 50);
    assert!(query.after.is_none() && query.expected_head.is_none());
    for limit in [1, 100] {
        assert_eq!(
            parse(&args([("limit", json::number(limit))]))
                .unwrap()
                .limit,
            u16::try_from(limit).unwrap()
        );
    }
    for limit in [0, 101] {
        assert_eq!(
            parse(&args([("limit", json::number(limit))]))
                .unwrap_err()
                .code,
            "invalid_limit"
        );
    }
    assert_eq!(
        parse(&args([("limit", text("5"))])).unwrap_err().code,
        "invalid_limit"
    );
}

#[test]
fn namespaces_are_closed_and_cursors_stay_inside_them() {
    assert_eq!(
        parse(&args([("namespace", text("tags"))]))
            .unwrap()
            .namespace,
        Namespace::Tags
    );
    assert_eq!(
        parse(&args([("namespace", text("refs"))]))
            .unwrap()
            .namespace,
        Namespace::All
    );
    for bad in ["heads", "refs/", "", "TAGS"] {
        assert_eq!(
            parse(&args([("namespace", text(bad))])).unwrap_err().code,
            "invalid_namespace"
        );
    }
    let branch = hex(b"refs/heads/main");
    let permitted = parse(&args([
        ("after_hex", text(branch.clone())),
        ("expected_head", text(TOKEN)),
    ]))
    .unwrap();
    assert_eq!(permitted.after.unwrap().as_bytes(), b"refs/heads/main");
    // The same branch cursor cannot continue a tag-only page.
    assert_eq!(
        parse(&args([
            ("namespace", text("tags")),
            ("after_hex", text(branch)),
            ("expected_head", text(TOKEN)),
        ]))
        .unwrap_err()
        .code,
        "invalid_reference_cursor"
    );
}

#[test]
fn continuations_require_the_first_page_snapshot() {
    let cursor = hex(b"refs/remotes/origin/\xff");
    assert_eq!(
        parse(&args([("after_hex", text(cursor.clone()))]))
            .unwrap_err()
            .code,
        "snapshot_required"
    );
    let query = parse(&args([
        ("after_hex", text(cursor)),
        ("expected_head", text(TOKEN)),
    ]))
    .unwrap();
    assert_eq!(query.after.unwrap().as_bytes(), b"refs/remotes/origin/\xff");
    assert!(query.expected_head.is_some());
    for bad in ["", "zz", "0", "2e2e2f"] {
        assert!(
            parse(&args([
                ("after_hex", text(bad)),
                ("expected_head", text(TOKEN)),
            ]))
            .is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(
        parse(&args([("expected_head", text("alg:x:05"))]))
            .unwrap_err()
            .code,
        "invalid_snapshot_token"
    );
}

#[test]
fn write_shaped_or_unknown_arguments_are_refused() {
    for field in [
        "reference",
        "expected_old",
        "target",
        "idempotency_key",
        "after",
    ] {
        assert_eq!(
            parse(&args([(field, text("x"))])).unwrap_err().code,
            "unknown_argument"
        );
    }
}

#[test]
fn node_refusals_keep_their_meaning() {
    assert_eq!(
        read_error(NodeWorkspaceRefusal::BranchOperation(
            "reference snapshot moved"
        ))
        .code,
        "snapshot_moved"
    );
    assert_eq!(
        read_error(NodeWorkspaceRefusal::BranchOperation(
            "reference page limit must be 1..100"
        ))
        .code,
        "invalid_reference_query"
    );
    assert_eq!(
        read_error(NodeWorkspaceRefusal::Cancelled { exhaustion: None }).code,
        "read_cancelled"
    );
    assert_eq!(
        read_error(NodeWorkspaceRefusal::RefUnavailable).code,
        "reference_read_failed"
    );
}
