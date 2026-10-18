use super::*;
use fgit_wire::smart_http::{HttpLimits, head};

fn envelope(method: &str, target: &str, extra: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: local\r\n{extra}\r\n").into_bytes()
}
fn query() -> String {
    format!(
        "ref_hex=726566732f68656164732f6d61696e&path_hex=617070&expected_head=alg:1:{}",
        "ab".repeat(32)
    )
}

#[test]
fn route_is_read_only_and_closed_to_body_protocol_or_method_substitution() {
    let target = format!("/repo.git/api/v1/source/verified-blob?{}", query());
    let bytes = envelope("GET", &target, "");
    let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    let request = Request::parse(&head).unwrap().unwrap();
    assert_eq!(request.repository_route, "/repo.git");
    assert!(request.selection().is_ok());
    assert!(!super::super::Request::parse(&head).unwrap().is_mutation());
    for (method, extra) in [
        ("POST", ""),
        ("HEAD", ""),
        ("GET", "Content-Length: 1\r\n"),
        ("GET", "Git-Protocol: version=2\r\n"),
        ("GET", "Content-Type: application/json\r\n"),
    ] {
        let bytes = envelope(method, &target, extra);
        let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&head).is_err());
    }
    for target in [
        "/../repo.git/api/v1/source/verified-blob?x=1",
        "/repo.git/api/v1/source/verified-blob",
    ] {
        let bytes = envelope("GET", target, "");
        let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&head).is_err());
    }
}

#[test]
fn shared_http_profile_bounds_the_encoded_target_before_endpoint_selection() {
    let limits = HttpLimits::default();
    let prefix = "/repo.git/api/v1/source/verified-blob?";
    let target = prefix.to_owned() + &"x".repeat(4096 - prefix.len());
    let bytes = envelope("GET", &target, "");
    assert!(head::parse(&bytes, limits).unwrap().is_some());
    let bytes = envelope("GET", &(target + "x"), "");
    assert!(head::parse(&bytes, limits).is_err());
}

#[test]
fn exact_selection_preserves_raw_paths_and_rejects_authority_overrides() {
    let query = query();
    let request = Request {
        repository_route: "/repo.git",
        query: &query,
    };
    let selected = request.selection().unwrap();
    assert_eq!(selected.reference.as_bytes(), b"refs/heads/main");
    assert_eq!(selected.path, b"app");
    for tail in [
        "&principal=admin",
        "&object_id=1234",
        "&ref_hex=61",
        "&force=true",
        "&mode=snapshot",
    ] {
        let value = query.clone() + tail;
        assert!(
            Request {
                repository_route: "/repo.git",
                query: &value
            }
            .selection()
            .is_err()
        );
    }
    for path in ["2f61", "612f2e2e2f62", "6100", "61FF", "", "612f2f62"] {
        let value = query.replace("path_hex=617070", &format!("path_hex={path}"));
        assert!(
            Request {
                repository_route: "/repo.git",
                query: &value
            }
            .selection()
            .is_err()
        );
    }
    let value = query.replace("path_hex=617070", "path_hex=61ff");
    assert_eq!(
        Request {
            repository_route: "/repo.git",
            query: &value
        }
        .selection()
        .unwrap()
        .path,
        b"a\xff"
    );
}

#[test]
fn error_mapping_does_not_disclose_a_hidden_reference_or_make_absence_a_proof() {
    assert_eq!(
        read_error(VerifiedBlobReadRefusal::RefUnavailable).code,
        read_error(VerifiedBlobReadRefusal::PathUnavailable).code
    );
    assert!(matches!(
        read_error(VerifiedBlobReadRefusal::SnapshotMoved).status,
        Status::Conflict
    ));
    assert_eq!(
        read_error(VerifiedBlobReadRefusal::UnsupportedLayout).code,
        "verified_blob_layout_unavailable"
    );
}
