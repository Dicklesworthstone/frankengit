use super::*;
use fgit_wire::smart_http::head;

fn request(operation: Operation) -> Request<'static> {
    Request { repository_route: "/r.git", operation }
}
fn form(format: GitHashAlgorithm) -> String {
    format!("object_format={}&ref=refs%2Fheads%2Fmain&expected_head=alg:1:{}&expected_ref_tip={}&at_commit={}",
        format.as_str(), "1".repeat(64), "a".repeat(format.digest_len() * 2), "b".repeat(format.digest_len() * 2))
}

#[test]
fn historical_selection_is_explicit_and_binds_both_native_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = form(format);
        let command = request(Operation::Tree).command(input.as_bytes(), format).unwrap();
        assert_ne!(command.commit, command.expected_ref_tip);
        assert_eq!(command.commit.algorithm(), format);
        assert_eq!(command.query.expected_commit, Some(command.commit));
        assert_eq!(command.selection.expected_commit, Some(command.commit));
        assert!(command.selection.expected_head.is_some());
        let command = request(Operation::Blob).command(
            (input + "&path_hex=66696c65ff&offset=7&limit=2").as_bytes(), format).unwrap();
        assert_eq!(command.query.path, Some(b"file\xff".to_vec()));
        assert!(matches!(command.query.action, SourceBrowseAction::Read { offset: 7, limit: 2 }));
    }
}

#[test]
fn every_selection_field_is_required_even_on_the_first_page() {
    let format = GitHashAlgorithm::Sha1;
    let valid = form(format);
    for omitted in ["object_format", "ref", "expected_head", "expected_ref_tip", "at_commit"] {
        let input = valid.split('&').filter(|part| part.split_once('=').unwrap().0 != omitted)
            .collect::<Vec<_>>().join("&");
        assert!(request(Operation::Tree).command(input.as_bytes(), format).is_err(), "{omitted}");
    }
    for duplicate in ["&at_commit=aa", "&ref=refs/heads/other", "&expected_ref_tip=bb", "&expected_head=alg:1:aa"] {
        assert!(request(Operation::Tree).command((valid.clone() + duplicate).as_bytes(), format).is_err());
    }
}

#[test]
fn arbitrary_authority_fields_invalid_domains_and_unbounded_paths_are_rejected() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let valid = form(format);
        for extra in ["&object_id=aa", "&source_tree=aa", "&principal=admin", "&force=true",
            "&expected_commit=aa", "&max_commits=999999", "&offset=1", "&limit=0", "&limit=1001",
            "&path_hex=FF", "&path_hex=2e2e2f66696c65", "&path_hex=610062", "&after_hex=2f"]
        {
            assert!(request(Operation::Tree).command((valid.clone() + extra).as_bytes(), format).is_err(), "{extra}");
        }
        let width = format.digest_len() * 2;
        for replacement in ["0".repeat(width), "B".repeat(width), "b".repeat(width - 2), "b".repeat(width + 2)] {
            let input = valid.replace(&format!("at_commit={}", "b".repeat(width)), &format!("at_commit={replacement}"));
            assert!(request(Operation::Tree).command(input.as_bytes(), format).is_err());
        }
        assert!(request(Operation::Blob).command(valid.as_bytes(), format).is_err());
        for extra in ["&path_hex=61&after_hex=61", "&path_hex=61&offset=-1", "&path_hex=61&limit=1048577"] {
            assert!(request(Operation::Blob).command((valid.clone() + extra).as_bytes(), format).is_err());
        }
        assert!(request(Operation::Tree).command((valid + "&path_hex=" + &"61".repeat(4097)).as_bytes(), format).is_err());
    }
}

#[test]
fn routes_are_post_only_bounded_forms_without_url_query_or_git_protocol() {
    for action in ["historical-tree", "historical-blob"] {
        for (method, route, extra, content_type, valid) in [
            ("POST", format!("/r.git/api/v1/source/{action}"), "", "application/x-www-form-urlencoded", true),
            ("GET", format!("/r.git/api/v1/source/{action}"), "", "application/x-www-form-urlencoded", false),
            ("POST", format!("/r.git/api/v1/source/{action}?at_commit=aa"), "", "application/x-www-form-urlencoded", false),
            ("POST", format!("/../r.git/api/v1/source/{action}"), "", "application/x-www-form-urlencoded", false),
            ("POST", format!("/r.git/api/v1/source/{action}"), "Git-Protocol: version=2\r\n", "application/x-www-form-urlencoded", false),
            ("POST", format!("/r.git/api/v1/source/{action}"), "", "application/json", false),
        ] {
            let bytes = format!("{method} {route} HTTP/1.1\r\nHost: local\r\nContent-Type: {content_type}\r\nContent-Length: 1\r\n{extra}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert_eq!(Request::parse(&envelope).is_ok(), valid);
            if valid {
                let outer = super::super::Request::parse(&envelope).unwrap();
                assert!(!outer.is_mutation());
                assert_eq!(outer.route(), "/r.git");
            }
        }
    }
    let bytes = format!("POST /r.git/api/v1/source/historical-tree HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n", MAX_FORM_BYTES + 1);
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    assert!(Request::parse(&envelope).is_err());
}

#[test]
fn historical_wrapper_identifies_both_commits_and_budget_covers_the_whole_reply() {
    let command = request(Operation::Tree).command(form(GitHashAlgorithm::Sha256).as_bytes(), GitHashAlgorithm::Sha256).unwrap();
    let prefix = prefix(&command);
    assert!(prefix.contains("\"selection\":\"visible-ref-ancestor-v1\""));
    assert!(prefix.contains(&format!("\"source_ref_tip\":\"{}\"", command.expected_ref_tip)));
    assert!(prefix.contains(&format!("\"at_commit\":\"{}\"", command.commit)));
    assert!(prefix.contains("\"transaction_created\":false"));
    let source = "{\"type\":\"source_tree\"}";
    let exact = prefix.len() + source.len() + 1;
    assert!(wrap(prefix.clone(), source, exact - 1, &mut || true).is_err());
    let result = wrap(prefix.clone(), source, exact, &mut || true).unwrap();
    assert_eq!(result.len(), exact);
    assert!(result.ends_with("\"source\":{\"type\":\"source_tree\"}}"));
    assert!(wrap(prefix.clone(), source, exact, &mut || false).is_err());
    let mut calls = 0;
    assert!(wrap(prefix, source, exact, &mut || { calls += 1; calls == 1 }).is_err());
}
