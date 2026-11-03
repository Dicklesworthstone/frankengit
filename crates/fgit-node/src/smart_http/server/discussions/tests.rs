use super::*;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionEdit};
use fgit_forge::{DiscussionNumber, ExpectedVersion};
use fgit_wire::smart_http::head;

fn wire(method: &str, suffix: &str, bytes: usize) -> String {
    let fields = if method == "POST" {
        format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {bytes}\r\n")
    } else {
        String::new()
    };
    format!("{method} /repo.git/api/v1/discussions{suffix} HTTP/1.1\r\nHost: local\r\n{fields}\r\n")
}
fn parse(bytes: &str) -> Result<Request<'_>, ApiError> {
    Request::parse(
        &head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap(),
    )
}

#[test]
fn exact_commands_validate_before_publication_and_preserve_empty_edits() {
    let id = DiscussionNumber::try_new(7).unwrap();
    let open = request::command(id, "open", b"expected_version=0&title=Design&body=").unwrap();
    assert_eq!(open.expected_version, ExpectedVersion::NewStream);
    assert!(matches!(open.action, DiscussionAction::Open { body, .. } if body.is_empty()));
    let edit = request::command(id, "edit", b"expected_version=1&body=").unwrap();
    assert!(
        matches!(edit.action, DiscussionAction::Edit(DiscussionEdit { title: None, body: Some(body) }) if body.is_empty())
    );
    for action in ["close", "reopen", "lock", "unlock"] {
        let value = request::command(id, action, b"expected_version=1").unwrap();
        assert_eq!(value.action.name(), action);
    }
    let comment = request::command(
        id,
        "comment",
        b"expected_version=1&body=%3Cscript%3Edata%3C%2Fscript%3E",
    )
    .unwrap();
    assert!(
        matches!(comment.action, DiscussionAction::Comment { body } if body == "<script>data</script>")
    );
    for (action, body) in [
        ("open", "expected_version=1&title=x&body="),
        ("open", "expected_version=0&title=&body="),
        ("edit", "expected_version=1"),
        ("comment", "expected_version=1&body=+"),
        ("close", "expected_version=0"),
        ("close", "expected_version=01"),
        ("close", "expected_version=18446744073709551615"),
        ("close", "expected_version=1&expected_version=1"),
        ("close", "expected_version=1&title=x"),
        ("close", "expected_version=1&principal=attacker"),
        ("comment", "expected_version=1&body=%00"),
        ("comment", "expected_version=1&body=%ff"),
        ("comment", "expected_version=1&body=%"),
        ("comment", "body=missing-version"),
    ] {
        assert!(
            request::command(id, action, body.as_bytes()).is_err(),
            "{action}: {body}"
        );
    }
}

#[test]
fn route_scope_pagination_body_and_media_are_closed() {
    let list = wire("GET", "?limit=1", 0);
    assert!(matches!(parse(&list).unwrap().operation, Operation::List(page) if page.limit == 1));
    let show = wire("GET", "/7?render=html_safe", 0);
    assert!(
        matches!(parse(&show).unwrap().operation, Operation::Show { page, .. } if page.render.is_some())
    );
    let body = "expected_version=1";
    let close = wire("POST", "/7/close", body.len());
    assert!(parse(&close).unwrap().is_mutation());
    for (method, suffix) in [
        ("GET", "/0"),
        ("GET", "/01"),
        ("GET", "/7/close"),
        ("GET", "?after=1"),
        ("GET", "/7?after_version=1"),
        ("GET", "?limit=0"),
        ("GET", "?limit=101"),
        ("GET", "?principal=attacker"),
        ("GET", "?render=unsafe_html"),
        ("POST", "/7/comment?limit=1"),
        ("POST", "/7/unknown"),
        ("DELETE", "/7"),
        ("PUT", "/7/close"),
    ] {
        assert!(
            parse(&wire(method, suffix, body.len())).is_err(),
            "{method} {suffix}"
        );
    }
    for invalid in [
        wire("GET", "", 0).replace("Host: local", "Host: local\r\nContent-Length: 1"),
        wire("POST", "/7/open", 12)
            .replace("application/x-www-form-urlencoded", "application/json"),
        wire("POST", "/7/open", 12).replace("/repo.git/", "/../"),
        wire("POST", "/7/open", 12).replace("/repo.git/", "/repo%2fgit/"),
        wire("POST", "/7/open", 12).replace("Content-Length: 12", "Content-Length: 262145"),
    ] {
        assert!(parse(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn canonical_text_is_retained_while_safe_rendering_escapes_markup() {
    let raw = "<script>alert(1)</script>\n[bad](javascript:alert(1))";
    let action = DiscussionAction::Comment { body: raw.into() };
    let plain = output::action(&action, None);
    assert!(!plain.contains("body_rendered"));
    let json = output::action(&action, Some(super::super::issues::Rendering::HtmlSafe));
    assert!(json.contains("\"body_rendered\""));
    assert!(plain.contains("<script>"));
    let presentation = json.split_once("\"body_rendered\":").unwrap().1;
    assert!(presentation.contains("&lt;script&gt;"));
    assert!(!presentation.contains("<script>"));
    assert!(!presentation.contains("href=\\\"javascript:"));
    assert_eq!(
        output::action(
            &DiscussionAction::Edit(DiscussionEdit {
                title: None,
                body: Some(String::new())
            }),
            None
        ),
        "{\"name\":\"edit\",\"body\":\"\"}"
    );
}
