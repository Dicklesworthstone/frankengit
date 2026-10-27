use super::*;

const BASE: &str = "object_format=sha1&ref=refs/heads/main&term_hex=6e6565646c65";

fn parse(input: &str, maximum: usize) -> Result<AgentCommand, ApiError> {
    command_fields(
        parse_form(input.as_bytes(), 199)?,
        GitHashAlgorithm::Sha1,
        maximum,
    )
}

#[test]
fn agent_context_has_a_closed_bounded_non_mutating_grammar() {
    let command = parse(BASE, 1024 * 1024).unwrap();
    assert_eq!(command.expires_after, Duration::from_secs(30));
    assert_eq!(command.max_output_bytes, 1024 * 1024);
    assert!(!command.context.ranked);
    let command = parse(
        &format!("{BASE}&expires_after_secs=1&max_output_bytes=4096&context_radius_bytes=0&context_max_files=1"),
        1024 * 1024,
    ).unwrap();
    assert_eq!(command.expires_after, Duration::from_secs(1));
    assert_eq!(command.max_output_bytes, 4096);
    assert_eq!(command.context.limits.max_files, 1);
    assert_eq!(command.context.limits.radius_bytes, 0);
    for suffix in [
        "&expires_after_secs=0",
        "&expires_after_secs=301",
        "&expires_after_secs=1&expires_after_secs=2",
        "&max_output_bytes=0",
        "&max_output_bytes=16777217",
        "&max_output_bytes=1&max_output_bytes=2",
        "&sponsor_id=42424242424242424242424242424242",
        "&sponsor=caller",
        "&principal=caller",
        "&principal_id=caller",
        "&run_id=caller",
        "&expected_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "&context_selection=source-context-ranked-v1",
        "&force=true",
    ] {
        assert!(
            parse(&(BASE.to_owned() + suffix), 1024 * 1024).is_err(),
            "{suffix}"
        );
    }
    assert_eq!(
        parse(
            &(BASE.to_owned() + "&max_output_bytes=1048577"),
            1024 * 1024
        )
        .err()
        .unwrap()
        .code,
        "resource_limit",
    );
    assert!(parse(BASE, 0).is_err());
}

#[test]
fn agent_route_is_a_source_read_and_preserves_framing_and_method_rules() {
    let wire = concat!(
        "POST /r.git/api/v1/source/agent-context HTTP/1.1\r\nHost: local\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
    );
    let envelope = fgit_wire::smart_http::head::parse(wire.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let request = super::super::Request::parse(&envelope).unwrap().unwrap();
    assert!(request.agent);
    assert_eq!(request.repository_route, "/r.git");
    assert!(
        !super::super::super::Request::parse(&envelope)
            .unwrap()
            .is_mutation()
    );
    for bad in [
        wire.replacen("POST", "GET", 1),
        wire.replace("agent-context HTTP", "agent-context?sponsor=caller HTTP"),
        wire.replace("Content-Length: 1", "Content-Length: 0"),
        wire.replace("application/x-www-form-urlencoded", "application/json"),
    ] {
        let envelope = fgit_wire::smart_http::head::parse(bad.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        assert!(super::super::Request::parse(&envelope).is_err());
    }
}
