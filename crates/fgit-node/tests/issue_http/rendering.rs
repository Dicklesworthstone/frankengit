//! Derived Markdown rendering on the real listener: the raw body stays
//! canonical, `render=html_safe` adds a sanitized fgit-doc rendering beside
//! it, and hostile markup never becomes active content.
use super::*;

fn form_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[test]
fn issue_reads_render_markdown_safely_beside_the_canonical_body() {
    let root = Scratch::new();
    let node = start_node(config(&root, GitHashAlgorithm::Sha256));
    let path = root.0.join("credentials");
    grants(&node, &path);
    let server = Server::start(node, path, 5, true);
    let markdown = "**bold** <script>alert(1)</script> [x](javascript:alert(1))";
    committed(&post(
        &server,
        "/api/v1/issues/1/open",
        'b',
        "render-open",
        &format!(
            "expected_version=0&title=Rendered&body={}",
            form_encode(markdown)
        ),
        false,
    ));

    let rendered = get(&server, "/api/v1/issues/1?render=html_safe", 'a');
    status(&rendered, 200);
    // The canonical body is returned byte-for-byte (JSON-escaped only).
    assert!(
        rendered
            .body
            .contains("\"body\":\"**bold** <script>alert(1)</script> [x](javascript:alert(1))\""),
        "{}",
        rendered.body
    );
    assert!(
        rendered
            .body
            .contains("\"body_rendered\":{\"renderer\":\"fgit-doc\"")
    );
    assert!(rendered.body.contains("\"profile\":\"html_safe\""));
    assert!(
        rendered.body.contains("<strong>bold</strong>"),
        "{}",
        rendered.body
    );
    // The hostile parts are inert in EVERY rendered value (snapshot and
    // event): escaped markup and a neutralised link, never live elements.
    let values: Vec<&str> = rendered
        .body
        .split("\"html\":\"")
        .skip(1)
        .map(|rest| &rest[..rest.find("\"}").expect("closed rendering")])
        .collect();
    assert_eq!(values.len(), 2, "snapshot and open-event renderings");
    for html in values {
        assert!(!html.contains("<script"), "{html}");
        assert!(!html.contains("javascript:"), "{html}");
        assert!(html.contains("data-fgit-doc-rejected"), "{html}");
    }

    let plain = get(&server, "/api/v1/issues/1", 'a');
    status(&plain, 200);
    assert!(!plain.body.contains("body_rendered"));
    assert_eq!(token(&plain), token(&rendered));

    let unsupported = get(&server, "/api/v1/issues/1?render=html_unsafe", 'a');
    status(&unsupported, 400);
    assert!(unsupported.body.contains("unsupported_rendering"));
    server.finish();
}
