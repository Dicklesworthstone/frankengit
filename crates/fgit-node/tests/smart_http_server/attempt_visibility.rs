#![forbid(unsafe_code)]

use super::*;

#[test]
fn attempt_aliases_do_not_disclose_the_configured_route_before_authentication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = config(&scratch, format);
        let alias = format!("/.fgit-receive/{}", "42".repeat(32));
        let discovery = "/info/refs?service=git-receive-pack";
        let cases = [
            ("GET", format!("/.fgit-receive/short{discovery}"), "", 401),
            (
                "GET",
                format!("/.fgit-receive/{}{discovery}", "AB".repeat(32)),
                "",
                401,
            ),
            ("GET", format!("{alias}/unsupported"), "", 405),
            ("GET", format!("{alias}/git-receive-pack"), "", 405),
            (
                "GET",
                format!("{alias}{discovery}"),
                "Idempotency-Key: conflicting-key\r\n",
                401,
            ),
            (
                "GET",
                format!("{alias}{discovery}"),
                "Idempotency-Key: one\r\nIdempotency-Key: two\r\n",
                401,
            ),
            (
                "GET",
                format!("{alias}{discovery}"),
                "Idempotency-Key: \r\n",
                401,
            ),
            (
                "POST",
                "/git-receive-pack".into(),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nIdempotency-Key: one\r\nIdempotency-Key: two\r\n",
                401,
            ),
            (
                "POST",
                "/git-receive-pack".into(),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nIdempotency-Key: \r\n",
                401,
            ),
            (
                "POST",
                "/git-receive-pack".into(),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nOrigin: https://attacker.invalid\r\n",
                403,
            ),
            (
                "POST",
                format!("{alias}/git-receive-pack"),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nOrigin: https://attacker.invalid\r\n",
                403,
            ),
            (
                "POST",
                "/git-receive-pack".into(),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nSec-Fetch-Site: cross-site\r\n",
                403,
            ),
            (
                "POST",
                format!("{alias}/git-receive-pack"),
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 4\r\nExpect: 100-continue\r\nSec-Fetch-Site: cross-site\r\n",
                403,
            ),
        ];
        let sessions = cases.len() * 4 + 5;
        let server = Server::start(initialized(config.clone()), sessions, true, 2);
        let wrong = format!("Authorization: Bearer {}\r\n", "b".repeat(64));
        for credential in ["", wrong.as_str()] {
            for (method, suffix, headers, expected) in &cases {
                let responses: Vec<Vec<u8>> = [server.route.as_str(), "/missing.git"]
                    .into_iter()
                    .map(|route| {
                        // A refused Expect request must answer before intake.
                        // Do not race that answer by eagerly sending its body.
                        let input = format!(
                            "{method} {route}{suffix} HTTP/1.1\r\nHost: loopback\r\n{credential}{headers}\r\n"
                        );
                        exchange(&server, input.as_bytes(), 1)
                    })
                    .collect();
                for response in &responses {
                    assert!(
                        response.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()),
                        "{format} {method} {suffix}: {}",
                        String::from_utf8_lossy(response)
                    );
                }
                // Include challenges, content type and body, not just status.
                assert_eq!(responses[0], responses[1], "{format} {method} {suffix}");
            }
        }
        assert_eq!(generation(&config, None), HeadGeneration::FIRST);

        let valid = request(&server, "GET", &format!("{alias}{discovery}"), &auth(), b"");
        response_body(&exchange(&server, &valid, 1));
        let invalid = request(
            &server,
            "GET",
            &format!("/.fgit-receive/short{discovery}"),
            &auth(),
            b"",
        );
        assert!(exchange(&server, &invalid, 1).starts_with(b"HTTP/1.1 404 "));
        let conflict = request(
            &server,
            "GET",
            &format!("{alias}{discovery}"),
            &format!("{}Idempotency-Key: conflicting-key\r\n", auth()),
            b"",
        );
        assert!(exchange(&server, &conflict, 1).starts_with(b"HTTP/1.1 400 "));
        assert_eq!(generation(&config, None), HeadGeneration::FIRST);

        // The same alias still publishes and recovers one real native push.
        let (commit, pack, _) = commit_pack(format);
        let body = packets(
            format!(
                "{} {commit} refs/heads/main\0report-status object-format={}",
                "0".repeat(format.digest_len() * 2),
                format.as_str()
            )
            .into_bytes(),
            &pack,
        );
        let push = request(
            &server,
            "POST",
            &format!("{alias}/git-receive-pack"),
            &post_headers("receive-pack", body.len(), ""),
            &body,
        );
        // A permitted browser origin may publish; the ordinary stock-client
        // retry without browser headers must recover that same decision.
        let mut browser_push = format!(
            "POST {}{alias}/git-receive-pack HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\n{}\r\n",
            server.route,
            server.address,
            server.address,
            post_headers("receive-pack", body.len(), "")
        )
        .into_bytes();
        browser_push.extend_from_slice(&body);
        let first = response_body(&exchange(&server, &browser_push, 1));
        assert!(
            first
                .windows(b"ok refs/heads/main".len())
                .any(|b| b == b"ok refs/heads/main")
        );
        let published = generation(&config, Some(commit));
        assert!(published > HeadGeneration::FIRST);
        assert_eq!(response_body(&exchange(&server, &push, 4096)), first);
        let receipt = server.finish();
        assert_eq!(receipt.accepted_sessions(), sessions);
        assert_eq!(receipt.completed_sessions(), 3);
        assert_eq!(receipt.refused_sessions(), sessions - 3);
        assert_eq!(generation(&config, Some(commit)), published);
    }
}
