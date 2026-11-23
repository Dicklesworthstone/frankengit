#![forbid(unsafe_code)]

//! Real loopback HTTP requests through one listener and separate canonical
//! repositories. These tests use native quarantine and authority publication,
//! not a substitute server, credential verifier, or repository projection.

#[path = "http_repository_routes/startup.rs"]
mod startup;
#[path = "http_repository_routes/stock_git.rs"]
mod stock_git;
#[path = "http_repository_routes/support.rs"]
mod support;

use fgit_node::OneNode;
use fgit_node::smart_http::server::{HttpRepositoryRoute, HttpRepositoryServices};
use fgit_types::{GitHashAlgorithm, RefName};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::time::{Duration, Instant};
use support::*;

fn writable() -> HttpRepositoryServices {
    HttpRepositoryServices {
        receive: true,
        issues: true,
        outcomes: true,
        pulls: true,
        source: true,
    }
}

#[test]
fn one_listener_isolates_tenants_formats_publication_and_restart() {
    let scratch = Scratch::new();
    let first_configuration = configuration(&scratch, "first", 0x71, GitHashAlgorithm::Sha1);
    let second_configuration = configuration(&scratch, "second", 0x81, GitHashAlgorithm::Sha256);
    let first = start_node(first_configuration.clone());
    let second = start_node(second_configuration.clone());
    // Deliberately use the SAME repository ID, principal, ref and retry key.
    // Tenant identity and route-selected authority must still separate them.
    assert_eq!(first.repository_id(), second.repository_id());
    assert_ne!(first.tenant_id(), second.tenant_id());
    let first_credentials = scratch.0.join("first.credentials");
    let second_credentials = scratch.0.join("second.credentials");
    replace(
        &first_credentials,
        &(header(&first) + &row('a', "read,receive")),
    );
    replace(
        &second_credentials,
        &(header(&second) + &row('b', "read,receive")),
    );
    let routes = vec![
        HttpRepositoryRoute::try_new(
            "/alpha/repo.git".into(),
            &first,
            &first_credentials,
            writable(),
        )
        .unwrap(),
        HttpRepositoryRoute::try_new(
            "/beta/repo.git".into(),
            &second,
            &second_credentials,
            writable(),
        )
        .unwrap(),
    ];
    second.shutdown().unwrap();
    let server = Server::start(first, routes, 12);
    let mut refusal = None;
    for (path, token) in [
        ("/alpha/repo.git", 'b'),
        ("/beta/repo.git", 'a'),
        ("/missing/repo.git", 'a'),
        ("/alpha/repo.git-neighbor", 'a'),
    ] {
        let reply = get(&server, path, "/info/refs?service=git-upload-pack", token);
        status(&reply, 401);
        if let Some(expected) = &refusal {
            assert_eq!(
                &reply, expected,
                "unknown and unauthorized routes must not disclose which exists"
            );
        } else {
            refusal = Some(reply);
        }
    }
    let native_unknown = get(&server, "/missing/repo.git", "/api/v1/issues", 'b');
    let native_unauthorized = get(&server, "/alpha/repo.git", "/api/v1/issues", 'b');
    status(&native_unknown, 401);
    assert_eq!(
        native_unknown, native_unauthorized,
        "the native response family must not disclose whether the route exists"
    );
    let inputs = [
        ("/alpha/repo.git", 'a', GitHashAlgorithm::Sha1, b'A'),
        ("/beta/repo.git", 'b', GitHashAlgorithm::Sha256, b'B'),
    ];
    let mut tips = Vec::new();
    let mut original = Vec::new();
    for (path, token, format, payload) in inputs {
        let (tip, body) = push_body(format, payload, "refs/tags/shared");
        let reply = push(&server, path, token, "same-key", &body);
        status(&reply, 200);
        assert!(
            text(&reply).contains("ok refs/tags/shared"),
            "{}",
            text(&reply)
        );
        tips.push(tip);
        original.push(reply);
    }
    for (index, (path, token, format, payload)) in inputs.into_iter().enumerate() {
        let reply = get(&server, path, "/info/refs?service=git-upload-pack", token);
        status(&reply, 200);
        let advertised = text(&reply);
        assert!(advertised.contains(&tips[index].to_string()));
        assert!(!advertised.contains(&tips[1 - index].to_string()));
        assert!(advertised.contains(&format!("object-format={}", format.as_str())));
        let (_, body) = push_body(format, payload, "refs/tags/shared");
        assert_eq!(
            push(&server, path, token, "same-key", &body),
            original[index]
        );
    }
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 12);
    assert_eq!(receipt.completed_sessions(), 6);
    assert_eq!(receipt.refused_sessions(), 6);
    for (index, configuration) in [first_configuration, second_configuration]
        .into_iter()
        .enumerate()
    {
        let node = OneNode::open_existing(configuration).unwrap();
        let snapshot = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            snapshot.basis().generation().get(),
            2,
            "the exact retry must not publish twice"
        );
        assert_eq!(snapshot.snapshot().refs.len(), 1);
        assert_eq!(
            snapshot.snapshot().refs[&RefName::try_new(b"refs/tags/shared").unwrap()],
            tips[index]
        );
        assert_eq!(
            node.read_git_object(tips[index]).unwrap().payload(),
            &[inputs[index].3]
        );
        assert!(
            node.read_git_object(tips[1 - index]).is_err(),
            "the other repository's object format is rejected by this fabric"
        );
        drop(snapshot);
        node.shutdown().unwrap();
    }
}

#[test]
fn credentials_reload_only_for_the_selected_incarnation_and_failures_do_not_disable_siblings() {
    let scratch = Scratch::new();
    let first = start_node(configuration(
        &scratch,
        "first",
        0x71,
        GitHashAlgorithm::Sha1,
    ));
    let second = start_node(configuration(
        &scratch,
        "second",
        0x81,
        GitHashAlgorithm::Sha1,
    ));
    let first_credentials = scratch.0.join("first.credentials");
    let second_credentials = scratch.0.join("second.credentials");
    let first_header = header(&first);
    let second_header = header(&second);
    replace(
        &first_credentials,
        &(first_header.clone() + &row('a', "read")),
    );
    replace(
        &second_credentials,
        &(second_header.clone() + &row('b', "read")),
    );
    let routes = vec![
        HttpRepositoryRoute::try_new(
            "/alpha/repo.git".into(),
            &first,
            &first_credentials,
            writable(),
        )
        .unwrap(),
        HttpRepositoryRoute::try_new(
            "/beta/repo.git".into(),
            &second,
            &second_credentials,
            writable(),
        )
        .unwrap(),
    ];
    second.shutdown().unwrap();
    let server = Server::start(first, routes, 11);
    let suffix = "/info/refs?service=git-upload-pack";
    status(&get(&server, "/alpha/repo.git", suffix, 'a'), 200);
    replace(
        &first_credentials,
        &(first_header.clone() + &row('c', "read")),
    );
    status(&get(&server, "/alpha/repo.git", suffix, 'a'), 401);
    status(&get(&server, "/alpha/repo.git", suffix, 'c'), 200);
    status(&get(&server, "/beta/repo.git", suffix, 'c'), 401);
    // A well-formed table bound to a different tenant/incarnation is not an
    // alternate source of authority for the selected route.
    replace(&first_credentials, &(second_header + &row('c', "read")));
    status(&get(&server, "/alpha/repo.git", suffix, 'c'), 503);
    status(&get(&server, "/beta/repo.git", suffix, 'b'), 200);
    replace(&first_credentials, &first_header);
    status(&get(&server, "/alpha/repo.git", suffix, 'c'), 401);
    replace(&first_credentials, "malformed table\n");
    status(&get(&server, "/alpha/repo.git", suffix, 'c'), 503);
    status(&get(&server, "/beta/repo.git", suffix, 'b'), 200);
    replace(&first_credentials, &(first_header + &row('c', "read")));
    status(&get(&server, "/alpha/repo.git", suffix, 'c'), 200);
    status(&get(&server, "/beta/repo.git", suffix, 'b'), 200);
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 11);
    assert_eq!(receipt.completed_sessions(), 6);
    assert_eq!(receipt.refused_sessions(), 5);
}

#[test]
fn repository_service_and_ref_ceilings_are_checked_before_publication() {
    let scratch = Scratch::new();
    let first_configuration = configuration(&scratch, "first", 0x71, GitHashAlgorithm::Sha1);
    let second_configuration = configuration(&scratch, "second", 0x81, GitHashAlgorithm::Sha256);
    let first = start_node(first_configuration.clone());
    let second = start_node(second_configuration.clone());
    let first_credentials = scratch.0.join("first.credentials");
    let second_credentials = scratch.0.join("second.credentials");
    let first_header = header(&first).replacen("credentials-v1", "credentials-v2", 1);
    replace(
        &first_credentials,
        &(first_header
            + &format!(
                "{} exact:{}\n",
                row('a', "read,receive,issues-read,issues-write").trim_end(),
                hex(b"refs/tags/permitted")
            )),
    );
    replace(
        &second_credentials,
        &(header(&second) + &row('b', "read,receive,issues-read,issues-write")),
    );
    let routes = vec![
        HttpRepositoryRoute::try_new(
            "/alpha/repo.git".into(),
            &first,
            &first_credentials,
            writable(),
        )
        .unwrap(),
        HttpRepositoryRoute::try_new(
            "/beta/repo.git".into(),
            &second,
            &second_credentials,
            HttpRepositoryServices::default(),
        )
        .unwrap(),
    ];
    second.shutdown().unwrap();
    let server = Server::start(first, routes, 6);
    let withheld = exchange(
        &server,
        "POST",
        "/beta/repo.git/git-receive-pack",
        'b',
        "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 1048576\r\nExpect: 100-continue\r\nIdempotency-Key: must-stay-unsealed\r\n",
        &[],
    );
    status(&withheld, 403);
    assert!(!text(&withheld).contains("100 Continue"));
    status(
        &get(
            &server,
            "/beta/repo.git",
            "/info/refs?service=git-upload-pack",
            'b',
        ),
        200,
    );
    status(&get(&server, "/beta/repo.git", "/api/v1/issues", 'b'), 403);
    let (_, denied) = push_body(GitHashAlgorithm::Sha1, b'x', "refs/tags/denied");
    let refused = push(&server, "/alpha/repo.git", 'a', "scoped-key", &denied);
    status(&refused, 200);
    assert!(text(&refused).contains("ERR "), "{}", text(&refused));
    assert!(!text(&refused).contains("ok refs/tags/denied"));
    let (tip, permitted) = push_body(GitHashAlgorithm::Sha1, b'x', "refs/tags/permitted");
    let accepted = push(&server, "/alpha/repo.git", 'a', "scoped-key", &permitted);
    status(&accepted, 200);
    assert!(text(&accepted).contains("ok refs/tags/permitted"));
    status(&get(&server, "/alpha/repo.git", "/api/v1/issues", 'a'), 200);
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 6);
    let first = OneNode::open_existing(first_configuration).unwrap();
    let state = first
        .runtime()
        .block_on(first.materialize_admission())
        .unwrap();
    assert_eq!(state.basis().generation().get(), 2);
    assert_eq!(state.snapshot().refs.len(), 1);
    assert_eq!(
        state.snapshot().refs[&RefName::try_new(b"refs/tags/permitted").unwrap()],
        tip
    );
    drop(state);
    first.shutdown().unwrap();
    let second = OneNode::open_existing(second_configuration).unwrap();
    let state = second
        .runtime()
        .block_on(second.materialize_admission())
        .unwrap();
    assert_eq!(state.basis().generation().get(), 1);
    assert!(state.snapshot().refs.is_empty());
    drop(state);
    second.shutdown().unwrap();
}

#[test]
fn native_writers_are_independent_and_stop_drains_the_original_route() {
    let scratch = Scratch::new();
    let configurations = [
        configuration(&scratch, "first", 0x71, GitHashAlgorithm::Sha1),
        configuration(&scratch, "second", 0x81, GitHashAlgorithm::Sha256),
    ];
    let first = start_node(configurations[0].clone());
    let second = start_node(configurations[1].clone());
    let first_credentials = scratch.0.join("first.credentials");
    let second_credentials = scratch.0.join("second.credentials");
    replace(
        &first_credentials,
        &(header(&first) + &row('a', "read,issues-read,issues-write")),
    );
    replace(
        &second_credentials,
        &(header(&second) + &row('b', "read,issues-read,issues-write")),
    );
    let routes = vec![
        HttpRepositoryRoute::try_new(
            "/alpha/repo.git".into(),
            &first,
            &first_credentials,
            writable(),
        )
        .unwrap(),
        HttpRepositoryRoute::try_new(
            "/beta/repo.git".into(),
            &second,
            &second_credentials,
            writable(),
        )
        .unwrap(),
    ];
    second.shutdown().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(AtomicBool::new(false));
    let child_stop = Arc::clone(&stop);
    let child_observed = Arc::clone(&observed);
    let worker = std::thread::spawn(move || {
        let result = first.serve_http_repositories_until_stopped(&listener, 2, routes, &|| {
            let stopped = child_stop.load(Ordering::Acquire);
            if stopped {
                child_observed.store(true, Ordering::Release);
            }
            Ok(stopped)
        });
        first.shutdown().unwrap();
        result.unwrap()
    });
    let endpoint = Endpoint { address };
    let first_body = b"expected_version=0&title=Alpha&body=first+tenant";
    let mut held = connect(address);
    held.write_all(request_head("POST", "/alpha/repo.git/api/v1/issues/1/open", 'a',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nExpect: 100-continue\r\nIdempotency-Key: same-issue-key\r\n", first_body.len())).as_bytes()).unwrap();
    let mut interim = [0; 25];
    held.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    // The first issue request holds its native writer gate before reading its
    // form. A second repository must not inherit that gate or its node lane.
    let second_body = b"expected_version=0&title=Beta&body=second+tenant";
    let reply = exchange(
        &endpoint,
        "POST",
        "/beta/repo.git/api/v1/issues/1/open",
        'b',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: same-issue-key\r\n",
            second_body.len()
        ),
        second_body,
    );
    // Release the held body even when the competing result is wrong, ensuring
    // test failure never strands a live server child.
    stop.store(true, Ordering::Release);
    let bound = Instant::now() + Duration::from_secs(5);
    while !observed.load(Ordering::Acquire) && Instant::now() < bound {
        std::thread::sleep(Duration::from_millis(1));
    }
    let draining = !worker.is_finished();
    held.write_all(first_body).unwrap();
    let original = read_reply(held);
    let receipt = worker.join().unwrap();
    status(&reply, 200);
    assert!(text(&reply).contains("\"outcome\":\"committed\""));
    status(&original, 200);
    assert!(text(&original).contains("\"outcome\":\"committed\""));
    assert!(observed.load(Ordering::Acquire) && draining);
    assert_eq!(receipt.accepted_sessions(), 2);
    assert_eq!(receipt.completed_sessions(), 2);
    assert_eq!(receipt.refused_sessions(), 0);
    for (configuration, title) in configurations.into_iter().zip(["Alpha", "Beta"]) {
        let node = reopen_node(configuration);
        let request = node.request_context();
        let page = node
            .runtime()
            .block_on(node.read_issues_in(&request, 0, 10, None))
            .unwrap();
        assert_eq!(page.issues.len(), 1);
        assert_eq!(page.issues[0].title, title);
        assert_eq!(page.issues[0].version.get(), 1);
        node.shutdown().unwrap();
    }
}
