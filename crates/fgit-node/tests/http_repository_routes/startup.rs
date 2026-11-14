use super::*;
use fgit_node::GitDaemonServerLimits;
use fgit_node::smart_http::server::MAX_HTTP_REPOSITORY_ROUTES;

#[test]
fn startup_refuses_ambiguous_roots_identities_and_unready_nodes_before_accepting() {
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
        GitHashAlgorithm::Sha256,
    ));
    let nested = start_node(configuration(
        &scratch,
        "first/nested",
        0x91,
        GitHashAlgorithm::Sha1,
    ));
    let first_credentials = scratch.0.join("first.credentials");
    let second_credentials = scratch.0.join("second.credentials");
    let nested_credentials = scratch.0.join("nested.credentials");
    for (node, path) in [
        (&first, &first_credentials),
        (&second, &second_credentials),
        (&nested, &nested_credentials),
    ] {
        replace(path, &(header(node) + &row('a', "read")));
    }
    let first_route = HttpRepositoryRoute::try_new(
        "/alpha/repo.git".into(),
        &first,
        &first_credentials,
        writable(),
    )
    .unwrap();
    let second_route = HttpRepositoryRoute::try_new(
        "/beta/repo.git".into(),
        &second,
        &second_credentials,
        writable(),
    )
    .unwrap();
    HttpRepositoryRoute::validate_catalog(&[first_route.clone(), second_route.clone()]).unwrap();
    let duplicate_path = HttpRepositoryRoute::try_new(
        "/alpha/repo.git".into(),
        &second,
        &second_credentials,
        writable(),
    )
    .unwrap();
    let duplicate_identity = HttpRepositoryRoute::try_new(
        "/alpha/alias.git".into(),
        &first,
        &first_credentials,
        writable(),
    )
    .unwrap();
    let nested_route = HttpRepositoryRoute::try_new(
        "/gamma/repo.git".into(),
        &nested,
        &nested_credentials,
        writable(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for (other, expected) in [
        (duplicate_path, "duplicate HTTP repository route"),
        (duplicate_identity, "duplicate HTTP repository identity"),
        (nested_route, "overlapping HTTP repository roots"),
    ] {
        let refused = first
            .serve_http_repositories_bounded(
                &listener,
                GitDaemonServerLimits::try_new(1, 1).unwrap(),
                vec![first_route.clone(), other],
                Duration::from_millis(1),
            )
            .unwrap_err();
        assert!(refused.to_string().contains(expected), "{refused}");
    }
    assert!(HttpRepositoryRoute::validate_catalog(&[]).is_err());
    let (unready, _) = OneNode::init(configuration(
        &scratch,
        "unready",
        0xa1,
        GitHashAlgorithm::Sha1,
    ))
    .unwrap();
    let unready_credentials = scratch.0.join("unready.credentials");
    replace(
        &unready_credentials,
        &(header(&unready) + &row('a', "read")),
    );
    assert!(
        HttpRepositoryRoute::try_new(
            "/unready/repo.git".into(),
            &unready,
            &unready_credentials,
            writable()
        )
        .is_err()
    );
    // An unavailable later grant file invalidates the whole catalog; the valid
    // first row cannot be served as a partially successful startup.
    replace(&second_credentials, "malformed later credential file\n");
    assert!(
        first
            .serve_http_repositories_bounded(
                &listener,
                GitDaemonServerLimits::try_new(1, 1).unwrap(),
                vec![first_route.clone(), second_route],
                Duration::from_millis(1),
            )
            .is_err()
    );
    let stopped = first
        .serve_http_repositories_until_stopped(&listener, 1, vec![first_route], &|| Ok(true))
        .unwrap();
    assert_eq!(stopped.accepted_sessions(), 0);
    assert_eq!(stopped.completed_sessions(), 0);
    assert_eq!(stopped.refused_sessions(), 0);
    unready.shutdown().unwrap();
    nested.shutdown().unwrap();
    second.shutdown().unwrap();
    first.shutdown().unwrap();
}

#[test]
fn the_full_catalog_bound_is_admitted_and_one_extra_route_is_refused() {
    let scratch = Scratch::new();
    let mut routes = Vec::new();
    // Repositories are initialized and closed one at a time. A catalog retains
    // configuration, not 64 live runtimes or database connections.
    for index in 0..MAX_HTTP_REPOSITORY_ROUTES {
        let label = format!("node-{index}");
        let node = start_node(configuration(
            &scratch,
            &label,
            u8::try_from(index + 1).unwrap(),
            GitHashAlgorithm::Sha1,
        ));
        let credentials = scratch.0.join(format!("credentials-{index}"));
        replace(&credentials, &(header(&node) + &row('a', "read")));
        routes.push(
            HttpRepositoryRoute::try_new(
                format!("/tenant/repo-{index}"),
                &node,
                &credentials,
                HttpRepositoryServices::default(),
            )
            .unwrap(),
        );
        node.shutdown().unwrap();
    }
    HttpRepositoryRoute::validate_catalog(&routes).unwrap();
    // The size bound must be evaluated before duplicate or file inspection.
    routes.push(routes[0].clone());
    let refused = HttpRepositoryRoute::validate_catalog(&routes).unwrap_err();
    assert!(refused.to_string().contains("1..64"), "{refused}");
}

#[test]
fn cold_open_refuses_a_replacement_incarnation_without_exposing_another_repository() {
    let scratch = Scratch::new();
    let first = start_node(configuration(
        &scratch,
        "first",
        0x71,
        GitHashAlgorithm::Sha1,
    ));
    let coordinator = start_node(configuration(
        &scratch,
        "coordinator",
        0x81,
        GitHashAlgorithm::Sha256,
    ));
    let first_credentials = scratch.0.join("first.credentials");
    let coordinator_credentials = scratch.0.join("coordinator.credentials");
    replace(&first_credentials, &(header(&first) + &row('a', "read")));
    replace(
        &coordinator_credentials,
        &(header(&coordinator) + &row('b', "read")),
    );
    let original_incarnation = first.repository_incarnation_id();
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
            &coordinator,
            &coordinator_credentials,
            writable(),
        )
        .unwrap(),
    ];
    first.shutdown().unwrap();
    std::fs::rename(scratch.0.join("first"), scratch.0.join("retained-original")).unwrap();
    // Make a genuinely different incarnation at the same exact operator path,
    // with matching tenant/repository IDs and hash format.
    let replacement = start_node(configuration(
        &scratch,
        "first",
        0x71,
        GitHashAlgorithm::Sha1,
    ));
    assert_ne!(
        replacement.repository_incarnation_id(),
        original_incarnation
    );
    replacement.shutdown().unwrap();
    let server = Server::start(coordinator, routes, 2);
    status(
        &get(
            &server,
            "/alpha/repo.git",
            "/info/refs?service=git-upload-pack",
            'a',
        ),
        503,
    );
    status(
        &get(
            &server,
            "/beta/repo.git",
            "/info/refs?service=git-upload-pack",
            'b',
        ),
        200,
    );
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 2);
    assert_eq!(receipt.completed_sessions(), 1);
    assert_eq!(receipt.refused_sessions(), 1);
}
