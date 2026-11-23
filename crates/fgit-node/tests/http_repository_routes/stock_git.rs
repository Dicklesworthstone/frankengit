use super::*;

#[test]
fn stock_receive_redirects_and_attempt_urls_preserve_selected_repository_and_authentication() {
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
    let server = Server::start(first, routes, 7);
    let mut tips = Vec::new();
    for (index, (path, token, format, byte)) in [
        ("/alpha/repo.git", 'a', GitHashAlgorithm::Sha1, b'A'),
        ("/beta/repo.git", 'b', GitHashAlgorithm::Sha256, b'B'),
    ]
    .into_iter()
    .enumerate()
    {
        let discovered = get(&server, path, "/info/refs?service=git-receive-pack", token);
        status(&discovered, 307);
        let rendered = text(&discovered);
        let location = rendered
            .lines()
            .find_map(|line| line.strip_prefix("Location: "))
            .unwrap()
            .trim();
        assert!(
            location.starts_with(&format!("{path}/.fgit-receive/")),
            "{location}"
        );
        let permitted = exchange(&server, "GET", location, token, "", &[]);
        status(&permitted, 200);
        assert!(text(&permitted).contains(&format!("object-format={}", format.as_str())));
        if index == 0 {
            let foreign = location.replacen(path, "/beta/repo.git", 1);
            status(&exchange(&server, "GET", &foreign, token, "", &[]), 401);
        }
        let target = format!(
            "{}/git-receive-pack",
            location
                .strip_suffix("/info/refs?service=git-receive-pack")
                .unwrap()
        );
        let (tip, body) = push_body(format, byte, "refs/tags/stock-route");
        tips.push(tip);
        // No explicit key: stock Git carries the public attempt identifier in
        // the redirected URL; the server derives and verifies its ordinary seal.
        let published = exchange(
            &server,
            "POST",
            &target,
            token,
            &format!(
                "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n",
                body.len()
            ),
            &body,
        );
        status(&published, 200);
        assert!(
            text(&published).contains("ok refs/tags/stock-route"),
            "{}",
            text(&published)
        );
    }
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 7);
    assert_eq!(receipt.completed_sessions(), 6);
    assert_eq!(receipt.refused_sessions(), 1);
    for (index, configuration) in configurations.into_iter().enumerate() {
        let node = OneNode::open_existing(configuration).unwrap();
        let state = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(state.basis().generation().get(), 2);
        assert_eq!(state.snapshot().refs.len(), 1);
        assert_eq!(
            state.snapshot().refs[&RefName::try_new(b"refs/tags/stock-route").unwrap()],
            tips[index]
        );
        drop(state);
        node.shutdown().unwrap();
    }
}
