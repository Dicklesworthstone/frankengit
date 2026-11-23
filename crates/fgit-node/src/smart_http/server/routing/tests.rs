use super::*;

#[test]
fn route_paths_are_literal_qualified_names() {
    for path in ["/team/repo.git", "/a/b", "/Team-2/.repo_3", "/team/repo"] {
        HttpRepositoryRoute::validate_path(path).unwrap();
        assert_eq!(repository_path(path), Some(path));
    }
    for path in [
        "",
        "/",
        "//",
        "team/repo",
        "/repo.git",
        "//team/repo.git",
        "/team//repo.git",
        "/team/repo.git/",
        "/team/nested/repo.git",
        "/./repo",
        "/team/..",
        "/-team/repo",
        "/team/-repo",
        "/team/repo name",
        "/team/repo;name",
        "/team/repo\\name",
        "/team/répô",
        "/team/%72epo",
        "/team/repo?query",
        "/team/repo#fragment",
        "/team/repo\n",
    ] {
        assert!(
            HttpRepositoryRoute::validate_path(path).is_err(),
            "{path:?}"
        );
    }
    let maximum = format!("/a/{}", "b".repeat(509));
    HttpRepositoryRoute::validate_path(&maximum).unwrap();
    assert!(HttpRepositoryRoute::validate_path(&(maximum + "b")).is_err());
}

#[test]
fn selection_keeps_component_boundaries_and_retry_routes_in_the_same_repository() {
    for suffix in [
        "",
        "?key=value",
        "/info/refs?service=git-upload-pack",
        "/git-receive-pack",
        "/.fgit-receive/0123456789abcdef/info/refs?service=git-receive-pack",
        "/.fgit-receive/0123456789abcdef/git-receive-pack",
        "/api/v1/issues/1/open",
        "/api/v1/source/tree",
        "/ui/",
        "/info/lfs/objects/batch",
    ] {
        let request = format!("/team/repo.git{suffix}");
        assert_eq!(repository_path(&request), Some("/team/repo.git"));
    }
    // Prefixes, case and suffix variants are distinct lookup keys, never
    // aliases. Endpoint validation remains with the selected native adapter.
    for request in [
        "/team/repo.git-extra/info/refs",
        "/Team/repo.git/info/refs",
        "/team/repo/info/refs",
        "/team/repository.git/info/refs",
    ] {
        assert_ne!(repository_path(request), Some("/team/repo.git"));
    }
    for request in [
        "http://localhost/team/repo.git/info/refs",
        "/team",
        "/team/",
        "/team//repo.git",
        "//team/repo.git/info/refs",
        "/team%2frepo.git/info/refs",
        "/team/%72epo.git/info/refs",
        "/./repo.git/info/refs",
        "/team/../repo.git/info/refs",
        "*",
        "/team?repo.git/info/refs",
    ] {
        assert_eq!(repository_path(request), None, "{request}");
    }
}
