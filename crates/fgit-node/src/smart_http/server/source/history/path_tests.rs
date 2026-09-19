use super::*;
use fgit_wire::smart_http::head;

fn form(format: GitHashAlgorithm) -> String {
    format!("object_format={}&ref=refs/heads/main", format.as_str())
}

#[test]
fn path_forms_accept_raw_bytes_and_keep_existing_snapshot_contracts() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let base = form(format);
        let command = Command::parse((base.clone() + "&path_hex=6469722fff").as_bytes(), format).unwrap();
        assert_eq!(command.path.as_deref(), Some(b"dir/\xff".as_slice()));
        assert_eq!(command.options, LogOptions::default());
        assert!(Command::parse((base.clone() + "&path_hex=61&after=1").as_bytes(), format).is_err());
        let pinned = format!("{base}&path_hex=61&after=1&expected_head=alg:1:{}", "a".repeat(64));
        assert_eq!(Command::parse(pinned.as_bytes(), format).unwrap().options.after, 1);
        let limited = format!("{base}&path_hex=61&max_tree_entries=12&max_cached_bytes=1024");
        let command = Command::parse(limited.as_bytes(), format).unwrap();
        assert_eq!(command.options.limits.max_tree_entries, 12);
        assert_eq!(command.options.limits.max_cached_bytes, 1024);
    }
}

#[test]
fn malformed_duplicate_oversized_and_inapplicable_path_fields_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let base = form(format);
    for suffix in ["&path_hex=", "&path_hex=f", "&path_hex=FF", "&path_hex=gg", "&path_hex=00",
        "&path_hex=2e2e2f61", "&path_hex=612f2f62", "&path_hex=2f61", "&path_hex=612f",
        "&path_hex=61&path_hex=62", "&path_hex=61&max_tree_entries=0",
        "&path_hex=61&max_tree_entries=100001", "&path_hex=61&max_cached_bytes=33554433",
        "&max_tree_entries=12", "&max_cached_bytes=1024", "&path=src", "&follow=true"] {
        assert!(Command::parse((base.clone() + suffix).as_bytes(), format).is_err(), "{suffix}");
    }
    assert!(path_hex(&"61".repeat(4097)).is_err());
    assert_eq!(path_hex(&"61".repeat(4096)).unwrap().len(), 4096);
    // The decoder preserves bytes; the typed path validator rejects traversal.
    assert_eq!(path_hex("2e2e2f61").unwrap(), b"../a");
}

#[test]
fn filtered_pages_allow_absent_tip_and_zero_matches_without_weakening_full_log() {
    let format = GitHashAlgorithm::Sha1;
    let tree = git_object_id(format, GitObjectKind::Tree, &[]);
    let body = format!("tree {tree}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nroot\n").into_bytes();
    let id = git_object_id(format, GitObjectKind::Commit, &body);
    let tip = git_object_id(format, GitObjectKind::Commit, b"different tip");
    let row = HistoryCommit { id, tree, parents: vec![], body };
    let page = HistoryPage { tip, total_commits: 1, after: 0, next_after: None, commits: vec![row.clone()] };
    assert!(validate_page_bounds(&page, LogOptions::default(), format).is_ok());
    assert!(validate_page(&page, LogOptions::default(), format).is_err());
    let empty = HistoryPage { tip, total_commits: 0, after: 0, next_after: None, commits: vec![] };
    assert!(validate_page_bounds(&empty, LogOptions::default(), format).is_ok());
    assert!(validate_page(&empty, LogOptions::default(), format).is_err());
    let mut partial = page.clone(); partial.total_commits = 2;
    assert!(validate_page_bounds(&partial, LogOptions::default(), format).is_err());
    partial.commits.push(row);
    assert!(validate_page_bounds(&partial, LogOptions::default(), format).is_err());
    let mut invalid = empty; invalid.next_after = Some(0);
    assert!(validate_page_bounds(&invalid, LogOptions::default(), format).is_err());
    let mut invalid = page; invalid.after = 2;
    assert!(validate_page_bounds(&invalid, LogOptions::default(), format).is_err());
}

#[test]
fn path_response_identifies_exact_unsimplified_selection_and_charges_output() {
    let mut out = Output::new(4096);
    render_path_selection(&mut out, b"dir/\xff", &mut || true).unwrap();
    assert!(out.body.contains("\"path_hex\":\"6469722fff\""));
    assert!(out.body.contains("\"path_selection\":\"changed-against-any-parent-v1\""));
    assert!(out.body.contains("\"total_commits_scope\":\"matching-path\""));
    assert!(out.body.contains("\"history_simplified\":false"));
    assert!(out.body.contains("\"renames_followed\":false"));
    assert!(render_path_selection(&mut Output::new(10), b"a", &mut || true).is_err());
    assert!(render_path_selection(&mut Output::new(4096), b"a", &mut || false).is_err());
}

#[test]
fn outer_source_routing_keeps_path_history_in_the_read_only_profile() {
    let form = "object_format=sha1&ref=refs/heads/main&path_hex=61";
    let bytes = format!("POST /repo.git/api/v1/source/log HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n", form.len());
    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    let outer = super::super::Request::parse(&envelope).unwrap();
    assert!(!outer.is_mutation());
    assert!(Command::parse(form.as_bytes(), GitHashAlgorithm::Sha1).unwrap().path.is_some());
}
