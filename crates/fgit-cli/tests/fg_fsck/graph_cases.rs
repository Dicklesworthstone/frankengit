use super::*;

#[test]
fn default_graph_scan_and_explicit_byte_scan_report_distinct_evidence() {
    let scratch = Scratch::new();
    let (root, fixture) = imported(&scratch);
    let graph = success(audit(&root, "sha1", &[]));
    assert_counts(&graph, 2, 6);
    for field in ["\"graph_profile\":\"native-closure-v1\"", "\"graph_acyclic\":true",
        "\"local_edges_verified\":4", "\"external_gitlinks\":0"]
    { assert!(graph.contains(field), "{field}: {graph}"); }
    let bytes = success(audit(&root, "sha1", &["--objects-only"]));
    assert_eq!(token(&bytes), token(&graph));
    assert!(bytes.contains(&format!("\"payload_bytes_verified\":{},", fixture.payload_bytes)));
    assert!(bytes.contains("\"objects_verified\":6,"));
    for field in ["\"object_graph_verified\":false", "\"graph_profile\":null",
        "\"local_edges_verified\":null", "\"graph_acyclic\":null"]
    { assert!(bytes.contains(field), "{field}: {bytes}"); }
    assert_eq!(success(audit(&root, "sha1", &[])), graph);
}

#[test]
fn edge_budget_exhaustion_has_no_partial_or_objects_only_success() {
    let scratch = Scratch::new();
    let (root, _) = imported(&scratch);
    let receipt = success(audit(&root, "sha1", &["--max-edges", "4"]));
    assert_counts(&receipt, 2, 6);
    let error = refused(audit(&root, "sha1", &["--max-edges", "3"]));
    assert!(error.contains("max-edges"), "{error}");
    assert!(!error.contains("graph_object_malformed"), "a work budget is not corruption: {error}");
    assert_eq!(success(audit(&root, "sha1", &[])), receipt);
    refused(audit(&root, "sha1", &["--objects-only", "--max-edges", "4"]));
    let absent = scratch.0.join("never-opened");
    for extra in [vec!["--max-edges", "0"], vec!["--max-edges", "8000001"],
        vec!["--objects-only", "--objects-only"], vec!["--objects-only", "--max-edges", "1"]]
    {
        refused(audit(&absent, "sha1", &extra));
        assert!(!absent.exists(), "bad graph options opened storage");
    }
}

fn loose_as(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let oid_text = oid.to_string();
    let path = root.join("objects").join(&oid_text[..2]).join(&oid_text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut framed = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    framed.extend_from_slice(body);
    let length = u16::try_from(framed.len()).expect("small graph fixture object");
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend_from_slice(&length.to_le_bytes());
    zlib.extend_from_slice(&(!length).to_le_bytes());
    zlib.extend_from_slice(&framed);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in framed { a = (a + u32::from(byte)) % 65_521; b = (b + a) % 65_521; }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    fs::write(path, zlib).unwrap();
    oid
}

#[test]
fn both_hash_formats_import_tag_chains_symlinks_and_external_gitlinks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let root = scratch.0.join("node");
        let source = scratch.0.join("source.git");
        let file = loose_as(&source, format, GitObjectKind::Blob, b"graph source\0binary\xff");
        let symlink = loose_as(&source, format, GitObjectKind::Blob, b"file");
        let foreign = git_object_id(format, GitObjectKind::Commit, b"external repository data");
        let mut tree = Vec::new();
        for (mode, name, oid) in [(b"100644".as_slice(), b"file".as_slice(), file),
            (b"120000", b"link", symlink), (b"160000", b"submodule", foreign)]
        {
            tree.extend_from_slice(mode);
            tree.push(b' ');
            tree.extend_from_slice(name);
            tree.push(0);
            tree.extend_from_slice(oid.as_bytes());
        }
        let tree = loose_as(&source, format, GitObjectKind::Tree, &tree);
        let commit = format!("tree {tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter C <c@example.invalid> 1 +0000\n\nsource graph\n");
        let commit = loose_as(&source, format, GitObjectKind::Commit, commit.as_bytes());
        let tag = format!("object {commit}\ntype commit\ntag inner\ntagger T <t@example.invalid> 1 +0000\n\ninner tag\n");
        let tag = loose_as(&source, format, GitObjectKind::Tag, tag.as_bytes());
        let outer = format!("object {tag}\ntype tag\ntag outer\ntagger T <t@example.invalid> 1 +0000\n\nouter tag\n");
        let outer = loose_as(&source, format, GitObjectKind::Tag, outer.as_bytes());
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::create_dir_all(source.join("refs/tags")).unwrap();
        fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        fs::write(source.join("refs/tags/v1"), format!("{outer}\n")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        if format == GitHashAlgorithm::Sha256 {
            fs::write(source.join("config"), "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectFormat = sha256\n").unwrap();
        }
        success(fg(&["init", text(&root), TENANT, REPOSITORY, format.as_str()]));
        success(fg(&["import", text(&root), TENANT, REPOSITORY, ACTOR, "fsck-graph-fixture", text(&source)]));
        let receipt = success(audit(&root, format.as_str(), &["--max-edges", "6"]));
        assert_counts(&receipt, 2, 6);
        assert!(receipt.contains("\"local_edges_verified\":5,"), "{receipt}");
        assert!(receipt.contains("\"external_gitlinks\":1,"), "{receipt}");
        // The foreign commit was never written to source or node storage.
        // It is still charged as an inspected edge, but not traversed locally.
        assert!(refused(audit(&root, format.as_str(), &["--max-edges", "5"])).contains("max-edges"));
        assert_eq!(success(audit(&root, format.as_str(), &[])), receipt);
    }
}
