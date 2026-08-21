//! Path-security corpus for `TreeFS`.
//!
//! Every planted negative is paired with a near-identical permitted case that
//! proceeds. A refusal-only suite would pass just as well against a parser that
//! refuses everything, which proves nothing about the capability the crate is
//! supposed to deliver.

use fgit_treefs::path::{HostProfile, PathPolicy, PathRefusal, TreePath};

fn strict() -> PathPolicy {
    PathPolicy::default()
}

fn windows() -> PathPolicy {
    PathPolicy {
        host_profile: HostProfile::WindowsCompatible,
        ..PathPolicy::default()
    }
}

/// `parse` accepts the shapes a repository legitimately contains.
#[test]
fn ordinary_paths_are_accepted() {
    for accepted in [
        &b"README.md"[..],
        b"src/lib.rs",
        b"a/b/c/d/e.txt",
        b"weird name with spaces.txt",
        b"caf\xc3\xa9/na\xc3\xafve.txt",
        b"dot.in.middle/file.tar.gz",
        b"..hidden-but-not-parent",
        b"...three-dots",
        b".gitignore",
        b".github/workflows/ci.yml",
    ] {
        let parsed = TreePath::parse(accepted, &strict());
        assert!(
            parsed.is_ok(),
            "expected {:?} to parse, got {:?}",
            String::from_utf8_lossy(accepted),
            parsed.err()
        );
        assert_eq!(parsed.unwrap().as_bytes(), accepted);
    }
}

/// A parent-escape component is refused, and the near-identical name that
/// merely *starts* with dots is accepted.
#[test]
fn parent_escape_is_refused_but_dotted_names_are_not() {
    assert!(matches!(
        TreePath::parse(b"a/../b", &strict()),
        Err(PathRefusal::ParentEscape { component: 1 })
    ));
    assert!(matches!(
        TreePath::parse(b"..", &strict()),
        Err(PathRefusal::ParentEscape { component: 0 })
    ));
    assert!(matches!(
        TreePath::parse(b"a/b/..", &strict()),
        Err(PathRefusal::ParentEscape { component: 2 })
    ));

    // Permitted counterparts: these are ordinary names, not traversal.
    assert!(TreePath::parse(b"a/..b/c", &strict()).is_ok());
    assert!(TreePath::parse(b"a/b../c", &strict()).is_ok());
    assert!(TreePath::parse(b"a/...", &strict()).is_ok());
}

/// `.` is refused; a name that merely contains a dot is not.
#[test]
fn current_directory_component_is_refused() {
    assert!(matches!(
        TreePath::parse(b"a/./b", &strict()),
        Err(PathRefusal::CurrentDirectory { component: 1 })
    ));
    assert!(matches!(
        TreePath::parse(b".", &strict()),
        Err(PathRefusal::CurrentDirectory { component: 0 })
    ));
    assert!(TreePath::parse(b"a/.b/c", &strict()).is_ok());
    assert!(TreePath::parse(b"a/b.c/d", &strict()).is_ok());
}

/// An absolute path is refused; the same path relative is accepted.
#[test]
fn absolute_paths_are_refused() {
    assert_eq!(
        TreePath::parse(b"/etc/passwd", &strict()),
        Err(PathRefusal::Absolute)
    );
    assert!(TreePath::parse(b"etc/passwd", &strict()).is_ok());
}

/// Empty components, from doubled or trailing separators, are refused.
#[test]
fn empty_components_are_refused() {
    assert!(matches!(
        TreePath::parse(b"a//b", &strict()),
        Err(PathRefusal::EmptyComponent { component: 1 })
    ));
    assert!(matches!(
        TreePath::parse(b"a/b/", &strict()),
        Err(PathRefusal::EmptyComponent { component: 2 })
    ));
    assert_eq!(TreePath::parse(b"", &strict()), Err(PathRefusal::Empty));
    assert!(TreePath::parse(b"a/b", &strict()).is_ok());
}

/// NUL and control bytes are refused; high bytes (valid UTF-8) are not.
#[test]
fn nul_and_control_bytes_are_refused_but_utf8_is_not() {
    assert!(matches!(
        TreePath::parse(b"a/b\0c", &strict()),
        Err(PathRefusal::NulByte { .. })
    ));
    assert!(matches!(
        TreePath::parse(b"a/b\nc", &strict()),
        Err(PathRefusal::ControlByte { byte: b'\n', .. })
    ));
    assert!(matches!(
        TreePath::parse(b"a/b\tc", &strict()),
        Err(PathRefusal::ControlByte { byte: b'\t', .. })
    ));
    // Permitted: multi-byte UTF-8 is ordinary content.
    assert!(TreePath::parse("a/日本語.txt".as_bytes(), &strict()).is_ok());
}

/// `.git` and the variants a host resolves to it are refused; names that merely
/// begin with `.git` are accepted.
#[test]
fn git_metadata_is_refused_including_host_aliases() {
    for refused in [
        &b".git"[..],
        b".GIT",
        b".Git",
        b"a/.git/config",
        b".git.",
        b".git ",
        b"git~1",
        b"GIT~1",
    ] {
        assert!(
            matches!(
                TreePath::parse(refused, &strict()),
                Err(PathRefusal::GitMetadata { .. })
            ),
            "expected {:?} to be refused as git metadata",
            String::from_utf8_lossy(refused)
        );
    }

    // Permitted near-identical names.
    for accepted in [
        &b".gitignore"[..],
        b".gitattributes",
        b".gitmodules",
        b"git",
        b"a/git/b",
        b".github",
    ] {
        assert!(
            TreePath::parse(accepted, &strict()).is_ok(),
            "expected {:?} to be accepted",
            String::from_utf8_lossy(accepted)
        );
    }
}

/// Turning the git-metadata rule off is possible but explicit.
#[test]
fn git_metadata_refusal_is_policy_controlled() {
    let permissive = PathPolicy {
        refuse_git_metadata: false,
        ..PathPolicy::default()
    };
    assert!(TreePath::parse(b".git/config", &permissive).is_ok());
    assert!(TreePath::parse(b".git/config", &strict()).is_err());
}

/// The Windows profile refuses names that host would mangle; the repository
/// profile accepts the very same names.
#[test]
fn windows_profile_refuses_only_under_that_profile() {
    for refused in [
        &b"con"[..],
        b"CON",
        b"com1.txt",
        b"nul",
        b"a/prn/b",
        b"trailing.",
        b"trailing ",
        b"has:colon",
        b"has|pipe",
        b"has?question",
    ] {
        assert!(
            TreePath::parse(refused, &windows()).is_err(),
            "expected {:?} to be refused under the Windows profile",
            String::from_utf8_lossy(refused)
        );
        assert!(
            TreePath::parse(refused, &strict()).is_ok(),
            "expected {:?} to be accepted under the repository profile",
            String::from_utf8_lossy(refused)
        );
    }

    // Permitted under both: near-identical but not reserved.
    for accepted in [&b"console"[..], b"com0", b"comx", b"nulls", b"prn2x"] {
        assert!(
            TreePath::parse(accepted, &windows()).is_ok(),
            "expected {:?} to be accepted under the Windows profile",
            String::from_utf8_lossy(accepted)
        );
    }
}

/// Budgets refuse oversized input and accept the same shape just under them.
#[test]
fn size_budgets_are_enforced_at_the_boundary() {
    let policy = PathPolicy {
        max_path_bytes: 32,
        max_component_bytes: 8,
        max_components: 3,
        ..PathPolicy::default()
    };

    let at_component_limit = vec![b'a'; 8];
    assert!(TreePath::parse(&at_component_limit, &policy).is_ok());
    let over_component_limit = vec![b'a'; 9];
    assert!(matches!(
        TreePath::parse(&over_component_limit, &policy),
        Err(PathRefusal::ComponentTooLong { .. })
    ));

    assert!(TreePath::parse(b"a/b/c", &policy).is_ok());
    assert!(matches!(
        TreePath::parse(b"a/b/c/d", &policy),
        Err(PathRefusal::TooManyComponents { .. })
    ));

    let over_path_limit = vec![b'a'; 33];
    assert!(matches!(
        TreePath::parse(&over_path_limit, &policy),
        Err(PathRefusal::PathTooLong { .. })
    ));
}

/// Prefix containment is component-wise.
///
/// This is the assertion that a byte-prefix implementation fails, and it is the
/// one every capability check depends on.
#[test]
fn prefix_containment_is_component_wise() {
    let ab = TreePath::parse_default(b"a/b").unwrap();
    let abc = TreePath::parse_default(b"a/b/c").unwrap();
    let abc_sibling = TreePath::parse_default(b"a/bc").unwrap();
    let ab_prefixed = TreePath::parse_default(b"a/bcd/e").unwrap();

    assert!(abc.starts_with(&ab), "a/b/c is inside a/b");
    assert!(ab.starts_with(&ab), "a path contains itself");
    assert!(
        !abc_sibling.starts_with(&ab),
        "a/bc must NOT be inside a/b -- byte-prefix containment would say yes"
    );
    assert!(
        !ab_prefixed.starts_with(&ab),
        "a/bcd/e must NOT be inside a/b"
    );
    assert!(!ab.starts_with(&abc), "a/b is not inside a/b/c");
}

/// Structural accessors agree with the component view.
#[test]
fn structural_accessors_are_consistent() {
    let path = TreePath::parse_default(b"a/b/c.txt").unwrap();
    assert_eq!(path.component_count(), 3);
    assert_eq!(path.file_name(), b"c.txt");
    assert_eq!(path.parent().unwrap().as_bytes(), b"a/b");

    let ancestors = path.ancestors();
    assert_eq!(ancestors.len(), 2);
    assert_eq!(ancestors[0].as_bytes(), b"a");
    assert_eq!(ancestors[1].as_bytes(), b"a/b");

    let top = TreePath::parse_default(b"solo").unwrap();
    assert!(top.parent().is_none());
    assert!(top.ancestors().is_empty());
    assert_eq!(top.file_name(), b"solo");
}

/// `join` re-validates, so a component cannot smuggle a separator or a `..`
/// past the parser by arriving through the back door.
#[test]
fn join_revalidates_the_result() {
    let base = TreePath::parse_default(b"a/b").unwrap();
    assert_eq!(
        base.join(b"c", &strict()).unwrap().as_bytes(),
        b"a/b/c",
        "an ordinary component joins"
    );
    assert!(matches!(
        base.join(b"..", &strict()),
        Err(PathRefusal::ParentEscape { .. })
    ));
    assert!(matches!(
        base.join(b"", &strict()),
        Err(PathRefusal::EmptyComponent { .. })
    ));
    assert!(
        base.join(b"c/d", &strict()).is_ok(),
        "a separator in the joined text is parsed as components, not smuggled"
    );
    assert!(matches!(
        base.join(b"c\0d", &strict()),
        Err(PathRefusal::NulByte { .. })
    ));
}

/// Case aliases are detected so they can be refused, and a path never aliases
/// itself.
#[test]
fn case_aliases_are_detected_without_rewriting() {
    let lower = TreePath::parse_default(b"src/File.rs").unwrap();
    let upper = TreePath::parse_default(b"src/FILE.rs").unwrap();
    let other = TreePath::parse_default(b"src/other.rs").unwrap();

    assert!(lower.case_aliases(&upper), "these alias on a folding host");
    assert!(!lower.case_aliases(&lower), "a path never aliases itself");
    assert!(!lower.case_aliases(&other), "distinct names do not alias");

    // Detection must not rewrite: the original bytes survive exactly.
    assert_eq!(lower.as_bytes(), b"src/File.rs");
    assert_eq!(upper.as_bytes(), b"src/FILE.rs");
}
