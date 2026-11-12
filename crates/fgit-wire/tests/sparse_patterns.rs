//! Sparse-checkout byte grammar and bounded execution, independent of storage.
use std::convert::Infallible;

use fgit_wire::sparse::{SparseError, SparseLimits, SparsePatterns};

fn compile(body: &[u8]) -> SparsePatterns {
    SparsePatterns::compile(body, SparseLimits::default(), &mut || {
        Ok::<_, Infallible>(())
    })
    .unwrap()
}

fn includes(patterns: &SparsePatterns, path: &[u8], directory: bool) -> bool {
    let mut inherited = patterns.root_included();
    for (index, byte) in path.iter().enumerate() {
        if *byte == b'/' {
            inherited = patterns
                .matches_entry(&path[..index], true, inherited, &mut || {
                    Ok::<_, Infallible>(())
                })
                .unwrap();
        }
    }
    patterns
        .matches_entry(path, directory, inherited, &mut || Ok::<_, Infallible>(()))
        .unwrap()
}

#[test]
fn directories_inherit_and_children_can_override_excluded_parents() {
    let patterns = compile(b"src/\n!src/private/\nsrc/private/keep.rs\n!src/tmp\n");
    for (path, expected) in [
        (b"README".as_slice(), false),
        (b"src/lib.rs", true),
        (b"src/nested/module.rs", true),
        (b"src/private/secret.rs", false),
        (b"src/private/keep.rs", true),
        (b"src/tmp", false),
        (b"other/src/file", true),
        (b"other/src/private/secret.rs", true),
    ] {
        assert_eq!(includes(&patterns, path, false), expected, "{path:?}");
    }
    assert!(
        !includes(&patterns, b"src", false),
        "directory-only rule does not select a blob"
    );
    assert!(includes(&patterns, b"src", true));
}

#[test]
fn cone_patterns_anchor_directories_and_keep_files_above_selected_cone() {
    let patterns = compile(b"/*\n!/*/\n/src/\n!/src/*/\n/src/kept/\n");
    for (path, expected) in [
        (b"README".as_slice(), true),
        (b"other/file", false),
        (b"src/lib.rs", true),
        (b"src/excluded/file", false),
        (b"src/kept/file", true),
        (b"src/kept/deeper/file", true),
    ] {
        assert_eq!(includes(&patterns, path, false), expected, "{path:?}");
    }
}

#[test]
fn wildcard_slashes_double_stars_and_byte_classes_are_distinct() {
    for (pattern, yes, no) in [
        (
            b"/src/*.rs".as_slice(),
            b"src/lib.rs".as_slice(),
            b"src/deep/lib.rs".as_slice(),
        ),
        (b"/src/**/test?.[ch]", b"src/test1.c", b"src/test12.c"),
        (
            b"/src/**/test?.[ch]",
            b"src/a/b/test9.h",
            b"else/src/test1.c",
        ),
        (b"**/name", b"a/b/name", b"a/b/names"),
        (b"src/**", b"src/a/b", b"else/src/a"),
        (b"[a-c][!0-9]", b"nested/bx", b"nested/b1"),
        (b"[^a]x", b"bx", b"ax"),
        (b"[]]", b"]", b"["),
        (b"[[]", b"[", b"]"),
        (b"ab**cd", b"abZZcd", b"ab/ZZcd"),
        (b"/a/**/b/**/c", b"a/b/c", b"a/b/d"),
    ] {
        let patterns = compile(pattern);
        assert!(
            includes(&patterns, yes, false),
            "{pattern:?} should match {yes:?}"
        );
        assert!(
            !includes(&patterns, no, false),
            "{pattern:?} should not match {no:?}"
        );
    }
}

#[test]
fn raw_bytes_comments_crlf_bom_escaping_and_trailing_spaces_are_preserved() {
    let patterns = compile(
        b"\xef\xbb\xbf# comment\r\n\n\\#file\r\n\\!file\nspace\\ \ntrimmed   \nfile\\*\n\xff?\n",
    );
    for path in [
        b"#file".as_slice(),
        b"!file",
        b"space ",
        b"trimmed",
        b"file*",
        b"\xffz",
    ] {
        assert!(includes(&patterns, path, false), "{path:?}");
    }
    for path in [b"comment".as_slice(), b"space", b"trimmed ", b"filez"] {
        assert!(!includes(&patterns, path, false), "{path:?}");
    }
}

#[test]
fn last_matching_rule_wins_without_making_unmatched_root_entries_visible() {
    let patterns = compile(b"*.rs\n!secret.rs\nsecret.rs\n!last.rs\n");
    assert!(includes(&patterns, b"nested/secret.rs", false));
    assert!(!includes(&patterns, b"nested/last.rs", false));
    assert!(!includes(&patterns, b"other", false));
    assert!(!includes(&compile(b"# empty\n"), b"any", false));
    assert!(!includes(&compile(b""), b"any", true));
}

#[test]
fn unsupported_grammar_fails_closed_instead_of_becoming_literal_or_locale_dependent() {
    for pattern in [
        b"[[:alpha:]]".as_slice(),
        b"[[.a.]]",
        b"[[=a=]]",
        b"[z-a]",
        b"abc\\",
        b"[abc",
        b"a\\/b",
        b"nul\0name",
    ] {
        assert!(
            matches!(
                SparsePatterns::compile(pattern, SparseLimits::default(), &mut || Ok::<
                    _,
                    Infallible,
                >(
                    ()
                )),
                Err(SparseError::Unsupported { .. })
            ),
            "{pattern:?}"
        );
    }
}

#[test]
fn document_line_count_path_and_allocation_bounds_are_explicit() {
    for limits in [
        SparseLimits {
            max_blob_bytes: 2,
            ..SparseLimits::default()
        },
        SparseLimits {
            max_pattern_bytes: 1,
            ..SparseLimits::default()
        },
        SparseLimits {
            max_patterns: 1,
            ..SparseLimits::default()
        },
    ] {
        assert!(matches!(
            SparsePatterns::compile(b"ab\ncd", limits, &mut || Ok::<_, Infallible>(())),
            Err(SparseError::Limit(_))
        ));
    }
    let patterns = SparsePatterns::compile(
        b"*",
        SparseLimits {
            max_path_bytes: 3,
            ..SparseLimits::default()
        },
        &mut || Ok::<_, Infallible>(()),
    )
    .unwrap();
    assert!(matches!(
        patterns.matches_entry(b"long", false, false, &mut || Ok::<_, Infallible>(())),
        Err(SparseError::Limit(_))
    ));
    for path in [
        b"".as_slice(),
        b"/a",
        b"a/",
        b"a//b",
        b".",
        b"..",
        b"a/../b",
        b"a\0b",
    ] {
        assert!(
            matches!(
                compile(b"*").matches_entry(path, false, false, &mut || Ok::<_, Infallible>(())),
                Err(SparseError::InvalidPath)
            ),
            "{path:?}"
        );
    }
}

#[test]
fn every_compile_and_wildcard_transition_stop_propagates_the_original_checkpoint() {
    let body = b"**/a*[a-z]?/**/end\n!**/private/\n";
    let mut compile_polls = 0;
    SparsePatterns::compile(body, SparseLimits::default(), &mut || {
        compile_polls += 1;
        Ok::<_, usize>(())
    })
    .unwrap();
    for stop in 1..=compile_polls {
        let mut polls = 0;
        let observed = SparsePatterns::compile(body, SparseLimits::default(), &mut || {
            polls += 1;
            if polls == stop { Err(stop) } else { Ok(()) }
        });
        assert!(matches!(observed, Err(SparseError::Checkpoint(value)) if value == stop));
    }
    let patterns = compile(body);
    let path = b"x/y/abcdef/end";
    let mut match_polls = 0;
    patterns
        .matches_entry(path, false, false, &mut || {
            match_polls += 1;
            Ok::<_, usize>(())
        })
        .unwrap();
    assert!(
        match_polls > path.len(),
        "inner wildcard transitions are charged"
    );
    for stop in 1..=match_polls {
        let mut polls = 0;
        let observed = patterns.matches_entry(path, false, false, &mut || {
            polls += 1;
            if polls == stop { Err(stop) } else { Ok(()) }
        });
        assert!(matches!(observed, Err(SparseError::Checkpoint(value)) if value == stop));
    }
}
