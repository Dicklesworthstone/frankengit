//! Independent path-context and wildcard reference checks for sparse fetches.
use std::convert::Infallible;

use fgit_wire::sparse::{SparseLimits, SparsePatterns};

fn compile(body: &[u8]) -> SparsePatterns {
    SparsePatterns::compile(body, SparseLimits::default(), &mut || {
        Ok::<_, Infallible>(())
    })
    .unwrap()
}

fn selected(patterns: &SparsePatterns, path: &[u8]) -> bool {
    let mut inherited = patterns.root_included();
    for (offset, byte) in path.iter().enumerate() {
        if *byte == b'/' {
            inherited = patterns
                .matches_entry(&path[..offset], true, inherited, &mut || {
                    Ok::<_, Infallible>(())
                })
                .unwrap();
        }
    }
    patterns
        .matches_entry(path, false, inherited, &mut || Ok::<_, Infallible>(()))
        .unwrap()
}

#[test]
fn root_directory_rules_are_applied_before_selecting_top_level_files() {
    // The sparse object walker visits the empty root directory. Basename rules
    // can match it; path-anchored rules require a nonempty repository path.
    for (document, root, top_level, nested) in [
        (b"*/\n".as_slice(), true, true, true),
        (b"**/\n", true, true, true),
        (b"/\n", true, true, true),
        (b"/*/\n", false, false, true),
        (b"/**/\n", false, false, true),
        (b"*/\n!\n", false, false, true),
        (b"*/\n!/\n", false, false, true),
        (b"/\n!/\n", false, false, false),
        (b"!\n/\n", true, true, true),
        (b"/*\n!/*/\n", false, true, false),
    ] {
        let patterns = compile(document);
        assert_eq!(patterns.root_included(), root, "{document:?}");
        assert_eq!(selected(&patterns, b"README"), top_level, "{document:?}");
        assert_eq!(selected(&patterns, b"folder/file"), nested, "{document:?}");
    }
}

#[test]
fn only_a_matching_child_rule_overrides_its_directory_state() {
    let patterns = compile(b"/\n!/private/\n/private/public.txt\n!/docs/*.md\n");
    for (path, expected) in [
        (b"README".as_slice(), true),
        (b"private/key", false),
        (b"private/deep/key", false),
        (b"private/public.txt", true),
        (b"private/deep/public.txt", false),
        (b"docs/guide.md", false),
        (b"docs/guide.txt", true),
        (b"docs/deeper/guide.md", true),
        (b"other/private/key", true),
    ] {
        assert_eq!(selected(&patterns, path), expected, "{path:?}");
    }
}

#[test]
fn byte_classes_and_escaped_spaces_do_not_change_path_context() {
    for (document, included, excluded) in [
        (
            b"/[\\-a-c]/file".as_slice(),
            b"-/file".as_slice(),
            b"d/file".as_slice(),
        ),
        (b"/[!a-c]/file", b"\xff/file", b"b/file"),
        (b"/folder\\ /file\\ \n", b"folder /file ", b"folder/file "),
        (b"/dir\\\\/file", b"dir\\/file", b"dir/file"),
        (b"/line\rname/\n", b"line\rname/file", b"linename/file"),
    ] {
        let patterns = compile(document);
        assert!(selected(&patterns, included), "{document:?}: {included:?}");
        assert!(!selected(&patterns, excluded), "{document:?}: {excluded:?}");
    }
}

// Deliberately use small exhaustive recursive matching as an independent
// reference for the production engine's bounded dynamic-programming matcher.
fn reference(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => {
            reference(rest, text) || (!text.is_empty() && reference(pattern, &text[1..]))
        }
        Some((b'?', rest)) => !text.is_empty() && reference(rest, &text[1..]),
        Some((byte, rest)) => text.first() == Some(byte) && reference(rest, &text[1..]),
    }
}

fn words(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut level = vec![Vec::new()];
    for _ in 0..maximum {
        let mut next = Vec::new();
        for prefix in &level {
            for byte in alphabet {
                let mut word = prefix.clone();
                word.push(*byte);
                next.push(word);
            }
        }
        all.extend(next.iter().cloned());
        level = next;
    }
    all
}

#[test]
fn bounded_wildcards_agree_with_exhaustive_independent_reference() {
    let paths = words(b"ab", 5);
    for pattern in words(b"ab?*", 4).into_iter().skip(1) {
        let compiled = compile(&pattern);
        for path in paths.iter().skip(1) {
            assert_eq!(
                selected(&compiled, path),
                reference(&pattern, path),
                "pattern={pattern:?}, path={path:?}"
            );
        }
    }
}
