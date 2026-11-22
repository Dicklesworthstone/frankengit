//! Structural Git diff fixtures, not object-store or differential evidence.
//! Native consumers bind the accepted full IDs to their selected tree and domain.

use super::*;
use std::cell::Cell;

fn parse(bytes: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse_with_gitlinks(bytes, PatchLimits::default(), &|| false)
}

fn image(id: &str) -> Vec<u8> {
    format!("Subproject commit {id}\n").into_bytes()
}

fn section(change: FileChange, path: &str, old: &str, new: &str) -> String {
    let prefix = format!("diff --git a/{path} b/{path}\n");
    match change {
        FileChange::Create => format!(
            "{prefix}new file mode 160000\nindex {old}..{new}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+Subproject commit {new}\n"
        ),
        FileChange::Modify => format!(
            "{prefix}index {old}..{new} 160000\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-Subproject commit {old}\n+Subproject commit {new}\n"
        ),
        FileChange::Delete => format!(
            "{prefix}deleted file mode 160000\nindex {old}..{new}\n--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-Subproject commit {old}\n"
        ),
    }
}

fn old_profiles(bytes: &[u8]) -> [Result<UnifiedPatch<'_>, PatchError>; 6] {
    let limits = PatchLimits::default();
    [
        UnifiedPatch::parse(bytes, limits, &|| false),
        UnifiedPatch::parse_with_renames(bytes, limits, &|| false),
        UnifiedPatch::parse_with_binary(bytes, limits, &|| false),
        UnifiedPatch::parse_with_binary_and_renames(bytes, limits, &|| false),
        UnifiedPatch::parse_with_binary_renames(bytes, limits, &|| false),
        UnifiedPatch::parse_with_symlinks(bytes, limits, &|| false),
    ]
}

#[test]
fn explicit_gitlink_profile_applies_full_pointer_add_update_and_delete() {
    for width in [40, 64] {
        let old = "a".repeat(width);
        let new = "b".repeat(width);
        let absent = "0".repeat(width);
        let old_image = image(&old);
        for (change, before, after, source, expected) in [
            (
                FileChange::Create,
                absent.as_str(),
                new.as_str(),
                None,
                Some(PatchedFile {
                    mode: 0o160000,
                    content: image(&new),
                }),
            ),
            (
                FileChange::Modify,
                old.as_str(),
                new.as_str(),
                Some((0o160000, old_image.as_slice())),
                Some(PatchedFile {
                    mode: 0o160000,
                    content: image(&new),
                }),
            ),
            (
                FileChange::Delete,
                old.as_str(),
                absent.as_str(),
                Some((0o160000, old_image.as_slice())),
                None,
            ),
        ] {
            let bytes = section(change, "vendor/sub", before, after);
            let patch = parse(bytes.as_bytes()).unwrap();
            let file = &patch.files()[0];
            assert!(file.allows_gitlinks());
            assert!(file.is_gitlink());
            assert!(!file.allows_symlinks());
            assert_eq!(file.path(), b"vendor/sub");
            assert_eq!(file.source_path(), b"vendor/sub");
            assert_eq!(file.renamed_from(), None);
            assert_eq!(file.change(), change);
            assert_eq!(file.hunk_count(), 1);
            assert_eq!(file.binary_hunks(), None);
            assert_eq!(
                file.index(),
                Some(&IndexExpectation {
                    old: before.as_bytes().to_vec(),
                    new: after.as_bytes().to_vec(),
                })
            );
            assert_eq!(file.apply(source, patch.limits(), &|| false), Ok(expected));
            for legacy in old_profiles(bytes.as_bytes()) {
                assert!(matches!(legacy, Err(PatchError::Unsupported { .. })));
            }
        }
    }
}

#[test]
fn ordinary_text_and_modes_keep_exact_file_behavior_in_the_new_profile() {
    for (bytes, source) in [
        (
            b"diff --git a/.gitmodules b/.gitmodules\nindex aaaa..bbbb 100644\n--- a/.gitmodules\n+++ b/.gitmodules\n@@ -1 +1 @@\n-old\n+new\n".as_slice(),
            Some((0o100644, b"old\n".as_slice())),
        ),
        (
            b"diff --git a/empty b/empty\nnew file mode 100644\n",
            None,
        ),
        (
            b"diff --git a/script b/script\nold mode 100644\nnew mode 100755\n",
            Some((0o100644, b"exact\0bytes".as_slice())),
        ),
        (
            b"diff --git a/gone b/gone\ndeleted file mode 100644\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
            Some((0o100644, b"old\n".as_slice())),
        ),
    ] {
        let ordinary = UnifiedPatch::parse(bytes, PatchLimits::default(), &|| false).unwrap();
        let opted_in = parse(bytes).unwrap();
        let file = &opted_in.files()[0];
        assert!(file.allows_gitlinks());
        assert!(!file.is_gitlink());
        assert_eq!(file.index(), ordinary.files()[0].index());
        assert_eq!(
            file.apply(source, opted_in.limits(), &|| false),
            ordinary.files()[0].apply(source, ordinary.limits(), &|| false)
        );
    }
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let combined = section(FileChange::Modify, "vendor/sub", &old, &new)
        + "diff --git a/.gitmodules b/.gitmodules\n--- a/.gitmodules\n+++ b/.gitmodules\n@@ -1 +1 @@\n-old\n+new\n";
    let patch = parse(combined.as_bytes()).unwrap();
    assert_eq!(patch.files().len(), 2);
    assert_eq!(patch.files()[0].path(), b".gitmodules");
    assert!(!patch.files()[0].is_gitlink());
    assert_eq!(patch.files()[1].path(), b"vendor/sub");
    assert!(patch.files()[1].is_gitlink());
}

#[test]
fn omitted_mode_cannot_reinterpret_a_gitlink_source_in_any_profile() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let bytes = section(FileChange::Modify, "sub", &old, &new)
        .replace(&format!("index {old}..{new} 160000\n"), "");
    let source = image(&old);
    let mut profiles = old_profiles(bytes.as_bytes())
        .into_iter()
        .collect::<Vec<_>>();
    profiles.push(parse(bytes.as_bytes()));
    for parsed in profiles {
        let patch = parsed.unwrap();
        let file = &patch.files()[0];
        assert!(!file.is_gitlink());
        assert_eq!(
            file.apply(Some((0o160000, &source)), patch.limits(), &|| false),
            Err(PatchError::SourceMode)
        );
        assert_eq!(
            file.apply(Some((0o100644, &source)), patch.limits(), &|| false)
                .unwrap(),
            Some(PatchedFile {
                mode: 0o100644,
                content: image(&new),
            })
        );
    }
}

#[test]
fn full_equal_width_nonzero_present_ids_are_mandatory() {
    for width in [40, 64] {
        let old = "a".repeat(width);
        let new = "b".repeat(width);
        let zero = "0".repeat(width);
        for (change, before, after) in [
            (FileChange::Create, old.as_str(), new.as_str()),
            (FileChange::Create, zero.as_str(), zero.as_str()),
            (FileChange::Modify, zero.as_str(), new.as_str()),
            (FileChange::Modify, old.as_str(), zero.as_str()),
            (FileChange::Delete, old.as_str(), new.as_str()),
            (FileChange::Delete, zero.as_str(), zero.as_str()),
        ] {
            let bytes = section(change, "sub", before, after);
            assert_eq!(parse(bytes.as_bytes()), Err(PatchError::SourcePresence));
        }
        for (before, after) in [
            (old[..7].to_owned(), new.clone()),
            (old.clone(), new[..7].to_owned()),
            ("a".repeat(width - 1), "b".repeat(width - 1)),
            (old.clone(), "b".repeat(if width == 40 { 64 } else { 40 })),
            (old.to_ascii_uppercase(), new.clone()),
            (old.clone(), new.to_ascii_uppercase()),
        ] {
            assert!(parse(section(FileChange::Modify, "sub", &before, &after).as_bytes()).is_err());
        }
        let bytes = section(FileChange::Create, "sub", &zero, &new)
            .replace(&format!("index {zero}..{new}\n"), "");
        assert!(parse(bytes.as_bytes()).is_err());
        let bytes = section(FileChange::Delete, "sub", &old, &zero)
            .replace(&format!("index {old}..{zero}\n"), "");
        assert!(parse(bytes.as_bytes()).is_err());
    }
}

#[test]
fn hunk_images_are_exact_full_index_id_lines_with_a_final_lf() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let canonical = section(FileChange::Modify, "sub", &old, &new);
    for (needle, replacement) in [
        (
            format!("-Subproject commit {old}\n"),
            format!("-Subproject commit {old}-dirty\n"),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {new}-dirty\n"),
        ),
        (
            format!("-Subproject commit {old}\n"),
            format!("-Subproject commit {}\n", &old[..7]),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {}\n", &new[..7]),
        ),
        (
            format!("-Subproject commit {old}\n"),
            format!("-Subproject commit {new}\n"),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {old}\n"),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {new}\r\n"),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {new} \n"),
        ),
        (
            format!("+Subproject commit {new}\n"),
            format!("+Subproject commit {new}\n\\ No newline at end of file\n"),
        ),
        (
            format!("-Subproject commit {old}\n"),
            format!("-Subproject commit {old}\n\\ No newline at end of file\n"),
        ),
        (
            "+Subproject commit ".to_owned(),
            "+Subproject commit  ".to_owned(),
        ),
        (
            "+Subproject commit ".to_owned(),
            "+subproject commit ".to_owned(),
        ),
    ] {
        assert!(parse(canonical.replace(&needle, &replacement).as_bytes()).is_err());
    }
    assert!(parse(canonical.trim_end_matches('\n').as_bytes()).is_err());
}

#[test]
fn gitlink_application_requires_the_exact_whole_original_pointer_image() {
    for width in [40, 64] {
        let old = "a".repeat(width);
        let new = "b".repeat(width);
        for change in [FileChange::Modify, FileChange::Delete] {
            let after = if change == FileChange::Delete {
                "0".repeat(width)
            } else {
                new.clone()
            };
            let bytes = section(change, "sub", &old, &after);
            let patch = parse(bytes.as_bytes()).unwrap();
            let file = &patch.files()[0];
            assert_eq!(
                file.apply(None, patch.limits(), &|| false),
                Err(PatchError::SourcePresence)
            );
            for mode in [0o100644, 0o100755, 0o120000, 0o40000] {
                assert_eq!(
                    file.apply(Some((mode, &image(&old))), patch.limits(), &|| false),
                    Err(PatchError::SourceMode)
                );
            }
            for wrong in [
                image(&new),
                format!("Subproject commit {old}").into_bytes(),
                format!("Subproject commit {old}\nextra\n").into_bytes(),
                format!("Subproject commit {old}-dirty\n").into_bytes(),
                format!("Subproject commit {old}\r\n").into_bytes(),
                format!("Subproject commit {}\n", &old[..7]).into_bytes(),
                Vec::new(),
            ] {
                assert!(matches!(
                    file.apply(Some((0o160000, &wrong)), patch.limits(), &|| false),
                    Err(PatchError::ContextMismatch { .. })
                ));
            }
        }
        let bytes = section(FileChange::Create, "sub", &"0".repeat(width), &new);
        let patch = parse(bytes.as_bytes()).unwrap();
        assert_eq!(
            patch.files()[0].apply(Some((0o160000, &image(&old))), patch.limits(), &|| false),
            Err(PatchError::SourcePresence)
        );
    }
}

#[test]
fn only_canonical_single_whole_image_hunks_and_unambiguous_headers_are_admitted() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let canonical = section(FileChange::Modify, "sub", &old, &new);
    for header in [
        "@@ -1,1 +1,1 @@\n",
        "@@ -01 +1 @@\n",
        "@@ -1 +1 @@ trailing\n",
        "@@ -2 +2 @@\n",
        "@@ -1,2 +1,2 @@\n",
        "@@ -0,0 +1 @@\n",
    ] {
        assert!(parse(canonical.replace("@@ -1 +1 @@\n", header).as_bytes()).is_err());
    }
    for bytes in [
        canonical.replace("--- a/sub\n", "--- a/other\n"),
        canonical.replace("+++ b/sub\n", "+++ b/other\n"),
        canonical.replace("--- a/sub\n", "--- a/sub\tstamp\n"),
        canonical.replace("+++ b/sub\n", "+++ b/sub\n--- a/sub\n+++ b/sub\n"),
        canonical.replace(
            &format!("index {old}..{new} 160000\n"),
            &format!("index {old}..{new} 160000\nindex {old}..{new} 160000\n"),
        ),
        canonical.replace(
            &format!("-Subproject commit {old}\n+Subproject commit {new}\n"),
            &format!("+Subproject commit {new}\n-Subproject commit {old}\n"),
        ),
        canonical.clone()
            + &format!("@@ -2 +2 @@\n-Subproject commit {old}\n+Subproject commit {new}\n"),
        format!("diff --git a/sub b/sub\nindex {old}..{new} 160000\n"),
        "diff --git a/sub b/sub\nnew file mode 160000\n".to_owned(),
        "diff --git a/sub b/sub\ndeleted file mode 160000\n".to_owned(),
    ] {
        assert!(parse(bytes.as_bytes()).is_err());
    }
    let creation = section(FileChange::Create, "sub", &"0".repeat(40), &new);
    let reordered = creation.replace(
        &format!("new file mode 160000\nindex {}..{new}\n", "0".repeat(40)),
        &format!("index {}..{new}\nnew file mode 160000\n", "0".repeat(40)),
    );
    assert!(parse(reordered.as_bytes()).is_err());
}

#[test]
fn binary_symlink_rename_copy_and_entry_type_conversions_refuse() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let text = format!(
        "--- a/sub\n+++ b/sub\n@@ -1 +1 @@\n-Subproject commit {old}\n+Subproject commit {new}\n"
    );
    for (before, after) in [
        (0o100644, 0o160000),
        (0o100755, 0o160000),
        (0o160000, 0o100644),
        (0o160000, 0o100755),
    ] {
        let bytes = format!(
            "diff --git a/sub b/sub\nold mode {before:06o}\nnew mode {after:06o}\nindex {old}..{new}\n{text}"
        );
        assert!(matches!(
            parse(bytes.as_bytes()),
            Err(PatchError::Unsupported { .. })
        ));
    }
    for bytes in [
        "diff --git a/sub b/sub\nnew file mode 120000\n".to_owned(),
        "diff --git a/sub b/sub\nnew file mode 040000\n".to_owned(),
        format!(
            "diff --git a/sub b/sub\nnew file mode 160000\nindex {}..{new}\nGIT binary patch\nliteral 1\nA00000\n\n",
            "0".repeat(40)
        ),
        format!(
            "diff --git a/sub b/sub\nindex {old}..{new} 100644\nGIT binary patch\nliteral 1\nA00000\n\n"
        ),
        "diff --git a/old b/new\nsimilarity index 100%\nrename from old\nrename to new\n"
            .to_owned(),
        format!(
            "diff --git a/sub b/sub\nindex {old}..{new} 160000\nrename from sub\nrename to sub\n{text}"
        ),
        "diff --git a/sub b/sub\ncopy from elsewhere\ncopy to sub\n".to_owned(),
    ] {
        assert!(matches!(
            parse(bytes.as_bytes()),
            Err(PatchError::Unsupported { .. })
        ));
    }
}

#[test]
fn raw_paths_remain_exact_and_targets_remain_disjoint() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let quoted = section(FileChange::Modify, "sub", &old, &new)
        .replace("a/sub", "\"a/raw\\377\\tlink\"")
        .replace("b/sub", "\"b/raw\\377\\tlink\"");
    let patch = parse(quoted.as_bytes()).unwrap();
    assert_eq!(patch.files()[0].path(), b"raw\xff\tlink");
    let spaced = section(FileChange::Modify, "with space", &old, &new)
        .replace("--- a/with space\n", "--- a/with space\t\n")
        .replace("+++ b/with space\n", "+++ b/with space\t\n");
    assert_eq!(
        parse(spaced.as_bytes()).unwrap().files()[0].path(),
        b"with space"
    );
    for path in ["../outside", "a/../b", ".git/config", "a//b", "/absolute"] {
        assert!(parse(section(FileChange::Modify, path, &old, &new).as_bytes()).is_err());
    }
    let first = section(FileChange::Modify, "sub", &old, &new);
    assert_eq!(
        parse((first.clone() + &first).as_bytes()),
        Err(PatchError::DuplicatePath)
    );
    let nested = section(FileChange::Modify, "sub/child", &old, &new);
    assert_eq!(
        parse((first + &nested).as_bytes()),
        Err(PatchError::OverlappingPaths)
    );
    let delete_create = section(FileChange::Delete, "sub", &old, &"0".repeat(40))
        + &section(FileChange::Create, "sub", &"0".repeat(40), &new);
    assert_eq!(
        parse(delete_create.as_bytes()),
        Err(PatchError::DuplicatePath)
    );
}

#[test]
fn gitlink_profiles_keep_parse_and_application_resource_ceilings() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let bytes = section(FileChange::Modify, "sub", &old, &new);
    let exact = PatchLimits {
        max_patch_bytes: bytes.len(),
        max_lines: 7,
        max_path_bytes: 3,
        ..PatchLimits::default()
    };
    assert!(UnifiedPatch::parse_with_gitlinks(bytes.as_bytes(), exact, &|| false).is_ok());
    for (limits, expected) in [
        (
            PatchLimits {
                max_patch_bytes: bytes.len() - 1,
                ..exact
            },
            PatchError::Budget("patch bytes"),
        ),
        (
            PatchLimits {
                max_lines: 6,
                ..exact
            },
            PatchError::Budget("patch lines"),
        ),
        (
            PatchLimits {
                max_path_bytes: 2,
                ..exact
            },
            PatchError::InvalidPath,
        ),
    ] {
        assert_eq!(
            UnifiedPatch::parse_with_gitlinks(bytes.as_bytes(), limits, &|| false),
            Err(expected)
        );
    }
    let two = bytes.clone() + &section(FileChange::Modify, "two", &old, &new);
    for (limits, expected) in [
        (
            PatchLimits {
                max_files: 1,
                ..PatchLimits::default()
            },
            PatchError::Budget("patch files"),
        ),
        (
            PatchLimits {
                max_hunks: 1,
                ..PatchLimits::default()
            },
            PatchError::Budget("patch hunks"),
        ),
    ] {
        assert_eq!(
            UnifiedPatch::parse_with_gitlinks(two.as_bytes(), limits, &|| false),
            Err(expected)
        );
    }
    let patch = parse(bytes.as_bytes()).unwrap();
    let file = &patch.files()[0];
    let source = image(&old);
    let tight = PatchLimits {
        max_file_bytes: source.len(),
        max_output_bytes: image(&new).len(),
        ..patch.limits()
    };
    assert_eq!(
        file.apply(Some((0o160000, &source)), tight, &|| false)
            .unwrap()
            .unwrap()
            .content,
        image(&new)
    );
    for (limits, expected) in [
        (
            PatchLimits {
                max_file_bytes: source.len() - 1,
                ..tight
            },
            PatchError::Budget("source file bytes"),
        ),
        (
            PatchLimits {
                max_output_bytes: image(&new).len() - 1,
                ..tight
            },
            PatchError::Budget("result file bytes"),
        ),
        (
            PatchLimits {
                max_lines: 1,
                ..tight
            },
            PatchError::Budget("hunk lines"),
        ),
    ] {
        assert_eq!(
            file.apply(Some((0o160000, &source)), limits, &|| false),
            Err(expected)
        );
    }
}

#[test]
fn cancellation_refuses_at_every_visited_parse_and_apply_checkpoint() {
    let old = "a".repeat(64);
    let new = "b".repeat(64);
    let bytes = section(FileChange::Modify, "sub", &old, &new);
    let calls = Cell::new(0);
    let patch =
        UnifiedPatch::parse_with_gitlinks(bytes.as_bytes(), PatchLimits::default(), &|| {
            calls.set(calls.get() + 1);
            false
        })
        .unwrap();
    for stop in 0..calls.get() {
        let seen = Cell::new(0);
        let cancelled = || {
            let now = seen.get();
            seen.set(now + 1);
            now == stop
        };
        assert_eq!(
            UnifiedPatch::parse_with_gitlinks(bytes.as_bytes(), PatchLimits::default(), &cancelled),
            Err(PatchError::Cancelled)
        );
    }
    calls.set(0);
    let source = image(&old);
    let file = &patch.files()[0];
    file.apply(Some((0o160000, &source)), patch.limits(), &|| {
        calls.set(calls.get() + 1);
        false
    })
    .unwrap();
    for stop in 0..calls.get() {
        let seen = Cell::new(0);
        assert_eq!(
            file.apply(Some((0o160000, &source)), patch.limits(), &|| {
                let now = seen.get();
                seen.set(now + 1);
                now == stop
            }),
            Err(PatchError::Cancelled)
        );
    }
}
