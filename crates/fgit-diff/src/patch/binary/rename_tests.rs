//! Structural contracts only. Native node tests independently decode the bodies.
use super::*;
use crate::patch::UnifiedPatch;
const MEMBER: &str = "literal 3\nC00000\n\n";
fn input(width: usize, metadata: &str) -> String {
    format!(
        "diff --git a/old b/new\n{metadata}rename from old\nrename to new\nindex {}..{} 100644\nGIT binary patch\n{MEMBER}{MEMBER}",
        "a".repeat(width),
        "b".repeat(width)
    )
}
fn parse(bytes: &[u8]) -> Result<UnifiedPatch<'_>, PatchError> {
    UnifiedPatch::parse_with_binary_renames(bytes, PatchLimits::default(), &|| false)
}
#[test]
fn binary_moves_are_an_explicit_profile_with_two_original_paths() {
    for width in [40, 64] {
        let text = input(width, "similarity index 42%\n");
        let b = text.as_bytes();
        let l = PatchLimits::default();
        assert!(UnifiedPatch::parse(b, l, &|| false).is_err());
        assert!(UnifiedPatch::parse_with_binary(b, l, &|| false).is_err());
        assert!(UnifiedPatch::parse_with_renames(b, l, &|| false).is_err());
        assert!(UnifiedPatch::parse_with_binary_and_renames(b, l, &|| false).is_err());
        let p = parse(b).unwrap();
        let f = &p.files()[0];
        assert_eq!(f.path(), b"new");
        assert_eq!(f.renamed_from(), Some(b"old".as_slice()));
        assert_eq!(f.change(), FileChange::Modify);
        assert_eq!(f.hunk_count(), 2);
        assert!(f.apply(Some((0o100644, b"old")), l, &|| false).is_err());
    }
}
#[test]
fn full_nonabsent_domains_both_directions_and_no_text_mixture_are_required() {
    let good = input(40, "");
    for bad in [
        good.replacen(&"a".repeat(40), &"a".repeat(7), 1),
        good.replacen(&"b".repeat(40), &"b".repeat(64), 1),
        good.replacen(&"a".repeat(40), &"0".repeat(40), 1),
        good.replacen(&"b".repeat(40), &"0".repeat(40), 1),
        good.strip_suffix(MEMBER).unwrap().to_owned(),
        good.replace("GIT binary patch", "--- a/old\n+++ b/new\nGIT binary patch"),
        good.replace("rename from old", "rename from other"),
        good.replace("rename to new", "rename to new\nrename to third"),
        good.replace("rename from old", "new file mode 100644\nrename from old"),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "{bad}");
    }
}
#[test]
fn both_endpoints_take_part_in_global_collision_and_overlap_checks() {
    let good = input(40, "");
    for name in ["old", "new", "old/child", "new/child"] {
        let combined =
            format!("{good}diff --git a/{name} b/{name}\nold mode 100644\nnew mode 100755\n");
        assert!(matches!(
            parse(combined.as_bytes()),
            Err(PatchError::DuplicatePath | PatchError::OverlappingPaths)
        ));
    }
    let chain = good.clone()
        + &good
            .replace("a/old", "a/new")
            .replace("from old", "from new")
            .replace("b/new", "b/third")
            .replace("to new", "to third");
    assert_eq!(parse(chain.as_bytes()), Err(PatchError::DuplicatePath));
    let allowed = format!("{good}diff --git a/other b/other\nold mode 100644\nnew mode 100755\n");
    assert_eq!(parse(allowed.as_bytes()).unwrap().files().len(), 2);
}
#[test]
fn binary_similarity_cannot_bypass_the_exact_unchanged_claim() {
    let s = input(40, "similarity index 100%\n");
    let p = parse(s.as_bytes()).unwrap();
    let f = &p.files()[0];
    assert!(
        f.apply_with_binary_decoder(
            Some((0o100644, b"old")),
            p.limits(),
            &|| false,
            |_, _, _| Ok(b"new".to_vec())
        )
        .is_err()
    );
    assert_eq!(
        f.apply_with_binary_decoder(
            Some((0o100644, b"old")),
            p.limits(),
            &|| false,
            |_, _, _| Ok(b"old".to_vec())
        )
        .unwrap()
        .unwrap()
        .content,
        b"old"
    );
}
#[test]
fn exact_budgets_and_cancellation_survive_the_new_profile() {
    let text = input(40, "");
    let n = text.lines().count();
    let limits = PatchLimits {
        max_patch_bytes: text.len(),
        max_files: 1,
        max_hunks: 2,
        max_lines: n,
        max_file_bytes: 3,
        max_output_bytes: 6,
        ..Default::default()
    };
    assert!(UnifiedPatch::parse_with_binary_renames(text.as_bytes(), limits, &|| false).is_ok());
    for l in [
        PatchLimits {
            max_patch_bytes: text.len() - 1,
            ..limits
        },
        PatchLimits {
            max_hunks: 1,
            ..limits
        },
        PatchLimits {
            max_lines: n - 1,
            ..limits
        },
        PatchLimits {
            max_output_bytes: 5,
            ..limits
        },
    ] {
        assert!(matches!(
            UnifiedPatch::parse_with_binary_renames(text.as_bytes(), l, &|| false),
            Err(PatchError::Budget(_))
        ));
    }
    assert_eq!(
        UnifiedPatch::parse_with_binary_renames(text.as_bytes(), limits, &|| true),
        Err(PatchError::Cancelled)
    );
    let p = parse(text.as_bytes()).unwrap();
    let stop = std::cell::Cell::new(false);
    assert_eq!(
        p.files()[0].apply_with_binary_decoder(
            Some((0o100644, b"old")),
            p.limits(),
            &|| stop.get(),
            |_, _, _| {
                stop.set(true);
                Ok(b"new".to_vec())
            }
        ),
        Err(PatchError::Cancelled)
    );
}
