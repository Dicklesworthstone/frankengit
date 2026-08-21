// Reference names: the `git check-ref-format` rules, plus the admission bound.
// Every planted negative is paired with the nearest legal name.

use fgit_types::TypeRefusal;
use fgit_types::refs::{MAX_REF_NAME_LEN, RefName};

fn reason_of(refusal: &TypeRefusal) -> &'static str {
    match refusal {
        TypeRefusal::RefNameStructureInvalid { reason, .. } => reason,
        other => panic!("expected a structural refusal, observed {other}"),
    }
}

#[test]
fn ordinary_reference_names_are_accepted() {
    for source in [
        &b"refs/heads/main"[..],
        b"refs/heads/feature/long/path",
        b"refs/tags/v1.2.3",
        b"refs/remotes/origin/HEAD",
        b"refs/heads/a.b.c",
        b"refs/heads/locked",
        b"refs/heads/x.locker",
    ] {
        let name = RefName::try_new(source).expect("legal reference name");
        assert_eq!(name.as_bytes(), source);
        assert!(!name.is_empty());
        assert_eq!(name.len(), source.len());
    }
}

#[test]
fn one_level_names_need_the_explicit_constructor() {
    let refusal =
        RefName::try_new(b"HEAD").expect_err("a full reference name has at least two components");
    assert_eq!(reason_of(&refusal), "name_is_one_level");
    // Permitted counterpart: the same name through the one-level constructor.
    let head = RefName::try_new_one_level(b"HEAD").expect("HEAD is a legal pseudo-ref");
    assert_eq!(head.as_str(), Some("HEAD"));
}

#[test]
fn bytes_git_forbids_anywhere_are_refused() {
    for (source, byte) in [
        (&b"refs/heads/a b"[..], b' '),
        (b"refs/heads/a~b", b'~'),
        (b"refs/heads/a^b", b'^'),
        (b"refs/heads/a:b", b':'),
        (b"refs/heads/a?b", b'?'),
        (b"refs/heads/a*b", b'*'),
        (b"refs/heads/a[b", b'['),
        (b"refs/heads/a\\b", b'\\'),
        (b"refs/heads/a\x7fb", 0x7f),
        (b"refs/heads/a\nb", b'\n'),
    ] {
        let refusal = RefName::try_new(source).expect_err("byte is forbidden anywhere");
        assert!(
            matches!(
                refusal,
                TypeRefusal::ByteNotPermitted { field: "RefName", byte: seen, .. } if seen == byte
            ),
            "unexpected refusal for {source:?}: {refusal}"
        );
    }
    // Permitted counterpart: the same shape with a legal separator.
    assert!(RefName::try_new(b"refs/heads/a-b").is_ok());
}

#[test]
fn structural_rules_match_git_check_ref_format() {
    for (source, reason) in [
        (&b"refs/heads/a..b"[..], "double_dot"),
        (b"refs/heads/a@{0}", "at_brace_sequence"),
        (b"refs/heads/a.", "name_ends_with_dot"),
        (b"refs/heads/a/", "name_ends_with_slash"),
        (b"/refs/heads/a", "name_starts_with_slash"),
        (b"refs//heads/a", "empty_component"),
        (b"refs/heads/.hidden", "component_starts_with_dot"),
        (b"refs/heads/work.lock", "component_ends_with_dot_lock"),
        (b"refs/.hidden/a", "component_starts_with_dot"),
        (b"refs/work.lock/a", "component_ends_with_dot_lock"),
    ] {
        let refusal = RefName::try_new(source).expect_err("structural rule must reject");
        assert_eq!(
            reason_of(&refusal),
            reason,
            "wrong reason for {source:?}: {refusal}"
        );
        assert_eq!(
            refusal.refusal_code(),
            fgit_types::RefusalCode::RefNameInvalid
        );
    }
    // Permitted counterparts for the two subtlest rules.
    assert!(
        RefName::try_new(b"refs/heads/a.b").is_ok(),
        "one dot is legal"
    );
    assert!(
        RefName::try_new(b"refs/heads/lock.work").is_ok(),
        "only a trailing .lock is illegal"
    );
    assert!(
        RefName::try_new(b"refs/heads/a@b").is_ok(),
        "an at sign is legal when it is not followed by a brace"
    );
}

#[test]
fn the_bare_at_sign_is_refused_but_a_longer_name_is_not() {
    let refusal =
        RefName::try_new_one_level(b"@").expect_err("the single at sign is reserved by Git");
    assert_eq!(reason_of(&refusal), "name_is_bare_at_sign");
    assert!(RefName::try_new_one_level(b"@a").is_ok());
}

#[test]
fn the_length_bound_is_enforced_at_the_boundary() {
    let prefix = b"refs/heads/";
    let mut at_bound = prefix.to_vec();
    at_bound.resize(MAX_REF_NAME_LEN, b'a');
    assert_eq!(at_bound.len(), MAX_REF_NAME_LEN);
    assert!(
        RefName::try_new(&at_bound).is_ok(),
        "exactly at the bound must be permitted"
    );

    let mut over_bound = at_bound.clone();
    over_bound.push(b'a');
    let refusal = RefName::try_new(&over_bound).expect_err("one byte over the bound is refused");
    assert!(matches!(
        refusal,
        TypeRefusal::LengthOutOfRange {
            field: "RefName",
            observed: 1025,
            maximum: 1024,
            ..
        }
    ));

    let empty = RefName::try_new(b"").expect_err("an empty name is not a reference");
    assert!(matches!(
        empty,
        TypeRefusal::LengthOutOfRange {
            field: "RefName",
            observed: 0,
            ..
        }
    ));
}

#[test]
fn components_and_prefix_matching_respect_boundaries() {
    let name = RefName::try_new(b"refs/heads/feature/x").expect("legal");
    assert_eq!(
        name.components().collect::<Vec<_>>(),
        vec![&b"refs"[..], b"heads", b"feature", b"x"]
    );
    assert!(name.is_under(b"refs"));
    assert!(name.is_under(b"refs/heads"));
    assert!(
        name.is_under(b"refs/heads/"),
        "a trailing slash is tolerated"
    );
    assert!(!name.is_under(b"refs/head"));
    assert!(
        !RefName::try_new(b"refs/headsup/x")
            .expect("legal")
            .is_under(b"refs/heads"),
        "a prefix must land on a component boundary"
    );
    assert!(
        !name.is_under(b"refs/heads/feature/x"),
        "a name is not under itself"
    );
}

#[test]
fn ordering_is_byte_order_over_the_name() {
    let mut names = vec![
        RefName::try_new(b"refs/tags/v1").expect("legal"),
        RefName::try_new(b"refs/heads/main").expect("legal"),
        RefName::try_new(b"refs/heads/dev").expect("legal"),
    ];
    names.sort();
    assert_eq!(
        names
            .iter()
            .map(|name| name.as_str().expect("text"))
            .collect::<Vec<_>>(),
        vec!["refs/heads/dev", "refs/heads/main", "refs/tags/v1"]
    );
}
