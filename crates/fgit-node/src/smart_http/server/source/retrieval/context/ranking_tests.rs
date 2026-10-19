use super::*;
const BASE: &str = "object_format=sha1&ref=refs/heads/main&term_hex=5468696e67";

#[test]
fn ranking_is_explicit_versioned_and_does_not_change_the_index_only_grammar() {
    let default = command(BASE.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    let raw = command(
        format!("{BASE}&context_selection=raw-path-prefix").as_bytes(),
        GitHashAlgorithm::Sha1,
    )
    .unwrap();
    assert!(!default.ranked && !raw.ranked);
    assert_eq!(default.limits, raw.limits);
    assert_eq!(default.initial.query.content(), raw.initial.query.content());
    let form = format!(
        "{BASE}&context_selection={}&context_max_files=1",
        ranked::PROFILE
    );
    let parsed = command(form.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    assert!(parsed.ranked);
    assert_eq!(parsed.limits.max_files, 1);
    assert_eq!(parsed.initial.limits, InitialLimits::default());
    assert!(super::super::command(form.as_bytes(), GitHashAlgorithm::Sha1).is_err());
    for suffix in [
        "&context_selection=latest",
        "&context_selection=semantic",
        "&context_selection=",
        "&context_selection=raw-path-prefix&context_selection=raw-path-prefix",
        "&rank_weight_symbol=100",
    ] {
        assert!(command(format!("{BASE}{suffix}").as_bytes(), GitHashAlgorithm::Sha1).is_err());
    }
}

#[test]
fn ranking_cannot_detach_symbol_options_or_override_source_and_checkpoint_pins() {
    let ranked = format!("{BASE}&context_selection={}", ranked::PROFILE);
    for suffix in [
        "&symbol_policy=required",
        "&minimum_symbol_number=1",
        "&expected_commit=00",
        "&force=true",
    ] {
        assert!(
            command(
                format!("{ranked}{suffix}").as_bytes(),
                GitHashAlgorithm::Sha1
            )
            .is_err()
        );
    }
    let pinned = format!(
        "{ranked}&symbol_name_hex=5468696e67&symbol_policy=required&minimum_symbol_token=alg:2:{}&minimum_symbol_number=2",
        "a".repeat(64)
    );
    let parsed = command(pinned.as_bytes(), GitHashAlgorithm::Sha1).unwrap();
    assert_eq!(
        parsed
            .initial
            .checkpoints
            .symbols
            .unwrap()
            .authority_generation
            .get(),
        2
    );
    assert_eq!(
        parsed.initial.query.symbols().unwrap().1,
        SymbolPolicy::Required
    );
}
