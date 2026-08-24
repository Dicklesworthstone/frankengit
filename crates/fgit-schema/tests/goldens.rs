//! The committed artifacts, the staleness gate, and the determinism the gate
//! depends on.
//!
//! A byte-identity test alone would be satisfied by a generator that emits the
//! same wrong bytes every time, so each property here is checked separately:
//! the emitters are deterministic, the committed files match them, the gate
//! notices when they do not, and the gate notices when they are absent.

use std::fs;
use std::path::PathBuf;

use fgit_schema::emit;
use fgit_schema::error::SchemaRefusal;
use fgit_schema::gate;

/// The committed artifact directory.
fn generated_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fgit_schema::GENERATED_DIR)
}

#[test]
fn the_emitters_are_deterministic() {
    // Same descriptors in, same bytes out. Everything else in this file rests
    // on this: a gate over a nondeterministic generator reports the machine,
    // not the tree.
    for _ in 0..4 {
        assert_eq!(emit::artifacts(), emit::artifacts());
    }
}

#[test]
fn every_committed_artifact_is_byte_identical_to_the_generator() {
    let directory = generated_dir();
    for artifact in emit::artifacts() {
        let path = directory.join(artifact.name);
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is not readable: {error}", path.display()));
        assert_eq!(
            gate::first_difference(&committed, &artifact.contents),
            None,
            "{} differs from the generator; run the generate command and commit the result",
            artifact.name
        );
    }
}

#[test]
fn the_gate_passes_on_the_committed_tree() {
    let checked = gate::check(&generated_dir()).expect("the committed artifacts are current");
    assert_eq!(checked, emit::artifacts().len());
    assert_eq!(
        checked, 4,
        "four artifacts: JSON Schema, TypeScript, Python, and the workflow construct registry"
    );
}

#[test]
fn the_gate_reports_a_stale_artifact_and_says_where() {
    // PRESENCE CASE. A gate that has never been seen to fail is decoration.
    // Copy the real artifacts into a temp directory, corrupt one byte, and
    // require the refusal — including the offset, because "something differs"
    // is not actionable and this gate's whole value is being actionable.
    let scratch = std::env::temp_dir().join(format!(
        "fgit-schema-gate-stale-{}-{}",
        std::process::id(),
        line!()
    ));
    gate::write(&scratch).expect("the temp directory is writable");

    let artifacts = emit::artifacts();
    let victim = &artifacts[0];
    let path = scratch.join(victim.name);
    let original = fs::read_to_string(&path).expect("just written");
    // Flip a character deep inside the file rather than at byte 0, so the
    // reported offset is a real measurement and not an artefact of position.
    let cut = original.len() / 2;
    let mut corrupted = original.clone();
    corrupted.replace_range(cut..=cut, "~");
    fs::write(&path, &corrupted).expect("writable");

    let refusal = gate::check(&scratch).expect_err("a corrupted artifact must be refused");
    match &refusal {
        SchemaRefusal::ArtifactStale { artifact, offset } => {
            assert_eq!(&**artifact, victim.name);
            assert_eq!(
                *offset, cut,
                "the gate must report the first differing byte, not merely that one exists"
            );
        }
        other => panic!("expected ArtifactStale, got {other:?}"),
    }
    assert!(refusal.to_string().contains(victim.name));

    // Permitted twin: restore the byte and the same directory passes, so the
    // refusal was about the corruption rather than about the temp directory.
    fs::write(&path, &original).expect("writable");
    gate::check(&scratch).expect("the restored directory is current again");

    for artifact in &artifacts {
        let _ = fs::remove_file(scratch.join(artifact.name));
    }
    let _ = fs::remove_dir(&scratch);
}

#[test]
fn the_gate_reports_a_missing_artifact_rather_than_regenerating_it() {
    // A gate that repairs what it finds can never fail, so absence must refuse.
    let scratch = std::env::temp_dir().join(format!(
        "fgit-schema-gate-missing-{}-{}",
        std::process::id(),
        line!()
    ));
    gate::write(&scratch).expect("the temp directory is writable");

    let artifacts = emit::artifacts();
    let victim = &artifacts[1];
    fs::remove_file(scratch.join(victim.name)).expect("present before removal");

    let refusal = gate::check(&scratch).expect_err("a missing artifact must be refused");
    match &refusal {
        SchemaRefusal::ArtifactMissing { artifact } => assert_eq!(&**artifact, victim.name),
        other => panic!("expected ArtifactMissing, got {other:?}"),
    }
    // The gate did NOT recreate it. This is the property that keeps the fast
    // lane read-only: a verify run must never write to the tree.
    assert!(
        !scratch.join(victim.name).exists(),
        "check() recreated the artifact; a gate that repairs cannot fail"
    );

    for artifact in &artifacts {
        let _ = fs::remove_file(scratch.join(artifact.name));
    }
    let _ = fs::remove_dir(&scratch);
}

#[test]
fn first_difference_reports_the_offset_and_handles_prefixes() {
    assert_eq!(gate::first_difference("same", "same"), None);
    assert_eq!(gate::first_difference("abcd", "abXd"), Some(2));
    // One a strict prefix of the other: the offset is where the shorter ends,
    // which is where a reader first notices. A trailing-newline difference is
    // exactly this case, and it is a real difference rather than whitespace.
    assert_eq!(gate::first_difference("abc", "abcd"), Some(3));
    assert_eq!(gate::first_difference("abcd", "abc"), Some(3));
    assert_eq!(gate::first_difference("", "a"), Some(0));
}

#[test]
fn the_generated_json_is_syntactically_well_formed() {
    // Byte-identity would happily reproduce broken JSON forever. This checks
    // the artifact is a document rather than merely a stable string, without
    // adding a JSON dependency: brace/bracket depth returns to zero exactly
    // once at the end, and every quote is balanced outside escapes.
    let json = emit::json_schema();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for byte in json.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                assert!(depth >= 0, "JSON closes a bracket that was never opened");
            }
            _ => {}
        }
    }
    assert!(!in_string, "JSON ends inside an unterminated string");
    assert_eq!(depth, 0, "JSON brackets do not balance");
    assert!(json.ends_with("}\n"), "the document ends with a newline");
}

#[test]
fn a_u64_field_is_a_string_in_the_javascript_facing_artifacts() {
    // The one emitter decision that is a correctness constraint rather than a
    // style choice, asserted on the artifacts rather than on the helper.
    let typescript = emit::typescript();
    assert!(
        typescript.contains("repository_sequence: string;"),
        "a u64 counter must not be typed as a JS number: it exceeds 2^53 - 1"
    );
    assert!(
        typescript.contains("latest_decision_sequence?: string;"),
        "an optional u64 is an optional string, not an optional number"
    );
    // Discrimination: the narrower widths DO stay numeric, so this is a rule
    // about precision rather than a blanket stringification.
    assert!(
        typescript.contains("major: number;"),
        "a u16 fits a double exactly and must stay numeric"
    );
    assert!(
        emit::fits_js_number(fgit_schema::ScalarWidth::U32),
        "u32 fits exactly in an IEEE-754 double"
    );
    assert!(
        !emit::fits_js_number(fgit_schema::ScalarWidth::U64),
        "u64 does not"
    );
}
