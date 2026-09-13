use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-rebase-resolutions-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn oid(format: GitHashAlgorithm) -> String {
    "1".repeat(format.digest_len() * 2)
}

#[test]
fn repeated_originals_group_paths_without_changing_bytes_or_accepting_duplicate_choices() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let id = oid(format);
        let first = format!("{id}:{}:theirs", hex(b"nested/\xff"));
        let second = format!("{id}:{}:delete", hex(b"other"));
        let input = [
            ("--resolve", first.as_str()),
            ("--resolve", second.as_str()),
        ];
        let parsed = parse(&input, format, PreparationLimits::default()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].paths[0].path, b"nested/\xff");
        assert!(matches!(
            parsed[0].paths[1].choice,
            ResolutionChoice::Delete
        ));
        assert!(parse(&[input[0], input[0]], format, PreparationLimits::default()).is_err());
        let bad = format!("{id}:{}:ours", hex(b"nested"));
        assert!(
            parse(
                &[input[0], ("--resolve", &bad)],
                format,
                PreparationLimits::default()
            )
            .is_err()
        );
        let bad = format!("{id}:{}:ours", hex(b".git/config"));
        assert!(parse(&[("--resolve", &bad)], format, PreparationLimits::default()).is_err());
    }
}

#[test]
fn file_input_is_byte_exact_and_aggregate_budget_is_checked_before_allocation() {
    let scratch = Scratch::new();
    let file = scratch.0.join("content:with-colon");
    let body = b"\0\xff<<<<<<< literal\n\r\n";
    std::fs::write(&file, body).unwrap();
    let format = GitHashAlgorithm::Sha256;
    let id = oid(format);
    let input = format!("{id}:{}:100755:{}", hex(b"file"), file.display());
    let parsed = parse(
        &[("--resolve-file", &input)],
        format,
        PreparationLimits::default(),
    )
    .unwrap();
    assert!(
        matches!(&parsed[0].paths[0].choice, ResolutionChoice::File { mode: 0o100755, bytes } if bytes == body)
    );
    assert!(
        parse(
            &[("--resolve-file", &input)],
            format,
            PreparationLimits {
                max_output_bytes: body.len() + 3,
                ..PreparationLimits::default()
            }
        )
        .is_err()
    );
    let missing = format!(
        "{id}:{}:120000:{}",
        hex(b"file"),
        scratch.0.join("absent").display()
    );
    assert!(
        parse(
            &[("--resolve-file", &missing)],
            format,
            PreparationLimits::default()
        )
        .unwrap_err()
        .contains("expected original")
    );
    let invalid = format!(
        "{id}:{}:100644:{}",
        hex(b"../escape"),
        scratch.0.join("absent").display()
    );
    assert!(
        parse(
            &[("--resolve-file", &invalid)],
            format,
            PreparationLimits::default()
        )
        .unwrap_err()
        .contains("InvalidResolution")
    );
    let second = format!(
        "{}:{}:100644:{}",
        "2".repeat(64),
        hex(b"file"),
        file.display()
    );
    assert!(
        parse(
            &[("--resolve-file", &input), ("--resolve-file", &second)],
            format,
            PreparationLimits {
                max_output_bytes: body.len() * 2 + 7,
                ..PreparationLimits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn unsupported_modes_cross_domains_extra_fields_and_empty_components_refuse() {
    let id = oid(GitHashAlgorithm::Sha1);
    for value in [
        format!("{id}:66696c65:guess"),
        format!("{id}:66696c65:ours:extra"),
        format!("{id}::ours"),
        format!("{id}:f:ours"),
        format!("{id}:66696c65"),
        format!("{}:66696c65:ours", "2".repeat(64)),
        format!("{}:66696c65:ours", "0".repeat(40)),
    ] {
        assert!(
            parse(
                &[("--resolve", &value)],
                GitHashAlgorithm::Sha1,
                PreparationLimits::default()
            )
            .is_err(),
            "{value}"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_resolution_files_are_not_followed() {
    let scratch = Scratch::new();
    let file = scratch.0.join("file");
    let link = scratch.0.join("link");
    std::fs::write(&file, b"exact").unwrap();
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let input = format!(
        "{}:66696c65:100644:{}",
        oid(GitHashAlgorithm::Sha1),
        link.display()
    );
    assert!(
        parse(
            &[("--resolve-file", &input)],
            GitHashAlgorithm::Sha1,
            PreparationLimits::default()
        )
        .is_err()
    );
}
