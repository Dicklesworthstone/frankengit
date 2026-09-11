use super::*;
use fgit_forge::preparation::{ConflictKind, MergeConflict};
use fgit_forge::preparation::replay::ReplayDirection;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-replay-choice-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn args(action: &str) -> Vec<String> {
    [action,"node",&"11".repeat(16),&"22".repeat(16),"refs/heads/main","resolved.bundle",
        "--trusted-local","--profile","path-v1","--source-ref","refs/heads/topic",
        "--expected-target",&"a".repeat(40),"--expected-source",&"b".repeat(40),"--commit",&"c".repeat(40),
        "--author","T <t@x>","--timestamp","2","--message","resolved"]
        .iter().map(|s| s.to_string()).collect()
}
fn parse(args: &[String]) -> Result<super::super::Options, String> {
    super::super::parse(args, ReplayDirection::CherryPick)
}
fn strings(args: &[&str]) -> Vec<String> { args.iter().map(|s| s.to_string()).collect() }

#[test]
fn resolve_is_explicit_and_duplicate_or_overlapping_raw_paths_refuse_before_io() {
    assert!(parse(&args("prepare")).unwrap().resolutions.is_none());
    assert!(parse(&args("resolve")).is_err());
    let mut wrong = args("prepare"); wrong.extend(strings(&["--ours","file"])); assert!(parse(&wrong).is_err());
    let mut valid = args("resolve"); valid.extend(strings(&["--ours-hex","7372632fff"]));
    let parsed = parse(&valid).unwrap();
    assert_eq!(parsed.resolutions.as_ref().unwrap()[0].path, b"src/\xff");
    for extra in [vec!["--ours","file","--theirs-hex","66696c65"],
        vec!["--ours","a","--ours","a-","--theirs","a/b"],
        vec!["--ours","../escape"],vec!["--delete",".git/config"],vec!["--file","file","120000","missing"]] {
        let mut bad = args("resolve"); bad.extend(strings(&extra)); assert!(parse(&bad).is_err(), "{extra:?}");
    }
    let mut valid = args("resolve"); valid.extend(strings(&["--file","file","100755","not-read-during-parse"]));
    assert!(parse(&valid).is_ok());
    for option in ["--force", "--continue", "--abort", "--approve"] {
        let mut bad = valid.clone(); bad.extend(strings(&[option,"true"])); assert!(parse(&bad).is_err());
    }
}

#[test]
fn exact_empty_binary_inputs_are_distinct_from_deletion_and_share_one_byte_budget() {
    let scratch = Scratch::new(); let empty = scratch.0.join("empty"); let raw = scratch.0.join("raw");
    fs::write(&empty, []).unwrap(); fs::write(&raw, b"\0\xff\r\nend").unwrap();
    let choices = vec![
        LocalResolution { path: b"empty".to_vec(), choice: LocalChoice::File { mode: 0o100644, source: empty } },
        LocalResolution { path: b"raw".to_vec(), choice: LocalChoice::File { mode: 0o100755, source: raw } },
        LocalResolution { path: b"gone".to_vec(), choice: LocalChoice::Side(ResolutionChoice::Delete) },
    ];
    let loaded = load(&choices, PreparationLimits::default()).unwrap();
    assert!(matches!(&loaded[0].choice, ResolutionChoice::File { mode: 0o100644, bytes } if bytes.is_empty()));
    assert!(matches!(&loaded[1].choice, ResolutionChoice::File { mode: 0o100755, bytes } if bytes == b"\0\xff\r\nend"));
    assert_eq!(loaded[2].choice, ResolutionChoice::Delete);
    let limit = PreparationLimits { max_output_bytes: 18, ..PreparationLimits::default() };
    // Paths consume 12 bytes and exact file content consumes seven more.
    assert!(load(&choices, limit).is_err());
    let enough = PreparationLimits { max_output_bytes: 19, ..PreparationLimits::default() };
    assert_eq!(load(&choices, enough).unwrap(), loaded);
}

#[test]
fn resolution_reader_refuses_nonregular_files_and_oversized_content() {
    let scratch = Scratch::new(); let file = scratch.0.join("content");
    fs::write(&file, b"12345").unwrap();
    assert!(read_file(&file, 4).is_err()); assert_eq!(read_file(&file, 5).unwrap(), b"12345");
    assert!(read_file(&scratch.0, 100).is_err());
    #[cfg(unix)] {
        let link = scratch.0.join("link"); std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_file(&link, 100).is_err());
    }
}

fn receipt_fixture() -> (ConflictResolution, ResolvedPath) {
    let format = GitHashAlgorithm::Sha1;
    let entry = |bytes: &[u8]| MergeEntry { name: b"file".to_vec(), mode: 0o100644,
        oid: git_object_id(format, GitObjectKind::Blob, bytes) };
    let requested = ConflictResolution { path: b"file".to_vec(),
        choice: ResolutionChoice::File { mode: 0o100755, bytes: b"manual\0\xff".to_vec() } };
    let result = MergeEntry { mode: 0o100755, ..entry(b"manual\0\xff") };
    let actual = ResolvedPath { conflict: MergeConflict { path: b"file".to_vec(), kind: ConflictKind::Content,
        base: Some(entry(b"base")), ours: Some(entry(b"ours")), theirs: Some(entry(b"theirs")) },
        choice: ResolutionKind::File, result: Some(result) };
    (requested, actual)
}

#[test]
fn receipt_checks_exact_file_identity_mode_count_and_choice_before_publication() {
    let (requested, actual) = receipt_fixture();
    let base = "{\"type\":\"commit_replay_preparation\",\"approval_granted\":false,\"published_to_repository\":false}";
    let rendered = decorate_receipt(base.into(), &[requested.clone()], &[actual.clone()], GitHashAlgorithm::Sha1).unwrap();
    assert!(rendered.contains("\"type\":\"commit_replay_resolution\""));
    assert!(rendered.contains("\"choice\":\"file\"")); assert!(rendered.contains("\"approval_granted\":false"));
    for mutation in 0..6 {
        let mut changed = actual.clone();
        match mutation {
            0 => changed.choice = ResolutionKind::Ours,
            1 => changed.result.as_mut().unwrap().mode = 0o100644,
            2 => changed.result.as_mut().unwrap().oid = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"wrong"),
            3 => changed.result = None,
            4 => changed.conflict.path = b"other".to_vec(),
            _ => changed.result.as_mut().unwrap().name = b"other".to_vec(),
        }
        assert!(decorate_receipt(base.into(), &[requested.clone()], &[changed], GitHashAlgorithm::Sha1).is_err());
    }
    assert!(decorate_receipt(base.into(), &[requested.clone()], &[], GitHashAlgorithm::Sha1).is_err());
    assert!(decorate_receipt(base.into(), &[requested.clone()], &[actual.clone(), actual.clone()], GitHashAlgorithm::Sha1).is_err());
    assert!(decorate_receipt(base.into(), &[requested], &[actual], GitHashAlgorithm::Sha256).is_err());
}

#[test]
fn receipt_never_relabels_a_missing_side_as_an_explicit_deletion() {
    let (_, mut row) = receipt_fixture(); row.conflict.theirs = None;
    row.result = None; row.choice = ResolutionKind::Theirs;
    let base = "{\"type\":\"commit_replay_preparation\"}";
    let mut requested = ConflictResolution { path: b"file".to_vec(), choice: ResolutionChoice::Theirs };
    assert!(decorate_receipt(base.into(), &[requested.clone()], &[row.clone()], GitHashAlgorithm::Sha1).is_err());
    requested.choice = ResolutionChoice::Delete; row.choice = ResolutionKind::Delete;
    assert!(decorate_receipt(base.into(), &[requested], &[row], GitHashAlgorithm::Sha1).is_ok());
}
