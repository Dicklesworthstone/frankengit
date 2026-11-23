use super::*;
use crate::preparation::{
    CommitInput, ConflictKind, MergeEntry, MergeMetadata, MergePreparation, MergeProfile,
    MergeSourceError, PreparationLimits, prepare_merge, prepare_merge_with_profile,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::GitHashAlgorithm;
use std::cell::Cell;

const BASE: &[u8] = b"one\ntwo\nthree\nfour\nfive\n";
const OURS: &[u8] = b"ONE\ntwo\nthree\nfour\nfive\n";
const THEIRS: &[u8] = b"one\ntwo\nthree\nfour\nFIVE\n";
const MERGED: &[u8] = b"ONE\ntwo\nthree\nfour\nFIVE\n";

type FileInput<'a> = (&'a [u8], &'a [u8]);

struct Source {
    format: GitHashAlgorithm,
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    checkpoints: Cell<usize>,
    cancel_at: Cell<usize>,
    blob_reads: Cell<usize>,
    attribute_mode: u32,
}

impl Source {
    fn new(format: GitHashAlgorithm) -> Self {
        Self {
            format,
            commits: BTreeMap::new(),
            trees: BTreeMap::new(),
            blobs: BTreeMap::new(),
            checkpoints: Cell::new(0),
            cancel_at: Cell::new(usize::MAX),
            blob_reads: Cell::new(0),
            attribute_mode: 0o100644,
        }
    }

    fn blob(&mut self, bytes: &[u8]) -> GitOid {
        let oid = git_object_id(self.format, GitObjectKind::Blob, bytes);
        self.blobs.insert(oid, bytes.to_vec());
        oid
    }

    fn snapshot(&mut self, files: &[FileInput<'_>]) -> GitOid {
        let mut children = BTreeMap::<&[u8], Vec<FileInput<'_>>>::new();
        let mut entries = Vec::new();
        for (path, bytes) in files {
            if let Some(slash) = path.iter().position(|byte| *byte == b'/') {
                children
                    .entry(&path[..slash])
                    .or_default()
                    .push((&path[slash + 1..], bytes));
            } else {
                entries.push(MergeEntry {
                    name: path.to_vec(),
                    mode: if *path == b".gitattributes" {
                        self.attribute_mode
                    } else {
                        0o100644
                    },
                    oid: self.blob(bytes),
                });
            }
        }
        for (name, files) in children {
            entries.push(MergeEntry {
                name: name.to_vec(),
                mode: 0o040000,
                oid: self.snapshot(&files),
            });
        }
        entries.sort_by_cached_key(|entry| {
            let mut key = entry.name.clone();
            key.push(if entry.mode == 0o040000 { b'/' } else { 0 });
            key
        });
        let mut bytes = Vec::new();
        for entry in &entries {
            bytes.extend_from_slice(format!("{:o} ", entry.mode).as_bytes());
            bytes.extend_from_slice(&entry.name);
            bytes.push(0);
            bytes.extend_from_slice(entry.oid.as_bytes());
        }
        let oid = git_object_id(self.format, GitObjectKind::Tree, &bytes);
        self.trees.insert(oid, entries);
        oid
    }

    fn commit(&mut self, tree: GitOid, parent: Option<GitOid>, message: &str) -> GitOid {
        let mut bytes = format!("tree {tree}\n");
        if let Some(parent) = parent {
            bytes.push_str(&format!("parent {parent}\n"));
        }
        bytes.push_str(&format!(
            "author T <t@x> 1 +0000\ncommitter T <t@x> 1 +0000\n\n{message}\n"
        ));
        let oid = git_object_id(self.format, GitObjectKind::Commit, bytes.as_bytes());
        self.commits.insert(
            oid,
            CommitInput {
                tree,
                parents: parent.into_iter().collect(),
            },
        );
        oid
    }

    fn pair(
        &mut self,
        base: &[FileInput<'_>],
        ours: &[FileInput<'_>],
        theirs: &[FileInput<'_>],
    ) -> [GitOid; 2] {
        let tree = self.snapshot(base);
        let base = self.commit(tree, None, "base");
        let tree = self.snapshot(ours);
        let ours = self.commit(tree, Some(base), "ours");
        let tree = self.snapshot(theirs);
        let theirs = self.commit(tree, Some(base), "theirs");
        [ours, theirs]
    }
}

impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let calls = self.checkpoints.get() + 1;
        self.checkpoints.set(calls);
        if calls >= self.cancel_at.get() {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.blob_reads.set(self.blob_reads.get() + 1);
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}

fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "T <t@x>".into(),
        committer: "T <t@x>".into(),
        timestamp: 1,
        message: b"merge\n".to_vec(),
    }
}

fn changed(
    format: GitHashAlgorithm,
    attributes: &[FileInput<'_>],
    path: &[u8],
) -> (Source, [GitOid; 2]) {
    let mut source = Source::new(format);
    let mut base = attributes.to_vec();
    let mut ours = attributes.to_vec();
    let mut theirs = attributes.to_vec();
    base.push((path, BASE));
    ours.push((path, OURS));
    theirs.push((path, THEIRS));
    let pair = source.pair(&base, &ours, &theirs);
    (source, pair)
}

fn prepare(
    source: &Source,
    pair: [GitOid; 2],
    profile: MergeProfile,
) -> Result<MergePreparation, PreparationError> {
    prepare_merge_with_profile(
        source,
        source.format,
        pair[0],
        pair[1],
        &metadata(),
        PreparationLimits::default(),
        profile,
    )
}

fn clean(source: &Source, pair: [GitOid; 2]) -> crate::preparation::PreparedMerge {
    let result = prepare(source, pair, MergeProfile::BuiltinAttributesV1).unwrap();
    let MergePreparation::Clean(plan) = result else {
        panic!("expected a complete candidate: {result:?}")
    };
    for object in &plan.objects {
        assert_eq!(
            object.id,
            git_object_id(source.format, object.kind, &object.body)
        );
    }
    plan
}

fn conflict(
    source: &Source,
    pair: [GitOid; 2],
    profile: MergeProfile,
    kind: ConflictKind,
    path: &[u8],
) {
    let result = prepare(source, pair, profile).unwrap();
    let MergePreparation::Conflicted { conflicts, .. } = result else {
        panic!("expected typed conflict: {result:?}")
    };
    assert!(
        conflicts
            .iter()
            .any(|conflict| conflict.kind == kind && conflict.path == path),
        "{conflicts:?}"
    );
}

#[test]
fn unrelated_lfs_rules_admit_native_text_merges_and_legacy_profiles_remain_unchanged() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let attributes = [(
            b".gitattributes".as_slice(),
            b"*.bin filter=lfs diff=lfs merge=lfs -text\n* text=auto eol=lf\n".as_slice(),
        )];
        let (source, pair) = changed(format, &attributes, b"src/main.rs");
        let plan = clean(&source, pair);
        assert!(
            plan.objects
                .iter()
                .any(|object| object.kind == GitObjectKind::Blob && object.body == MERGED)
        );
        assert_eq!(
            MergePreparation::Clean(plan.clone()),
            prepare(&source, pair, MergeProfile::BuiltinAttributesV1).unwrap()
        );
        for profile in [MergeProfile::PathMergeV1, MergeProfile::ExactRenamesV1] {
            conflict(
                &source,
                pair,
                profile,
                ConflictKind::AttributesRequireDriver,
                b"src/main.rs",
            );
        }
        assert_eq!(
            prepare_merge(
                &source,
                format,
                pair[0],
                pair[1],
                &metadata(),
                PreparationLimits::default()
            )
            .unwrap(),
            prepare(&source, pair, MergeProfile::PathMergeV1).unwrap()
        );
        let (bare, bare_pair) = changed(format, &[], b"src/main.rs");
        assert_eq!(
            prepare(&bare, bare_pair, MergeProfile::PathMergeV1).unwrap(),
            prepare(&bare, bare_pair, MergeProfile::BuiltinAttributesV1).unwrap()
        );
    }
}

#[test]
fn nested_precedence_last_assignment_reset_and_binary_macro_suppression_are_per_attribute() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for nested in [
            b"*.txt merge=binary\nmain.txt !merge\n".as_slice(),
            b"*.txt merge=custom merge=text\n".as_slice(),
            b"*.txt merge=text\n*.txt text eol=crlf diff=custom\n".as_slice(),
        ] {
            let (source, pair) = changed(
                format,
                &[
                    (b".gitattributes", b"* merge=custom\n"),
                    (b"src/.gitattributes", nested),
                ],
                b"src/main.txt",
            );
            assert!(
                clean(&source, pair)
                    .objects
                    .iter()
                    .any(|object| object.body == MERGED)
            );
        }
        for (rules, expected) in [
            (b"* binary\n* -binary\n".as_slice(), Driver::Text),
            (b"* binary\n* !binary\n".as_slice(), Driver::Text),
            (
                b"* binary\n* binary=ordinary-value\n".as_slice(),
                Driver::Text,
            ),
            (b"* binary merge=text\n".as_slice(), Driver::Text),
            (b"* merge=text binary\n".as_slice(), Driver::Binary),
            (b"* binary\n* !merge\n".as_slice(), Driver::Text),
            (
                b"* merge=custom\n* binary\n* -binary\n".as_slice(),
                Driver::Unsupported,
            ),
        ] {
            let (source, pair) = changed(format, &[(b".gitattributes", rules)], b"main.txt");
            match expected {
                Driver::Text => {
                    clean(&source, pair);
                }
                Driver::Binary => conflict(
                    &source,
                    pair,
                    MergeProfile::BuiltinAttributesV1,
                    ConflictKind::Binary,
                    b"main.txt",
                ),
                Driver::Unsupported => conflict(
                    &source,
                    pair,
                    MergeProfile::BuiltinAttributesV1,
                    ConflictKind::AttributesRequireDriver,
                    b"main.txt",
                ),
            }
        }
    }
}

#[test]
fn built_in_binary_and_unsupported_drivers_preserve_explicit_conflict_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, pair) = changed(
            format,
            &[(b".gitattributes", b"\xef\xbb\xbf* binary\n")],
            b"main.txt",
        );
        conflict(
            &source,
            pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::Binary,
            b"main.txt",
        );
        let rules = b"* merge=text\n\xef\xbb\xbf* binary\n";
        let (ordinary, ordinary_pair) = changed(format, &[(b".gitattributes", rules)], b"main.txt");
        clean(&ordinary, ordinary_pair);
        let (literal, literal_pair) = changed(
            format,
            &[(b".gitattributes", rules)],
            b"\xef\xbb\xbfmain.txt",
        );
        conflict(
            &literal,
            literal_pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::Binary,
            b"\xef\xbb\xbfmain.txt",
        );
        for (assignment, kind) in [
            ("-merge", ConflictKind::Binary),
            ("merge=binary", ConflictKind::Binary),
            ("binary", ConflictKind::Binary),
            ("merge=lfs", ConflictKind::AttributesRequireDriver),
            ("merge=custom", ConflictKind::AttributesRequireDriver),
            ("merge=union", ConflictKind::AttributesRequireDriver),
            ("merge=", ConflictKind::AttributesRequireDriver),
        ] {
            let rule = format!("*.bin {assignment}\n");
            let (source, pair) = changed(
                format,
                &[(b".gitattributes", rule.as_bytes())],
                b"asset.bin",
            );
            conflict(
                &source,
                pair,
                MergeProfile::BuiltinAttributesV1,
                kind,
                b"asset.bin",
            );
            let (other, other_pair) = changed(
                format,
                &[(b".gitattributes", rule.as_bytes())],
                b"src/main.rs",
            );
            clean(&other, other_pair);
        }
        for value in ["merge", "merge=text", "!merge"] {
            let rule = format!("* {value}\n");
            let (source, pair) =
                changed(format, &[(b".gitattributes", rule.as_bytes())], b"main.txt");
            clean(&source, pair);
        }
        let mut source = Source::new(format);
        let attributes = (b".gitattributes".as_slice(), b"* merge=text\n".as_slice());
        let pair = source.pair(
            &[attributes, (b"opaque", b"\0base")],
            &[attributes, (b"opaque", b"\0ours")],
            &[attributes, (b"opaque", b"\0theirs")],
        );
        conflict(
            &source,
            pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::Binary,
            b"opaque",
        );
    }
}

#[test]
fn changed_or_nonregular_attribute_declarations_refuse_content_merge_but_not_trivial_reuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        for replacement in [b"* text=auto\n".as_slice(), b"* merge=text\n".as_slice()] {
            let pair = source.pair(
                &[(b".gitattributes", b"* eol=lf\n"), (b"main", BASE)],
                &[(b".gitattributes", replacement), (b"main", OURS)],
                &[(b".gitattributes", b"* eol=lf\n"), (b"main", THEIRS)],
            );
            conflict(
                &source,
                pair,
                MergeProfile::BuiltinAttributesV1,
                ConflictKind::AttributesRequireDriver,
                b"main",
            );
        }
        let pair = source.pair(
            &[(b"main", BASE)],
            &[(b".gitattributes", b"*.bin merge=lfs\n"), (b"main", OURS)],
            &[(b"main", THEIRS)],
        );
        conflict(
            &source,
            pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::AttributesRequireDriver,
            b"main",
        );
        source.attribute_mode = 0o120000;
        let declarations = (b".gitattributes".as_slice(), b"elsewhere".as_slice());
        let pair = source.pair(
            &[declarations, (b"main", BASE)],
            &[declarations, (b"main", OURS)],
            &[declarations, (b"main", THEIRS)],
        );
        conflict(
            &source,
            pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::AttributesRequireDriver,
            b"main",
        );
        source.attribute_mode = 0o100644;
        let pair = source.pair(
            &[(b"main", BASE)],
            &[
                (b".gitattributes", b"[attr]custom merge=external\n"),
                (b"main", BASE),
            ],
            &[(b"main", THEIRS)],
        );
        source.blob_reads.set(0);
        clean(&source, pair);
        assert_eq!(
            source.blob_reads.get(),
            0,
            "trivial content must not parse or merge attributes"
        );
    }
}

#[test]
fn unsupported_grammars_refuse_and_metadata_never_converts_the_native_blob_bytes() {
    for rules in [
        b"[attr]custom merge=text\n* custom\n".as_slice(),
        b"\"*.txt\" merge=text\n".as_slice(),
        b"\\*.txt merge=text\n".as_slice(),
        b"*.[ch] merge=text\n".as_slice(),
        b"!*.bin merge=text\n".as_slice(),
        b"a/***/b merge=binary\n".as_slice(),
        b"a/****/b merge=binary\n".as_slice(),
        b"* bad$name\n".as_slice(),
        b"* merge=text\0\n".as_slice(),
    ] {
        let (source, pair) = changed(
            GitHashAlgorithm::Sha1,
            &[(b".gitattributes", rules)],
            b"main.txt",
        );
        conflict(
            &source,
            pair,
            MergeProfile::BuiltinAttributesV1,
            ConflictKind::AttributesRequireDriver,
            b"main.txt",
        );
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = Source::new(format);
        let attribute = (
            b".gitattributes".as_slice(),
            b"* text=auto eol=lf filter=unconfigured ident working-tree-encoding=UTF-16\n"
                .as_slice(),
        );
        let pair = source.pair(
            &[attribute, (b"main.txt", b"a\r\nb\r\nc\r\nd\r\ne\r\n")],
            &[attribute, (b"main.txt", b"A\r\nb\r\nc\r\nd\r\ne\r\n")],
            &[attribute, (b"main.txt", b"a\r\nb\r\nc\r\nd\r\nE\r\n")],
        );
        assert!(
            clean(&source, pair)
                .objects
                .iter()
                .any(|object| object.body == b"A\r\nb\r\nc\r\nd\r\nE\r\n")
        );
    }
}

#[test]
fn pattern_components_follow_anchors_basename_and_double_star_semantics() {
    let source = Source::new(GitHashAlgorithm::Sha1);
    for unsupported in [
        b"a/***/b".as_slice(),
        b"a/****/b".as_slice(),
        b"***".as_slice(),
    ] {
        assert!(Pattern::parse(unsupported).is_none());
    }
    for (pattern, path, matches) in [
        (b"*.bin".as_slice(), b"dir/deep/a.bin".as_slice(), true),
        (b"/a.bin".as_slice(), b"a.bin".as_slice(), true),
        (b"/a.bin".as_slice(), b"dir/a.bin".as_slice(), false),
        (b"dir/*.bin".as_slice(), b"dir/a.bin".as_slice(), true),
        (b"dir/*.bin".as_slice(), b"dir/deep/a.bin".as_slice(), false),
        (b"**/a.bin".as_slice(), b"a.bin".as_slice(), true),
        (b"**/a.bin".as_slice(), b"dir/deep/a.bin".as_slice(), true),
        (b"a/**/b".as_slice(), b"a/b".as_slice(), true),
        (b"a/**/b".as_slice(), b"a/x/y/b".as_slice(), true),
        (b"a/**/b".as_slice(), b"x/a/b".as_slice(), false),
        (b"a/**".as_slice(), b"a".as_slice(), false),
        (b"a/**".as_slice(), b"a/b/c".as_slice(), true),
        (b"dir/".as_slice(), b"dir/a.bin".as_slice(), false),
        (b"dir".as_slice(), b"dir/a.bin".as_slice(), false),
        (
            b"raw-?.txt".as_slice(),
            b"dir/raw-\xff.txt".as_slice(),
            true,
        ),
        (b"raw-?.txt".as_slice(), b"raw-ab.txt".as_slice(), false),
    ] {
        let parsed = Pattern::parse(pattern).unwrap();
        assert_eq!(
            parsed
                .matches(path, &mut State::default(), &source)
                .unwrap(),
            matches,
            "{pattern:?} against {path:?}"
        );
    }
    let repeated = Pattern::parse(b"*a*a*a*a*a*a*a*a*a*a*a*a*b").unwrap();
    assert!(
        !repeated
            .matches(&vec![b'a'; 2048], &mut State::default(), &source)
            .unwrap()
    );
}

#[test]
fn parser_and_matching_limits_have_permitted_boundary_twins() {
    let source = Source::new(GitHashAlgorithm::Sha1);
    for count in [FILE_RULES, FILE_RULES + 1] {
        let bytes = b"*.bin merge=lfs\n".repeat(count);
        let result = parse(&bytes, &mut State::default(), &source);
        assert_eq!(result.is_ok(), count == FILE_RULES);
    }
    for count in [ASSIGNMENTS, ASSIGNMENTS + 1] {
        let bytes = format!("* {}\n", vec!["metadata"; count].join(" "));
        assert_eq!(
            parse(bytes.as_bytes(), &mut State::default(), &source).is_ok(),
            count == ASSIGNMENTS
        );
    }
    for count in [PATTERN_BYTES, PATTERN_BYTES + 1] {
        let bytes = format!("{} merge=text\n", "a".repeat(count));
        assert_eq!(
            parse(bytes.as_bytes(), &mut State::default(), &source).is_ok(),
            count == PATTERN_BYTES
        );
    }
    let mut all_rules = State {
        rules: TOTAL_RULES - FILE_RULES,
        ..State::default()
    };
    parse(
        &b"*.bin merge=lfs\n".repeat(FILE_RULES),
        &mut all_rules,
        &source,
    )
    .unwrap();
    assert_eq!(all_rules.rules, TOTAL_RULES);
    assert!(matches!(
        parse(b"*.txt merge=text\n", &mut all_rules, &source),
        Err(PreparationError::Budget("attribute rules"))
    ));
    let pattern = Pattern::parse(&vec![b'?'; PATTERN_BYTES]).unwrap();
    let mut state = State {
        steps: MATCH_STEPS - PATTERN_BYTES * 2 - 1,
        ..State::default()
    };
    assert!(!pattern.matches(b"x", &mut state, &source).unwrap());
    assert_eq!(state.steps, MATCH_STEPS);
    assert!(matches!(
        pattern.matches(b"x", &mut state, &source),
        Err(PreparationError::Budget("attribute matching work"))
    ));
}

#[test]
fn a_queue_prefix_shares_attribute_matching_work_across_all_candidates() {
    use crate::preparation::queue_prefix::{PrefixInput, PrefixPreparation, prepare_queue_prefix};

    let name = vec![b'a'; 3000];
    let rule = format!("{} merge=lfs\n", "?".repeat(700));
    let attributes = (b".gitattributes".as_slice(), rule.as_bytes());
    let (mut source, pair) = changed(GitHashAlgorithm::Sha1, &[attributes], &name);
    let base = source.commits[&pair[0]].parents[0];
    let tree = source.snapshot(&[attributes, (&name, b"one\ntwo\nTHREE\nfour\nfive\n")]);
    let second = source.commit(tree, Some(base), "second queued source");
    let metadata = metadata();
    let inputs = [
        PrefixInput {
            source: pair[1],
            metadata: &metadata,
        },
        PrefixInput {
            source: second,
            metadata: &metadata,
        },
    ];
    for input in &inputs {
        assert!(matches!(
            prepare_queue_prefix(
                &source,
                source.format,
                pair[0],
                &[*input],
                PreparationLimits::default(),
                MergeProfile::BuiltinAttributesV1
            ),
            Ok(PrefixPreparation::Clean(_))
        ));
    }
    // Each candidate costs just over half the fixed matcher envelope. Reusing
    // the same cached attribute blob must not reset that cumulative work.
    assert!(matches!(
        prepare_queue_prefix(
            &source,
            source.format,
            pair[0],
            &inputs,
            PreparationLimits::default(),
            MergeProfile::BuiltinAttributesV1
        ),
        Err(PreparationError::Budget("attribute matching work"))
    ));
}

#[test]
fn attribute_cache_limits_and_full_preparation_cancellation_never_return_partial_candidates() {
    for bytes in [FILE_BYTES, FILE_BYTES + 1] {
        let mut rules = vec![b'x'; bytes];
        rules[0] = b'#';
        let (source, pair) = changed(
            GitHashAlgorithm::Sha1,
            &[(b".gitattributes", &rules)],
            b"main.txt",
        );
        let result = prepare(&source, pair, MergeProfile::BuiltinAttributesV1);
        if bytes == FILE_BYTES {
            assert!(matches!(result, Ok(MergePreparation::Clean(_))));
        } else {
            assert!(matches!(
                result,
                Err(PreparationError::Budget("attribute file bytes"))
            ));
        }
    }
    for (count, bytes_per_file, expected) in [
        (FILES + 1, 16, "attribute files"),
        (TOTAL_BYTES / FILE_BYTES + 1, FILE_BYTES, "attribute bytes"),
    ] {
        let mut source = Source::new(GitHashAlgorithm::Sha1);
        let mut ids = Vec::new();
        for index in 0..count {
            let mut bytes = format!("# {index:04} ").into_bytes();
            bytes.resize(bytes_per_file, b'x');
            ids.push(source.blob(&bytes));
        }
        let planner = Planner::new(&source, source.format, PreparationLimits::default());
        let mut state = State::default();
        for id in &ids[..count - 1] {
            state.load(&planner, *id).unwrap();
        }
        let reads = source.blob_reads.get();
        state.load(&planner, ids[0]).unwrap();
        assert_eq!(
            source.blob_reads.get(),
            reads,
            "identical native attribute blobs reuse one bounded parse"
        );
        assert!(
            matches!(state.load(&planner, ids[count - 1]), Err(PreparationError::Budget(reason)) if reason == expected)
        );
    }
    let (source, pair) = changed(
        GitHashAlgorithm::Sha256,
        &[(b".gitattributes", b"**/*.bin merge=lfs\n*.txt merge=text\n")],
        b"src/main.txt",
    );
    let expected = clean(&source, pair);
    let calls = source.checkpoints.get();
    for stop in [1, calls / 2, calls] {
        source.checkpoints.set(0);
        source.cancel_at.set(stop);
        assert!(prepare(&source, pair, MergeProfile::BuiltinAttributesV1).is_err());
    }
    source.checkpoints.set(0);
    source.cancel_at.set(usize::MAX);
    assert_eq!(clean(&source, pair), expected);
}
