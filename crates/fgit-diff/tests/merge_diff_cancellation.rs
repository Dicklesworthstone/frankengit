#![forbid(unsafe_code)]

use std::cell::Cell;

use fgit_diff::{
    ContentMergeError, ContentMergeOptions, DiffError, DiffLimits, DiffOptions,
    MergeCancellation, VirtualBaseProfile, diff_with_cancellation, merge_content,
    merge_content_many, merge_content_many_with_cancellation, merge_content_with_cancellation,
};

struct CancelOn {
    calls: Cell<usize>,
    at: usize,
}

impl CancelOn {
    const fn new(at: usize) -> Self {
        Self {
            calls: Cell::new(0),
            at,
        }
    }
}

impl MergeCancellation for CancelOn {
    fn is_cancelled(&self) -> bool {
        self.calls.set(self.calls.get() + 1);
        self.calls.get() == self.at
    }
}

fn profiles() -> [ContentMergeOptions; 4] {
    let limits = DiffLimits::default();
    [
        DiffOptions::myers_lines(limits),
        DiffOptions::patience_lines(limits),
        DiffOptions::histogram_lines(limits),
        DiffOptions::myers_lines(DiffLimits {
            max_trace_cells: 0,
            ..limits
        }),
    ]
    .map(|diff_options| {
        let mut options = ContentMergeOptions::default();
        options.profile.diff_options = diff_options;
        options
    })
}

fn versions() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut base = Vec::new();
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    for index in 0..64 {
        base.extend_from_slice(format!("base-{index}\n").as_bytes());
        ours.extend_from_slice(format!("ours-{index}\n").as_bytes());
        theirs.extend_from_slice(format!("theirs-{index}\n").as_bytes());
    }
    (base, ours, theirs)
}

#[test]
fn cancelled_diff_maps_to_top_level_merge_cancellation_only() {
    assert_eq!(
        ContentMergeError::from(DiffError::Cancelled),
        ContentMergeError::Cancelled,
    );
    let work = DiffError::WorkExceeded { limit: 7 };
    assert_eq!(
        ContentMergeError::from(work.clone()),
        ContentMergeError::Diff(work),
    );
    assert_eq!(
        ContentMergeError::from(DiffError::MalformedScript),
        ContentMergeError::Diff(DiffError::MalformedScript),
    );
}

#[test]
fn first_side_diff_is_interruptible_for_every_profile_and_retry_has_no_residue() {
    let (base, ours, theirs) = versions();
    for options in profiles() {
        let expected = merge_content(&base, &ours, &theirs, options).unwrap();
        let cancel = CancelOn::new(32);
        assert_eq!(
            merge_content_with_cancellation(&base, &ours, &theirs, options, &cancel),
            Err(ContentMergeError::Cancelled),
        );
        assert_eq!(cancel.calls.get(), 32);
        assert_eq!(merge_content(&base, &ours, &theirs, options).unwrap(), expected);
    }
}

#[test]
fn second_side_diff_uses_the_same_request_probe() {
    let (base, ours, theirs) = versions();
    for options in profiles() {
        let first_side_calls = Cell::new(0);
        diff_with_cancellation(&base, &ours, options.profile.diff_options, &|| {
            first_side_calls.set(first_side_calls.get() + 1);
            false
        })
        .unwrap();
        // One merge-entry check, all first-diff checkpoints, one between-side
        // check, then 32 checks inside the second diff. The all-changed inputs
        // have just one conflict cluster; later merge checks cannot fake this.
        let stop = 1 + first_side_calls.get() + 1 + 32;
        let cancel = CancelOn::new(stop);
        assert_eq!(
            merge_content_with_cancellation(&base, &ours, &theirs, options, &cancel),
            Err(ContentMergeError::Cancelled),
        );
        assert_eq!(cancel.calls.get(), stop);
        assert!(merge_content(&base, &ours, &theirs, options).is_ok());
    }
}

#[test]
fn recursive_virtual_base_construction_forwards_cancellation_into_diff() {
    let (first_base, second_base, ours) = versions();
    let theirs = b"a different descendant\n";
    for mut options in profiles() {
        options.profile.virtual_base = VirtualBaseProfile::RecursiveConflictPreservingV1;
        let bases = [first_base.as_slice(), second_base.as_slice()];
        // Two checks precede the fold; the fold checks once before diff.
        // The fourth check must be the first diff's entry checkpoint. With
        // zero work admitted, an unwired diff returns WorkExceeded instead,
        // so a later merge checkpoint cannot satisfy this test vacuously.
        let mut exhausted = options;
        exhausted.profile.diff_options.limits.max_work = 0;
        let cancel = CancelOn::new(4);
        assert_eq!(
            merge_content_many_with_cancellation(&bases, &ours, theirs, exhausted, &cancel),
            Err(ContentMergeError::Cancelled),
        );
        assert_eq!(cancel.calls.get(), 4);
        assert_eq!(
            merge_content_many(&bases, &ours, theirs, exhausted),
            Err(ContentMergeError::Diff(DiffError::WorkExceeded { limit: 0 })),
        );
        assert!(merge_content_many(&bases, &ours, theirs, options).is_ok());
    }
}

#[test]
fn unchanged_request_preserves_clean_conflicted_and_binary_proposals() {
    for options in profiles() {
        for (base, ours, theirs) in [
            (
                b"a\nb\nc\n".as_slice(),
                b"ours\nb\nc\n".as_slice(),
                b"a\nb\ntheirs\n".as_slice(),
            ),
            (b"a\n", b"ours\n", b"theirs\n"),
            (b"a\0", b"ours\0", b"theirs\0"),
            (b"a\n", b"a\n", b"theirs\n"),
            (b"a\n", b"same\n", b"same\n"),
        ] {
            let expected = merge_content(base, ours, theirs, options).unwrap();
            let never = CancelOn::new(usize::MAX);
            assert_eq!(
                merge_content_with_cancellation(base, ours, theirs, options, &never).unwrap(),
                expected,
            );
        }
    }
}
