#![forbid(unsafe_code)]

use std::cell::Cell;

use fgit_diff::{
    DiffAlgorithm, DiffError, DiffLimits, DiffOptions, SequenceGranularity, diff,
    diff_with_cancellation,
};

fn profiles() -> [DiffOptions; 4] {
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
}

fn changed_inputs() -> (Vec<u8>, Vec<u8>) {
    let mut old = Vec::new();
    let mut new = Vec::new();
    for index in 0..128 {
        old.extend_from_slice(format!("old-{index}\n").as_bytes());
        new.extend_from_slice(format!("new-{index}\n").as_bytes());
    }
    (old, new)
}

#[test]
fn cancellation_before_preparation_returns_no_script_even_for_empty_input() {
    for options in profiles() {
        for (old, new) in [(b"".as_slice(), b"".as_slice()), (b"a\n", b"b\n")] {
            assert_eq!(
                diff_with_cancellation(old, new, options, &|| true),
                Err(DiffError::Cancelled),
            );
            assert_eq!(
                diff_with_cancellation(old, new, options, &|| false),
                diff(old, new, options),
            );
        }
    }
}

#[test]
fn every_algorithm_observes_cancellation_during_work_and_retry_is_clean() {
    let (old, new) = changed_inputs();
    for options in profiles() {
        let expected = diff(&old, &new, options).unwrap();
        assert_eq!(expected.apply_to(&old).unwrap(), new);
        if options.limits.max_trace_cells == 0 {
            assert_eq!(expected.algorithm, DiffAlgorithm::MyersLinearRefinement);
        }
        // Preparation has fewer than 32 checkpoints; this cancellation occurs
        // inside the algorithm, not at the entry or result boundary.
        let calls = Cell::new(0);
        let cancel = || {
            let next = calls.get() + 1;
            calls.set(next);
            next == 32
        };
        assert_eq!(
            diff_with_cancellation(&old, &new, options, &cancel),
            Err(DiffError::Cancelled),
            "profile {:?}, trace bound {}", options.profile, options.limits.max_trace_cells,
        );
        assert_eq!(calls.get(), 32, "no work may resume after observing cancellation");
        assert_eq!(
            diff_with_cancellation(&old, &new, options, &|| false).unwrap(),
            expected,
        );
    }
}

#[test]
fn cancellation_at_every_checkpoint_refuses_instead_of_returning_partial_output() {
    for options in profiles() {
        let (old, new) = (b"one\ntwo\nthree\n".as_slice(), b"three\nfour\none\n".as_slice());
        let observed = Cell::new(0);
        let expected = diff_with_cancellation(old, new, options, &|| {
            observed.set(observed.get() + 1);
            false
        }).unwrap();
        assert_eq!(expected.apply_to(old).unwrap(), new);
        for stop in 1..=observed.get() {
            let calls = Cell::new(0);
            let actual = diff_with_cancellation(old, new, options, &|| {
                calls.set(calls.get() + 1);
                calls.get() == stop
            });
            assert_eq!(actual, Err(DiffError::Cancelled), "checkpoint {stop}");
            assert_eq!(calls.get(), stop);
        }
        // A cancellation not reached by the completed operation must not turn
        // an otherwise valid result into a fabricated refusal.
        let calls = Cell::new(0);
        assert_eq!(diff_with_cancellation(old, new, options, &|| {
            calls.set(calls.get() + 1);
            calls.get() > observed.get()
        }).unwrap(), expected);
    }
}

#[test]
fn noncancelled_calls_preserve_resource_refusals() {
    for options in profiles() {
        for limits in [
            DiffLimits { max_input_bytes: 1, ..options.limits },
            DiffLimits { max_units: 1, ..options.limits },
            DiffLimits { max_work: 0, ..options.limits },
        ] {
            let options = DiffOptions { limits, ..options };
            let expected = diff(b"one\ntwo\n", b"three\nfour\n", options);
            assert!(expected.is_err());
            assert_eq!(
                diff_with_cancellation(b"one\ntwo\n", b"three\nfour\n", options, &|| false),
                expected,
            );
        }
    }
}

#[test]
fn false_probes_preserve_exact_scripts_on_a_bounded_exhaustive_byte_corpus() {
    let mut corpus = vec![Vec::new()];
    for length in 1..=4 {
        for bits in 0..(1 << length) {
            corpus.push((0..length).map(|offset| {
                if bits & (1 << offset) == 0 { b'a' } else { b'b' }
            }).collect());
        }
    }
    for mut options in profiles() {
        options.granularity = SequenceGranularity::Bytes;
        for old in &corpus {
            for new in &corpus {
                let expected = diff(old, new, options).unwrap();
                let actual = diff_with_cancellation(old, new, options, &|| false).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(actual.apply_to(old).unwrap(), *new);
            }
        }
    }
}
