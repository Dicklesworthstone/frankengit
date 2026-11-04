#![forbid(unsafe_code)]

use fgit_diff::{
    DiffAlgorithm, DiffError, DiffLimits, DiffOptions, diff, diff_with_cancellation,
    diff_with_cancellation_and_work,
};
use std::cell::Cell;

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

#[test]
fn receipt_preserves_scripts_and_exact_work_boundary_for_every_algorithm() {
    for options in profiles() {
        for (old, new) in [
            (b"".as_slice(), b"".as_slice()),
            (b"same\n", b"same\n"),
            (b"a\nb\na\nc\n", b"b\na\nd\na\n"),
            (b"raw\xff\r\ntail", b"prefix\nraw\xff\r\ntail"),
        ] {
            let (actual, work) =
                diff_with_cancellation_and_work(old, new, options, &|| false).unwrap();
            assert_eq!(actual, diff(old, new, options).unwrap());
            assert_eq!(
                actual,
                diff_with_cancellation(old, new, options, &|| false).unwrap()
            );
            assert_eq!(actual.apply_to(old).unwrap(), new);
            if options.limits.max_trace_cells == 0 && !old.is_empty() && !new.is_empty() {
                assert_eq!(actual.algorithm, DiffAlgorithm::MyersLinearRefinement);
            }
            let exact = DiffOptions {
                limits: DiffLimits {
                    max_work: work,
                    ..options.limits
                },
                ..options
            };
            assert_eq!(
                diff_with_cancellation_and_work(old, new, exact, &|| false).unwrap(),
                (actual, work)
            );
            if let Some(below) = work.checked_sub(1) {
                let limited = DiffOptions {
                    limits: DiffLimits {
                        max_work: below,
                        ..options.limits
                    },
                    ..options
                };
                assert_eq!(
                    diff_with_cancellation_and_work(old, new, limited, &|| false),
                    Err(DiffError::WorkExceeded { limit: below })
                );
            }
        }
    }
}

#[test]
fn consumed_work_composes_without_resetting_the_aggregate_allowance() {
    let options = DiffOptions::myers_lines(DiffLimits::default());
    let (first, work_a) =
        diff_with_cancellation_and_work(b"a\nb\n", b"a\nc\n", options, &|| false).unwrap();
    let (second, work_b) =
        diff_with_cancellation_and_work(b"a\nc\n", b"d\nc\n", options, &|| false).unwrap();
    assert!(work_a > 0 && work_b > 0);
    for (allowance, succeeds) in [(work_a + work_b - 1, false), (work_a + work_b, true)] {
        let mut limited = options;
        limited.limits.max_work = allowance;
        let (result, spent) =
            diff_with_cancellation_and_work(b"a\nb\n", b"a\nc\n", limited, &|| false).unwrap();
        assert_eq!(result, first);
        limited.limits.max_work -= spent;
        let result = diff_with_cancellation_and_work(b"a\nc\n", b"d\nc\n", limited, &|| false);
        if succeeds {
            assert_eq!(result.unwrap(), (second.clone(), work_b));
        } else {
            assert_eq!(result, Err(DiffError::WorkExceeded { limit: work_b - 1 }));
        }
    }
}

#[test]
fn cancellation_at_every_checkpoint_returns_neither_partial_script_nor_receipt() {
    for options in profiles() {
        let probes = Cell::new(0);
        let expected = diff_with_cancellation_and_work(
            b"one\ntwo\nthree\n",
            b"three\nfour\none\n",
            options,
            &|| {
                probes.set(probes.get() + 1);
                false
            },
        )
        .unwrap();
        for stop in 1..=probes.get() {
            let calls = Cell::new(0);
            assert_eq!(
                diff_with_cancellation_and_work(
                    b"one\ntwo\nthree\n",
                    b"three\nfour\none\n",
                    options,
                    &|| {
                        calls.set(calls.get() + 1);
                        calls.get() == stop
                    },
                ),
                Err(DiffError::Cancelled)
            );
            assert_eq!(calls.get(), stop);
        }
        assert_eq!(
            diff_with_cancellation_and_work(
                b"one\ntwo\nthree\n",
                b"three\nfour\none\n",
                options,
                &|| false,
            )
            .unwrap(),
            expected
        );
    }
}
