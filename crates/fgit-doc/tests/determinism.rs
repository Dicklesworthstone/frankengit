//! Determinism: identical inputs render to identical bytes, every time.

mod common;

use common::{corpus, parse_case, render_all};
use fgit_doc::{
    Anchor, BatchInput, Limits, ParseProfile, RenderProfile, SourceObjectId, VarianceClass,
    WorkloadProfile, render_batch,
};

#[test]
fn parsing_the_same_source_twice_produces_the_same_document() {
    for case in corpus() {
        let first = parse_case(&case);
        let second = parse_case(&case);
        assert_eq!(first, second, "{}: parsing is not deterministic", case.name);
    }
}

#[test]
fn rendering_the_same_document_repeatedly_produces_the_same_bytes() {
    for case in corpus() {
        let document = parse_case(&case);
        let first = render_all(case.name, &document);
        for _ in 0..4 {
            let again = render_all(case.name, &document);
            assert_eq!(
                first, again,
                "{}: rendering is not byte-deterministic",
                case.name
            );
        }
    }
}

#[test]
fn rendering_a_freshly_parsed_document_matches_the_first_parse() {
    for case in corpus() {
        let first = render_all(case.name, &parse_case(&case));
        let second = render_all(case.name, &parse_case(&case));
        assert_eq!(
            first, second,
            "{}: a second parse changed the rendered output",
            case.name
        );
    }
}

#[test]
fn diagnostics_are_deterministic_in_content_and_order() {
    for case in corpus() {
        let first = fgit_doc::parse(case.source).map(|parsed| parsed.diagnostics().to_vec());
        let second = fgit_doc::parse(case.source).map(|parsed| parsed.diagnostics().to_vec());
        assert_eq!(first, second, "{}: diagnostics are not stable", case.name);
    }
}

#[test]
fn anchor_identities_are_deterministic() {
    for case in corpus() {
        let document = parse_case(&case);
        for root in document.roots() {
            let first = Anchor::create(
                &document,
                *root,
                SourceObjectId::new(b"blob").expect("identity accepted"),
                Limits::DEFAULT,
            )
            .expect("anchor created");
            let second = Anchor::create(
                &document,
                *root,
                SourceObjectId::new(b"blob").expect("identity accepted"),
                Limits::DEFAULT,
            )
            .expect("anchor created");
            assert_eq!(
                first.id(),
                second.id(),
                "{}: anchor identity is not deterministic",
                case.name
            );
        }
    }
}

#[test]
fn the_batch_result_does_not_depend_on_the_plan() {
    let cases = corpus();
    let inputs = cases
        .iter()
        .map(|case| BatchInput::render(case.source))
        .collect::<Vec<_>>();
    let plans = [
        WorkloadProfile {
            cpu_cap: 1,
            memory_budget_bytes: 1024 * 1024 * 1024,
            per_job_bytes: 1024 * 1024,
            variance: VarianceClass::Uniform,
        },
        WorkloadProfile {
            cpu_cap: 7,
            memory_budget_bytes: 1024 * 1024 * 1024,
            per_job_bytes: 1024 * 1024,
            variance: VarianceClass::Uniform,
        },
        WorkloadProfile {
            cpu_cap: 64,
            memory_budget_bytes: 1024 * 1024 * 1024,
            per_job_bytes: 1024 * 1024,
            variance: VarianceClass::Skewed,
        },
        WorkloadProfile {
            cpu_cap: 3,
            memory_budget_bytes: 8 * 1024 * 1024,
            per_job_bytes: 4 * 1024 * 1024,
            variance: VarianceClass::Mixed,
        },
    ];
    for surface in RenderProfile::all() {
        let mut baseline = None;
        let mut widths = Vec::new();
        for workload in plans {
            let receipt = render_batch(&inputs, ParseProfile::DEFAULT, surface, workload)
                .expect("the batch runs");
            widths.push(receipt.plan().workers());
            let outcomes = receipt.outcomes().to_vec();
            match &baseline {
                None => baseline = Some(outcomes),
                Some(expected) => assert_eq!(
                    *expected,
                    outcomes,
                    "profile {} produced a different receipt under a different plan",
                    surface.tag()
                ),
            }
        }
        assert!(
            widths.windows(2).any(|pair| pair[0] != pair[1]),
            "the test is only meaningful if the plans really differ: {widths:?}"
        );
    }
}
