//! Staged multi-output publication: all siblings, or none of them.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_doc::ast::Document;
use fgit_doc::{
    Limits, OutputRequest, RefusalKind, RenderProfile, parse, stage, standard_requests,
};

fn document_of(source: &str) -> Document {
    parse(source)
        .unwrap_or_else(|refusal| panic!("source refused: {refusal}"))
        .into_document()
}

fn requests() -> Vec<OutputRequest> {
    vec![
        OutputRequest::new("note.plain_text.txt", RenderProfile::PlainText).expect("name"),
        OutputRequest::new("note.html_safe.html", RenderProfile::HtmlSafe).expect("name"),
        OutputRequest::new("note.compact_machine.txt", RenderProfile::CompactMachine)
            .expect("name"),
    ]
}

#[test]
fn staging_renders_every_requested_surface_from_one_document() {
    let document = document_of("# Title\n\nbody *text*\n");
    let reservation = stage(&document, &requests(), Limits::DEFAULT).expect("staging succeeds");
    assert_eq!(reservation.len(), 3);
    assert!(!reservation.is_empty());
    assert!(reservation.body_bytes() > 0);
    let names = reservation
        .outputs()
        .iter()
        .map(|entry| entry.name().as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "note.plain_text.txt",
            "note.html_safe.html",
            "note.compact_machine.txt"
        ],
        "staging preserves request order"
    );
    assert_eq!(
        reservation.outputs()[1].body(),
        "<h1>Title</h1>\n<p>body <em>text</em></p>\n"
    );
}

#[test]
fn a_duplicate_output_name_is_refused_and_distinct_names_proceed() {
    let document = document_of("body\n");
    let distinct = vec![
        OutputRequest::new("a.txt", RenderProfile::PlainText).expect("name"),
        OutputRequest::new("b.txt", RenderProfile::PlainText).expect("name"),
    ];
    stage(&document, &distinct, Limits::DEFAULT).expect("distinct names proceed");

    let clashing = vec![
        OutputRequest::new("a.txt", RenderProfile::PlainText).expect("name"),
        OutputRequest::new("a.txt", RenderProfile::HtmlSafe).expect("name"),
    ];
    let refusal = stage(&document, &clashing, Limits::DEFAULT).expect_err("a collision is refused");
    assert_eq!(refusal.kind(), RefusalKind::DuplicateOutputName);
}

#[test]
fn a_path_unsafe_output_name_is_refused_and_a_safe_one_is_accepted() {
    OutputRequest::new("release-notes.v2.html", RenderProfile::HtmlSafe)
        .expect("a safe name is accepted");
    for hostile in [
        "",
        "../escape",
        "sub/dir",
        ".hidden",
        "a..b",
        "with space",
        "nul\0",
    ] {
        let refusal = OutputRequest::new(hostile, RenderProfile::PlainText)
            .expect_err("a path-unsafe name is refused");
        assert_eq!(
            refusal.kind(),
            RefusalKind::OutputNameInvalid,
            "name {hostile:?}"
        );
    }
    let too_long = "a".repeat(201);
    assert_eq!(
        OutputRequest::new(&too_long, RenderProfile::PlainText)
            .expect_err("an overlong name is refused")
            .kind(),
        RefusalKind::OutputNameInvalid
    );
    OutputRequest::new(&"a".repeat(200), RenderProfile::PlainText)
        .expect("exactly the ceiling is accepted");
}

#[test]
fn an_empty_request_set_is_refused_and_a_single_request_proceeds() {
    let document = document_of("body\n");
    let refusal = stage(&document, &[], Limits::DEFAULT).expect_err("no outputs is refused");
    assert_eq!(refusal.kind(), RefusalKind::TooManyOutputs);
    let single = vec![OutputRequest::new("a.txt", RenderProfile::PlainText).expect("name")];
    stage(&document, &single, Limits::DEFAULT).expect("one output proceeds");
}

#[test]
fn a_refusal_while_staging_yields_no_reservation_at_all() {
    let document = document_of("a paragraph long enough to pass a very small ceiling\n");
    let tight = Limits {
        max_output_bytes: 8,
        ..Limits::DEFAULT
    };
    let refusal = stage(&document, &requests(), tight).expect_err("a tight ceiling refuses");
    assert_eq!(refusal.kind(), RefusalKind::OutputTooLarge);
    // There is no partially staged reservation to inspect: the type system
    // makes the failure total, which is the point of preflight staging.
    stage(&document, &requests(), Limits::DEFAULT).expect("a sufficient ceiling stages");
}

#[test]
fn a_successful_commit_publishes_every_output_in_order() {
    let document = document_of("# T\n\nbody\n");
    let reservation = stage(&document, &requests(), Limits::DEFAULT).expect("staging succeeds");
    let host = RefCell::new(BTreeMap::<String, String>::new());
    let receipt = reservation
        .commit_with(
            |name, body| -> Result<(), &'static str> {
                host.borrow_mut()
                    .insert(name.as_str().to_owned(), body.to_owned());
                Ok(())
            },
            |name| -> Result<(), &'static str> {
                host.borrow_mut().remove(name.as_str());
                Ok(())
            },
        )
        .expect("every write succeeds");
    let published = receipt
        .published()
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        published,
        vec![
            "note.plain_text.txt",
            "note.html_safe.html",
            "note.compact_machine.txt"
        ]
    );
    assert_eq!(host.borrow().len(), 3);
}

#[test]
fn a_failed_write_rolls_back_every_sibling_and_leaves_nothing() {
    // The rollback drill: the third of three writes fails, and the host must
    // be left exactly as it was found.
    let document = document_of("# T\n\nbody\n");
    let reservation = stage(&document, &requests(), Limits::DEFAULT).expect("staging succeeds");
    let host = RefCell::new(BTreeMap::<String, String>::new());
    let failure = reservation
        .commit_with(
            |name, body| -> Result<(), &'static str> {
                if name.as_str().contains("compact") {
                    return Err("host refused the write");
                }
                host.borrow_mut()
                    .insert(name.as_str().to_owned(), body.to_owned());
                Ok(())
            },
            |name| -> Result<(), &'static str> {
                host.borrow_mut().remove(name.as_str());
                Ok(())
            },
        )
        .expect_err("the commit fails");

    assert!(
        host.borrow().is_empty(),
        "zero partial outputs may survive a failed publication, found {:?}",
        host.borrow().keys().collect::<Vec<_>>()
    );
    assert_eq!(failure.failed().as_str(), "note.compact_machine.txt");
    assert_eq!(*failure.cause(), "host refused the write");
    assert!(failure.contained(), "the rollback itself must have held");
    let undone = failure
        .rolled_back()
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        undone,
        vec!["note.html_safe.html", "note.plain_text.txt"],
        "siblings are undone in reverse publication order"
    );
}

#[test]
fn a_rollback_that_itself_fails_is_reported_as_uncontained() {
    // A half-undone publication is exactly the state an operator must be told
    // about, so it is a reported outcome rather than a swallowed one.
    let document = document_of("body\n");
    let reservation = stage(&document, &requests(), Limits::DEFAULT).expect("staging succeeds");
    let host = RefCell::new(BTreeMap::<String, String>::new());
    let failure = reservation
        .commit_with(
            |name, body| -> Result<(), &'static str> {
                if name.as_str().contains("compact") {
                    return Err("host refused the write");
                }
                host.borrow_mut()
                    .insert(name.as_str().to_owned(), body.to_owned());
                Ok(())
            },
            |name| -> Result<(), &'static str> {
                if name.as_str().contains("plain_text") {
                    return Err("host could not undo");
                }
                host.borrow_mut().remove(name.as_str());
                Ok(())
            },
        )
        .expect_err("the commit fails");
    assert!(
        !failure.contained(),
        "an undo failure must not be reported as contained"
    );
    assert_eq!(failure.rollback_failures().len(), 1);
    assert_eq!(
        failure.rollback_failures()[0].0.as_str(),
        "note.plain_text.txt"
    );
    assert_eq!(
        host.borrow().keys().collect::<Vec<_>>(),
        vec!["note.plain_text.txt"],
        "the receipt names exactly what survived"
    );
}

#[test]
fn an_explicit_abort_publishes_nothing() {
    let document = document_of("body\n");
    let reservation = stage(&document, &requests(), Limits::DEFAULT).expect("staging succeeds");
    let receipt = reservation.abort();
    let discarded = receipt
        .discarded()
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(discarded.len(), 3);
    assert!(discarded.contains(&"note.html_safe.html".to_owned()));
}

#[test]
fn the_standard_request_set_names_all_four_surfaces_once() {
    let built = standard_requests("release-notes").expect("standard names are valid");
    let names = built
        .iter()
        .map(|request| request.name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "release-notes.plain_text.txt",
            "release-notes.html_safe.html",
            "release-notes.compact_machine.txt",
            "release-notes.api_json.json"
        ]
    );
    let document = document_of("# T\n\nbody\n");
    let reservation = stage(&document, &built, Limits::DEFAULT).expect("staging succeeds");
    assert_eq!(reservation.len(), 4);
}
