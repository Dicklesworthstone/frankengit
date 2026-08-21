//! Review anchors: stable identity, and one explicit outcome per remap.

use crate::common::default_profile;
use fgit_doc::ast::Document;
use fgit_doc::{
    Anchor, Limits, NodeId, RefusalKind, RemapOutcome, SourceObjectId, StructuralLimits, parse,
    parse_with,
};

fn document_of(source: &str) -> Document {
    parse(source)
        .unwrap_or_else(|refusal| panic!("source refused: {refusal}"))
        .into_document()
}

/// The first paragraph whose plain text equals `text`.
fn paragraph_with(document: &Document, text: &str) -> NodeId {
    document
        .preorder()
        .map(|(id, _)| id)
        .find(|id| {
            document
                .node(*id)
                .is_some_and(|node| node.kind().tag() == "paragraph")
                && fgit_doc::subtree_text(document, *id) == text
        })
        .unwrap_or_else(|| panic!("no paragraph with text {text:?}"))
}

fn anchor_on(document: &Document, text: &str, blob: &[u8]) -> Anchor {
    let node = paragraph_with(document, text);
    Anchor::create(
        document,
        node,
        SourceObjectId::new(blob).expect("source identity accepted"),
        Limits::DEFAULT,
    )
    .expect("anchor created")
}

#[test]
fn anchor_binds_source_profile_span_and_context() {
    let document = document_of("alpha\n\nbeta\n\ngamma\n");
    let anchor = anchor_on(&document, "beta", b"blob-a");
    assert_eq!(anchor.source().as_bytes(), b"blob-a");
    assert_eq!(anchor.profile(), document.profile());
    assert_eq!(document.text(anchor.span()), Some("beta"));
    assert_eq!(anchor.context().kind, "paragraph");
    assert_eq!(anchor.context().content.as_ref(), "beta");
    assert_eq!(anchor.context().prefix.as_ref(), "alpha");
    assert_eq!(anchor.context().suffix.as_ref(), "gamma");
    assert_eq!(anchor.context().occurrence, 0);
    assert_eq!(anchor.context().occurrence_total, 1);
    assert_eq!(anchor.context().path, vec![1]);
}

#[test]
fn identity_is_domain_separated_and_distinguishes_content() {
    let document = document_of("alpha\n\nbeta\n");
    let first = anchor_on(&document, "alpha", b"blob-a");
    let second = anchor_on(&document, "beta", b"blob-a");
    let domain = b"frankengit/doc-anchor/v1\0";
    assert!(
        first.id().canonical_bytes().starts_with(domain),
        "canonical bytes must begin with the anchor domain tag"
    );
    assert_ne!(first.id(), second.id());
    assert_eq!(
        first.id().to_hex().len(),
        first.id().canonical_bytes().len() * 2
    );
}

#[test]
fn identity_survives_an_edit_that_does_not_touch_the_anchored_text() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("alpha\n\nbeta\n\ngamma\n\ndelta appended later\n");
    let original = anchor_on(&before, "beta", b"blob-a");
    let recreated = anchor_on(&after, "beta", b"blob-b");
    assert_eq!(
        original.id(),
        recreated.id(),
        "an unrelated edit, and even a different source object, must not change the identity"
    );
}

#[test]
fn identity_survives_an_insertion_above_the_anchored_text() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("inserted first\n\nalpha\n\nbeta\n\ngamma\n");
    let original = anchor_on(&before, "beta", b"blob-a");
    let recreated = anchor_on(&after, "beta", b"blob-b");
    assert_eq!(original.id(), recreated.id());
}

#[test]
fn an_edit_below_the_anchor_leaves_it_exact() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("alpha\n\nbeta\n\ngamma rewritten entirely\n");
    let anchor = anchor_on(&before, "beta", b"blob-a");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Exact);
    assert_eq!(report.original_span(), anchor.span());
    let (_, span) = report.resolved().expect("an exact outcome attaches");
    assert_eq!(span, anchor.span());
}

#[test]
fn an_edit_above_the_anchor_remaps_it_and_keeps_the_original_span() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("inserted first\n\nalpha\n\nbeta\n\ngamma\n");
    let anchor = anchor_on(&before, "beta", b"blob-a");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Remapped);
    assert_eq!(
        report.original_span(),
        anchor.span(),
        "the original anchor is never rewritten"
    );
    let (node, span) = report.resolved().expect("a remap attaches");
    assert_ne!(span, anchor.span(), "the resolved span moved");
    assert_eq!(after.text(span), Some("beta"));
    assert_eq!(after.path_of(node), vec![2]);
}

#[test]
fn an_edit_inside_the_anchored_span_makes_it_outdated() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("alpha\n\nbeta rewritten\n\ngamma\n");
    let anchor = anchor_on(&before, "beta", b"blob-a");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Outdated);
    assert!(
        report.resolved().is_none(),
        "an outdated anchor never reattaches"
    );
    assert!(report.candidates().is_empty());
}

#[test]
fn indistinguishable_duplicates_are_ambiguous_and_reattach_nothing() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("alpha\n\nbeta\n\ngamma\n\nalpha\n\nbeta\n\ngamma\n");
    let anchor = anchor_on(&before, "beta", b"blob-a");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Ambiguous);
    assert!(
        report.resolved().is_none(),
        "ambiguity must never silently pick one"
    );
    assert_eq!(report.candidates().len(), 2);
}

#[test]
fn surrounding_context_disambiguates_duplicates_into_a_remap() {
    let before = document_of("alpha\n\nbeta\n\ngamma\n");
    let after = document_of("preface\n\nalpha\n\nbeta\n\ngamma\n\ndelta\n\nbeta\n\nepsilon\n");
    let anchor = anchor_on(&before, "beta", b"blob-a");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Remapped);
    assert_eq!(report.candidates().len(), 2);
    let (node, _) = report.resolved().expect("context picked one candidate");
    assert_eq!(
        after.path_of(node),
        vec![2],
        "the candidate between alpha and gamma is the one that matches"
    );
}

#[test]
fn a_stable_duplicate_population_resolves_by_recorded_occurrence() {
    // Both duplicates keep identical neighbours, so context cannot separate
    // them; the recorded occurrence index may only be used because the
    // population size is unchanged.
    let before = document_of("x\n\ndup\n\ny\n\nx\n\ndup\n\ny\n");
    let after = document_of("lead\n\nx\n\ndup\n\ny\n\nx\n\ndup\n\ny\n");
    let node = before
        .roots()
        .get(4)
        .copied()
        .expect("the second duplicate paragraph");
    assert_eq!(
        before.text(before.node(node).expect("node").span()),
        Some("dup")
    );
    let anchor = Anchor::create(
        &before,
        node,
        SourceObjectId::new(b"blob-a").expect("identity accepted"),
        Limits::DEFAULT,
    )
    .expect("anchor created");
    assert_eq!(anchor.context().occurrence, 1);
    assert_eq!(anchor.context().occurrence_total, 2);
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Remapped);
    let (resolved, _) = report.resolved().expect("occurrence picked one candidate");
    assert_eq!(after.path_of(resolved), vec![5]);
}

#[test]
fn a_changed_duplicate_population_refuses_to_guess() {
    let before = document_of("x\n\ndup\n\ny\n\nx\n\ndup\n\ny\n");
    let after = document_of("x\n\ndup\n\ny\n\nx\n\ndup\n\ny\n\nx\n\ndup\n\ny\n");
    let node = before.roots().get(4).copied().expect("second duplicate");
    let anchor = Anchor::create(
        &before,
        node,
        SourceObjectId::new(b"blob-a").expect("identity accepted"),
        Limits::DEFAULT,
    )
    .expect("anchor created");
    let report = anchor.remap(&after, Limits::DEFAULT).expect("remap runs");
    assert_eq!(report.outcome(), RemapOutcome::Ambiguous);
    assert!(report.resolved().is_none());
    assert_eq!(report.candidates().len(), 3);
}

#[test]
fn remapping_across_profiles_is_refused_but_the_same_profile_proceeds() {
    let source = "alpha\n\nbeta\n";
    let permitted = document_of(source);
    let anchor = anchor_on(&permitted, "beta", b"blob-a");
    let same_profile = anchor
        .remap(&permitted, Limits::DEFAULT)
        .expect("the permitted case proceeds");
    assert_eq!(same_profile.outcome(), RemapOutcome::Exact);

    let mut limits = Limits::DEFAULT;
    limits.structural = StructuralLimits {
        max_depth: 8,
        ..StructuralLimits::DEFAULT
    };
    let other = parse_with(source, fgit_doc::ParseProfile::with_limits(limits))
        .expect("the other profile parses")
        .into_document();
    let refusal = anchor
        .remap(&other, Limits::DEFAULT)
        .expect_err("a foreign profile is refused");
    assert_eq!(refusal.kind(), RefusalKind::ProfileMismatch);
}

#[test]
fn an_unknown_node_is_refused_and_a_known_node_proceeds() {
    let document = document_of("alpha\n");
    let known = document.roots().first().copied().expect("one root");
    Anchor::create(
        &document,
        known,
        SourceObjectId::new(b"blob").expect("identity accepted"),
        Limits::DEFAULT,
    )
    .expect("the permitted case proceeds");

    let stranger = document_of("a different document entirely\n\nwith more nodes\n\nand more\n");
    let missing = stranger
        .preorder()
        .map(|(id, _)| id)
        .last()
        .expect("a node that the first document does not have");
    assert!(
        document.node(missing).is_none(),
        "the test needs an identifier outside the first document"
    );
    let refusal = Anchor::create(
        &document,
        missing,
        SourceObjectId::new(b"blob").expect("identity accepted"),
        Limits::DEFAULT,
    )
    .expect_err("an unknown node is refused");
    assert_eq!(refusal.kind(), RefusalKind::UnknownNode);
}

#[test]
fn an_oversized_source_identity_is_refused_and_the_largest_accepted_one_is_not() {
    let permitted = vec![0x5a_u8; 64];
    SourceObjectId::new(&permitted).expect("sixty-four bytes are accepted");
    let refusal = SourceObjectId::new(&vec![0x5a_u8; 65]).expect_err("sixty-five are refused");
    assert_eq!(refusal.kind(), RefusalKind::SourceIdTooLong);
    assert_eq!(refusal.limit(), 64);
    assert_eq!(refusal.observed(), 65);
}

#[test]
fn long_content_records_its_full_length_so_a_prefix_cannot_impersonate_it() {
    let mut limits = Limits::DEFAULT;
    limits.max_anchor_context_bytes = 16;
    let long = "abcdefghijklmnopqrstuvwxyz0123456789";
    let short = "abcdefghijklmnopqrstuvwxyz";
    let first = document_of(&format!("{long}\n"));
    let second = document_of(&format!("{short}\n"));
    let anchor_long = Anchor::create(
        &first,
        first.roots()[0],
        SourceObjectId::new(b"a").expect("identity"),
        limits,
    )
    .expect("anchor created");
    let anchor_short = Anchor::create(
        &second,
        second.roots()[0],
        SourceObjectId::new(b"a").expect("identity"),
        limits,
    )
    .expect("anchor created");
    assert_eq!(anchor_long.context().content.as_ref(), &long[..16]);
    assert_eq!(
        anchor_long.context().content_bytes,
        u64::try_from(long.len()).expect("length fits")
    );
    assert_ne!(
        anchor_long.id(),
        anchor_short.id(),
        "two texts sharing a truncated prefix must not share an identity"
    );

    let report = anchor_long
        .remap(&second, limits)
        .expect("remap runs across the two documents");
    assert_eq!(
        report.outcome(),
        RemapOutcome::Outdated,
        "a shorter text with the same prefix is not the anchored text"
    );
}

#[test]
fn anchoring_works_for_every_block_kind_in_a_mixed_document() {
    let document =
        document_of("# Heading\n\npara\n\n> quoted\n\n- item\n\n```\ncode\n```\n\n---\n");
    let profile = default_profile();
    assert_eq!(document.profile(), profile.id());
    for root in document.roots() {
        let anchor = Anchor::create(
            &document,
            *root,
            SourceObjectId::new(b"blob").expect("identity accepted"),
            Limits::DEFAULT,
        )
        .expect("every block kind can be anchored");
        let report = anchor
            .remap(&document, Limits::DEFAULT)
            .expect("remap runs");
        assert_eq!(
            report.outcome(),
            RemapOutcome::Exact,
            "an unmodified document must resolve every anchor exactly ({})",
            anchor.context().kind
        );
    }
}

#[test]
fn the_preimage_domain_matches_the_identity_domain_the_types_crate_pins() {
    // Two crates spell this domain independently: fgit-doc stamps it into every
    // anchor preimage, and fgit-types pins it on the fixed-width identity. If
    // they ever drift, a digest taken over one crate's preimage would be
    // published under the other's domain, so the agreement is checked rather
    // than trusted.
    assert_eq!(
        fgit_doc::ANCHOR_PREIMAGE_DOMAIN,
        fgit_types::identity::DocumentAnchorId::DOMAIN
    );
    let document = document_of("alpha\n");
    let anchor = anchor_on(&document, "alpha", b"blob");
    let mut domain = fgit_doc::ANCHOR_PREIMAGE_DOMAIN.as_bytes().to_vec();
    domain.push(0);
    assert!(
        anchor.id().canonical_bytes().starts_with(&domain),
        "the preimage must carry the domain it claims"
    );
}

#[test]
fn a_digest_over_the_preimage_becomes_a_domain_pinned_identity() {
    // The seam this crate deliberately stops at: it produces the preimage, the
    // caller digests it, and the identity is stamped with one domain that no
    // consumer has to spell for itself.
    let document = document_of("alpha\n");
    let anchor = anchor_on(&document, "alpha", b"blob");
    let preimage = anchor.id().canonical_bytes();
    assert!(!preimage.is_empty());

    // A stand-in digest: this crate does not compute one, and the test must not
    // pretend otherwise. What is under test is the domain stamping, not the hash.
    let algorithm = fgit_types::hash::DigestAlgorithmId::try_new(1).expect("an algorithm slot");
    let digest = fgit_types::hash::DigestBytes::try_new(&[0x11_u8; 32]).expect("digest bytes");
    let codec = fgit_types::numeric::CodecVersion::new(1, 0);
    let identity = fgit_doc::document_anchor_id(algorithm, codec, digest);
    let internal = identity.as_internal_object_id();
    assert_eq!(internal.domain().as_str(), "frankengit/doc-anchor/v1");
    assert_eq!(internal.digest().as_bytes(), &[0x11_u8; 32]);
}
