//! Cross-surface equivalence goldens.
//!
//! One frozen corpus, parsed **once** per document, with every surface pinned
//! byte for byte: the four render profiles, the AST shape listing, the anchor
//! table, and the anchor remap table against an edited sibling. A change to any
//! of these is a change in observable behaviour and must arrive as an explicit,
//! marked commit that says why — never as a regeneration to make a lane green.
//!
//! When a golden is missing or differs, the actual bytes are written under the
//! test target directory and the failure names the exact path, so promoting a
//! deliberate change is a copy rather than a guess.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_doc::ast::{Document, NodeId};
use fgit_doc::{
    Anchor, Limits, RemapOutcome, RenderProfile, SourceObjectId, parse, render, subtree_text,
};

fn goldens_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens")
}

fn actual_root() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("fgit-doc-goldens")
}

/// Corpus document identifiers, excluding the edited siblings.
fn corpus_ids() -> Vec<String> {
    let dir = goldens_root().join("corpus");
    let mut ids = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".mdin").map(str::to_owned))
        .filter(|name| !name.ends_with(".edited"))
        .collect::<Vec<_>>();
    ids.sort();
    assert!(!ids.is_empty(), "the golden corpus must not be empty");
    ids
}

fn read_corpus(id: &str) -> String {
    let path = goldens_root().join("corpus").join(format!("{id}.mdin"));
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn parse_corpus(id: &str) -> Document {
    parse(&read_corpus(id))
        .unwrap_or_else(|refusal| panic!("corpus document {id} was refused: {refusal}"))
        .into_document()
}

/// Escapes a value so one record always occupies one line.
fn field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        match value {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(value),
        }
    }
    out
}

/// The AST as a flat, readable, fully-spanned listing.
fn shape_listing(document: &Document) -> String {
    let mut out = String::from("depth\tkind\tbytes\tchars\tliteral\n");
    for (id, depth) in document.preorder() {
        let Some(node) = document.node(id) else {
            continue;
        };
        let span = node.span();
        let literal = if node.children().is_empty() {
            field(document.node_text(id).unwrap_or(""))
        } else {
            "-".to_owned()
        };
        writeln!(
            out,
            "{depth}\t{}\t{}..{}\t{}..{}\t{literal}",
            node.kind().tag(),
            span.byte_start(),
            span.byte_end(),
            span.char_start(),
            span.char_end()
        )
        .expect("writing to a String is infallible");
    }
    out
}

fn block_nodes(document: &Document) -> Vec<NodeId> {
    document
        .preorder()
        .map(|(id, _)| id)
        .filter(|id| {
            document
                .node(*id)
                .is_some_and(|node| node.kind().is_block())
        })
        .collect()
}

fn anchor_of(document: &Document, id: NodeId, blob: &[u8]) -> Anchor {
    Anchor::create(
        document,
        id,
        SourceObjectId::new(blob).expect("source identity accepted"),
        Limits::DEFAULT,
    )
    .expect("every block node can be anchored")
}

fn path_of(document: &Document, id: NodeId) -> String {
    document
        .path_of(id)
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The anchor table: every input the identity is derived from, pinned.
fn anchor_table(document: &Document, blob: &[u8]) -> String {
    let mut out = String::from(
        "path\tkind\tbytes\tchars\toccurrence\ttotal\tcontent_bytes\tcontent_chars\tid_bytes\tcontent\n",
    );
    for id in block_nodes(document) {
        let anchor = anchor_of(document, id, blob);
        let context = anchor.context();
        let span = anchor.span();
        writeln!(
            out,
            "{}\t{}\t{}..{}\t{}..{}\t{}\t{}\t{}\t{}\t{}\t{}",
            path_of(document, id),
            context.kind,
            span.byte_start(),
            span.byte_end(),
            span.char_start(),
            span.char_end(),
            context.occurrence,
            context.occurrence_total,
            context.content_bytes,
            context.content_chars,
            anchor.id().canonical_bytes().len(),
            field(&context.content)
        )
        .expect("writing to a String is infallible");
    }
    out
}

/// How every anchor of the base document resolves against an edited sibling.
fn remap_table(base: &Document, edited: &Document) -> String {
    let mut out = String::from("path\tkind\toutcome\tresolved\tcandidates\n");
    for id in block_nodes(base) {
        let anchor = anchor_of(base, id, b"base");
        let report = anchor
            .remap(edited, Limits::DEFAULT)
            .expect("the edited sibling shares the profile");
        let resolved = report.resolved().map_or_else(
            || "-".to_owned(),
            |(_, span)| format!("{}..{}", span.byte_start(), span.byte_end()),
        );
        writeln!(
            out,
            "{}\t{}\t{}\t{resolved}\t{}",
            path_of(base, id),
            anchor.context().kind,
            report.outcome().tag(),
            report.candidates().len()
        )
        .expect("writing to a String is infallible");
    }
    out
}

/// One golden that is absent or no longer matches.
struct Mismatch {
    relative: String,
    reason: &'static str,
    actual_path: PathBuf,
}

/// Compares one produced artifact against its golden, recording the actual bytes.
fn compare(relative: &str, actual: &str, found: &mut Vec<Mismatch>) {
    let golden = goldens_root().join(relative);
    let existing = fs::read_to_string(&golden).ok();
    if existing.as_deref() == Some(actual) {
        return;
    }
    let target = actual_root().join(relative);
    if let Some(parent) = target.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&target, actual);
    found.push(Mismatch {
        relative: relative.to_owned(),
        reason: if existing.is_none() {
            "missing"
        } else {
            "differs"
        },
        actual_path: target,
    });
}

const fn profile_extension(profile: RenderProfile) -> &'static str {
    match profile {
        RenderProfile::PlainText => "plain_text.txt",
        RenderProfile::HtmlSafe => "html_safe.html",
        RenderProfile::CompactMachine => "compact_machine.txt",
        RenderProfile::ApiJson => "api_json.json",
    }
}

#[test]
fn every_surface_matches_its_golden() {
    let mut found = Vec::new();
    for id in corpus_ids() {
        // Parse ONCE. Every surface below is derived from this one tree, which
        // is the property the whole golden set exists to pin.
        let document = parse_corpus(&id);
        for profile in RenderProfile::all() {
            let rendered = render(&document, profile, Limits::DEFAULT)
                .unwrap_or_else(|refusal| panic!("{id}/{}: {refusal}", profile.tag()));
            compare(
                &format!("surfaces/{id}.{}", profile_extension(profile)),
                rendered.as_str(),
                &mut found,
            );
        }
        compare(
            &format!("shape/{id}.shape.tsv"),
            &shape_listing(&document),
            &mut found,
        );
        compare(
            &format!("anchors/{id}.anchors.tsv"),
            &anchor_table(&document, id.as_bytes()),
            &mut found,
        );
        let edited_path = goldens_root()
            .join("corpus")
            .join(format!("{id}.edited.mdin"));
        if let Ok(edited_source) = fs::read_to_string(&edited_path) {
            let edited = parse(&edited_source)
                .unwrap_or_else(|refusal| panic!("{id}.edited was refused: {refusal}"))
                .into_document();
            compare(
                &format!("remap/{id}.remap.tsv"),
                &remap_table(&document, &edited),
                &mut found,
            );
        }
    }
    assert!(
        found.is_empty(),
        "{} golden artifact(s) are missing or changed.\n{}\n\
         Promoting these is a deliberate act: copy each actual over its golden \
         in a commit that states the semantic reason for the change. Never \
         regenerate goldens to make a lane green.",
        found.len(),
        found
            .iter()
            .map(|entry| format!(
                "  {} ({}) -> {}",
                entry.relative,
                entry.reason,
                entry.actual_path.display()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn no_render_surface_reparses_its_input() {
    // "Every surface derives from one AST" is a structural claim, so check it
    // structurally: a renderer that called back into the parser could not be
    // reading the caller's tree.
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in ["render.rs", "html.rs", "json.rs", "publication.rs"] {
        let path = source_dir.join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        for forbidden in ["parse_with(", "parse_bytes(", "crate::parse::"] {
            assert!(
                !text.contains(forbidden),
                "{name} reaches for {forbidden}; a render surface must consume the caller's tree"
            );
        }
    }
}

#[test]
fn the_api_and_shape_surfaces_report_the_same_spans() {
    // Two independently serialized artifacts, compared as multisets. A surface
    // that recomputed spans instead of reading the tree would diverge here.
    for id in corpus_ids() {
        let document = parse_corpus(&id);
        let json = render(&document, RenderProfile::ApiJson, Limits::DEFAULT)
            .expect("json render succeeds")
            .into_string();
        let shape = shape_listing(&document);

        let mut from_json: BTreeMap<(u32, u32), usize> = BTreeMap::new();
        for chunk in json.split("\"byte_start\":").skip(1) {
            let start = chunk
                .split(',')
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .expect("a byte_start value");
            let end = chunk
                .split("\"byte_end\":")
                .nth(1)
                .and_then(|rest| rest.split([',', '}']).next())
                .and_then(|value| value.parse::<u32>().ok())
                .expect("a byte_end value");
            *from_json.entry((start, end)).or_default() += 1;
        }

        let mut from_shape: BTreeMap<(u32, u32), usize> = BTreeMap::new();
        for line in shape.lines().skip(1) {
            let bytes = line.split('\t').nth(2).expect("a byte span column");
            let (start, end) = bytes.split_once("..").expect("a byte range");
            let pair = (
                start.parse::<u32>().expect("a start"),
                end.parse::<u32>().expect("an end"),
            );
            *from_shape.entry(pair).or_default() += 1;
        }

        assert_eq!(
            from_json, from_shape,
            "{id}: the api and shape surfaces disagree about spans"
        );
    }
}

#[test]
fn anchors_survive_an_edit_that_does_not_touch_them() {
    // 002-headings.edited inserts a paragraph near the top. Nothing else about
    // the anchored blocks changed, so every one of them must still resolve.
    let base = parse_corpus("002-headings");
    let edited_source = read_corpus("002-headings.edited");
    let edited = parse(&edited_source)
        .expect("the edited sibling parses")
        .into_document();
    let mut resolved = 0_usize;
    for id in block_nodes(&base) {
        let anchor = anchor_of(&base, id, b"base");
        let report = anchor
            .remap(&edited, Limits::DEFAULT)
            .expect("the sibling shares the profile");
        assert!(
            report.outcome().is_attached(),
            "an insertion elsewhere must not orphan the {} anchor, got {}",
            anchor.context().kind,
            report.outcome().tag()
        );
        assert_eq!(
            anchor_of(&edited, report.resolved().expect("attached").0, b"edited").id(),
            anchor.id(),
            "the identity must survive an unrelated edit"
        );
        resolved += 1;
    }
    assert!(resolved >= 4, "the fixture must exercise several anchors");
}

#[test]
fn an_edit_to_the_anchored_text_itself_is_reported_as_outdated() {
    // The paired counterpart: 012-mixed.edited rewrites the closing paragraph,
    // so that one anchor must NOT silently follow the change.
    let base = parse_corpus("012-mixed");
    let edited_source = read_corpus("012-mixed.edited");
    let edited = parse(&edited_source)
        .expect("the edited sibling parses")
        .into_document();
    let mut outdated = 0_usize;
    for id in block_nodes(&base) {
        let anchor = anchor_of(&base, id, b"base");
        let report = anchor
            .remap(&edited, Limits::DEFAULT)
            .expect("the sibling shares the profile");
        if report.outcome() == RemapOutcome::Outdated {
            outdated += 1;
            assert!(report.resolved().is_none());
            assert!(
                subtree_text(&base, id).contains("closing paragraph"),
                "only the rewritten block may go outdated"
            );
        }
    }
    assert_eq!(
        outdated, 1,
        "exactly the rewritten paragraph loses its anchor"
    );
}
