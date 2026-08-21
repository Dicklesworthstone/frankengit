#![forbid(unsafe_code)]
//! One source-spanned document lineage for every `FrankenGit` surface.
//!
//! `fgit-doc` parses issue, review, release, wiki, and policy text once into a
//! single tree in which every node carries exact byte *and* codepoint spans
//! into the source it was parsed from. Human markup, a compact agent view, an
//! `API` representation, search text, and review anchors are all derived from
//! that one tree, so a source location cannot mean one thing in a browser and
//! another in an agent context packet.
//!
//! # Invariants this crate maintains
//!
//! These are invariant claims about the implementation, held by the crate's
//! integration suite. They are not proofs, and the cross-platform half of the
//! determinism claim is argued from the mechanism below rather than measured
//! on a second platform.
//!
//! - **Span fidelity.** A leaf node's span slices the source to exactly that
//!   leaf's text; a container's span is the exact source extent of the whole
//!   construct. Siblings never overlap and children are always contained in
//!   their parent. See [`ast`] for the full discipline.
//! - **Determinism.** Parsing and rendering are pure functions of the source
//!   bytes and the profile. No clock, filesystem, network, environment, hash
//!   iteration order, or floating point value participates.
//! - **Boundedness.** Every ceiling in [`limits::Limits`] is checked before the
//!   work it bounds. A breach is a [`limits::Refusal`] value, never a panic, a
//!   truncated document, or a silently degraded parse.
//! - **Safe by default.** Raw markup is captured and escaped, never passed
//!   through; link destinations are policy-checked at parse time so every
//!   surface makes the same decision; neutralisation is visible in the output.
//!
//! # What this crate does not do
//!
//! It performs no `I/O` and holds no ambient authority: the host supplies bytes
//! and ceilings. It does not fetch remote assets, resolve link references,
//! decode entity references, highlight syntax, or make any authorisation
//! decision. It does not implement a digest: an anchor produces canonical
//! *preimage* bytes, and a fixed-width identifier over those bytes belongs to
//! the crate that owns domain-separated digests.
//!
//! # Example
//!
//! ```
//! use fgit_doc::{Limits, RenderProfile, parse, render};
//!
//! let parsed = parse("# Title\n\nSome *text*.\n")?;
//! let html = render(parsed.document(), RenderProfile::HtmlSafe, Limits::DEFAULT)?;
//! assert_eq!(html.as_str(), "<h1>Title</h1>\n<p>Some <em>text</em>.</p>\n");
//! # Ok::<(), fgit_doc::Refusal>(())
//! ```

pub mod anchors;
pub mod ast;
pub mod batch;
pub mod diagnostic;
pub mod html;
pub mod limits;
pub mod parse;
pub mod profile;
pub mod render;
pub mod span;

mod block;
mod builder;
mod inline;
mod json;
mod url;

pub use anchors::{Anchor, AnchorId, RemapOutcome, RemapReport, SourceObjectId};
pub use ast::{Document, Node, NodeId, NodeKind};
pub use batch::{
    BatchInput, BatchPlan, BatchReceipt, InputOutcome, VarianceClass, WorkloadProfile,
    render_batch, worker_count,
};
pub use diagnostic::{Diagnostic, DiagnosticCode};
pub use limits::{Limits, Refusal, RefusalKind, StructuralLimits};
pub use parse::{ParseOutput, parse, parse_bytes, parse_with};
pub use profile::{ParseProfile, ProfileFamily, ProfileId};
pub use render::{RenderProfile, Rendered, render, subtree_text};
pub use span::{LineCol, Span};
