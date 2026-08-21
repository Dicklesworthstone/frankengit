//! Review anchors and their remap outcomes.
//!
//! An anchor binds a piece of reviewed text to the source object, parse
//! profile, comparison basis, byte and codepoint span, structural path, and
//! surrounding context that identified it. Re-resolving an anchor against a later version of the
//! same document produces one of four explicit outcomes and never silently
//! attaches a comment to different text because a heuristic found something
//! similar.
//!
//! # Identity
//!
//! [`AnchorId`] is not a digest. It is the **canonical preimage**: a
//! domain-separated, length-prefixed byte string over the parse profile, the
//! node kind, the normalised anchored text (with its full length, so a
//! truncated context cannot masquerade as a complete one), and the occurrence
//! index that distinguishes otherwise identical text in the same document.
//! Because the encoding is injective, equality of identifiers is equality of
//! those fields; no hash function is involved and this crate deliberately does
//! not implement one. A fixed-width identifier is obtained by applying the
//! domain-separated digest owned by the crypto crate to
//! [`AnchorId::canonical_bytes`].
//!
//! The identity deliberately excludes the source object, the comparison basis,
//! the span, and the structural path, so an edit elsewhere in the document
//! leaves it unchanged. Those bindings live on the [`Anchor`] itself, where
//! remapping can compare them.

use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::DocumentAnchorId;
use fgit_types::numeric::CodecVersion;

use crate::ast::{Document, NodeId};
use crate::basis::AnchorBasis;
use crate::limits::{Limits, Refusal, RefusalKind, as_u64, offset_u32, usize_of};
use crate::profile::ProfileId;
use crate::render::{hex_digit, normalize_text, subtree_text};
use crate::span::Span;

/// Longest host-supplied source object identity this crate stores.
const MAX_SOURCE_ID_BYTES: usize = 64;

/// Domain tag prefixed to every canonical anchor encoding.
///
/// The tag matches the domain requested from the types crate for the
/// fixed-width `DocumentAnchorId` that a digest over
/// [`AnchorId::canonical_bytes`] produces, so the preimage this crate emits and
/// the identifier another crate derives from it agree on one domain.
pub const ANCHOR_PREIMAGE_DOMAIN: &str = "frankengit/doc-anchor/v1";

/// Domain tag prefixed to every canonical anchor encoding.
const ANCHOR_DOMAIN: &[u8] = b"frankengit/doc-anchor/v1\0";

/// Binds a digest of an anchor preimage to the document-anchor identity domain.
///
/// The caller computes `digest` over [`AnchorId::canonical_bytes`] using the
/// crate that owns domain-separated digests. This crate implements no digest and
/// will not: an identity function belongs with the registry that governs its
/// algorithms. What this function removes is the last reason for a consumer to
/// spell the domain itself, which is exactly how two schemas end up sharing a
/// tag and one body's digest becomes readable as another's identity.
#[must_use]
pub const fn document_anchor_id(
    algorithm: DigestAlgorithmId,
    codec_version: CodecVersion,
    digest: DigestBytes,
) -> DocumentAnchorId {
    DocumentAnchorId::from_digest(algorithm, codec_version, digest)
}

/// An opaque host-supplied identity for the object the source came from.
///
/// This crate never interprets the bytes. The host supplies whatever identity
/// its object model uses, and the anchor carries it unchanged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceObjectId(Box<[u8]>);

impl SourceObjectId {
    /// Records a host-supplied identity, refusing one that is too long.
    pub fn new(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_SOURCE_ID_BYTES {
            return Err(Refusal::exceeded(
                RefusalKind::SourceIdTooLong,
                as_u64(MAX_SOURCE_ID_BYTES),
                as_u64(bytes.len()),
            ));
        }
        Ok(Self(Box::from(bytes)))
    }

    /// The recorded identity bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The canonical preimage identifying an anchor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorId(Box<[u8]>);

impl AnchorId {
    /// The canonical, injective encoding of this identity.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lowercase hexadecimal rendering, for logs and receipts.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.0.len() * 2);
        for byte in self.0.iter() {
            let value = u32::from(*byte);
            out.push(hex_digit(value >> 4));
            out.push(hex_digit(value));
        }
        out
    }
}

/// Everything an anchor remembers about the text it identifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorContext {
    /// Structural path from the document root: child indices.
    pub path: Vec<u32>,
    /// Stable tag of the anchored node's kind.
    pub kind: &'static str,
    /// Normalised anchored text, truncated to the configured context budget.
    pub content: Box<str>,
    /// Byte length of the untruncated normalised text.
    pub content_bytes: u64,
    /// Codepoint length of the untruncated normalised text.
    pub content_chars: u64,
    /// Normalised text of the preceding sibling, truncated.
    pub prefix: Box<str>,
    /// Normalised text of the following sibling, truncated.
    pub suffix: Box<str>,
    /// Index of this node among identically keyed nodes in the source document.
    pub occurrence: u32,
    /// How many identically keyed nodes the source document contained.
    pub occurrence_total: u32,
}

/// A review anchor: reviewed text bound to where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    source: SourceObjectId,
    profile: ProfileId,
    basis: AnchorBasis,
    span: Span,
    node: NodeId,
    context: AnchorContext,
    id: AnchorId,
}

/// How an anchor resolved against a later document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemapOutcome {
    /// The anchored text is unchanged and still occupies the same span and path.
    Exact,
    /// The anchored text was found once, at a new span or path.
    Remapped,
    /// Several indistinguishable candidates exist; nothing is reattached.
    Ambiguous,
    /// The anchored text is gone; nothing is reattached.
    Outdated,
}

impl RemapOutcome {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Remapped => "remapped",
            Self::Ambiguous => "ambiguous",
            Self::Outdated => "outdated",
        }
    }

    /// Whether this outcome attaches the anchor to a node in the new document.
    #[must_use]
    pub const fn is_attached(self) -> bool {
        matches!(self, Self::Exact | Self::Remapped)
    }
}

/// The result of remapping one anchor onto one document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemapReport {
    outcome: RemapOutcome,
    original: Span,
    resolved: Option<(NodeId, Span)>,
    candidates: Vec<(NodeId, Span)>,
    basis_advanced: bool,
}

impl RemapReport {
    /// Which of the four outcomes occurred.
    #[must_use]
    pub const fn outcome(&self) -> RemapOutcome {
        self.outcome
    }

    /// The span the anchor was created against; it is never rewritten.
    #[must_use]
    pub const fn original_span(&self) -> Span {
        self.original
    }

    /// Where the anchor now points, for an attached outcome only.
    #[must_use]
    pub const fn resolved(&self) -> Option<(NodeId, Span)> {
        self.resolved
    }

    /// Every candidate considered, in document order.
    #[must_use]
    pub fn candidates(&self) -> &[(NodeId, Span)] {
        &self.candidates
    }

    /// Whether the target was the same side of a comparison against a
    /// different version than the anchor was created against.
    ///
    /// An outcome of [`RemapOutcome::Exact`] with this set means the reviewed
    /// text survived the version change untouched; it does not mean nothing
    /// about the comparison changed.
    #[must_use]
    pub const fn basis_advanced(&self) -> bool {
        self.basis_advanced
    }
}

/// The comparable identity of one node's anchored text.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ContentKey {
    kind: &'static str,
    content: String,
    content_bytes: u64,
    content_chars: u64,
}

impl Anchor {
    /// Creates an anchor for one node of a parsed document.
    pub fn create(
        document: &Document,
        node: NodeId,
        source: SourceObjectId,
        basis: AnchorBasis,
        limits: Limits,
    ) -> Result<Self, Refusal> {
        let Some(entry) = document.node(node) else {
            return Err(Refusal::precondition(RefusalKind::UnknownNode));
        };
        let budget = usize_of(limits.max_anchor_context_bytes);
        let key = content_key(document, node, budget);
        let matches = collect_keyed(document, &key, budget);
        let occurrence = matches
            .iter()
            .position(|(candidate, _)| *candidate == node)
            .map_or(0, offset_u32);
        let (prefix, suffix) = sibling_context(document, node, budget);
        let context = AnchorContext {
            path: document.path_of(node),
            kind: key.kind,
            content: Box::from(key.content.as_str()),
            content_bytes: key.content_bytes,
            content_chars: key.content_chars,
            prefix: Box::from(prefix.as_str()),
            suffix: Box::from(suffix.as_str()),
            occurrence,
            occurrence_total: offset_u32(matches.len()),
        };
        let id = derive_id(document.profile(), &context);
        Ok(Self {
            source,
            profile: document.profile(),
            basis,
            span: entry.span(),
            node,
            context,
            id,
        })
    }

    /// The anchor's stable identity.
    #[must_use]
    pub const fn id(&self) -> &AnchorId {
        &self.id
    }

    /// The source object the anchor was created against.
    #[must_use]
    pub const fn source(&self) -> &SourceObjectId {
        &self.source
    }

    /// The parse profile the anchor was created under.
    #[must_use]
    pub const fn profile(&self) -> ProfileId {
        self.profile
    }

    /// The presentation the anchor was created against.
    #[must_use]
    pub const fn basis(&self) -> &AnchorBasis {
        &self.basis
    }

    /// The span the anchor was created against.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// The node the anchor was created against.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Everything the anchor remembers about the text it identifies.
    #[must_use]
    pub const fn context(&self) -> &AnchorContext {
        &self.context
    }

    /// Resolves this anchor against a document parsed by the same profile.
    ///
    /// The precedence is fixed and documented, so the outcome is a function of
    /// the two documents alone:
    ///
    /// 1. no candidate with the same content key exists: [`RemapOutcome::Outdated`];
    /// 2. exactly one candidate: [`RemapOutcome::Exact`] if its span and path
    ///    are unchanged, otherwise [`RemapOutcome::Remapped`];
    /// 3. several candidates, exactly one of which has the same preceding and
    ///    following sibling context: that one, by the rule in step two;
    /// 4. several candidates and the population is the same size as when the
    ///    anchor was created: the candidate at the recorded occurrence index,
    ///    by the rule in step two;
    /// 5. otherwise: [`RemapOutcome::Ambiguous`], attaching nothing.
    ///
    /// `basis` is the presentation `document` represents. A basis that is not
    /// comparable with the one the anchor was created against is refused
    /// before any candidate is considered, because the four outcomes above
    /// describe one reviewed location moving within one presentation. The same
    /// side of a comparison against a newer version IS comparable -- that is a
    /// branch advancing -- and the report records it through
    /// [`RemapReport::basis_advanced`].
    pub fn remap(
        &self,
        document: &Document,
        basis: &AnchorBasis,
        limits: Limits,
    ) -> Result<RemapReport, Refusal> {
        if document.profile() != self.profile {
            return Err(Refusal::precondition(RefusalKind::ProfileMismatch));
        }
        if !self.basis.is_comparable_to(basis) {
            return Err(Refusal::precondition(RefusalKind::BasisMismatch));
        }
        let advanced = self.basis.advances_to(basis);
        let budget = usize_of(limits.max_anchor_context_bytes);
        let key = ContentKey {
            kind: self.context.kind,
            content: self.context.content.to_string(),
            content_bytes: self.context.content_bytes,
            content_chars: self.context.content_chars,
        };
        let candidates = collect_keyed(document, &key, budget);
        if candidates.is_empty() {
            return Ok(RemapReport {
                outcome: RemapOutcome::Outdated,
                original: self.span,
                resolved: None,
                candidates: Vec::new(),
                basis_advanced: advanced,
            });
        }
        if let [only] = candidates.as_slice() {
            return Ok(self.attach(*only, &candidates, document, advanced));
        }
        let contextual = candidates
            .iter()
            .filter(|(candidate, _)| {
                let (prefix, suffix) = sibling_context(document, *candidate, budget);
                prefix.as_str() == self.context.prefix.as_ref()
                    && suffix.as_str() == self.context.suffix.as_ref()
            })
            .copied()
            .collect::<Vec<_>>();
        if let [only] = contextual.as_slice() {
            return Ok(self.attach(*only, &candidates, document, advanced));
        }
        if offset_u32(candidates.len()) == self.context.occurrence_total
            && let Some(entry) = candidates.get(usize_of(self.context.occurrence))
        {
            return Ok(self.attach(*entry, &candidates, document, advanced));
        }
        Ok(RemapReport {
            outcome: RemapOutcome::Ambiguous,
            original: self.span,
            resolved: None,
            candidates,
            basis_advanced: advanced,
        })
    }

    fn attach(
        &self,
        entry: (NodeId, Span),
        candidates: &[(NodeId, Span)],
        document: &Document,
        basis_advanced: bool,
    ) -> RemapReport {
        let (node, span) = entry;
        let same_place = span == self.span && document.path_of(node) == self.context.path;
        RemapReport {
            outcome: if same_place {
                RemapOutcome::Exact
            } else {
                RemapOutcome::Remapped
            },
            original: self.span,
            resolved: Some(entry),
            candidates: candidates.to_vec(),
            basis_advanced,
        }
    }
}

/// Derives the canonical anchor identity from the profile and context.
fn derive_id(profile: ProfileId, context: &AnchorContext) -> AnchorId {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(ANCHOR_DOMAIN);
    push_field(&mut out, &profile.canonical_bytes());
    push_field(&mut out, context.kind.as_bytes());
    out.extend_from_slice(&context.content_bytes.to_be_bytes());
    out.extend_from_slice(&context.content_chars.to_be_bytes());
    push_field(&mut out, context.content.as_bytes());
    out.extend_from_slice(&context.occurrence.to_be_bytes());
    AnchorId(out.into_boxed_slice())
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&as_u64(field.len()).to_be_bytes());
    out.extend_from_slice(field);
}

/// Truncates normalised text to a byte budget, on a character boundary.
fn truncate(text: &str, budget: usize) -> &str {
    if text.len() <= budget {
        return text;
    }
    let mut end = budget;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

fn content_key(document: &Document, node: NodeId, budget: usize) -> ContentKey {
    let normalized = normalize_text(&subtree_text(document, node));
    let kind = document
        .node(node)
        .map_or("unknown", |entry| entry.kind().tag());
    ContentKey {
        kind,
        content: truncate(&normalized, budget).to_owned(),
        content_bytes: as_u64(normalized.len()),
        content_chars: as_u64(normalized.chars().count()),
    }
}

/// Every node whose content key equals `key`, in document order.
fn collect_keyed(document: &Document, key: &ContentKey, budget: usize) -> Vec<(NodeId, Span)> {
    let mut found = Vec::new();
    for (id, _) in document.preorder() {
        let Some(entry) = document.node(id) else {
            continue;
        };
        if entry.kind().tag() != key.kind {
            continue;
        }
        let candidate = content_key(document, id, budget);
        if candidate == *key {
            found.push((id, entry.span()));
        }
    }
    found
}

/// Normalised, truncated text of the preceding and following siblings.
fn sibling_context(document: &Document, node: NodeId, budget: usize) -> (String, String) {
    let Some(entry) = document.node(node) else {
        return (String::new(), String::new());
    };
    let siblings = entry.parent().map_or_else(
        || document.roots().to_vec(),
        |parent| {
            document
                .node(parent)
                .map(|value| value.children().to_vec())
                .unwrap_or_default()
        },
    );
    let Some(position) = siblings.iter().position(|entry| *entry == node) else {
        return (String::new(), String::new());
    };
    let before = position
        .checked_sub(1)
        .and_then(|index| siblings.get(index))
        .map(|id| normalize_text(&subtree_text(document, *id)))
        .unwrap_or_default();
    let after = siblings
        .get(position.saturating_add(1))
        .map(|id| normalize_text(&subtree_text(document, *id)))
        .unwrap_or_default();
    (
        truncate(&before, budget).to_owned(),
        truncate(&after, budget).to_owned(),
    )
}
