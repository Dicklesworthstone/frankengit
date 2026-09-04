//! Hidden-ref authorization for advertisement, want-validation, and disclosure.
//!
//! The [`UploadPackRepository`] super-type decides what exists; this module
//! decides what a fetch client may *see*.  A [`RefVisibility`] policy holds an
//! ordered list of hide/unhide rules with upstream `transfer.hideRefs`
//! semantics: each rule matches one ref name exactly or as a slash-bounded
//! prefix, the last matching rule wins, and names start hidden only when some
//! rule hides them.  [`VisibleUploadPackRepository`] wraps any repository and
//! enforces the policy at every disclosure seam the protocol machines consult:
//!
//! 1. `advertised_refs()` yields only visible refs, so v0/v1 want-validation
//!    rejects hidden-only tips with the same typed error an unknown object
//!    produces;
//! 2. `contains_want` refuses an object that is solely a hidden-ref tip even
//!    when an inner closure would admit it, so v2 cannot be used to probe
//!    hidden tips either;
//! 3. `is_common`, `resolve_ref`, `symref_target`, and `peeled` never answer
//!    for hidden-only identities, so negotiation acknowledgements and
//!    attribute lookups cannot confirm their existence.
//!
//! The refusal-indistinguishability invariant matters more than any single
//! mechanism: a client must not be able to distinguish "that ref is hidden"
//! from "that ref does not exist", because distinguishability is an oracle.
//! Every guard here therefore reuses the exact error variants and payloads
//! the unfiltered paths already produce for absent objects.

use std::collections::{BTreeMap, HashSet};

use crate::{AdvertisedRef, AnyGitOid, UploadPackRepository, WireError, WireLimits};

/// Ordered hide/unhide policy over fully qualified ref names.
///
/// With no rules every ref is visible.  Each rule is either a plain pattern
/// ("hide what matches") or a `!`-prefixed pattern ("unhide what matches").
/// A name is hidden exactly when the last matching rule is a hide rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RefVisibility {
    rules: Vec<VisibilityRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VisibilityRule {
    /// Validated ref-name-shaped pattern (leading `!` stripped).
    pattern: Vec<u8>,
    /// Whether matching names become visible again.
    negated: bool,
}

impl RefVisibility {
    /// Creates an empty policy under which every ref is visible.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Appends one hide (`!`-less) or unhide (`!`-prefixed) rule.
    ///
    /// The pattern after any `!` must be a valid ref name.  Matching is
    /// byte-exact or extends the pattern at a `/` boundary, so `refs/hidden`
    /// matches `refs/hidden/tip` but never `refs/hiddenx`.  Rule storage is
    /// bounded by `max_ref_prefixes` and each pattern by `max_ref_name_bytes`,
    /// mirroring the other bounded collections in this crate. A tighter limit
    /// on a later call refuses new rules without changing the existing policy.
    pub fn push_rule(&mut self, rule: &[u8], limits: &WireLimits) -> Result<(), WireError> {
        if self.rules.len() >= limits.max_ref_prefixes {
            return Err(WireError::TooManyObjectIds {
                field: "visibility rule",
                limit: limits.max_ref_prefixes,
            });
        }
        let (negated, pattern) = rule
            .strip_prefix(b"!")
            .map_or((false, rule), |rest| (true, rest));
        let pattern = crate::parse_ref_name(pattern, limits)?;
        self.rules.push(VisibilityRule { pattern, negated });
        Ok(())
    }

    /// Whether the policy hides `name`; the last matching rule wins.
    ///
    /// A peeled advertisement (`<ref>^{}`) is an attribute of its base ref,
    /// not a separate name that can escape an exact hide rule. Apply every
    /// hide/unhide rule to that base so both records receive one decision.
    #[must_use]
    pub fn hides(&self, name: &[u8]) -> bool {
        let name = name.strip_suffix(b"^{}").unwrap_or(name);
        let mut hidden = false;
        for rule in &self.rules {
            if Self::pattern_matches(&rule.pattern, name) {
                hidden = !rule.negated;
            }
        }
        hidden
    }

    /// Whether no rule has been configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn pattern_matches(pattern: &[u8], name: &[u8]) -> bool {
        if !name.starts_with(pattern) {
            return false;
        }
        // Byte-exact, or the extension crosses a `/` boundary so `refs/hidden`
        // matches `refs/hidden/tip` but never `refs/hiddenx`.
        name.len() == pattern.len() || name.get(pattern.len()) == Some(&b'/')
    }
}

/// Filters advertised refs down to the visible subset, preserving order.
///
/// This name-only filter also covers peeled records. It has no symbolic-ref
/// metadata: adapters that expose aliases or unborn `HEAD` must use
/// [`VisibleUploadPackRepository`] (or an equivalent authority-bound view)
/// before encoding, rather than treating name filtering as full authorization.
#[must_use]
pub fn filter_advertised_refs(
    refs: &[AdvertisedRef],
    visibility: &RefVisibility,
) -> Vec<AdvertisedRef> {
    refs.iter()
        .filter(|reference| !visibility.hides(&reference.name))
        .cloned()
        .collect()
}

/// A repository view that discloses only what the policy permits.
///
/// All protocol machines in this crate accept `&impl UploadPackRepository`;
/// handing them this wrapper makes hidden-ref authorization load-bearing at
/// advertisement, want-validation, and negotiation without modifying the
/// machines themselves.  The inner repository remains the authority for
/// object-existence facts (`contains_want` on interior objects); this view
/// only removes authority the policy withdraws.
#[derive(Clone, Debug)]
pub struct VisibleUploadPackRepository<'a, R: ?Sized + UploadPackRepository> {
    inner: &'a R,
    visible: Vec<AdvertisedRef>,
    /// Symbolic metadata selected with the same policy as `visible`.
    symref_targets: BTreeMap<Vec<u8>, Vec<u8>>,
    unborn_target: Option<Vec<u8>>,
    visible_tips: HashSet<AnyGitOid>,
    /// Tips reachable only through hidden refs; existence must stay deniable.
    hidden_only_tips: HashSet<AnyGitOid>,
}

impl<'a, R: ?Sized + UploadPackRepository> VisibleUploadPackRepository<'a, R> {
    /// Partitions the inner repository's refs through `visibility`.
    ///
    /// An object that is simultaneously a visible and a hidden tip stays
    /// disclosed: a client can obtain it through the visible path anyway, so
    /// refusing it would leak nothing while breaking legitimate fetches.
    ///
    /// A symbolic alias cannot disclose a hidden target, even through another
    /// advertised alias. Snapshot each alias edge once and propagate hiding
    /// backwards; every name enters the worklist at most once, including cycles.
    /// Peeled records depend on their base names in the same graph. Both passes
    /// use one advertised slice, so policy analysis and output cannot mix ref
    /// snapshots. Output retains that slice's order, not map or worklist order.
    pub fn new(inner: &'a R, visibility: &RefVisibility) -> Self {
        let advertised = inner.advertised_refs();
        let mut targets = BTreeMap::new();
        let mut dependents: BTreeMap<&[u8], Vec<&[u8]>> = BTreeMap::new();
        let mut hidden_names: HashSet<&[u8]> = HashSet::new();
        let mut pending = Vec::new();
        for reference in advertised {
            let name = reference.name.as_slice();
            if visibility.hides(name) && hidden_names.insert(name) {
                pending.push(name);
            }
            // A peeled record inherits hiding through aliases as well as
            // direct policy rules. Otherwise a hidden symbolic tag could
            // leave its derived record and peeled identity in the visible set.
            if let Some(base) = name.strip_suffix(b"^{}") {
                dependents.entry(base).or_default().push(name);
            }
            if let Some(target) = inner.symref_target(name) {
                targets.insert(name, target);
                dependents.entry(target).or_default().push(name);
                if visibility.hides(target) && hidden_names.insert(target) {
                    pending.push(target);
                }
            }
        }
        while let Some(hidden) = pending.pop() {
            if let Some(aliases) = dependents.get(hidden) {
                for &alias in aliases {
                    if hidden_names.insert(alias) {
                        pending.push(alias);
                    }
                }
            }
        }
        let symref_targets = targets
            .into_iter()
            .filter(|(name, _)| !hidden_names.contains(*name))
            .map(|(name, target)| (name.to_vec(), target.to_vec()))
            .collect();
        // Never infer unbornness from an empty filtered advertisement. Only
        // the canonical inner snapshot may supply an unborn target.
        let unborn_target = inner
            .unborn_symref_target()
            .filter(|target| {
                !visibility.hides(b"HEAD")
                    && !visibility.hides(target)
                    && !hidden_names.contains(b"HEAD".as_slice())
                    && !hidden_names.contains(*target)
            })
            .map(|target| target.to_vec());
        let mut visible = Vec::new();
        let mut visible_tips = HashSet::new();
        let mut hidden_tips = HashSet::new();
        for reference in advertised {
            if hidden_names.contains(reference.name.as_slice()) {
                hidden_tips.insert(reference.oid);
            } else {
                visible_tips.insert(reference.oid);
                visible.push(reference.clone());
            }
        }
        hidden_tips.retain(|oid| !visible_tips.contains(oid));
        Self {
            inner,
            visible,
            symref_targets,
            unborn_target,
            visible_tips,
            hidden_only_tips: hidden_tips,
        }
    }

    /// Whether this view may acknowledge or resolve `oid` at all.
    fn disclosable(&self, oid: AnyGitOid) -> bool {
        !self.hidden_only_tips.contains(&oid) || self.visible_tips.contains(&oid)
    }

    fn visible_ref(&self, name: &[u8]) -> Option<&AdvertisedRef> {
        self.visible.iter().find(|reference| reference.name == name)
    }
}

impl<R: ?Sized + UploadPackRepository> UploadPackRepository for VisibleUploadPackRepository<'_, R> {
    fn object_format(&self) -> crate::GitObjectFormat {
        self.inner.object_format()
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.visible
    }

    fn contains_want(&self, oid: AnyGitOid) -> bool {
        self.disclosable(oid) && self.inner.contains_want(oid)
    }

    fn is_common(&self, oid: AnyGitOid) -> bool {
        self.disclosable(oid) && self.inner.is_common(oid)
    }

    fn resolve_ref(&self, name: &[u8]) -> Option<AnyGitOid> {
        self.visible_ref(name).map(|reference| reference.oid)
    }

    fn symref_target(&self, name: &[u8]) -> Option<&[u8]> {
        self.symref_targets.get(name).map(Vec::as_slice)
    }

    fn unborn_symref_target(&self) -> Option<&[u8]> {
        self.unborn_target.as_deref()
    }

    fn peeled(&self, oid: AnyGitOid) -> Option<AnyGitOid> {
        if self.visible_tips.contains(&oid) {
            self.inner.peeled(oid)
        } else {
            None
        }
    }
}
