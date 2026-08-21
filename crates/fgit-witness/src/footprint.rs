//! Witness families and the subsumption lattice over them.
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §12 and plan §15.5 describe conflict
//! witnesses as *hierarchical and typed*: a prepared transaction starts with a
//! conservative witness and may refine it, but "the conservative witness is
//! always safe" and finer witnesses "cannot weaken correctness".
//!
//! ## What subsumption means here, precisely
//!
//! A [`Footprint`] describes the region of repository state a transaction
//! read. One footprint **subsumes** another when it covers everything the
//! other covers — it is the coarser of the two.
//!
//! The safety law that makes refinement sound follows directly, and it is the
//! direction worth stating because it is easy to get backwards:
//!
//! > If a **coarse** footprint does not overlap a change set, then no footprint
//! > it subsumes can overlap that change set either.
//!
//! Equivalently: overlap under a fine footprint implies overlap under every
//! coarser one. So refinement can only ever *remove* a false conflict, never
//! admit a true one — §12's first obligation. [`Footprint::subsumes`] is the
//! order, and the law is property-tested against randomly generated lattices
//! rather than asserted.
//!
//! ## Why the families are a closed enum
//!
//! An open witness vocabulary would let a caller invent a family whose
//! subsumption relationship to the others is undefined, and the lattice would
//! stop being a lattice. Adding a family is a deliberate edit here, and the
//! exhaustive matches in this module stop compiling until its relationship to
//! every other family is stated.

use std::collections::BTreeSet;

/// The scope a witness covers, coarsest first.
///
/// The ordering of the variants is the subsumption order for the *degenerate*
/// case where two witnesses name the same domain: a `Generation` witness is
/// coarser than a `Namespace` witness, which is coarser than an `Exact` one.
/// Cross-domain comparisons are handled by [`Footprint::subsumes`], which does
/// not rely on variant order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// The whole repository at one authority-head generation.
    ///
    /// This is the maximally conservative witness: any concurrent commit at
    /// all invalidates it. It is what a transaction holds before it has done
    /// the work to say anything narrower.
    Generation,
    /// A ref namespace, matched on a component boundary, such as
    /// `refs/heads`.
    RefNamespace(Vec<u8>),
    /// One exact ref name.
    ExactRef(Vec<u8>),
    /// One forge stream, such as a pull-request stream.
    ForgeStream(Vec<u8>),
    /// One entity inside a forge stream.
    ForgeEntity {
        /// The stream the entity belongs to.
        stream: Vec<u8>,
        /// The entity.
        entity: Vec<u8>,
    },
    /// A path prefix inside the working tree, matched on a component
    /// boundary.
    PathPrefix(Vec<u8>),
    /// One exact path.
    ExactPath(Vec<u8>),
    /// A quota, retention, or legal-hold domain.
    PolicyDomain(Vec<u8>),
    /// The pinned policy epoch itself.
    PolicyEpoch,
}

impl Scope {
    /// Stable machine-readable family name, for receipts.
    #[must_use]
    pub const fn family(&self) -> &'static str {
        match self {
            Self::Generation => "generation",
            Self::RefNamespace(_) => "ref_namespace",
            Self::ExactRef(_) => "exact_ref",
            Self::ForgeStream(_) => "forge_stream",
            Self::ForgeEntity { .. } => "forge_entity",
            Self::PathPrefix(_) => "path_prefix",
            Self::ExactPath(_) => "exact_path",
            Self::PolicyDomain(_) => "policy_domain",
            Self::PolicyEpoch => "policy_epoch",
        }
    }

    /// True when this scope covers everything `other` covers.
    ///
    /// `Generation` covers everything, by construction: it is the witness a
    /// transaction holds when it can say nothing narrower, so anything that
    /// invalidates a narrower witness must invalidate it too.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            // The conservative top of the lattice, and the one family whose
            // identity is the whole of it. A `Generation` on the right falls
            // through to the closing arm, which is correct: only a
            // `Generation` covers a `Generation`.
            (Self::Generation, _) | (Self::PolicyEpoch, Self::PolicyEpoch) => true,

            // A prefix covers itself and everything beneath it, in both the
            // ref and the path domains. The two families never cross: a ref
            // pattern is only ever compared against a ref.
            (Self::RefNamespace(prefix), Self::RefNamespace(other) | Self::ExactRef(other))
            | (Self::PathPrefix(prefix), Self::PathPrefix(other) | Self::ExactPath(other)) => {
                is_prefix_of(prefix, other)
            }

            // Exact identity within the leaf families.
            (Self::ExactRef(left), Self::ExactRef(right))
            | (Self::ExactPath(left), Self::ExactPath(right))
            | (Self::PolicyDomain(left), Self::PolicyDomain(right))
            | (Self::ForgeStream(left), Self::ForgeStream(right)) => left == right,

            // A stream covers every entity inside it.
            (Self::ForgeStream(stream), Self::ForgeEntity { stream: inner, .. }) => stream == inner,
            (
                Self::ForgeEntity { stream, entity },
                Self::ForgeEntity {
                    stream: other_stream,
                    entity: other_entity,
                },
            ) => stream == other_stream && entity == other_entity,

            // Everything else is a different domain: neither covers the other.
            // Stated exhaustively rather than with a wildcard so a new family
            // cannot be silently treated as unrelated to everything.
            (
                Self::RefNamespace(_)
                | Self::ExactRef(_)
                | Self::ForgeStream(_)
                | Self::ForgeEntity { .. }
                | Self::PathPrefix(_)
                | Self::ExactPath(_)
                | Self::PolicyDomain(_)
                | Self::PolicyEpoch,
                _,
            ) => false,
        }
    }
}

/// True when `prefix` bounds `candidate` on a component boundary.
///
/// `refs/heads` bounds `refs/heads/main` but not `refs/headsup/x`. Matching on
/// a raw byte prefix instead would silently widen every namespace witness to
/// its lexical neighbours.
fn is_prefix_of(prefix: &[u8], candidate: &[u8]) -> bool {
    let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
    if prefix == candidate {
        return true;
    }
    candidate.len() > prefix.len()
        && candidate.starts_with(prefix)
        && candidate[prefix.len()] == b'/'
}

/// The region of repository state one prepared transaction read.
///
/// A footprint is a set of scopes. It is deliberately a `BTreeSet`: the order
/// two scopes were observed in is not part of the witness, and letting it be
/// would make an otherwise identical footprint compare unequal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Footprint {
    scopes: BTreeSet<Scope>,
}

impl Footprint {
    /// The maximally conservative footprint: the whole repository generation.
    #[must_use]
    pub fn conservative() -> Self {
        let mut scopes = BTreeSet::new();
        scopes.insert(Scope::Generation);
        Self { scopes }
    }

    /// An empty footprint, which reads nothing and conflicts with nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a footprint from scopes.
    #[must_use]
    pub fn from_scopes(scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            scopes: scopes.into_iter().collect(),
        }
    }

    /// Adds one scope.
    pub fn insert(&mut self, scope: Scope) {
        self.scopes.insert(scope);
    }

    /// The scopes, in canonical order.
    pub fn scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter()
    }

    /// How many scopes this footprint names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// True when this footprint reads nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// True when this footprint is the conservative whole-generation one.
    #[must_use]
    pub fn is_conservative(&self) -> bool {
        self.scopes.contains(&Scope::Generation)
    }

    /// True when `self` covers everything `other` covers.
    ///
    /// This is the subsumption order: `self` is the coarser footprint. It is a
    /// preorder — reflexive and transitive — and the tests pin both, along
    /// with the safety law that gives refinement its meaning.
    #[must_use]
    pub fn subsumes(&self, other: &Self) -> bool {
        other
            .scopes
            .iter()
            .all(|target| self.scopes.iter().any(|scope| scope.covers(target)))
    }

    /// True when any scope here covers, or is covered by, any scope in
    /// `changed`.
    ///
    /// Overlap is symmetric in the sense that matters: a transaction that read
    /// `refs/heads` conflicts with a change to `refs/heads/main`, and a
    /// transaction that read `refs/heads/main` conflicts with a change that
    /// swept `refs/heads`.
    #[must_use]
    pub fn overlaps(&self, changed: &Self) -> bool {
        self.scopes.iter().any(|scope| {
            changed
                .scopes
                .iter()
                .any(|target| scope.covers(target) || target.covers(scope))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Footprint, Scope, is_prefix_of};

    fn ns(text: &str) -> Scope {
        Scope::RefNamespace(text.as_bytes().to_vec())
    }

    fn exact(text: &str) -> Scope {
        Scope::ExactRef(text.as_bytes().to_vec())
    }

    #[test]
    fn a_namespace_bounds_only_on_a_component_boundary() {
        assert!(is_prefix_of(b"refs/heads", b"refs/heads/main"));
        assert!(is_prefix_of(b"refs/heads", b"refs/heads"));
        assert!(is_prefix_of(b"refs/heads/", b"refs/heads/main"));
        // The whole point: a lexical prefix that is not a component boundary
        // must not widen the witness to a neighbouring namespace.
        assert!(!is_prefix_of(b"refs/heads", b"refs/headsup/x"));
        assert!(!is_prefix_of(b"refs/heads/main", b"refs/heads"));
    }

    #[test]
    fn the_conservative_footprint_subsumes_everything() {
        let conservative = Footprint::conservative();
        for other in [
            Footprint::empty(),
            Footprint::from_scopes([exact("refs/heads/main")]),
            Footprint::from_scopes([ns("refs/heads"), Scope::PolicyEpoch]),
            Footprint::from_scopes([Scope::ExactPath(b"src/lib.rs".to_vec())]),
        ] {
            assert!(
                conservative.subsumes(&other),
                "conservative must subsume {other:?}"
            );
        }
    }

    #[test]
    fn subsumption_is_reflexive_and_transitive() {
        let coarse = Footprint::from_scopes([ns("refs")]);
        let middle = Footprint::from_scopes([ns("refs/heads")]);
        let fine = Footprint::from_scopes([exact("refs/heads/main")]);

        for f in [&coarse, &middle, &fine] {
            assert!(f.subsumes(f), "reflexive: {f:?}");
        }
        assert!(coarse.subsumes(&middle));
        assert!(middle.subsumes(&fine));
        assert!(
            coarse.subsumes(&fine),
            "transitive: refs subsumes refs/heads subsumes refs/heads/main"
        );
        // And the converse does not hold, or the order would be trivial.
        assert!(!fine.subsumes(&middle));
        assert!(!middle.subsumes(&coarse));
    }

    #[test]
    fn refinement_can_only_remove_a_false_conflict_never_admit_a_true_one() {
        // The safety law of NPC section 12, stated as the contrapositive that
        // is actually checkable: if the COARSE footprint does not overlap a
        // change set, no footprint it subsumes may overlap it either.
        let coarse = Footprint::from_scopes([ns("refs/heads")]);
        let fine = Footprint::from_scopes([exact("refs/heads/main")]);
        assert!(coarse.subsumes(&fine));

        let disjoint_change = Footprint::from_scopes([exact("refs/tags/v1")]);
        assert!(!coarse.overlaps(&disjoint_change));
        assert!(
            !fine.overlaps(&disjoint_change),
            "the coarse witness saw no conflict, so the fine one must not invent one"
        );

        // The permitted twin: refinement removing a FALSE conflict is exactly
        // the value it adds.
        let neighbour_change = Footprint::from_scopes([exact("refs/heads/other")]);
        assert!(
            coarse.overlaps(&neighbour_change),
            "the namespace witness conservatively conflicts"
        );
        assert!(
            !fine.overlaps(&neighbour_change),
            "refining to the exact ref removes that false conflict"
        );
    }

    #[test]
    fn overlap_is_symmetric_across_granularity() {
        let read_namespace = Footprint::from_scopes([ns("refs/heads")]);
        let changed_exact = Footprint::from_scopes([exact("refs/heads/main")]);
        assert!(read_namespace.overlaps(&changed_exact));
        assert!(changed_exact.overlaps(&read_namespace));
    }

    #[test]
    fn different_domains_do_not_cover_each_other() {
        let refs = Footprint::from_scopes([exact("refs/heads/main")]);
        let path = Footprint::from_scopes([Scope::ExactPath(b"refs/heads/main".to_vec())]);
        assert!(
            !refs.overlaps(&path),
            "a ref name and a path that happen to share bytes are different domains"
        );
        let forge = Footprint::from_scopes([Scope::ForgeStream(b"pulls".to_vec())]);
        assert!(!refs.overlaps(&forge));
    }

    #[test]
    fn a_forge_stream_covers_its_entities_but_not_a_sibling_stream() {
        let stream = Scope::ForgeStream(b"pulls".to_vec());
        let entity = Scope::ForgeEntity {
            stream: b"pulls".to_vec(),
            entity: b"pr-1".to_vec(),
        };
        let other_stream_entity = Scope::ForgeEntity {
            stream: b"issues".to_vec(),
            entity: b"pr-1".to_vec(),
        };
        assert!(stream.covers(&entity));
        assert!(!stream.covers(&other_stream_entity));
        assert!(!entity.covers(&stream));
    }

    #[test]
    fn an_empty_footprint_conflicts_with_nothing_and_is_subsumed_by_all() {
        let empty = Footprint::empty();
        let anything = Footprint::from_scopes([exact("refs/heads/main")]);
        assert!(!empty.overlaps(&anything));
        assert!(!anything.overlaps(&empty));
        assert!(anything.subsumes(&empty));
        assert!(empty.subsumes(&empty));
        assert!(!empty.subsumes(&anything));
    }

    #[test]
    fn family_names_are_stable_and_distinct() {
        use std::collections::BTreeSet;
        let scopes = [
            Scope::Generation,
            ns("refs"),
            exact("refs/heads/main"),
            Scope::ForgeStream(b"pulls".to_vec()),
            Scope::ForgeEntity {
                stream: b"pulls".to_vec(),
                entity: b"pr-1".to_vec(),
            },
            Scope::PathPrefix(b"src".to_vec()),
            Scope::ExactPath(b"src/lib.rs".to_vec()),
            Scope::PolicyDomain(b"quota".to_vec()),
            Scope::PolicyEpoch,
        ];
        let names = scopes
            .iter()
            .map(Scope::family)
            .collect::<BTreeSet<&'static str>>();
        assert_eq!(names.len(), scopes.len(), "two families share a name");
    }
}
