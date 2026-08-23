//! Immutable graph-generation bodies and their root-last activation path.

use fgit_authority::{
    AuthorityFailure, AuthorityStore, CasOutcome, HeadInit, HeadKey, HeadRead, ImmutableKey,
    KeyError, PutOutcome,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    decode_body, encode_body,
};
use fgit_types::{
    AsciiSlug, Digest, GenerationId, HeadGeneration, RepositoryCommitId, SchemaFamily, SchemaId,
    TypeRefusal,
};

/// The identity of an immutable graph generation.
pub type GraphGenerationId = GenerationId;

/// The schema selected for a graph view.
pub type GraphSchemaId = SchemaId;

/// The authority semantics of one immutable graph generation.
///
/// The class is identity material: an exact generation cannot be silently
/// reinterpreted as a deterministic-derived or statistical one (or vice
/// versa) after it has been activated.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GraphAuthorityClass {
    /// Derived directly from canonical source records and eligible only for
    /// exact verification paths.
    Exact,
    /// Reproducible from canonical inputs under a pinned parser or
    /// normalization profile, but not itself canonical source truth.
    DeterministicDerived,
    /// Inferred or probabilistic graph material, which remains advisory.
    Statistical,
}

impl GraphAuthorityClass {
    const fn tag(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::DeterministicDerived => 1,
            Self::Statistical => 2,
        }
    }

    fn from_tag(tag: u8, offset: u64) -> Result<Self, CodecRefusal> {
        match tag {
            0 => Ok(Self::Exact),
            1 => Ok(Self::DeterministicDerived),
            2 => Ok(Self::Statistical),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "graph_generation.authority_class",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// Why a caller requiring exact graph material was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphAuthorityClassRefusal {
    /// A deterministic-derived or statistical generation cannot stand in for
    /// exact graph material.
    ExactRequired { observed: GraphAuthorityClass },
}

/// Proof that a borrowed graph generation is classified as exact.
///
/// Only [`GraphGenerationBody::require_exact`] can construct this token, so
/// APIs that require exact graph material can take it directly instead of
/// trusting a caller-supplied boolean or documentation claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactGraphGeneration<'a> {
    body: &'a GraphGenerationBody,
}

impl<'a> ExactGraphGeneration<'a> {
    /// The exact immutable generation body admitted by the checked boundary.
    #[must_use]
    pub const fn body(self) -> &'a GraphGenerationBody {
        self.body
    }
}

/// A bounded identifier for the graph view a generation serves.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GraphViewId(AsciiSlug);

impl GraphViewId {
    /// Builds an identifier from canonical lowercase ASCII bytes.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        AsciiSlug::try_new("graph_view_id", source).map(Self)
    }

    /// The canonical bytes of this identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A bounded identifier for the pinned graph-builder profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BuilderProfileId(AsciiSlug);

impl BuilderProfileId {
    /// Builds an identifier from canonical lowercase ASCII bytes.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        AsciiSlug::try_new("builder_profile_id", source).map(Self)
    }

    /// The canonical bytes of this identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Position and profile facts from which a graph builder derived a view.
///
/// The builder receives canonical roots from its owning source subsystem.  It
/// does not manufacture a mutable side index or claim that a local projection
/// is authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphSourceStamp {
    /// Exact committed repository position.
    pub source_rcr_id: RepositoryCommitId,
    /// Forge position committed with that repository position.
    pub source_forge_position_root: Digest,
    /// Pinned builder behavior.
    pub builder_profile: BuilderProfileId,
    /// Pinned parser/model basis, including the deterministic no-model profile.
    pub parser_model_root: Digest,
}

/// Canonical immutable body of one graph generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphGenerationBody {
    graph_view_id: GraphViewId,
    schema_id: GraphSchemaId,
    authority_class: GraphAuthorityClass,
    source: GraphSourceStamp,
    vertices_root: Digest,
    edges_root: Digest,
    index_manifest_root: Digest,
    evidence_root: Digest,
    predecessor_generation_id: Option<GraphGenerationId>,
}

impl GraphGenerationBody {
    /// Assembles one generation body from committed source and graph roots.
    #[must_use]
    pub const fn new(
        graph_view_id: GraphViewId,
        schema_id: GraphSchemaId,
        authority_class: GraphAuthorityClass,
        source: GraphSourceStamp,
        vertices_root: Digest,
        edges_root: Digest,
        index_manifest_root: Digest,
        evidence_root: Digest,
        predecessor_generation_id: Option<GraphGenerationId>,
    ) -> Self {
        Self {
            graph_view_id,
            schema_id,
            authority_class,
            source,
            vertices_root,
            edges_root,
            index_manifest_root,
            evidence_root,
            predecessor_generation_id,
        }
    }

    /// The view this generation serves.
    #[must_use]
    pub const fn graph_view_id(&self) -> GraphViewId {
        self.graph_view_id
    }

    /// The graph schema this body selected.
    #[must_use]
    pub const fn graph_schema_id(&self) -> GraphSchemaId {
        self.schema_id
    }

    /// The distinct authority semantics bound into this generation's identity.
    #[must_use]
    pub const fn authority_class(&self) -> GraphAuthorityClass {
        self.authority_class
    }

    /// Produces the exact-only proof required by exact graph call sites.
    ///
    /// Deterministic-derived and statistical generations remain useful for
    /// their declared advisory or derived consumers, but cannot be promoted
    /// through this boundary.
    pub const fn require_exact(
        &self,
    ) -> Result<ExactGraphGeneration<'_>, GraphAuthorityClassRefusal> {
        match self.authority_class {
            GraphAuthorityClass::Exact => Ok(ExactGraphGeneration { body: self }),
            observed => Err(GraphAuthorityClassRefusal::ExactRequired { observed }),
        }
    }

    /// The canonical source position and builder profile.
    #[must_use]
    pub const fn source(&self) -> &GraphSourceStamp {
        &self.source
    }

    /// The direct predecessor required for activation, if this is not genesis.
    #[must_use]
    pub const fn predecessor_generation_id(&self) -> Option<GraphGenerationId> {
        self.predecessor_generation_id
    }

    /// Computes the registered, domain-pinned identity of this generation.
    pub fn generation_id(&self) -> Result<GraphGenerationId, GenerationAuthorityError> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(GraphGenerationId::from_internal_object_id(identity)?)
    }
}

impl CanonicalBody for GraphGenerationBody {
    const DOMAIN: fgit_types::DomainTag = GraphGenerationId::DOMAIN_TAG;
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("graph-generation");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_bytes("graph_generation.view", self.graph_view_id.as_bytes())?;
        out.write_schema_id(self.schema_id)?;
        out.write_scalar(self.authority_class.tag());
        out.write_internal_object_id(self.source.source_rcr_id.as_internal_object_id())?;
        out.write_digest(&self.source.source_forge_position_root)?;
        out.write_bytes(
            "graph_generation.builder",
            self.source.builder_profile.as_bytes(),
        )?;
        out.write_digest(&self.source.parser_model_root)?;
        out.write_digest(&self.vertices_root)?;
        out.write_digest(&self.edges_root)?;
        out.write_digest(&self.index_manifest_root)?;
        out.write_digest(&self.evidence_root)?;
        out.write_option(
            self.predecessor_generation_id.as_ref(),
            |encoder, predecessor| {
                encoder.write_internal_object_id(predecessor.as_internal_object_id())
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let graph_view_id = GraphViewId::try_new(input.read_bytes("graph_generation.view")?)?;
        let schema_id = input.read_schema_id()?;
        let authority_class_offset = input.offset();
        let authority_class = GraphAuthorityClass::from_tag(
            input.read_scalar::<u8>("graph_generation.authority_class")?,
            authority_class_offset,
        )?;
        let source_rcr_id =
            RepositoryCommitId::from_internal_object_id(input.read_internal_object_id()?)?;
        let source_forge_position_root = input.read_digest()?;
        let builder_profile =
            BuilderProfileId::try_new(input.read_bytes("graph_generation.builder")?)?;
        let parser_model_root = input.read_digest()?;
        let vertices_root = input.read_digest()?;
        let edges_root = input.read_digest()?;
        let index_manifest_root = input.read_digest()?;
        let evidence_root = input.read_digest()?;
        let predecessor_generation_id =
            input.read_option("graph_generation.predecessor", |decoder| {
                Ok(GraphGenerationId::from_internal_object_id(
                    decoder.read_internal_object_id()?,
                )?)
            })?;
        Ok(Self::new(
            graph_view_id,
            schema_id,
            authority_class,
            GraphSourceStamp {
                source_rcr_id,
                source_forge_position_root,
                builder_profile,
                parser_model_root,
            },
            vertices_root,
            edges_root,
            index_manifest_root,
            evidence_root,
            predecessor_generation_id,
        ))
    }
}

/// Why a generation activation did not produce a confirmed authority transition.
#[derive(Debug)]
pub enum GenerationAuthorityError {
    /// Canonical body encoding or decoding refused the supplied bytes.
    Codec(CodecRefusal),
    /// A typed value conversion refused a cross-domain or invalid value.
    Type(TypeRefusal),
    /// The derived authority key exceeded the authority key contract.
    Key(KeyError),
    /// The authority backend failed or reported ambiguity; callers must reconcile it.
    Authority(AuthorityFailure),
    /// An immutable key already names different bytes.
    ImmutableConflict {
        generation_id: Box<GraphGenerationId>,
    },
    /// Genesis cannot claim a predecessor.
    GenesisHasPredecessor {
        generation_id: Box<GraphGenerationId>,
    },
    /// A non-genesis candidate did not name the active generation exactly.
    PredecessorMismatch {
        expected: Box<GraphGenerationId>,
        supplied: Option<Box<GraphGenerationId>>,
    },
    /// A head key must serve exactly one graph view.
    ViewMismatch {
        active: Box<GraphViewId>,
        proposed: Box<GraphViewId>,
    },
    /// Another generation already initialized the vacant head slot.
    HeadAlreadyInitialized,
    /// A concurrent activation replaced the observed predecessor.
    ConcurrentActivation,
}

impl From<CodecRefusal> for GenerationAuthorityError {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<TypeRefusal> for GenerationAuthorityError {
    fn from(value: TypeRefusal) -> Self {
        Self::Type(value)
    }
}

impl From<KeyError> for GenerationAuthorityError {
    fn from(value: KeyError) -> Self {
        Self::Key(value)
    }
}

impl From<AuthorityFailure> for GenerationAuthorityError {
    fn from(value: AuthorityFailure) -> Self {
        Self::Authority(value)
    }
}

/// The confirmed authority transition that activated a graph generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationActivation {
    /// The immutable generation body whose bytes were staged.
    pub generation_id: GraphGenerationId,
    /// The monotone authority-head generation after activation.
    pub authority_generation: HeadGeneration,
}

/// Exact-predecessor, root-last activation for one graph-view authority head.
///
/// This generic semantic core is intentionally built on [`AuthorityStore`],
/// the deterministic authority verification surface.  Node-facing callers use
/// the sibling `AsyncAuthorityStore` adapter; neither path may decide a CAS
/// differently.  An ambiguous backend result is returned unchanged rather
/// than relabeled as a rejected activation.
pub struct GenerationAuthority<'a, S> {
    store: &'a S,
    head_key: HeadKey,
}

impl<'a, S: AuthorityStore> GenerationAuthority<'a, S> {
    /// Binds the graph activation protocol to one authority backend and head key.
    #[must_use]
    pub const fn new(store: &'a S, head_key: HeadKey) -> Self {
        Self { store, head_key }
    }

    /// Stages `candidate` immutably, then activates it only against its exact predecessor.
    pub fn stage_and_activate(
        &self,
        candidate: &GraphGenerationBody,
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        let generation_id = candidate.generation_id()?;
        let body = encode_body(candidate)?;
        let immutable_key = immutable_generation_key(generation_id)?;
        match self.store.put_if_absent(&immutable_key, &body)? {
            PutOutcome::Created | PutOutcome::IdenticalRetry => {}
            PutOutcome::Conflict => {
                return Err(GenerationAuthorityError::ImmutableConflict {
                    generation_id: Box::new(generation_id),
                });
            }
        }

        match self.store.read_head(&self.head_key)? {
            HeadRead::Absent => self.activate_genesis(candidate, generation_id, &body),
            HeadRead::Present(receipt) => {
                let active =
                    decode_body::<GraphGenerationBody>(receipt.body(), DecodeLimits::default())?;
                if active.graph_view_id != candidate.graph_view_id {
                    return Err(GenerationAuthorityError::ViewMismatch {
                        active: Box::new(active.graph_view_id),
                        proposed: Box::new(candidate.graph_view_id),
                    });
                }
                let active_id = active.generation_id()?;
                if candidate.predecessor_generation_id != Some(active_id) {
                    return Err(GenerationAuthorityError::PredecessorMismatch {
                        expected: Box::new(active_id),
                        supplied: candidate.predecessor_generation_id.map(Box::new),
                    });
                }
                let next_generation = receipt.generation().next()?;
                match self.store.compare_exchange_head(
                    &self.head_key,
                    receipt.token(),
                    next_generation,
                    &body,
                )? {
                    CasOutcome::Committed(committed) => Ok(GenerationActivation {
                        generation_id,
                        authority_generation: committed.generation(),
                    }),
                    CasOutcome::PredecessorMismatch => {
                        Err(GenerationAuthorityError::ConcurrentActivation)
                    }
                }
            }
        }
    }

    fn activate_genesis(
        &self,
        candidate: &GraphGenerationBody,
        generation_id: GraphGenerationId,
        body: &[u8],
    ) -> Result<GenerationActivation, GenerationAuthorityError> {
        if candidate.predecessor_generation_id.is_some() {
            return Err(GenerationAuthorityError::GenesisHasPredecessor {
                generation_id: Box::new(generation_id),
            });
        }
        match self
            .store
            .initialize_head(&self.head_key, HeadGeneration::FIRST, body)?
        {
            HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt) => {
                Ok(GenerationActivation {
                    generation_id,
                    authority_generation: receipt.generation(),
                })
            }
            HeadInit::Conflict => Err(GenerationAuthorityError::HeadAlreadyInitialized),
        }
    }
}

fn immutable_generation_key(
    generation_id: GraphGenerationId,
) -> Result<ImmutableKey, GenerationAuthorityError> {
    let mut key = b"fgit-graph/generation/".to_vec();
    key.extend_from_slice(generation_id.as_internal_object_id().digest().as_bytes());
    Ok(ImmutableKey::new(key)?)
}

#[cfg(test)]
mod tests {
    use fgit_authority::{HeadKey, MemoryAuthorityStore, StoreInstanceId};
    use fgit_codec::{CodecRefusal, DecodeLimits, decode_body, encode_body};
    use fgit_crypto::{
        IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
    };
    use fgit_types::{
        CodecVersion, Digest, HeadGeneration, RepositoryCommitId, SchemaFamily, SchemaId,
    };

    use super::{
        BuilderProfileId, ExactGraphGeneration, GenerationAuthority, GenerationAuthorityError,
        GraphAuthorityClass, GraphAuthorityClassRefusal, GraphGenerationBody, GraphGenerationId,
        GraphSourceStamp, GraphViewId,
    };

    fn digest(label: &[u8]) -> Digest {
        let bytes = internal_digest_value(
            IdentityDomain::MerkleLeaf,
            SchemaId::new(SchemaFamily::from_static("graph-generation-test"), 1, 0),
            label,
        );
        Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf), bytes)
    }

    fn source() -> GraphSourceStamp {
        let rcr = internal_object_id(
            IdentityDomain::RepositoryCommitRecord,
            SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
            CodecVersion::new(1, 0),
            b"graph-generation-test-rcr",
        );
        GraphSourceStamp {
            source_rcr_id: RepositoryCommitId::from_internal_object_id(rcr)
                .expect("repository-commit identity uses its registered domain"),
            source_forge_position_root: digest(b"forge"),
            builder_profile: BuilderProfileId::try_new(b"exact-test-builder")
                .expect("static builder profile is canonical"),
            parser_model_root: digest(b"parser"),
        }
    }

    fn generation_with_class(
        authority_class: GraphAuthorityClass,
        predecessor: Option<GraphGenerationId>,
    ) -> GraphGenerationBody {
        GraphGenerationBody::new(
            GraphViewId::try_new(b"commit-ancestry").expect("static graph view is canonical"),
            SchemaId::new(SchemaFamily::from_static("graph-test"), 1, 0),
            authority_class,
            source(),
            digest(b"vertices"),
            digest(b"edges"),
            digest(b"index"),
            digest(b"evidence"),
            predecessor,
        )
    }

    fn generation(predecessor: Option<GraphGenerationId>) -> GraphGenerationBody {
        generation_with_class(GraphAuthorityClass::Exact, predecessor)
    }

    fn accepts_exact_generation(_: ExactGraphGeneration<'_>) {}

    #[test]
    fn activation_stages_immutable_generation_then_requires_the_exact_predecessor() {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(91));
        let authority = GenerationAuthority::new(
            &store,
            HeadKey::new(b"tenant/repository/graph/commit-ancestry".to_vec())
                .expect("bounded head key"),
        );
        let genesis = generation(None);
        let first = authority
            .stage_and_activate(&genesis)
            .expect("vacant graph head accepts predecessor-free genesis");
        assert_eq!(first.authority_generation, HeadGeneration::FIRST);

        let next = generation(Some(first.generation_id));
        let second = authority
            .stage_and_activate(&next)
            .expect("candidate naming the exact active identity activates");
        assert!(
            first
                .authority_generation
                .is_immediate_predecessor_of(second.authority_generation)
        );

        let stale = generation(Some(first.generation_id));
        assert!(matches!(
            authority.stage_and_activate(&stale),
            Err(GenerationAuthorityError::PredecessorMismatch { .. })
        ));
    }

    #[test]
    fn generation_identity_is_registered_and_body_round_trips() {
        for authority_class in [
            GraphAuthorityClass::Exact,
            GraphAuthorityClass::DeterministicDerived,
            GraphAuthorityClass::Statistical,
        ] {
            let body = generation_with_class(authority_class, None);
            let id = body
                .generation_id()
                .expect("registered generation identity");
            let frame = encode_body(&body).expect("canonical graph-generation frame");
            let decoded = decode_body::<GraphGenerationBody>(&frame, DecodeLimits::default())
                .expect("strict graph-generation decode");
            assert_eq!(decoded, body);
            assert_eq!(
                decoded
                    .generation_id()
                    .expect("registered generation identity"),
                id
            );
            assert_eq!(decoded.authority_class(), authority_class);
        }
    }

    #[test]
    fn authority_class_is_identity_material_and_exact_callers_refuse_other_classes() {
        let exact = generation_with_class(GraphAuthorityClass::Exact, None);
        let deterministic = generation_with_class(GraphAuthorityClass::DeterministicDerived, None);
        let statistical = generation_with_class(GraphAuthorityClass::Statistical, None);

        assert_ne!(
            exact.generation_id().expect("exact identity is registered"),
            deterministic
                .generation_id()
                .expect("derived identity is registered")
        );
        assert_ne!(
            exact.generation_id().expect("exact identity is registered"),
            statistical
                .generation_id()
                .expect("statistical identity is registered")
        );
        assert_ne!(
            deterministic
                .generation_id()
                .expect("derived identity is registered"),
            statistical
                .generation_id()
                .expect("statistical identity is registered")
        );

        let exact_proof = exact.require_exact().expect("exact class is admitted");
        assert_eq!(
            exact_proof.body().authority_class(),
            GraphAuthorityClass::Exact
        );
        accepts_exact_generation(exact_proof);
        assert_eq!(
            deterministic.require_exact(),
            Err(GraphAuthorityClassRefusal::ExactRequired {
                observed: GraphAuthorityClass::DeterministicDerived,
            })
        );
        assert_eq!(
            statistical.require_exact(),
            Err(GraphAuthorityClassRefusal::ExactRequired {
                observed: GraphAuthorityClass::Statistical,
            })
        );
    }

    #[test]
    fn unknown_authority_class_wire_tag_is_refused() {
        assert_eq!(
            GraphAuthorityClass::from_tag(3, 41),
            Err(CodecRefusal::VariantUnknown {
                field: "graph_generation.authority_class",
                observed: 3,
                offset: 41,
            })
        );
    }
}
