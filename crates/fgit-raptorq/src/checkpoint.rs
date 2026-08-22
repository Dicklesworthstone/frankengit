//! `RaptorQ` protection for the registered `checkpoint_segment_v1` classes.
//!
//! Two durable classes share this one coding profile, and they are NOT
//! interchangeable:
//!
//! | class     | registry object                  | post-decode verification              |
//! |-----------|----------------------------------|---------------------------------------|
//! | `DUR-012` | `forge_event_checkpoint_segment` | digest, roots, deterministic replay    |
//! | `DUR-014` | `policy_key_format_checkpoint`   | **AEAD**, digest, signatures, semantics|
//!
//! The AEAD column is the reason these are one module and not one function.
//! `DUR-014` bytes are ciphertext: a decoded candidate whose digest matches is
//! still unauthenticated, and accepting it on digest alone would publish
//! attacker-chosen ciphertext that happens to hash correctly under a digest the
//! attacker also supplied. [`reconstruct_checkpoint`] therefore refuses to
//! return a [`VerifiedCheckpoint`] for [`CheckpointClass::PolicyKey`] until an
//! AEAD open succeeds, and refuses symmetrically if an envelope is offered for
//! a class that has no ciphertext to authenticate.
//!
//! Domain separation is real rather than positional. Each class digests its
//! bytes under its own registered [`IdentityDomain`], so the same byte string
//! protected as a forge checkpoint, as a policy checkpoint, and as a
//! microsegment yields three different identities and none of the three can be
//! substituted for another.

use asupersync::EncodingPipeline;
use asupersync::decoding::{DecodingPipeline, RejectReason, SymbolAcceptResult};
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::{ObjectId, ObjectParams, Symbol};
use fgit_crypto::{
    DigestHasher, EnvelopeError, IdentityDomain, Sha256Hasher, internal_id_preimage_header,
};
use fgit_types::{SchemaFamily, SchemaId};

use crate::{RaptorRefusal, decoding_config, encoding_config, symbol_pool};

/// Stable coding-profile identifier named by the durable-object registry.
pub const PROFILE_ID: &str = "checkpoint_segment_v1";

/// Registry row for the forge event checkpoint class.
pub const FORGE_EVENT_CLASS: &str = "DUR-012";
/// Registry row for the AEAD-wrapped policy/key checkpoint class.
pub const POLICY_KEY_CLASS: &str = "DUR-014";

const FORGE_EVENT_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.forge-event-checkpoint-segment"),
    1,
    0,
);
const POLICY_KEY_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.policy-key-format-checkpoint"),
    1,
    0,
);

/// The two durable classes carried by [`PROFILE_ID`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointClass {
    /// `DUR-012`: plaintext forge event checkpoint segment.
    ForgeEvent,
    /// `DUR-014`: AEAD-wrapped policy and key-format checkpoint.
    PolicyKey,
}

impl CheckpointClass {
    /// Durable-object registry row protected by this class.
    #[must_use]
    pub const fn durable_class(self) -> &'static str {
        match self {
            Self::ForgeEvent => FORGE_EVENT_CLASS,
            Self::PolicyKey => POLICY_KEY_CLASS,
        }
    }

    /// Registered identity domain, which is what separates the two classes.
    #[must_use]
    pub const fn identity_domain(self) -> IdentityDomain {
        match self {
            Self::ForgeEvent => IdentityDomain::ForgeCheckpoint,
            Self::PolicyKey => IdentityDomain::PolicyCheckpoint,
        }
    }

    /// Canonical schema bound into the identity preimage.
    #[must_use]
    pub const fn schema(self) -> SchemaId {
        match self {
            Self::ForgeEvent => FORGE_EVENT_SCHEMA,
            Self::PolicyKey => POLICY_KEY_SCHEMA,
        }
    }

    /// Whether acceptance requires an AEAD open after decode.
    ///
    /// This is the whole difference between the two classes at the repair
    /// boundary, so it is a method rather than a comment.
    #[must_use]
    pub const fn requires_aead(self) -> bool {
        matches!(self, Self::PolicyKey)
    }
}

/// Fixed, deterministic `RaptorQ` parameters for [`PROFILE_ID`].
///
/// Deliberately identical to the microsegment profile's block geometry: one
/// source block, 128-byte symbols, 8 repair symbols. Sharing the geometry is
/// what lets both profiles use one symbol pool and one decode budget without a
/// second set of tuning constants to keep in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRaptorProfile;

impl CheckpointRaptorProfile {
    /// Bytes in each source or repair symbol.
    pub const SYMBOL_BYTES: u16 = 128;
    /// Largest canonical checkpoint admitted by this single-block profile.
    pub const MAX_SOURCE_BYTES: usize = 8 * 1024;
    /// Exact number of repair symbols emitted for every protected checkpoint.
    pub const REPAIR_SYMBOLS: usize = 8;
    /// Maximum symbols admitted to one decode attempt.
    pub const MAX_DECODE_SYMBOLS: usize = 72;

    /// Registry coding-profile name.
    #[must_use]
    pub const fn profile_id(self) -> &'static str {
        PROFILE_ID
    }
}

/// Authenticates an AEAD-wrapped checkpoint after decode.
///
/// A trait over raw candidate bytes rather than a concrete key or a parsed
/// `SealedEnvelope`, for two reasons. `fgit-raptorq` must not learn key
/// handling in order to gate a class; and it must not learn the `DUR-014` wire
/// framing either, because that framing belongs to the checkpoint format owner,
/// not to the erasure layer. The implementor parses and opens; this crate only
/// enforces that it happened before acceptance.
pub trait CheckpointAeadVerifier {
    /// Authenticates and decrypts a decoded `DUR-014` candidate.
    ///
    /// `associated_data` is the scope's domain-separated checkpoint digest, so
    /// a ciphertext authenticated for one checkpoint cannot be replayed into
    /// another.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`EnvelopeError`] when the candidate does not
    /// authenticate under the caller's key.
    fn authenticate(
        &self,
        candidate: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError>;
}

/// Scope committed beside every checkpoint symbol before a decoder sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointScope {
    class: CheckpointClass,
    source_len: u64,
    checkpoint_digest: [u8; 32],
}

impl CheckpointScope {
    /// Derives the scope from canonical checkpoint bytes.
    ///
    /// # Errors
    ///
    /// Refuses input outside the single-block envelope rather than silently
    /// splitting it, which would mint a second identity for the same object.
    pub fn from_canonical_bytes(
        class: CheckpointClass,
        bytes: &[u8],
    ) -> Result<Self, RaptorRefusal> {
        let maximum = u64::try_from(CheckpointRaptorProfile::MAX_SOURCE_BYTES).unwrap_or(u64::MAX);
        if bytes.is_empty() || bytes.len() > CheckpointRaptorProfile::MAX_SOURCE_BYTES {
            return Err(RaptorRefusal::SourceTooLarge {
                offered: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                maximum,
            });
        }
        let source_len = u64::try_from(bytes.len()).map_err(|_| RaptorRefusal::SourceTooLarge {
            offered: u64::MAX,
            maximum,
        })?;
        Ok(Self {
            class,
            source_len,
            checkpoint_digest: checkpoint_digest(class, bytes),
        })
    }

    /// Durable class this scope protects.
    #[must_use]
    pub const fn class(&self) -> CheckpointClass {
        self.class
    }

    /// Exact canonical source length.
    #[must_use]
    pub const fn source_len(&self) -> u64 {
        self.source_len
    }

    /// Domain-separated checkpoint identity.
    #[must_use]
    pub const fn checkpoint_digest(&self) -> &[u8; 32] {
        &self.checkpoint_digest
    }

    /// Asupersync engine key. A 128-bit routing key only, never the identity.
    ///
    /// The full 256-bit checkpoint digest remains the identity verified after
    /// decode; this truncation exists solely to key the decoder.
    #[must_use]
    pub const fn engine_object_id(&self) -> ObjectId {
        let d = &self.checkpoint_digest;
        let high = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        let low = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
        ObjectId::new(high, low)
    }

    fn source_symbols(&self) -> Result<u16, RaptorRefusal> {
        let maximum = u64::try_from(CheckpointRaptorProfile::MAX_SOURCE_BYTES).unwrap_or(u64::MAX);
        let source_len =
            usize::try_from(self.source_len).map_err(|_| RaptorRefusal::SourceTooLarge {
                offered: self.source_len,
                maximum,
            })?;
        if source_len == 0 || source_len > CheckpointRaptorProfile::MAX_SOURCE_BYTES {
            return Err(RaptorRefusal::SourceTooLarge {
                offered: self.source_len,
                maximum,
            });
        }
        let symbol_bytes = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);
        let count = source_len.div_ceil(symbol_bytes);
        u16::try_from(count).map_err(|_| RaptorRefusal::SourceTooLarge {
            offered: self.source_len,
            maximum,
        })
    }
}

/// Domain-separated digest over canonical checkpoint bytes.
///
/// The preimage header carries the registered domain tag and schema, so the
/// same bytes under a different class produce a different identity.
fn checkpoint_digest(class: CheckpointClass, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    let header = internal_id_preimage_header(
        class.identity_domain(),
        class.schema(),
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    );
    DigestHasher::update(&mut hasher, &header);
    DigestHasher::update(&mut hasher, bytes);
    DigestHasher::finish(hasher)
}

/// One authenticated symbol that cannot be decoded outside its checkpoint scope.
#[derive(Debug, Clone)]
pub struct ScopedCheckpointSymbol {
    scope: CheckpointScope,
    symbol: Symbol,
    tag: AuthenticationTag,
}

impl ScopedCheckpointSymbol {
    /// Symbol scope validated before the decoder sees its payload.
    #[must_use]
    pub const fn scope(&self) -> &CheckpointScope {
        &self.scope
    }

    /// `RaptorQ` symbol metadata and payload.
    #[must_use]
    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }
}

/// The protected representation of one canonical checkpoint.
#[derive(Debug, Clone)]
pub struct ProtectedCheckpoint {
    scope: CheckpointScope,
    symbols: Vec<ScopedCheckpointSymbol>,
}

impl ProtectedCheckpoint {
    /// Original checkpoint scope.
    #[must_use]
    pub const fn scope(&self) -> &CheckpointScope {
        &self.scope
    }

    /// Systematic and repair symbols in deterministic encoding order.
    #[must_use]
    pub fn symbols(&self) -> &[ScopedCheckpointSymbol] {
        &self.symbols
    }
}

/// Candidate bytes that passed every commitment their class requires.
///
/// For [`CheckpointClass::PolicyKey`] this type cannot be constructed without a
/// successful AEAD open, so holding one is itself the evidence of
/// authentication rather than a promise that it happened somewhere earlier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    scope: CheckpointScope,
    bytes: Vec<u8>,
    plaintext: Option<Vec<u8>>,
}

impl VerifiedCheckpoint {
    /// Scope re-established from the quarantined candidate bytes.
    #[must_use]
    pub const fn scope(&self) -> &CheckpointScope {
        &self.scope
    }

    /// Exact canonical checkpoint bytes, after verification.
    ///
    /// For `DUR-014` these remain the ciphertext; the authenticated plaintext
    /// is [`Self::authenticated_plaintext`].
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Authenticated plaintext, present only for `DUR-014`.
    #[must_use]
    pub fn authenticated_plaintext(&self) -> Option<&[u8]> {
        self.plaintext.as_deref()
    }
}

/// Encodes one canonical checkpoint into scoped, authenticated symbols.
///
/// # Errors
///
/// Refuses input beyond the single-block envelope and any encode whose symbol
/// count would exceed the profile's decode budget.
pub fn protect_checkpoint(
    class: CheckpointClass,
    bytes: &[u8],
    security: &SecurityContext,
) -> Result<ProtectedCheckpoint, RaptorRefusal> {
    let scope = CheckpointScope::from_canonical_bytes(class, bytes)?;
    let source_symbols = scope.source_symbols()?;
    let mut encoder = EncodingPipeline::new(encoding_config(), symbol_pool());
    let mut symbols =
        Vec::with_capacity(usize::from(source_symbols) + CheckpointRaptorProfile::REPAIR_SYMBOLS);
    for encoded in encoder.encode_with_repair(
        scope.engine_object_id(),
        bytes,
        CheckpointRaptorProfile::REPAIR_SYMBOLS,
    ) {
        let symbol = encoded
            .map_err(|_| RaptorRefusal::DecodeFailed)?
            .into_symbol();
        symbols.push(ScopedCheckpointSymbol {
            scope: scope.clone(),
            tag: security.sign_symbol_tag(&symbol),
            symbol,
        });
    }
    if symbols.len() > CheckpointRaptorProfile::MAX_DECODE_SYMBOLS {
        return Err(RaptorRefusal::DecodeBudgetExceeded {
            offered: symbols.len(),
            maximum: CheckpointRaptorProfile::MAX_DECODE_SYMBOLS,
        });
    }
    Ok(ProtectedCheckpoint { scope, symbols })
}

/// Reconstructs into quarantine and re-verifies every commitment the class requires.
///
/// The AEAD argument is checked against the class rather than merely consumed:
/// a `DUR-014` reconstruction without a verifier is
/// [`RaptorRefusal::AeadVerifierRequired`], and a `DUR-012` reconstruction with
/// one is [`RaptorRefusal::AeadVerifierNotPermitted`]. Silently ignoring a
/// mismatched argument would let a caller believe a plaintext class had been
/// authenticated.
///
/// # Errors
///
/// Refuses on decode-budget overrun, symbol scope or authentication mismatch,
/// digest mismatch after decode, and AEAD failure.
pub fn reconstruct_checkpoint(
    expected: &CheckpointScope,
    symbols: &[ScopedCheckpointSymbol],
    security: &SecurityContext,
    aead: Option<&dyn CheckpointAeadVerifier>,
) -> Result<VerifiedCheckpoint, RaptorRefusal> {
    match (expected.class().requires_aead(), aead.is_some()) {
        (true, false) => return Err(RaptorRefusal::AeadVerifierRequired),
        (false, true) => return Err(RaptorRefusal::AeadVerifierNotPermitted),
        _ => {}
    }
    let source_symbols = expected.source_symbols()?;
    if symbols.len() > CheckpointRaptorProfile::MAX_DECODE_SYMBOLS {
        return Err(RaptorRefusal::DecodeBudgetExceeded {
            offered: symbols.len(),
            maximum: CheckpointRaptorProfile::MAX_DECODE_SYMBOLS,
        });
    }
    let mut decoder = DecodingPipeline::with_auth(decoding_config(), security.clone());
    decoder
        .set_object_params(ObjectParams::new(
            expected.engine_object_id(),
            expected.source_len(),
            CheckpointRaptorProfile::SYMBOL_BYTES,
            1,
            source_symbols,
        ))
        .map_err(|_| RaptorRefusal::DecodeFailed)?;
    for scoped in symbols {
        validate_checkpoint_symbol(expected, scoped, source_symbols)?;
        let result = decoder
            .feed(AuthenticatedSymbol::from_parts(
                scoped.symbol.clone(),
                scoped.tag,
            ))
            .map_err(|_| RaptorRefusal::DecodeFailed)?;
        match result {
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed) => {
                return Err(RaptorRefusal::AuthenticationRejected);
            }
            SymbolAcceptResult::Rejected(_) => return Err(RaptorRefusal::DecodeFailed),
            SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. }
            | SymbolAcceptResult::Duplicate => {}
            // One source block per profile: once complete, further repair
            // symbols are redundant and feeding them would yield a terminal
            // decoder state that is not a refusal of the candidate.
            SymbolAcceptResult::BlockComplete { .. } => break,
        }
    }
    let candidate = decoder
        .into_data()
        .map_err(|_| RaptorRefusal::DecodeFailed)?;
    // DEFENSIVE, NOT INPUT-REACHABLE, and deliberately kept. The decoder was
    // handed `expected.source_len()` in its `ObjectParams` above, and this
    // compares its output against that same value, so no caller-supplied
    // symbol set can make it fire -- only an engine that violates its own
    // parameter contract. It is not covered by a fixture for that reason
    // (frankengit-zrxa); manufacturing one would mean faking a decoder.
    if u64::try_from(candidate.len()).ok() != Some(expected.source_len()) {
        return Err(RaptorRefusal::CandidateLengthMismatch);
    }
    if checkpoint_digest(expected.class(), &candidate) != *expected.checkpoint_digest() {
        return Err(RaptorRefusal::CandidateCommitmentMismatch);
    }
    let plaintext = match aead {
        Some(verifier) => {
            let opened = verifier
                .authenticate(&candidate, expected.checkpoint_digest())
                .map_err(|_| RaptorRefusal::AeadUnauthenticated)?;
            Some(opened)
        }
        None => None,
    };
    Ok(VerifiedCheckpoint {
        scope: expected.clone(),
        bytes: candidate,
        plaintext,
    })
}

fn validate_checkpoint_symbol(
    expected: &CheckpointScope,
    scoped: &ScopedCheckpointSymbol,
    source_symbols: u16,
) -> Result<(), RaptorRefusal> {
    if scoped.scope != *expected {
        return Err(RaptorRefusal::ScopeMismatch);
    }
    let id = scoped.symbol.id();
    if id.object_id() != expected.engine_object_id() {
        return Err(RaptorRefusal::EngineObjectIdMismatch);
    }
    if id.sbn() != 0 {
        return Err(RaptorRefusal::SourceBlockMismatch);
    }
    if id.is_source(u32::from(source_symbols)) != scoped.symbol.kind().is_source() {
        return Err(RaptorRefusal::EncodingSymbolKindMismatch);
    }
    let expected_size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);
    if scoped.symbol.len() != expected_size {
        return Err(RaptorRefusal::SymbolSizeMismatch {
            offered: scoped.symbol.len(),
            expected: expected_size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Not imported by the parent: the production paths never construct a
    // symbol id or kind, only read them. The forgeries below have to.
    use asupersync::types::{SymbolId, SymbolKind};

    fn security() -> SecurityContext {
        SecurityContext::for_testing(24)
    }

    fn canonical(fill: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| fill ^ u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    /// Accepts or refuses on demand, so the gate can be exercised in both
    /// directions without minting real key material.
    struct StubVerifier {
        accept: bool,
    }

    impl CheckpointAeadVerifier for StubVerifier {
        fn authenticate(
            &self,
            candidate: &[u8],
            associated_data: &[u8],
        ) -> Result<Vec<u8>, EnvelopeError> {
            assert_eq!(
                associated_data.len(),
                32,
                "the AAD must be the 32-byte checkpoint digest, not a truncation"
            );
            if self.accept {
                let mut plaintext = b"opened:".to_vec();
                plaintext.extend_from_slice(candidate);
                Ok(plaintext)
            } else {
                Err(EnvelopeError::Unauthenticated)
            }
        }
    }

    #[test]
    fn both_classes_round_trip_through_erasure() {
        let security = security();
        for (class, aead) in [
            (CheckpointClass::ForgeEvent, false),
            (CheckpointClass::PolicyKey, true),
        ] {
            let bytes = canonical(0x21, 900);
            let protected =
                protect_checkpoint(class, &bytes, &security).expect("canonical input must protect");
            let stub = StubVerifier { accept: true };
            let verifier: Option<&dyn CheckpointAeadVerifier> =
                if aead { Some(&stub) } else { None };
            let accepted =
                reconstruct_checkpoint(protected.scope(), protected.symbols(), &security, verifier)
                    .expect("a full symbol set must reconstruct");
            assert_eq!(accepted.bytes(), bytes.as_slice());
            assert_eq!(accepted.scope().class(), class);
            assert_eq!(
                accepted.authenticated_plaintext().is_some(),
                aead,
                "plaintext is present exactly when the class is AEAD-wrapped"
            );
        }
    }

    /// Domain separation is the property that stops one class being substituted
    /// for another, so it is asserted rather than assumed from the registry.
    #[test]
    fn identical_bytes_get_different_identities_per_class() {
        let bytes = canonical(0x5c, 512);
        let forge = CheckpointScope::from_canonical_bytes(CheckpointClass::ForgeEvent, &bytes)
            .expect("forge scope");
        let policy = CheckpointScope::from_canonical_bytes(CheckpointClass::PolicyKey, &bytes)
            .expect("policy scope");
        assert_ne!(
            forge.checkpoint_digest(),
            policy.checkpoint_digest(),
            "the same bytes under two classes must not share an identity"
        );
        assert_ne!(forge.engine_object_id(), policy.engine_object_id());
    }

    /// Pins WHY the identities differ, not merely that they do.
    ///
    /// Mutation testing found this gap: collapsing both classes onto one
    /// `IdentityDomain` left the digests distinct anyway, because the schema
    /// family also differs, so the test above still passed. Separation would
    /// then rest on a schema string rather than on the registered domain, and
    /// the digests would no longer be the `domain_separated_*` identities the
    /// DUR-012 and DUR-014 rows name. These assertions bind the code to the
    /// registry rather than to any distinctness.
    #[test]
    fn each_class_binds_its_own_registered_identity_domain() {
        assert_eq!(
            CheckpointClass::ForgeEvent.identity_domain(),
            IdentityDomain::ForgeCheckpoint
        );
        assert_eq!(
            CheckpointClass::PolicyKey.identity_domain(),
            IdentityDomain::PolicyCheckpoint
        );
        assert_ne!(
            CheckpointClass::ForgeEvent.identity_domain(),
            CheckpointClass::PolicyKey.identity_domain(),
        );
        assert_eq!(CheckpointClass::ForgeEvent.durable_class(), "DUR-012");
        assert_eq!(CheckpointClass::PolicyKey.durable_class(), "DUR-014");
        assert!(!CheckpointClass::ForgeEvent.requires_aead());
        assert!(CheckpointClass::PolicyKey.requires_aead());
    }

    #[test]
    fn policy_key_requires_an_aead_verifier() {
        let security = security();
        let bytes = canonical(0x33, 400);
        let protected = protect_checkpoint(CheckpointClass::PolicyKey, &bytes, &security)
            .expect("input must protect");
        let refusal =
            reconstruct_checkpoint(protected.scope(), protected.symbols(), &security, None)
                .expect_err("DUR-014 without a verifier must refuse");
        assert_eq!(refusal, RaptorRefusal::AeadVerifierRequired);
    }

    /// The symmetric half. Ignoring a verifier offered for a plaintext class
    /// would let a caller believe DUR-012 bytes had been authenticated.
    #[test]
    fn forge_event_refuses_an_offered_verifier() {
        let security = security();
        let bytes = canonical(0x44, 400);
        let protected = protect_checkpoint(CheckpointClass::ForgeEvent, &bytes, &security)
            .expect("input must protect");
        let stub = StubVerifier { accept: true };
        let refusal = reconstruct_checkpoint(
            protected.scope(),
            protected.symbols(),
            &security,
            Some(&stub),
        )
        .expect_err("DUR-012 with a verifier must refuse");
        assert_eq!(refusal, RaptorRefusal::AeadVerifierNotPermitted);
    }

    /// The point of the whole gate: the digest agrees and acceptance is still
    /// refused. A decoded DUR-014 candidate that hashes correctly is not
    /// authenticated, and this is the test that would fail if someone
    /// "simplified" the AEAD step away.
    #[test]
    fn a_matching_digest_does_not_authenticate() {
        let security = security();
        let bytes = canonical(0x55, 700);
        let protected = protect_checkpoint(CheckpointClass::PolicyKey, &bytes, &security)
            .expect("input must protect");
        let refusing = StubVerifier { accept: false };
        let refusal = reconstruct_checkpoint(
            protected.scope(),
            protected.symbols(),
            &security,
            Some(&refusing),
        )
        .expect_err("a refusing AEAD must block acceptance");
        assert_eq!(refusal, RaptorRefusal::AeadUnauthenticated);

        // Permitted twin: the identical symbol set, identical digest, accepted
        // once the AEAD succeeds. Without this the refusal above could be
        // caused by anything.
        let accepting = StubVerifier { accept: true };
        reconstruct_checkpoint(
            protected.scope(),
            protected.symbols(),
            &security,
            Some(&accepting),
        )
        .expect("the same candidate must be accepted when the AEAD authenticates");
    }

    #[test]
    fn beyond_envelope_source_is_refused() {
        let security = security();
        let oversized = canonical(0x66, CheckpointRaptorProfile::MAX_SOURCE_BYTES + 1);
        let refusal = protect_checkpoint(CheckpointClass::ForgeEvent, &oversized, &security)
            .expect_err("input past the single-block envelope must refuse");
        assert!(matches!(refusal, RaptorRefusal::SourceTooLarge { .. }));

        let empty = protect_checkpoint(CheckpointClass::ForgeEvent, &[], &security)
            .expect_err("an empty checkpoint must refuse");
        assert!(matches!(empty, RaptorRefusal::SourceTooLarge { .. }));

        // Permitted twin at the boundary: exactly MAX_SOURCE_BYTES protects.
        let exact = canonical(0x67, CheckpointRaptorProfile::MAX_SOURCE_BYTES);
        protect_checkpoint(CheckpointClass::ForgeEvent, &exact, &security)
            .expect("the largest admitted checkpoint must protect");
    }

    /// Malicious-symbol corpus. These are built in-module because
    /// `ScopedCheckpointSymbol` has private fields and no public constructor,
    /// so an external test could not forge them at all.
    /// Section-11 destructive drill: every source symbol destroyed, rebuilt
    /// from repair material alone, byte-identical for both classes.
    ///
    /// Run per class because the two do not share an acceptance rule, and the
    /// DUR-014 rebuild must still clear the AEAD gate rather than being handed
    /// a pass because the bytes happened to reconstruct.
    #[test]
    fn the_destructive_drill_rebuilds_both_classes_from_repair_material_alone() {
        let security = security();
        for class in [CheckpointClass::ForgeEvent, CheckpointClass::PolicyKey] {
            let original = canonical(0x9a, 600);
            let protected = protect_checkpoint(class, &original, &security)
                .expect("canonical input must protect");
            let source_count = usize::from(
                protected
                    .scope()
                    .source_symbols()
                    .expect("scope must yield a source count"),
            );

            let repair_only: Vec<ScopedCheckpointSymbol> = protected
                .symbols()
                .iter()
                .filter(|s| !s.symbol.kind().is_source())
                .cloned()
                .collect();

            assert_eq!(
                repair_only.len(),
                CheckpointRaptorProfile::REPAIR_SYMBOLS,
                "the drill must run against the full repair set, not a subset"
            );
            assert!(
                repair_only.len() >= source_count,
                "the drill is only meaningful when repair material alone can cover the block"
            );
            assert!(
                repair_only.iter().all(|s| !s.symbol.kind().is_source()),
                "no source symbol may survive into a destructive drill"
            );

            let accepting = StubVerifier { accept: true };
            let verifier: Option<&dyn CheckpointAeadVerifier> = if class.requires_aead() {
                Some(&accepting)
            } else {
                None
            };
            let rebuilt =
                reconstruct_checkpoint(protected.scope(), &repair_only, &security, verifier)
                    .expect("repair material alone must rebuild the checkpoint");
            assert_eq!(
                rebuilt.bytes(),
                original.as_slice(),
                "the rebuild must be byte-identical, not merely successful"
            );
            assert_eq!(rebuilt.scope(), protected.scope());
        }
    }

    /// A symbol flood must be refused on the budget BEFORE decoding starts,
    /// not absorbed and then rejected.
    #[test]
    fn the_decode_budget_refuses_a_flood_before_decoding() {
        let security = security();
        let bytes = canonical(0xb2, 600);
        let protected = protect_checkpoint(CheckpointClass::ForgeEvent, &bytes, &security)
            .expect("input must protect");

        let mut flood = Vec::new();
        while flood.len() <= CheckpointRaptorProfile::MAX_DECODE_SYMBOLS {
            flood.extend(protected.symbols().iter().cloned());
        }
        assert!(
            flood.len() > CheckpointRaptorProfile::MAX_DECODE_SYMBOLS,
            "the flood must actually exceed the budget or it tests nothing"
        );

        let refusal = reconstruct_checkpoint(protected.scope(), &flood, &security, None)
            .expect_err("a flood past the decode budget must refuse");
        assert!(
            matches!(refusal, RaptorRefusal::DecodeBudgetExceeded { .. }),
            "the refusal must name the budget, not fail generically: {refusal:?}"
        );

        // Permitted twin at the boundary: the legitimate set is well inside the
        // budget and still reconstructs, so the refusal is a bound and not a
        // blanket rejection.
        reconstruct_checkpoint(protected.scope(), protected.symbols(), &security, None)
            .expect("the legitimate symbol set must remain within budget");
    }

    /// Acceptance requires a corpus PER CLASS, so this runs the whole corpus
    /// against each class in turn rather than against one and assuming the
    /// other behaves the same. They do not share an acceptance rule, so that
    /// assumption would be exactly the wrong one to make.
    #[test]
    fn malicious_symbol_corpus_yields_zero_acceptances() {
        for target_class in [CheckpointClass::ForgeEvent, CheckpointClass::PolicyKey] {
            malicious_corpus_for(target_class);
        }
    }

    fn malicious_corpus_for(target_class: CheckpointClass) {
        let security = security();
        let other_class = match target_class {
            CheckpointClass::ForgeEvent => CheckpointClass::PolicyKey,
            CheckpointClass::PolicyKey => CheckpointClass::ForgeEvent,
        };
        let accepting = StubVerifier { accept: true };
        let verifier: Option<&dyn CheckpointAeadVerifier> = if target_class.requires_aead() {
            Some(&accepting)
        } else {
            None
        };
        let victim = canonical(0x77, 600);
        let other = canonical(0x88, 600);
        let target =
            protect_checkpoint(target_class, &victim, &security).expect("victim must protect");
        let foreign =
            protect_checkpoint(target_class, &other, &security).expect("foreign must protect");
        let cross_class =
            protect_checkpoint(other_class, &victim, &security).expect("cross-class must protect");

        let mut corpus: Vec<(&str, Vec<ScopedCheckpointSymbol>)> = Vec::new();

        // 1. Symbols from a different checkpoint, relabelled with the victim scope.
        corpus.push((
            "foreign symbol under victim scope",
            foreign
                .symbols()
                .iter()
                .map(|s| ScopedCheckpointSymbol {
                    scope: target.scope().clone(),
                    symbol: s.symbol.clone(),
                    tag: s.tag,
                })
                .collect(),
        ));

        // 2. The same bytes protected under the OTHER durable class.
        corpus.push((
            "cross-class symbol replay",
            cross_class
                .symbols()
                .iter()
                .map(|s| ScopedCheckpointSymbol {
                    scope: target.scope().clone(),
                    symbol: s.symbol.clone(),
                    tag: s.tag,
                })
                .collect(),
        ));

        // 3. Authentication tags swapped between two legitimate symbols.
        let mut swapped = target.symbols().to_vec();
        if swapped.len() >= 2 {
            let first = swapped[0].tag;
            swapped[0].tag = swapped[1].tag;
            swapped[1].tag = first;
        }
        corpus.push(("swapped authentication tags", swapped));

        // 4. A scope that agrees on the engine key but not on the scope itself.
        //
        //    Mutation testing found that entries 1-3 are all caught by
        //    EngineObjectIdMismatch, so disabling the scope equality check
        //    changed nothing and ScopeMismatch was dead from the corpus's point
        //    of view. It is not redundant: engine_object_id is the digest
        //    TRUNCATED to 128 bits, so a scope differing only in a field the
        //    truncation drops still routes to the same decoder. That is
        //    unreachable through the public API -- it needs a forged scope --
        //    which is exactly why it is built here, in-module, where the
        //    private fields are reachable.
        let mut forged_scope = target.scope().clone();
        forged_scope.source_len = target.scope().source_len() + 1;
        assert_eq!(
            forged_scope.engine_object_id(),
            target.scope().engine_object_id(),
            "the forged scope must keep the same engine key, or it tests the wrong guard"
        );
        corpus.push((
            "scope forged past the 128-bit engine key truncation",
            target
                .symbols()
                .iter()
                .map(|s| ScopedCheckpointSymbol {
                    scope: forged_scope.clone(),
                    symbol: s.symbol.clone(),
                    tag: s.tag,
                })
                .collect(),
        ));

        let mut acceptances = 0usize;
        for (label, symbols) in &corpus {
            if reconstruct_checkpoint(target.scope(), symbols, &security, verifier).is_ok() {
                acceptances += 1;
                eprintln!(
                    "ACCEPTED a malicious corpus entry for {}: {label}",
                    target_class.durable_class()
                );
            }
        }
        assert_eq!(
            acceptances,
            0,
            "every malicious corpus entry must be refused for {}",
            target_class.durable_class()
        );
        assert_eq!(
            corpus.len(),
            4,
            "the corpus denominator is asserted, so a silently empty corpus cannot pass"
        );

        // Permitted twin: the untampered symbol set from the same builder still
        // reconstructs, so the zero above is discrimination and not a store
        // that refuses everything.
        reconstruct_checkpoint(target.scope(), target.symbols(), &security, verifier)
            .expect("the untampered set must still reconstruct");
    }

    /// The ordered accept chain in [`validate_checkpoint_symbol`], one guard at
    /// a time, through the public entry point rather than by calling the guard
    /// directly -- so each probe also witnesses that the guard is still ON the
    /// production path, not merely that it exists.
    ///
    /// Each forged symbol differs from a well-formed one in exactly ONE field,
    /// and every earlier guard is satisfied deliberately: the scope is cloned
    /// from a real `protect_checkpoint` result and the object id comes from that
    /// scope, so `ScopeMismatch` and `EngineObjectIdMismatch` cannot fire first
    /// and mask the guard under test.
    ///
    /// # Why each refusal is paired with a near-identical permitted twin
    ///
    /// A guard that refused unconditionally would satisfy every "is refused"
    /// assertion here. The twin flips only the field under test back to a legal
    /// value and asserts the refusal is no longer THAT one -- it does not assert
    /// success, because a synthetic symbol still cannot complete a decode. That
    /// is the strongest claim the construction supports, and overstating it
    /// would be the vacuous half of a permitted-twin pair.
    fn forged(
        scope: &CheckpointScope,
        sbn: u8,
        esi: u32,
        len: usize,
        kind: SymbolKind,
        security: &SecurityContext,
    ) -> ScopedCheckpointSymbol {
        let data = vec![0x5a_u8; len];
        let symbol = Symbol::from_slice(
            SymbolId::new(scope.engine_object_id(), sbn, esi),
            &data,
            kind,
        );
        ScopedCheckpointSymbol {
            scope: scope.clone(),
            tag: security.sign_symbol_tag(&symbol),
            symbol,
        }
    }

    /// Builds a protected checkpoint whose scope the forgeries borrow.
    fn borrowed_scope(security: &SecurityContext) -> ProtectedCheckpoint {
        protect_checkpoint(CheckpointClass::ForgeEvent, &canonical(0x31, 600), security)
            .expect("canonical input must protect")
    }

    #[test]
    fn a_symbol_naming_a_second_source_block_is_refused_for_that_exact_reason() {
        let security = security();
        let protected = borrowed_scope(&security);
        let scope = protected.scope();
        let size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);

        // The profile declares ONE source block, so any sbn but 0 is a symbol
        // from a segmentation this scope never described.
        let refusal = reconstruct_checkpoint(
            scope,
            &[forged(scope, 1, 0, size, SymbolKind::Source, &security)],
            &security,
            None,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::SourceBlockMismatch)),
            "a non-zero source block number must refuse as SourceBlockMismatch, got {refusal:?}"
        );

        // Permitted twin: identical but for sbn, which must clear this guard.
        let twin = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size, SymbolKind::Source, &security)],
            &security,
            None,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::SourceBlockMismatch)),
            "sbn 0 must pass the source-block guard; the guard is keyed on sbn alone"
        );
    }

    #[test]
    fn a_repair_symbol_occupying_a_source_slot_is_refused_as_a_kind_mismatch() {
        let security = security();
        let protected = borrowed_scope(&security);
        let scope = protected.scope();
        let size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);
        let source_symbols = scope
            .source_symbols()
            .expect("a protected scope counts its symbols");
        assert!(
            source_symbols > 0,
            "the denominator must be non-zero or esi 0 would not be a source slot"
        );

        // esi 0 is inside the source range, so the id says source and the kind
        // says repair. The guard exists to catch exactly that disagreement.
        let refusal = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size, SymbolKind::Repair, &security)],
            &security,
            None,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a repair-kind symbol in a source slot must refuse as EncodingSymbolKindMismatch, got {refusal:?}"
        );

        // Permitted twin: same slot, kind corrected to agree with the id.
        let twin = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size, SymbolKind::Source, &security)],
            &security,
            None,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "an agreeing kind must clear the guard; it is keyed on the disagreement, not on the kind"
        );
    }

    #[test]
    fn a_short_symbol_is_refused_with_both_the_offered_and_expected_sizes_named() {
        let security = security();
        let protected = borrowed_scope(&security);
        let scope = protected.scope();
        let size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);

        // The payload field is the point: a caller must be able to tell WHICH
        // size was wrong without re-deriving the profile constant.
        let refusal = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size - 1, SymbolKind::Source, &security)],
            &security,
            None,
        );
        match refusal {
            Err(RaptorRefusal::SymbolSizeMismatch { offered, expected }) => {
                assert_eq!(
                    offered,
                    size - 1,
                    "the refusal must name the size actually offered"
                );
                assert_eq!(
                    expected, size,
                    "the refusal must name the profile's symbol size"
                );
            }
            other => panic!("a short symbol must refuse as SymbolSizeMismatch, got {other:?}"),
        }

        // Permitted twin: the exact profile size clears the guard.
        let twin = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size, SymbolKind::Source, &security)],
            &security,
            None,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::SymbolSizeMismatch { .. })),
            "a correctly sized symbol must clear the size guard"
        );
    }

    /// The SECOND axis of the kind guard, which the probe above does not reach.
    ///
    /// `validate_checkpoint_symbol` compares `id.is_source(k)` against
    /// `kind().is_source()` -- a DISAGREEMENT test, so it has two directions and
    /// a probe from one side leaves the other uncharacterised. The test above
    /// puts a repair-kind symbol in a source slot; this one puts a source-kind
    /// symbol in a repair slot (`esi >= k`, since `is_source` is `esi < k`).
    ///
    /// Both matter: an implementation that only checked "repair symbols must not
    /// claim source slots" would pass the first probe and fail this one.
    #[test]
    fn a_source_kind_symbol_in_a_repair_slot_is_refused_the_same_way() {
        let security = security();
        let protected = borrowed_scope(&security);
        let scope = protected.scope();
        let size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);
        let source_symbols = scope
            .source_symbols()
            .expect("a protected scope counts its source symbols");
        // The first repair slot. `is_source` is `esi < k`, so this is the exact
        // boundary at which the id stops claiming to be a source symbol.
        let repair_slot = u32::from(source_symbols);

        let refusal = reconstruct_checkpoint(
            scope,
            &[forged(
                scope,
                0,
                repair_slot,
                size,
                SymbolKind::Source,
                &security,
            )],
            &security,
            None,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a source-kind symbol in a repair slot must refuse as EncodingSymbolKindMismatch, got {refusal:?}"
        );

        // Permitted twin at the exact boundary: same slot, kind corrected.
        let twin = reconstruct_checkpoint(
            scope,
            &[forged(
                scope,
                0,
                repair_slot,
                size,
                SymbolKind::Repair,
                &security,
            )],
            &security,
            None,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a repair-kind symbol in a repair slot agrees with its id and must clear the guard"
        );
    }

    /// The oversize direction of the size guard.
    ///
    /// `scoped.symbol.len() != expected_size` is an inequality, so it too has
    /// two directions, and the probe above only covers the short one. A guard
    /// written as `len < expected_size` would pass that test and admit an
    /// oversized symbol -- extra bytes the decoder was never told about.
    ///
    /// This also witnesses that `offered` reports the ACTUAL length in the over
    /// direction, not a saturated or clamped value.
    #[test]
    fn an_oversized_symbol_is_refused_and_reports_its_real_length() {
        let security = security();
        let protected = borrowed_scope(&security);
        let scope = protected.scope();
        let size = usize::from(CheckpointRaptorProfile::SYMBOL_BYTES);

        let refusal = reconstruct_checkpoint(
            scope,
            &[forged(scope, 0, 0, size + 1, SymbolKind::Source, &security)],
            &security,
            None,
        );
        match refusal {
            Err(RaptorRefusal::SymbolSizeMismatch { offered, expected }) => {
                assert_eq!(
                    offered,
                    size + 1,
                    "the refusal must report the oversized length as offered"
                );
                assert_eq!(expected, size, "the expected size is the profile constant");
            }
            other => panic!("an oversized symbol must refuse as SymbolSizeMismatch, got {other:?}"),
        }
    }
}
