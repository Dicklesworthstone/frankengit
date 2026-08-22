#![forbid(unsafe_code)]
//! `RaptorQ` protection for the registered immutable microsegment class.
//!
//! The only durable class this first slice protects is `DUR-016`, the
//! `microsegment_v1` canonical object-fabric segment.  `RaptorQ` symbols are a
//! transport and repair aid, never a new object identity: decoded bytes enter
//! quarantine and must pass the object-fabric segment reader again before a
//! placement authority can make them visible.

pub mod checkpoint;

use std::error::Error;
use std::fmt;
use std::time::Duration;

use asupersync::EncodingPipeline;
use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, ObjectParams, Symbol};
use fgit_object_fabric::fabric::SegmentManifest;
use fgit_object_fabric::{Commitment, CryptoDigest, MicrosegmentReader, SegmentLimits};
use fgit_resource::kinds::{
    AuthorityRevalidation, CommitmentCheck, DecodeOutcome, RepairAbortReason, RepairNotPublished,
    RepairPermit, RepairPublished, RepairRequest,
};
use fgit_resource::{BudgetGrant, ObligationLedger, ResourceVector};
use fgit_types::{RepositoryAuthorityHeadId, SegmentManifestId};

/// Registry row naming the protected durable class.
pub const DURABLE_CLASS: &str = "DUR-016";
/// Stable coding-profile identifier named by the durable-object registry.
pub const PROFILE_ID: &str = "microsegment_v1";

/// Fixed, deterministic `RaptorQ` parameters for [`PROFILE_ID`].
///
/// One profile covers a single source block up to 8 KiB. Larger microsegments
/// are a typed refusal until a separately registered multi-block profile is
/// admitted; callers must not silently split canonical bytes themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicrosegmentRaptorProfile;

impl MicrosegmentRaptorProfile {
    /// Bytes in each source or repair symbol.
    pub const SYMBOL_BYTES: u16 = 128;
    /// Largest canonical segment admitted by this single-block profile.
    pub const MAX_SOURCE_BYTES: usize = 8 * 1024;
    /// Exact number of repair symbols emitted for every protected segment.
    pub const REPAIR_SYMBOLS: usize = 8;
    /// Maximum symbols admitted to one decode attempt.
    pub const MAX_DECODE_SYMBOLS: usize = 72;

    /// Registry durable-class name.
    #[must_use]
    pub const fn durable_class(self) -> &'static str {
        DURABLE_CLASS
    }

    /// Registry coding-profile name.
    #[must_use]
    pub const fn profile_id(self) -> &'static str {
        PROFILE_ID
    }
}

/// Scope committed beside every `RaptorQ` symbol before it reaches a decoder.
///
/// The 128-bit `ObjectId` is an Asupersync engine key only.  The complete
/// 256-bit segment digest remains the identity that is verified after decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosegmentScope {
    namespace: Vec<u8>,
    source_len: u64,
    segment_digest: Commitment,
    merkle_root: Commitment,
    record_count: u32,
}

impl MicrosegmentScope {
    fn from_verified_reader(
        reader: &MicrosegmentReader<'_, CryptoDigest>,
        source_len: usize,
    ) -> Result<Self, RaptorRefusal> {
        let record_count =
            u32::try_from(reader.len()).map_err(|_| RaptorRefusal::RecordCountTooLarge)?;
        let source_len = u64::try_from(source_len).map_err(|_| RaptorRefusal::SourceTooLarge {
            offered: u64::MAX,
            maximum: u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES).unwrap_or(u64::MAX),
        })?;
        Ok(Self {
            namespace: reader.namespace().to_vec(),
            source_len,
            segment_digest: reader.segment_digest(),
            merkle_root: reader.merkle_root(),
            record_count,
        })
    }

    /// Canonical object-fabric namespace.
    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Exact canonical source length.
    #[must_use]
    pub const fn source_len(&self) -> u64 {
        self.source_len
    }

    /// Full segment identity commitment.
    #[must_use]
    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

    /// Merkle root the decoded segment must reproduce.
    #[must_use]
    pub const fn merkle_root(&self) -> Commitment {
        self.merkle_root
    }

    /// Number of committed records.
    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Asupersync's non-authoritative 128-bit engine key.
    #[must_use]
    pub const fn engine_object_id(&self) -> ObjectId {
        let high = u64::from_be_bytes([
            self.segment_digest[0],
            self.segment_digest[1],
            self.segment_digest[2],
            self.segment_digest[3],
            self.segment_digest[4],
            self.segment_digest[5],
            self.segment_digest[6],
            self.segment_digest[7],
        ]);
        let low = u64::from_be_bytes([
            self.segment_digest[8],
            self.segment_digest[9],
            self.segment_digest[10],
            self.segment_digest[11],
            self.segment_digest[12],
            self.segment_digest[13],
            self.segment_digest[14],
            self.segment_digest[15],
        ]);
        ObjectId::new(high, low)
    }

    fn source_symbols(&self) -> Result<u16, RaptorRefusal> {
        let source_len =
            usize::try_from(self.source_len).map_err(|_| RaptorRefusal::SourceTooLarge {
                offered: self.source_len,
                maximum: u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES)
                    .unwrap_or(u64::MAX),
            })?;
        if source_len == 0 || source_len > MicrosegmentRaptorProfile::MAX_SOURCE_BYTES {
            return Err(RaptorRefusal::SourceTooLarge {
                offered: self.source_len,
                maximum: u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES)
                    .unwrap_or(u64::MAX),
            });
        }
        u16::try_from(source_len.div_ceil(usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES)))
            .map_err(|_| RaptorRefusal::SourceTooLarge {
                offered: self.source_len,
                maximum: u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES)
                    .unwrap_or(u64::MAX),
            })
    }
}

/// One authenticated symbol that cannot be decoded outside its microsegment scope.
#[derive(Debug, Clone)]
pub struct ScopedSymbol {
    scope: MicrosegmentScope,
    symbol: Symbol,
    tag: AuthenticationTag,
}

impl ScopedSymbol {
    /// Symbol scope validated before the decoder sees its payload.
    #[must_use]
    pub const fn scope(&self) -> &MicrosegmentScope {
        &self.scope
    }

    /// `RaptorQ` symbol metadata and payload.
    #[must_use]
    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }
}

/// The protected representation of one verified immutable microsegment.
#[derive(Debug, Clone)]
pub struct ProtectedMicrosegment {
    scope: MicrosegmentScope,
    symbols: Vec<ScopedSymbol>,
}

impl ProtectedMicrosegment {
    /// Original immutable source scope.
    #[must_use]
    pub const fn scope(&self) -> &MicrosegmentScope {
        &self.scope
    }

    /// Systematic and repair symbols in deterministic encoding order.
    #[must_use]
    pub fn symbols(&self) -> &[ScopedSymbol] {
        &self.symbols
    }
}

/// Candidate bytes that passed all object-fabric structural commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMicrosegment {
    scope: MicrosegmentScope,
    bytes: Vec<u8>,
}

impl VerifiedMicrosegment {
    /// Scope re-established from the quarantined candidate bytes.
    #[must_use]
    pub const fn scope(&self) -> &MicrosegmentScope {
        &self.scope
    }

    /// Exact canonical microsegment bytes, after verification.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Typed refusal from profile admission, symbol validation, reconstruction, or publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaptorRefusal {
    SourceTooLarge {
        offered: u64,
        maximum: u64,
    },
    RecordCountTooLarge,
    SourceSegmentInvalid,
    ScopeMismatch,
    EngineObjectIdMismatch,
    SourceBlockMismatch,
    EncodingSymbolKindMismatch,
    SymbolSizeMismatch {
        offered: usize,
        expected: usize,
    },
    DecodeBudgetExceeded {
        offered: usize,
        maximum: usize,
    },
    AuthenticationRejected,
    DecodeFailed,
    CandidateLengthMismatch,
    CandidateCommitmentMismatch,
    CandidateStructureMismatch,
    ManifestScopeMismatch,
    ManifestRealityMismatch,
    ManifestIdentityUnavailable,
    AuthorityHeadMoved,
    RetentionExpired,
    PlacementPublicationRefused,
    RepairReservationRefused,
    RepairSettlementRefused,
    /// A `DUR-014` reconstruction was attempted with no AEAD verifier.
    AeadVerifierRequired,
    /// An AEAD verifier was offered for a class that carries no ciphertext.
    AeadVerifierNotPermitted,
    /// The decoded candidate did not authenticate under the caller's key.
    AeadUnauthenticated,
}

impl fmt::Display for RaptorRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { offered, maximum } => {
                write!(
                    formatter,
                    "RaptorQ source has {offered} bytes; profile allows {maximum}"
                )
            }
            Self::RecordCountTooLarge => {
                formatter.write_str("microsegment record count does not fit profile scope")
            }
            Self::SourceSegmentInvalid => {
                formatter.write_str("source bytes are not a verified canonical microsegment")
            }
            Self::ScopeMismatch => {
                formatter.write_str("symbol scope does not match the requested microsegment")
            }
            Self::EngineObjectIdMismatch => {
                formatter.write_str("symbol engine object key does not match its full digest scope")
            }
            Self::SourceBlockMismatch => {
                formatter.write_str("symbol belongs to an unsupported source block")
            }
            Self::EncodingSymbolKindMismatch => {
                formatter.write_str("symbol kind does not match its encoding symbol identifier")
            }
            Self::SymbolSizeMismatch { offered, expected } => write!(
                formatter,
                "symbol has {offered} bytes; profile requires {expected}"
            ),
            Self::DecodeBudgetExceeded { offered, maximum } => write!(
                formatter,
                "decode offered {offered} symbols; profile permits {maximum}"
            ),
            Self::AuthenticationRejected => {
                formatter.write_str("symbol authentication did not verify")
            }
            Self::DecodeFailed => {
                formatter.write_str("RaptorQ could not reconstruct the source bytes")
            }
            Self::CandidateLengthMismatch => {
                formatter.write_str("decoded candidate length differs from its scope")
            }
            Self::CandidateCommitmentMismatch => formatter
                .write_str("decoded candidate differs from the original segment commitments"),
            Self::CandidateStructureMismatch => {
                formatter.write_str("decoded candidate failed canonical microsegment verification")
            }
            Self::ManifestScopeMismatch => formatter
                .write_str("repair scope disagrees with the authenticated segment manifest"),
            Self::ManifestRealityMismatch => formatter
                .write_str("candidate segment does not match authenticated manifest reality"),
            Self::ManifestIdentityUnavailable => {
                formatter.write_str("authenticated manifest identity cannot be derived")
            }
            Self::AuthorityHeadMoved => {
                formatter.write_str("repair basis head is stale; candidate was not published")
            }
            Self::RetentionExpired => {
                formatter.write_str("retention no longer permits the repaired placement")
            }
            Self::PlacementPublicationRefused => {
                formatter.write_str("verified repair placement could not be published")
            }
            Self::RepairReservationRefused => {
                formatter.write_str("repair permit reservation was refused")
            }
            Self::RepairSettlementRefused => {
                formatter.write_str("repair permit settlement was refused")
            }
            Self::AeadVerifierRequired => formatter.write_str(
                "DUR-014 reconstruction requires an AEAD verifier; digest agreement alone is not authentication",
            ),
            Self::AeadVerifierNotPermitted => formatter.write_str(
                "an AEAD verifier was offered for a checkpoint class that carries no ciphertext",
            ),
            Self::AeadUnauthenticated => formatter.write_str(
                "the decoded checkpoint candidate did not authenticate under the offered key",
            ),
        }
    }
}

impl Error for RaptorRefusal {}

/// Encodes a canonical microsegment with the registered `RaptorQ` profile.
///
/// The strict security context signs every emitted symbol.  The profile scope
/// is then checked independently before a receiver allocates decoder state.
pub fn protect_microsegment(
    bytes: &[u8],
    limits: &SegmentLimits,
    security: &SecurityContext,
) -> Result<ProtectedMicrosegment, RaptorRefusal> {
    let reader = MicrosegmentReader::open(bytes, &CryptoDigest, limits)
        .map_err(|_| RaptorRefusal::SourceSegmentInvalid)?;
    let scope = MicrosegmentScope::from_verified_reader(&reader, bytes.len())?;
    let source_symbols = scope.source_symbols()?;
    let mut encoder = EncodingPipeline::new(encoding_config(), symbol_pool());
    let mut symbols =
        Vec::with_capacity(usize::from(source_symbols) + MicrosegmentRaptorProfile::REPAIR_SYMBOLS);
    for encoded in encoder.encode_with_repair(
        scope.engine_object_id(),
        bytes,
        MicrosegmentRaptorProfile::REPAIR_SYMBOLS,
    ) {
        let symbol = encoded
            .map_err(|_| RaptorRefusal::DecodeFailed)?
            .into_symbol();
        symbols.push(ScopedSymbol {
            scope: scope.clone(),
            tag: security.sign_symbol_tag(&symbol),
            symbol,
        });
    }
    if symbols.len() > MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS {
        return Err(RaptorRefusal::DecodeBudgetExceeded {
            offered: symbols.len(),
            maximum: MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
        });
    }
    Ok(ProtectedMicrosegment { scope, symbols })
}

/// Reconstructs into quarantine and re-verifies every original microsegment commitment.
pub fn reconstruct_microsegment(
    expected: &MicrosegmentScope,
    symbols: &[ScopedSymbol],
    limits: &SegmentLimits,
    security: &SecurityContext,
) -> Result<VerifiedMicrosegment, RaptorRefusal> {
    let source_symbols = expected.source_symbols()?;
    if symbols.len() > MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS {
        return Err(RaptorRefusal::DecodeBudgetExceeded {
            offered: symbols.len(),
            maximum: MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
        });
    }
    let mut decoder = DecodingPipeline::with_auth(decoding_config(), security.clone());
    decoder
        .set_object_params(ObjectParams::new(
            expected.engine_object_id(),
            expected.source_len(),
            MicrosegmentRaptorProfile::SYMBOL_BYTES,
            1,
            source_symbols,
        ))
        .map_err(|_| RaptorRefusal::DecodeFailed)?;
    for scoped in symbols {
        validate_symbol(expected, scoped, source_symbols)?;
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
            // `microsegment_v1` declares exactly one source block.  Once the
            // decoder completes it, later repair symbols are redundant and
            // feeding them would correctly yield `BlockAlreadyDecoded`; that
            // terminal decoder state is not a refusal of the verified
            // candidate.
            SymbolAcceptResult::BlockComplete { .. } => break,
        }
    }
    let bytes = decoder
        .into_data()
        .map_err(|_| RaptorRefusal::DecodeFailed)?;
    // DEFENSIVE, NOT INPUT-REACHABLE -- same argument as the checkpoint chain.
    // `ObjectParams` above carries `expected.source_len()`, which is exactly
    // what this compares against, so only an engine breaking its own contract
    // reaches this arm. Uncovered on purpose (frankengit-zrxa).
    if u64::try_from(bytes.len()).ok() != Some(expected.source_len()) {
        return Err(RaptorRefusal::CandidateLengthMismatch);
    }
    let reader = MicrosegmentReader::open(&bytes, &CryptoDigest, limits)
        .map_err(|_| RaptorRefusal::CandidateStructureMismatch)?;
    let candidate_scope = MicrosegmentScope::from_verified_reader(&reader, bytes.len())?;
    if candidate_scope != *expected {
        return Err(RaptorRefusal::CandidateCommitmentMismatch);
    }
    Ok(VerifiedMicrosegment {
        scope: candidate_scope,
        bytes,
    })
}

/// Authority-and-placement seam used after quarantine verification succeeds.
///
/// Storage listing never reaches this trait.  The implementation must read the
/// current authority/retention basis and perform a root-last placement publish.
pub trait RepairPlacementAuthority {
    /// Revalidates current authority and retention immediately before publication.
    fn revalidate(
        &self,
        manifest: &SegmentManifest,
        authority_basis: RepositoryAuthorityHeadId,
    ) -> AuthorityRevalidation;

    /// Publishes only a verified candidate under the revalidated authority basis.
    ///
    /// An `Ok(())` result means that the supplied manifest's existing identity
    /// is the placement identity. Implementations use body-first, root-last
    /// publication and return `Err` without partial visibility.
    fn publish_verified(
        &self,
        candidate: &VerifiedMicrosegment,
        manifest: &SegmentManifest,
        authority_basis: RepositoryAuthorityHeadId,
    ) -> Result<(), RaptorRefusal>;
}

/// Immutable authority inputs for one repair attempt.
#[derive(Clone, Copy)]
pub struct RepairPlan<'a> {
    /// The scope retained with the protected microsegment symbols.
    pub expected: &'a MicrosegmentScope,
    /// The authenticated location manifest; physical listings are not accepted.
    pub manifest: &'a SegmentManifest,
    /// The authority head against which the repair was planned.
    pub authority_basis: RepositoryAuthorityHeadId,
}

/// Quarantine repair followed by current-authority revalidation and publication.
pub fn repair_microsegment(
    plan: RepairPlan<'_>,
    symbols: &[ScopedSymbol],
    limits: &SegmentLimits,
    security: &SecurityContext,
    ledger: &ObligationLedger,
    budget: BudgetGrant,
    authority: &impl RepairPlacementAuthority,
) -> Result<SegmentManifestId, RaptorRefusal> {
    let manifest_id = match plan.manifest.identity() {
        Ok(identity) => identity,
        Err(_) => {
            let _receipt = budget.release();
            return Err(RaptorRefusal::ManifestIdentityUnavailable);
        }
    };
    if plan.manifest.namespace() != plan.expected.namespace()
        || plan.manifest.segment_digest() != plan.expected.segment_digest()
    {
        let _receipt = budget.release();
        return Err(RaptorRefusal::ManifestScopeMismatch);
    }
    let source_symbols = match plan.expected.source_symbols() {
        Ok(count) => count,
        Err(refusal) => {
            let _receipt = budget.release();
            return Err(refusal);
        }
    };
    let decode_budget_symbols = match u32::try_from(symbols.len()) {
        Ok(count) => count,
        Err(_) => {
            let _receipt = budget.release();
            return Err(RaptorRefusal::DecodeBudgetExceeded {
                offered: symbols.len(),
                maximum: MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
            });
        }
    };
    // NOT EXERCISABLE THROUGH THE CURRENT SOLE CALLER, and the distinction
    // matters: this one is caller-DEPENDENT, unlike the two below.
    // `reserve` refuses when a grade in `RepairPermit::REQUIRED_GRADES`
    // (`fgit-resource` kinds.rs:915 -- `[Bytes, CpuMicros]`) is zero in the
    // grant. The only production caller is `fgit-repair` (lib.rs:795), which
    // passes a `ScrubProfile` budget, and `ScrubProfile::new` already rejects a
    // zero over `[Grade::Bytes, Grade::CpuMicros]` (fgit-repair lib.rs:131) --
    // the SAME two grades. The profile constructor therefore pre-empts this
    // refusal today.
    //
    // `repair_microsegment` is `pub` and takes `budget` as a parameter, so a
    // second caller supplying a zero-grade grant reaches this immediately. It
    // is uncovered because nothing can currently reach it, NOT because it
    // cannot be reached (frankengit-zrxa, frankengit-0om4).
    let reservation = ledger
        .reserve::<RepairPermit>(
            RepairRequest {
                target: manifest_id,
                decode_budget_symbols,
                source_symbols: u32::from(source_symbols),
            },
            budget,
        )
        .map_err(|_| RaptorRefusal::RepairReservationRefused)?;
    let spent = reservation.reserved();
    let candidate = match reconstruct_microsegment(plan.expected, symbols, limits, security) {
        Ok(candidate) => candidate,
        Err(refusal) => {
            settle_abort(reservation, RepairAbortReason::DecodeFailed, &spent)?;
            return Err(refusal);
        }
    };
    let reader = match MicrosegmentReader::open(candidate.bytes(), &CryptoDigest, limits) {
        Ok(reader) => reader,
        Err(_) => {
            settle_abort(reservation, RepairAbortReason::CommitmentMismatch, &spent)?;
            return Err(RaptorRefusal::CandidateStructureMismatch);
        }
    };
    if plan.manifest.verify_segment_reality(&reader).is_err() {
        settle_abort(reservation, RepairAbortReason::CommitmentMismatch, &spent)?;
        return Err(RaptorRefusal::ManifestRealityMismatch);
    }
    match authority.revalidate(plan.manifest, plan.authority_basis) {
        AuthorityRevalidation::StillCurrent => {}
        AuthorityRevalidation::HeadMoved => {
            settle_abort(reservation, RepairAbortReason::AuthorityMoved, &spent)?;
            return Err(RaptorRefusal::AuthorityHeadMoved);
        }
        AuthorityRevalidation::RetentionExpired => {
            settle_abort(reservation, RepairAbortReason::RetentionExpired, &spent)?;
            return Err(RaptorRefusal::RetentionExpired);
        }
    }
    // UNREACHABLE BY CONSTRUCTION, caller-independent. `spent` is
    // `reservation.reserved()`, taken above, and `can_settle(actual)` is
    // `self.reserved().first_deficit(actual)` (fgit-resource twophase.rs:409),
    // where `first_deficit` yields `Some` only where `available < requested`
    // (algebra.rs:231). This compares the reservation against ITSELF, so no
    // grade can be short and no caller can change that. Kept as a
    // fail-closed guard against a future change that makes `spent` a real
    // measurement rather than the reservation (frankengit-zrxa).
    if reservation.can_settle(&spent).is_err() {
        let _settled = reservation.abort_unused(RepairNotPublished {
            reason: RepairAbortReason::PlacementWriteFailed,
        });
        return Err(RaptorRefusal::RepairSettlementRefused);
    }
    match authority.publish_verified(&candidate, plan.manifest, plan.authority_basis) {
        Ok(()) => {}
        Err(_) => {
            settle_abort(reservation, RepairAbortReason::PlacementWriteFailed, &spent)?;
            return Err(RaptorRefusal::PlacementPublicationRefused);
        }
    }
    let placement = manifest_id;
    // UNREACHABLE BY CONSTRUCTION, caller-independent. `RepairPublished::verified`
    // refuses only on its first three arguments, and all three are passed here
    // as literal accepting constants. The `Err` arm below is therefore dead
    // until one of them becomes a computed value -- which is exactly when it
    // starts earning its keep (frankengit-zrxa).
    let receipt = match RepairPublished::verified(
        DecodeOutcome::Succeeded,
        CommitmentCheck::AllVerified,
        AuthorityRevalidation::StillCurrent,
        placement,
        plan.authority_basis,
    ) {
        Ok(receipt) => receipt,
        Err(_) => {
            settle_abort(reservation, RepairAbortReason::CommitmentMismatch, &spent)?;
            return Err(RaptorRefusal::RepairSettlementRefused);
        }
    };
    let _settled = reservation
        .commit_internal(receipt, &spent)
        .map_err(|failure| {
            let _settled = failure.into_obligation().abort_unused(RepairNotPublished {
                reason: RepairAbortReason::PlacementWriteFailed,
            });
            RaptorRefusal::RepairSettlementRefused
        })?;
    Ok(placement)
}

fn settle_abort(
    reservation: fgit_resource::ReservedObligation<RepairPermit>,
    reason: RepairAbortReason,
    spent: &ResourceVector,
) -> Result<(), RaptorRefusal> {
    reservation
        .can_settle(spent)
        .map_err(|_| RaptorRefusal::RepairSettlementRefused)?;
    reservation
        .abort(RepairNotPublished { reason }, spent)
        .map(|_| ())
        .map_err(|failure| {
            let _settled = failure
                .into_obligation()
                .abort_unused(RepairNotPublished { reason });
            RaptorRefusal::RepairSettlementRefused
        })
}

fn validate_symbol(
    expected: &MicrosegmentScope,
    scoped: &ScopedSymbol,
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
    let source = id.is_source(u32::from(source_symbols));
    if source != scoped.symbol.kind().is_source() {
        return Err(RaptorRefusal::EncodingSymbolKindMismatch);
    }
    let expected_size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);
    if scoped.symbol.len() != expected_size {
        return Err(RaptorRefusal::SymbolSizeMismatch {
            offered: scoped.symbol.len(),
            expected: expected_size,
        });
    }
    Ok(())
}

pub(crate) const fn encoding_config() -> EncodingConfig {
    EncodingConfig {
        repair_overhead: 1.0,
        max_block_size: MicrosegmentRaptorProfile::MAX_SOURCE_BYTES,
        symbol_size: MicrosegmentRaptorProfile::SYMBOL_BYTES,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

pub(crate) const fn decoding_config() -> DecodingConfig {
    DecodingConfig {
        symbol_size: MicrosegmentRaptorProfile::SYMBOL_BYTES,
        max_block_size: MicrosegmentRaptorProfile::MAX_SOURCE_BYTES,
        repair_overhead: 1.0,
        min_overhead: 0,
        max_buffered_symbols: MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
        block_timeout: Duration::from_secs(30),
        verify_auth: true,
    }
}

pub(crate) fn symbol_pool() -> SymbolPool {
    SymbolPool::new_with_pool_id(
        PoolConfig::new(
            MicrosegmentRaptorProfile::SYMBOL_BYTES,
            MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
            MicrosegmentRaptorProfile::MAX_DECODE_SYMBOLS,
            false,
            0,
        ),
        0,
    )
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use fgit_object_fabric::fabric::ManifestLimits;
    use fgit_object_fabric::{
        DigestAlgorithm, MicrosegmentBuilder, ObjectEnvelope, ObjectKind, SegmentRecordInput,
    };
    use fgit_resource::{Grade, LeakDisposition, RegionId};
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitOid, GitOidSha1};

    use super::*;
    // Not imported by the parent: production reads symbol ids and kinds,
    // never constructs them. The forgeries below have to.
    use asupersync::types::{SymbolId, SymbolKind};

    fn canonical_segment() -> Vec<u8> {
        let limits = SegmentLimits::default();
        let payload = b"raptorq protected canonical microsegment";
        let digest = CryptoDigest;
        let envelope = ObjectEnvelope::new(
            b"tenant-a".to_vec(),
            GitOid::Sha1(GitOidSha1::from_bytes([7; GitOidSha1::LEN])),
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("test payload length fits u64"),
            digest
                .payload_commitment(ObjectKind::Blob, payload)
                .expect("test payload has a native commitment"),
            b"canonical-codec".to_vec(),
            [9; 32],
            None,
            &limits,
        )
        .expect("test envelope is canonical");
        let mut builder = MicrosegmentBuilder::new(&digest, limits);
        builder
            .push(SegmentRecordInput {
                envelope,
                payload: payload.to_vec(),
            })
            .expect("test record is canonical");
        builder
            .build()
            .expect("test microsegment builds")
            .as_bytes()
            .to_vec()
    }

    fn security() -> SecurityContext {
        SecurityContext::for_testing(24)
    }

    fn lossy_symbols(protected: &ProtectedMicrosegment) -> Vec<ScopedSymbol> {
        protected
            .symbols()
            .iter()
            .filter(|scoped| !(scoped.symbol.kind().is_source() && scoped.symbol.id().esi() < 2))
            .cloned()
            .collect()
    }

    fn manifest(bytes: &[u8]) -> SegmentManifest {
        let limits = SegmentLimits::default();
        let reader = MicrosegmentReader::open(bytes, &CryptoDigest, &limits)
            .expect("test microsegment verifies");
        SegmentManifest::from_verified_segment(&reader, Vec::new(), &ManifestLimits::default())
            .expect("test manifest comes from verified reality")
    }

    fn head(value: u8) -> RepositoryAuthorityHeadId {
        RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[value; 32]).expect("32-byte corpus fixture body"),
        )
    }

    fn ledger(region: u64) -> ObligationLedger {
        ObligationLedger::root(
            RegionId::new(region),
            LeakDisposition::RecordAndContinue,
            ResourceVector::from_grades(&[(Grade::Bytes, 16_384), (Grade::CpuMicros, 1_000)]),
        )
    }

    #[derive(Debug)]
    struct TestAuthority {
        revalidation: AuthorityRevalidation,
        published: Cell<bool>,
    }

    impl RepairPlacementAuthority for TestAuthority {
        fn revalidate(
            &self,
            _manifest: &SegmentManifest,
            _authority_basis: RepositoryAuthorityHeadId,
        ) -> AuthorityRevalidation {
            self.revalidation
        }

        fn publish_verified(
            &self,
            _candidate: &VerifiedMicrosegment,
            _manifest: &SegmentManifest,
            _authority_basis: RepositoryAuthorityHeadId,
        ) -> Result<(), RaptorRefusal> {
            self.published.set(true);
            Ok(())
        }
    }

    #[test]
    fn encode_lose_symbols_repair_and_verify_byte_identical_microsegment() {
        let bytes = canonical_segment();
        let security = security();
        let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("canonical microsegment is profile-admitted");
        let repaired = reconstruct_microsegment(
            protected.scope(),
            &lossy_symbols(&protected),
            &SegmentLimits::default(),
            &security,
        )
        .expect("repair symbols reconstruct the missing source symbols");
        assert_eq!(repaired.bytes(), bytes);
        assert_eq!(repaired.scope(), protected.scope());
    }

    #[test]
    fn wrong_scope_is_refused_before_decode_and_matching_scope_proceeds() {
        let bytes = canonical_segment();
        let security = security();
        let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("canonical microsegment is profile-admitted");
        assert!(
            reconstruct_microsegment(
                protected.scope(),
                protected.symbols(),
                &SegmentLimits::default(),
                &security,
            )
            .is_ok()
        );
        let mut injected = protected.symbols().to_vec();
        injected[0].scope.namespace = b"tenant-b".to_vec();
        assert_eq!(
            reconstruct_microsegment(
                protected.scope(),
                &injected,
                &SegmentLimits::default(),
                &security,
            ),
            Err(RaptorRefusal::ScopeMismatch)
        );
    }

    #[test]
    fn corrupt_symbol_is_not_accepted_and_the_signed_twin_proceeds() {
        let bytes = canonical_segment();
        let security = security();
        let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("canonical microsegment is profile-admitted");
        assert!(
            reconstruct_microsegment(
                protected.scope(),
                protected.symbols(),
                &SegmentLimits::default(),
                &security,
            )
            .is_ok()
        );
        let mut corrupt = protected.symbols().to_vec();
        corrupt[0].symbol.data_mut()[0] ^= 1;
        assert_eq!(
            reconstruct_microsegment(
                protected.scope(),
                &corrupt,
                &SegmentLimits::default(),
                &security,
            ),
            Err(RaptorRefusal::AuthenticationRejected)
        );
    }

    #[test]
    fn profile_encoding_is_deterministic_for_identical_scope_and_key() {
        let bytes = canonical_segment();
        let security = security();
        let first = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("first encoding succeeds");
        let second = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("second encoding succeeds");
        assert_eq!(first.scope(), second.scope());
        assert_eq!(first.symbols().len(), second.symbols().len());
        for (left, right) in first.symbols().iter().zip(second.symbols()) {
            assert_eq!(left.symbol, right.symbol);
            assert_eq!(left.tag, right.tag);
        }
    }

    #[test]
    fn stale_repair_is_discarded_and_current_authority_publishes_verified_candidate() {
        let bytes = canonical_segment();
        let security = security();
        let protected = protect_microsegment(&bytes, &SegmentLimits::default(), &security)
            .expect("canonical microsegment is profile-admitted");
        let manifest = manifest(&bytes);
        let plan = RepairPlan {
            expected: protected.scope(),
            manifest: &manifest,
            authority_basis: head(5),
        };
        let stale_ledger = ledger(1);
        let stale_authority = TestAuthority {
            revalidation: AuthorityRevalidation::HeadMoved,
            published: Cell::new(false),
        };
        let stale_budget = stale_ledger
            .grant(ResourceVector::from_grades(&[
                (Grade::Bytes, 4096),
                (Grade::CpuMicros, 100),
            ]))
            .expect("test repair budget is available");
        assert_eq!(
            repair_microsegment(
                plan,
                &lossy_symbols(&protected),
                &SegmentLimits::default(),
                &security,
                &stale_ledger,
                stale_budget,
                &stale_authority,
            ),
            Err(RaptorRefusal::AuthorityHeadMoved)
        );
        assert!(!stale_authority.published.get());
        assert!(stale_ledger.close().is_quiescent());

        let current_ledger = ledger(2);
        let current_authority = TestAuthority {
            revalidation: AuthorityRevalidation::StillCurrent,
            published: Cell::new(false),
        };
        let current_budget = current_ledger
            .grant(ResourceVector::from_grades(&[
                (Grade::Bytes, 4096),
                (Grade::CpuMicros, 100),
            ]))
            .expect("test repair budget is available");
        let placement = repair_microsegment(
            plan,
            &lossy_symbols(&protected),
            &SegmentLimits::default(),
            &security,
            &current_ledger,
            current_budget,
            &current_authority,
        )
        .expect("current authority permits verified repair publication");
        assert_eq!(placement, manifest.identity().expect("manifest identifies"));
        assert!(current_authority.published.get());
        assert!(current_ledger.close().is_quiescent());
    }

    /// The microsegment twins of the checkpoint accept-chain probes.
    ///
    /// These are NOT redundant with the ones in `checkpoint.rs`. The two chains
    /// are byte-for-byte indistinguishable from their refusals, payload
    /// included, because `CheckpointRaptorProfile::SYMBOL_BYTES` and
    /// `MicrosegmentRaptorProfile::SYMBOL_BYTES` are both 128. The only thing
    /// that tells the two sites apart is which entry point the caller invoked,
    /// so a probe against one chain says nothing about the other. If either
    /// profile constant ever diverges, these are the tests that keep the split
    /// honest.
    fn forged_scoped(
        scope: &MicrosegmentScope,
        sbn: u8,
        esi: u32,
        len: usize,
        kind: SymbolKind,
        security: &SecurityContext,
    ) -> ScopedSymbol {
        let data = vec![0x5a_u8; len];
        let symbol = Symbol::from_slice(
            SymbolId::new(scope.engine_object_id(), sbn, esi),
            &data,
            kind,
        );
        ScopedSymbol {
            scope: scope.clone(),
            tag: security.sign_symbol_tag(&symbol),
            symbol,
        }
    }

    #[test]
    fn a_microsegment_symbol_naming_a_second_source_block_is_refused_for_that_reason() {
        let security = security();
        let protected =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = protected.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);

        let refusal = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                1,
                0,
                size,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::SourceBlockMismatch)),
            "a non-zero source block number must refuse as SourceBlockMismatch, got {refusal:?}"
        );

        let twin = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::SourceBlockMismatch)),
            "sbn 0 must clear the source-block guard on the microsegment chain too"
        );
    }

    #[test]
    fn a_microsegment_repair_symbol_in_a_source_slot_is_refused_as_a_kind_mismatch() {
        let security = security();
        let protected =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = protected.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);
        let source_symbols = scope
            .source_symbols()
            .expect("a protected scope counts its source symbols");
        assert!(
            source_symbols > 0,
            "the denominator must be non-zero or esi 0 would not name a source slot"
        );

        let refusal = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size,
                SymbolKind::Repair,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a repair-kind symbol in a source slot must refuse as EncodingSymbolKindMismatch, got {refusal:?}"
        );

        let twin = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "an agreeing kind must clear the guard; it is keyed on the disagreement"
        );
    }

    #[test]
    fn a_short_microsegment_symbol_is_refused_with_both_sizes_named() {
        let security = security();
        let protected =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = protected.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);

        let refusal = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size - 1,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        match refusal {
            Err(RaptorRefusal::SymbolSizeMismatch { offered, expected }) => {
                assert_eq!(offered, size - 1, "the refusal must name the offered size");
                assert_eq!(
                    expected, size,
                    "the refusal must name this profile's symbol size"
                );
            }
            other => panic!("a short symbol must refuse as SymbolSizeMismatch, got {other:?}"),
        }
    }

    /// `protect_microsegment` refuses bytes that are not a readable segment
    /// before it derives a scope, so a malformed source can never acquire an
    /// identity it would then be encoded under.
    #[test]
    fn bytes_that_are_not_a_readable_segment_are_refused_before_a_scope_exists() {
        let security = security();
        let limits = SegmentLimits::default();

        let refusal = protect_microsegment(b"not a canonical microsegment", &limits, &security);
        assert!(
            matches!(refusal, Err(RaptorRefusal::SourceSegmentInvalid)),
            "unreadable source bytes must refuse as SourceSegmentInvalid, got {refusal:?}"
        );

        // Permitted twin: the canonical builder's output protects, so the guard
        // discriminates on readability rather than refusing every input.
        protect_microsegment(&canonical_segment(), &limits, &security)
            .expect("a canonical segment must still protect");
    }

    /// The SECOND axis of the kind guard, which the probe above does not reach.
    ///
    /// `validate_symbol` compares `id.is_source(k)` against
    /// `kind().is_source()` -- a DISAGREEMENT test, so it has two directions and
    /// a probe from one side leaves the other uncharacterised. The test above
    /// puts a repair-kind symbol in a source slot; this one puts a source-kind
    /// symbol in a repair slot (`esi >= k`, since `is_source` is `esi < k`).
    ///
    /// Both matter: an implementation that only checked "repair symbols must not
    /// claim source slots" would pass the first probe and fail this one.
    #[test]
    fn a_source_kind_microsegment_symbol_in_a_repair_slot_is_refused_the_same_way() {
        let security = security();
        let protected =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = protected.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);
        let source_symbols = scope
            .source_symbols()
            .expect("a protected scope counts its source symbols");
        // The first repair slot. `is_source` is `esi < k`, so this is the exact
        // boundary at which the id stops claiming to be a source symbol.
        let repair_slot = u32::from(source_symbols);

        let refusal = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                repair_slot,
                size,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            matches!(refusal, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a source-kind symbol in a repair slot must refuse as EncodingSymbolKindMismatch, got {refusal:?}"
        );

        // Permitted twin at the exact boundary: same slot, kind corrected.
        let twin = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                repair_slot,
                size,
                SymbolKind::Repair,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::EncodingSymbolKindMismatch)),
            "a repair-kind symbol in a repair slot agrees with its id and must clear the guard"
        );
    }

    /// The oversize direction of the microsegment size guard, for the same
    /// reason as its checkpoint counterpart: the guard is an inequality and the
    /// short-side probe alone would not catch a `len <` implementation.
    #[test]
    fn an_oversized_microsegment_symbol_is_refused_and_reports_its_real_length() {
        let security = security();
        let protected =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = protected.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);

        let refusal = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size + 1,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
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

    /// The microsegment twin of the `EngineObjectIdMismatch` probe. Same reason
    /// as every other paired probe in this crate: both profiles use
    /// SYMBOL_BYTES = 128, so no refusal payload separates the two chains and
    /// only the entry point does.
    #[test]
    fn a_microsegment_symbol_with_a_foreign_engine_object_id_is_refused() {
        let security = security();
        let victim =
            protect_microsegment(&canonical_segment(), &SegmentLimits::default(), &security)
                .expect("canonical microsegment is profile-admitted");
        let scope = victim.scope();
        let size = usize::from(MicrosegmentRaptorProfile::SYMBOL_BYTES);

        // A fixed object id that is not this scope's. The assertion below is
        // what makes it safe to pick one literally: if it ever collided with
        // the real id the probe would pass while testing nothing, so the
        // collision fails the test loudly instead.
        let foreign_id = ObjectId::new(0xdead_beef_dead_beef, 0xfeed_face_feed_face);
        assert_ne!(
            foreign_id,
            scope.engine_object_id(),
            "the chosen id must differ from the scope's or this probe is vacuous"
        );

        let data = vec![0x5a_u8; size];
        let symbol = Symbol::from_slice(SymbolId::new(foreign_id, 0, 0), &data, SymbolKind::Source);
        let foreign = ScopedSymbol {
            scope: scope.clone(),
            tag: security.sign_symbol_tag(&symbol),
            symbol,
        };

        let refusal =
            reconstruct_microsegment(scope, &[foreign], &SegmentLimits::default(), &security);
        assert!(
            matches!(refusal, Err(RaptorRefusal::EngineObjectIdMismatch)),
            "a foreign engine object id must refuse as EngineObjectIdMismatch, got {refusal:?}"
        );

        let twin = reconstruct_microsegment(
            scope,
            &[forged_scoped(
                scope,
                0,
                0,
                size,
                SymbolKind::Source,
                &security,
            )],
            &SegmentLimits::default(),
            &security,
        );
        assert!(
            !matches!(twin, Err(RaptorRefusal::EngineObjectIdMismatch)),
            "the scope's own engine object id must clear the guard"
        );
    }
}
