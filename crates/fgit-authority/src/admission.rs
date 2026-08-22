//! Admission receipts over a seal identity.
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §5.2 keeps four facts deliberately outside
//! the seal body: the admission capability, the policy epoch, the issuer, and
//! the first-seen time. They are *separate immutable admission receipts over
//! the seal ID*, and they are **not fields a retry must regenerate**.
//!
//! That last clause is the whole design. A retry arrives later, under a
//! possibly different capability, in a possibly later policy epoch, and it must
//! not overwrite what was recorded when the transaction was first admitted —
//! otherwise the record of when and under what authority a mutation entered the
//! system would drift every time a client retried.
//!
//! So admission is put-if-absent against a slot keyed by the seal identity, and
//! a second attempt does not fail and does not overwrite: it *inherits*. The
//! caller learns what the first admission said, which is the fact it actually
//! needs.
//!
//! # No wall clock
//!
//! First-seen is an [`AdmissionInstant`], a caller-supplied logical instant. A
//! wall-clock read here would make the record non-deterministic and would put a
//! clock inside the publication boundary; the gateway that owns a clock passes
//! one in.

use fgit_codec::wire::{CanonicalBody, encode_body};
use fgit_codec::{CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::identity::{AdmissionReceiptId, PrincipalId, TransactionSealId};
use fgit_types::label::{AsciiSlug, DomainTag, SchemaFamily};
use fgit_types::numeric::PolicyEpoch;

use crate::async_contract::AsyncAuthorityStore;
use crate::contract::AuthorityStore;
use crate::identity::canonical_body_id;
use crate::keys::ImmutableKey;
use crate::seal::SealFailure;
use crate::vocabulary::{ImmutableRead, PutOutcome};

/// Namespace prefix of an admission-receipt slot.
pub const ADMISSION_KEY_PREFIX: &[u8] = b"fg/admit/v1/";

/// A logical instant supplied by the admitting gateway.
///
/// Not a wall clock: the value is whatever monotone logical time the caller
/// keeps, so an admission record is reproducible in a replay.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdmissionInstant(u64);

impl AdmissionInstant {
    /// Name an instant.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw instant.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The immutable record of how one sealed transaction was admitted.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdmissionReceiptBody {
    /// The seal this receipt is over.
    pub seal_id: TransactionSealId,
    /// The capability the gateway admitted the request under.
    pub admission_capability: AsciiSlug,
    /// The policy epoch pinned at admission.
    pub policy_epoch: PolicyEpoch,
    /// The principal that issued the admission.
    pub issuer: PrincipalId,
    /// When the request was first seen, in the caller's logical time.
    pub first_seen: AdmissionInstant,
}

impl CanonicalBody for AdmissionReceiptBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/admission-receipt/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("admission-receipt");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_internal_object_id(self.seal_id.as_internal_object_id())?;
        out.write_bytes("admission_capability", self.admission_capability.as_bytes())?;
        out.write_scalar(self.policy_epoch.get());
        out.write_opaque_id(self.issuer.as_bytes());
        out.write_scalar(self.first_seen.raw());
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let seal_id = TransactionSealId::from_internal_object_id(input.read_internal_object_id()?)?;
        let admission_capability = AsciiSlug::try_new(
            "admission_capability",
            input.read_bytes("admission_capability")?,
        )?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("policy_epoch")?)?;
        let issuer = PrincipalId::from_bytes(input.read_opaque_id("issuer")?);
        let first_seen = AdmissionInstant::from_raw(input.read_scalar::<u64>("first_seen")?);
        Ok(Self {
            seal_id,
            admission_capability,
            policy_epoch,
            issuer,
            first_seen,
        })
    }
}

impl AdmissionReceiptBody {
    /// The receipt's own domain-pinned identity.
    ///
    /// Typed rather than a bare `InternalObjectId`: `AdmissionReceiptId`
    /// refuses a digest carrying any other domain on the way in, so an
    /// evidence record cannot arrive where an admission receipt belongs.
    pub fn identity(&self) -> Result<AdmissionReceiptId, SealFailure> {
        let id = canonical_body_id(
            IdentityDomain::AdmissionReceipt,
            CANONICAL_CODEC_VERSION,
            self,
        )?;
        AdmissionReceiptId::from_internal_object_id(id).map_err(|_| {
            SealFailure::SlotContentUnexpected {
                slot: "admission-receipt",
            }
        })
    }
}

/// How an admission attempt resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    /// This attempt recorded the admission.
    Admitted(AdmissionReceiptBody),
    /// An earlier attempt already did, and this is what it recorded.
    ///
    /// A retry inherits rather than regenerating, so the capability, epoch,
    /// issuer, and first-seen time stay those of the first admission.
    AlreadyAdmitted(AdmissionReceiptBody),
}

impl AdmissionOutcome {
    /// The receipt in force, however this attempt resolved.
    #[must_use]
    pub const fn receipt(&self) -> &AdmissionReceiptBody {
        match self {
            Self::Admitted(receipt) | Self::AlreadyAdmitted(receipt) => receipt,
        }
    }

    /// Whether this attempt is the one that recorded the admission.
    #[must_use]
    pub const fn is_first(&self) -> bool {
        matches!(*self, Self::Admitted(_))
    }
}

/// The deterministic admission slot key for one seal identity.
pub fn admission_key(seal_id: TransactionSealId) -> Result<ImmutableKey, SealFailure> {
    let mut bytes = Vec::with_capacity(ADMISSION_KEY_PREFIX.len() + 80);
    bytes.extend_from_slice(ADMISSION_KEY_PREFIX);
    bytes.extend_from_slice(seal_id.as_internal_object_id().digest().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}

/// Record how a sealed transaction was admitted, or report the earlier record.
pub fn record_admission<S>(
    store: &S,
    receipt: &AdmissionReceiptBody,
) -> Result<AdmissionOutcome, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = admission_key(receipt.seal_id)?;
    let bytes = encode_body(receipt)?;
    match classify_admission(store.put_if_absent(&key, &bytes)?, receipt) {
        Some(settled) => Ok(settled),
        None => Ok(AdmissionOutcome::AlreadyAdmitted(
            read_admission(store, receipt.seal_id)?.ok_or(SealFailure::SlotContentUnexpected {
                slot: "admission-receipt",
            })?,
        )),
    }
}

/// What a receipt write means, when the store's answer settles it alone.
///
/// Shared decision core. `None` means the slot already holds a *different*
/// receipt for this seal and must be read back, which is the only step where
/// the two surfaces differ.
///
/// The `Conflict` arm is deliberately not an error: a second admission attempt
/// for an already-admitted seal is the idempotent case §5.2 requires, and the
/// caller is owed the receipt that won rather than a refusal.
fn classify_admission(
    outcome: PutOutcome,
    receipt: &AdmissionReceiptBody,
) -> Option<AdmissionOutcome> {
    match outcome {
        PutOutcome::Created => Some(AdmissionOutcome::Admitted(receipt.clone())),
        PutOutcome::IdenticalRetry => Some(AdmissionOutcome::AlreadyAdmitted(receipt.clone())),
        PutOutcome::Conflict => None,
    }
}

/// Interpret the bytes an admission slot holds, requiring them to name `seal_id`.
///
/// The other half of the shared core: both surfaces must apply the same
/// cross-check, or one of them returns a receipt belonging to another seal.
fn interpret_admission_slot(
    read: ImmutableRead,
    seal_id: TransactionSealId,
) -> Result<Option<AdmissionReceiptBody>, SealFailure> {
    let ImmutableRead::Present(bytes) = read else {
        return Ok(None);
    };
    let receipt: AdmissionReceiptBody = decode_body(&bytes, DecodeLimits::DEFAULT)?;
    if receipt.seal_id == seal_id {
        Ok(Some(receipt))
    } else {
        Err(SealFailure::SlotContentUnexpected {
            slot: "admission-receipt",
        })
    }
}

/// Read the admission record for one seal identity, if it has one.
pub fn read_admission<S>(
    store: &S,
    seal_id: TransactionSealId,
) -> Result<Option<AdmissionReceiptBody>, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let key = admission_key(seal_id)?;
    interpret_admission_slot(store.read_immutable(&key)?, seal_id)
}

// --- the production surface -------------------------------------------------
//
// Asynchronous siblings of `record_admission` and `read_admission`, sharing the
// pure core above. A node publishing its first RCR must record how the
// transaction was admitted before the head moves, and `FsqliteAuthorityStore`
// implements `AsyncAuthorityStore` only — so without these the rule would be
// copied into the node and the two copies would be free to disagree.

/// Record how a sealed transaction was admitted, asynchronously.
///
/// The asynchronous twin of [`record_admission`], including the idempotent
/// reading of a conflict: a second attempt for an already-admitted seal returns
/// the receipt that won rather than refusing.
///
/// # Errors
///
/// [`SealFailure::SlotContentUnexpected`] when a conflicting slot reads back
/// empty, or holds a receipt naming a different seal.
pub async fn record_admission_async<S>(
    store: &S,
    cx: &S::Context,
    receipt: &AdmissionReceiptBody,
) -> Result<AdmissionOutcome, SealFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = admission_key(receipt.seal_id)?;
    let bytes = encode_body(receipt)?;
    match classify_admission(store.put_if_absent(cx, &key, &bytes).await?, receipt) {
        Some(settled) => Ok(settled),
        None => Ok(AdmissionOutcome::AlreadyAdmitted(
            read_admission_async(store, cx, receipt.seal_id)
                .await?
                .ok_or(SealFailure::SlotContentUnexpected {
                    slot: "admission-receipt",
                })?,
        )),
    }
}

/// Read the admission record for one seal identity, asynchronously.
///
/// The asynchronous twin of [`read_admission`], including its cross-check that
/// the decoded receipt names the seal whose slot was read.
///
/// # Errors
///
/// [`SealFailure::SlotContentUnexpected`] when the slot holds a receipt for a
/// different seal.
pub async fn read_admission_async<S>(
    store: &S,
    cx: &S::Context,
    seal_id: TransactionSealId,
) -> Result<Option<AdmissionReceiptBody>, SealFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let key = admission_key(seal_id)?;
    interpret_admission_slot(store.read_immutable(cx, &key).await?, seal_id)
}
