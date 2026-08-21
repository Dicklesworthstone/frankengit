//! Key rotation, revocation, and cryptographic erasure.
//!
//! The bead's rotation drill is three statements that have to hold at once:
//! data written under an old key stays readable through the key history, new
//! writes use the new key, and revocation cuts issuance and is receipted.
//! [`KeyHistory`] is where those meet, because they are the same question
//! asked of different epochs — *may this epoch issue?* versus *may this epoch
//! verify?* — and answering them with one boolean is how a revoked key keeps
//! signing.
//!
//! # Erasure is a state, not an absence
//!
//! Plan section 19.4 makes cryptographic erasure a typed deletion state with
//! its own evidence. That is a stronger requirement than it looks: an erased
//! epoch must not answer "unknown key", because unknown invites a caller to
//! retry, resynchronise, or treat the data as corrupt. It answers
//! [`KeyLifecycleError::MaterialErased`], which says the ciphertext is
//! permanently unrecoverable *by design* and names the epoch that was
//! destroyed. [`Recoverability`] states the same fact as a value a caller can
//! branch on without matching an error.
//!
//! # Receipts
//!
//! Every transition returns a receipt with canonical bytes and a
//! domain-separated identity under
//! [`IdentityDomain::KeyLifecycleReceipt`](crate::IdentityDomain), so the
//! deletion and revocation evidence fg033 and fg010 need is a body they can
//! commit rather than a log line. This crate produces the receipt; it does not
//! store it, and it does not decide retention.
//!
//! # Non-claims
//!
//! A receipt is a canonical record, not an authenticated one: nothing here
//! signs it, because signing is behind the D8 primitive ruling. It binds its
//! own contents through its identity digest, which detects alteration by
//! anyone who re-derives it, and proves nothing about who issued it.
//!
//! Erasing an epoch here removes this process's copy of the material and
//! records the state. It cannot reach copies a caller made, backups, or pages
//! the allocator has not reused — see [`crate::HmacSha256`] on why scrubbing
//! is a dependency decision. Erasure evidence is a claim about the key
//! registry, not about every byte that ever held the key.

use core::fmt;
use core::marker::PhantomData;

use fgit_types::identity::InternalObjectId;
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::numeric::CodecVersion;

use crate::body_identity::internal_object_id;
use crate::keys::{KeyEpoch, KeyPurpose, KeyPurposeMarker, SecretKey};
use crate::mac::TAG_BYTES;
use crate::registry::IdentityDomain;

/// Schema family for a key-lifecycle receipt body.
pub const RECEIPT_SCHEMA_FAMILY: &str = "frankengit.key-lifecycle-receipt";

/// Schema identifier for a key-lifecycle receipt body.
pub const RECEIPT_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static(RECEIPT_SCHEMA_FAMILY), 1, 0);

/// What an epoch is permitted to do.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyLifecycle {
    /// Issues new material and verifies existing material.
    Active,
    /// Verifies existing material only. Rotation retires the previous epoch.
    Retired,
    /// Neither issues nor verifies. Revocation is a judgement that material
    /// produced under this epoch should no longer be honoured.
    Revoked,
    /// Material destroyed. Dependent ciphertext is permanently unrecoverable.
    Erased,
}

impl KeyLifecycle {
    /// Stable lowercase token used in receipt bodies.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Erased => "erased",
        }
    }

    /// Whether this state may produce new material.
    #[must_use]
    pub const fn may_issue(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this state may verify or decrypt existing material.
    #[must_use]
    pub const fn may_verify(self) -> bool {
        matches!(self, Self::Active | Self::Retired)
    }
}

impl fmt::Display for KeyLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// Whether data under an epoch can still be read.
///
/// Stated as a value rather than only as an error, so a caller can record the
/// distinction without matching on a refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Recoverability {
    /// The key exists and may verify or decrypt.
    Recoverable,
    /// The key is revoked: the material exists but must not be honoured.
    WithheldByRevocation,
    /// The key material is destroyed. No future decision restores this.
    PermanentlyUnrecoverable,
}

/// Refusal from a key-lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyLifecycleError {
    /// No epoch is currently active, so nothing may issue.
    NoActiveEpoch,
    /// The history has no record of this epoch.
    EpochUnknown {
        /// Epoch asked about.
        epoch: KeyEpoch,
    },
    /// The epoch exists but is retired, so it may verify and not issue.
    EpochRetired {
        /// Epoch asked about.
        epoch: KeyEpoch,
        /// Epoch that may issue instead.
        active: KeyEpoch,
    },
    /// The epoch is revoked. Distinct from erased: the material still exists.
    EpochRevoked {
        /// Epoch asked about.
        epoch: KeyEpoch,
    },
    /// The material is destroyed and dependent data is unrecoverable.
    ///
    /// Deliberately not [`Self::EpochUnknown`]: an unknown key invites a
    /// retry, and this is a permanent, intended state.
    MaterialErased {
        /// Epoch whose material was destroyed.
        epoch: KeyEpoch,
    },
    /// Rotation must move to a strictly later epoch.
    EpochNotMonotone {
        /// Epoch offered.
        offered: KeyEpoch,
        /// Latest epoch already recorded.
        latest: KeyEpoch,
    },
}

impl fmt::Display for KeyLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveEpoch => formatter.write_str("no epoch is active, so nothing may issue"),
            Self::EpochUnknown { epoch } => {
                write!(formatter, "epoch {epoch} is not in this key history")
            }
            Self::EpochRetired { epoch, active } => write!(
                formatter,
                "epoch {epoch} is retired and may only verify; epoch {active} issues"
            ),
            Self::EpochRevoked { epoch } => {
                write!(
                    formatter,
                    "epoch {epoch} is revoked and must not be honoured"
                )
            }
            Self::MaterialErased { epoch } => write!(
                formatter,
                "epoch {epoch} was cryptographically erased; dependent data is permanently unrecoverable"
            ),
            Self::EpochNotMonotone { offered, latest } => write!(
                formatter,
                "rotation must advance: offered {offered}, latest is {latest}"
            ),
        }
    }
}

impl std::error::Error for KeyLifecycleError {}

/// One epoch's record in a key history.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyRecord {
    epoch: KeyEpoch,
    lifecycle: KeyLifecycle,
    commitment: [u8; TAG_BYTES],
}

impl KeyRecord {
    /// The epoch this record describes.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// What this epoch may do.
    #[must_use]
    pub const fn lifecycle(&self) -> KeyLifecycle {
        self.lifecycle
    }

    /// The key commitment, which survives erasure so an erased epoch is still
    /// identifiable in evidence.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; TAG_BYTES] {
        &self.commitment
    }
}

/// A receipt for one lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LifecycleReceipt {
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    from: KeyLifecycle,
    to: KeyLifecycle,
    commitment: [u8; TAG_BYTES],
}

impl LifecycleReceipt {
    /// The purpose whose history moved.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The epoch that changed state.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The state before the transition.
    #[must_use]
    pub const fn from(&self) -> KeyLifecycle {
        self.from
    }

    /// The state after the transition.
    #[must_use]
    pub const fn to(&self) -> KeyLifecycle {
        self.to
    }

    /// Canonical bytes of this receipt.
    ///
    /// Length-prefixed like every other identity-bearing body in this crate,
    /// so two receipts cannot frame to the same bytes.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let tag = self.purpose.tag().as_bytes();
        let from = self.from.token().as_bytes();
        let to = self.to.token().as_bytes();
        let mut body = Vec::with_capacity(tag.len() + from.len() + to.len() + TAG_BYTES + 16);
        body.push(u8::try_from(tag.len()).expect("a purpose tag is shorter than 255 bytes"));
        body.extend_from_slice(tag);
        body.extend_from_slice(&self.purpose.code_point().to_be_bytes());
        body.extend_from_slice(&self.epoch.get().to_be_bytes());
        body.push(u8::try_from(from.len()).expect("a lifecycle token is shorter than 255 bytes"));
        body.extend_from_slice(from);
        body.push(u8::try_from(to.len()).expect("a lifecycle token is shorter than 255 bytes"));
        body.extend_from_slice(to);
        body.extend_from_slice(&self.commitment);
        body
    }

    /// The receipt's domain-separated identity, for binding into evidence.
    #[must_use]
    pub fn identity(&self, codec_version: CodecVersion) -> InternalObjectId {
        internal_object_id(
            IdentityDomain::KeyLifecycleReceipt,
            RECEIPT_SCHEMA,
            codec_version,
            &self.canonical_body(),
        )
    }
}

/// The rotation history of one key purpose in one scope.
#[derive(Clone, Debug)]
pub struct KeyHistory<P: KeyPurposeMarker> {
    records: Vec<KeyRecord>,
    active: Option<KeyEpoch>,
    purpose: PhantomData<P>,
}

impl<P: KeyPurposeMarker> KeyHistory<P> {
    /// Begin a history with its first active key.
    #[must_use]
    pub fn new(first: &SecretKey<P>) -> Self {
        let epoch = first.id().epoch();
        Self {
            records: vec![KeyRecord {
                epoch,
                lifecycle: KeyLifecycle::Active,
                commitment: *first.id().commitment(),
            }],
            active: Some(epoch),
            purpose: PhantomData,
        }
    }

    /// Every recorded epoch, oldest first.
    #[must_use]
    pub fn records(&self) -> &[KeyRecord] {
        &self.records
    }

    /// The epoch that may issue, if any.
    pub fn issuing_epoch(&self) -> Result<KeyEpoch, KeyLifecycleError> {
        self.active.ok_or(KeyLifecycleError::NoActiveEpoch)
    }

    fn record(&self, epoch: KeyEpoch) -> Result<&KeyRecord, KeyLifecycleError> {
        self.records
            .iter()
            .find(|record| record.epoch == epoch)
            .ok_or(KeyLifecycleError::EpochUnknown { epoch })
    }

    fn index_of(&self, epoch: KeyEpoch) -> Result<usize, KeyLifecycleError> {
        self.records
            .iter()
            .position(|record| record.epoch == epoch)
            .ok_or(KeyLifecycleError::EpochUnknown { epoch })
    }

    /// May this epoch produce new material?
    ///
    /// Only the active epoch may. A retired epoch is refused *distinctly* from
    /// a revoked or erased one, because "you are reading old data" and "this
    /// key must not be honoured" are different operational facts.
    pub fn authorize_issue(&self, epoch: KeyEpoch) -> Result<(), KeyLifecycleError> {
        let record = self.record(epoch)?;
        match record.lifecycle {
            KeyLifecycle::Active => Ok(()),
            KeyLifecycle::Retired => Err(KeyLifecycleError::EpochRetired {
                epoch,
                active: self.issuing_epoch()?,
            }),
            KeyLifecycle::Revoked => Err(KeyLifecycleError::EpochRevoked { epoch }),
            KeyLifecycle::Erased => Err(KeyLifecycleError::MaterialErased { epoch }),
        }
    }

    /// May this epoch verify or decrypt existing material?
    ///
    /// Active and retired epochs may; this is what keeps data written before a
    /// rotation readable.
    pub fn authorize_verify(&self, epoch: KeyEpoch) -> Result<(), KeyLifecycleError> {
        let record = self.record(epoch)?;
        match record.lifecycle {
            KeyLifecycle::Active | KeyLifecycle::Retired => Ok(()),
            KeyLifecycle::Revoked => Err(KeyLifecycleError::EpochRevoked { epoch }),
            KeyLifecycle::Erased => Err(KeyLifecycleError::MaterialErased { epoch }),
        }
    }

    /// Whether data under this epoch can still be read, as a value.
    pub fn recoverability(&self, epoch: KeyEpoch) -> Result<Recoverability, KeyLifecycleError> {
        Ok(match self.record(epoch)?.lifecycle {
            KeyLifecycle::Active | KeyLifecycle::Retired => Recoverability::Recoverable,
            KeyLifecycle::Revoked => Recoverability::WithheldByRevocation,
            KeyLifecycle::Erased => Recoverability::PermanentlyUnrecoverable,
        })
    }

    /// Rotate to a later epoch: the new key issues, the old one keeps
    /// verifying.
    pub fn rotate(&mut self, next: &SecretKey<P>) -> Result<LifecycleReceipt, KeyLifecycleError> {
        let epoch = next.id().epoch();
        let latest = self
            .records
            .last()
            .map_or(KeyEpoch::FIRST, |record| record.epoch);
        if epoch <= latest {
            return Err(KeyLifecycleError::EpochNotMonotone {
                offered: epoch,
                latest,
            });
        }

        if let Some(active) = self.active
            && let Ok(index) = self.index_of(active)
            && self.records[index].lifecycle == KeyLifecycle::Active
        {
            self.records[index].lifecycle = KeyLifecycle::Retired;
        }

        self.records.push(KeyRecord {
            epoch,
            lifecycle: KeyLifecycle::Active,
            commitment: *next.id().commitment(),
        });
        self.active = Some(epoch);

        Ok(LifecycleReceipt {
            purpose: P::PURPOSE,
            epoch,
            from: KeyLifecycle::Retired,
            to: KeyLifecycle::Active,
            commitment: *next.id().commitment(),
        })
    }

    /// Revoke an epoch: it stops issuing and stops being honoured.
    ///
    /// Revoking the active epoch leaves the history with nothing issuing,
    /// which is deliberate — the caller must rotate to a new key rather than
    /// have one silently chosen.
    pub fn revoke(&mut self, epoch: KeyEpoch) -> Result<LifecycleReceipt, KeyLifecycleError> {
        let index = self.index_of(epoch)?;
        let previous = self.records[index].lifecycle;
        if previous == KeyLifecycle::Erased {
            return Err(KeyLifecycleError::MaterialErased { epoch });
        }
        self.records[index].lifecycle = KeyLifecycle::Revoked;
        if self.active == Some(epoch) {
            self.active = None;
        }
        Ok(LifecycleReceipt {
            purpose: P::PURPOSE,
            epoch,
            from: previous,
            to: KeyLifecycle::Revoked,
            commitment: self.records[index].commitment,
        })
    }

    /// Cryptographically erase an epoch.
    ///
    /// Terminal: an erased epoch never returns to any other state, and data
    /// that depended on it is permanently unrecoverable. The commitment is
    /// retained so the destroyed epoch stays identifiable in evidence.
    pub fn erase(&mut self, epoch: KeyEpoch) -> Result<LifecycleReceipt, KeyLifecycleError> {
        let index = self.index_of(epoch)?;
        let previous = self.records[index].lifecycle;
        if previous == KeyLifecycle::Erased {
            return Err(KeyLifecycleError::MaterialErased { epoch });
        }
        self.records[index].lifecycle = KeyLifecycle::Erased;
        if self.active == Some(epoch) {
            self.active = None;
        }
        Ok(LifecycleReceipt {
            purpose: P::PURPOSE,
            epoch,
            from: previous,
            to: KeyLifecycle::Erased,
            commitment: self.records[index].commitment,
        })
    }
}
