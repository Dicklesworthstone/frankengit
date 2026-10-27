//! Bounded transport of an original run across process death.
//!
//! A decoded checkpoint is untrusted data. Restoring it requires both the
//! independently retained complete run commitment and reauthentication of the
//! original head-read receipt by its issuing authority store. No current read,
//! clock, scope, budget or expiry is substituted. Recovery does not issue a
//! capability, resume a broker, or publish repository state.

use core::fmt;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityStore,
    AuthorityVersionToken, HeadKey, HeadReadReceipt, StoreInstanceId,
};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::HeadGeneration;

use crate::{AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime, RunId};

/// Hard limit for a complete local recovery checkpoint.
pub const MAX_RUN_CHECKPOINT_BYTES: usize = 64 * 1024;
/// A head is bounded before its bytes are copied or handed to a backend.
pub const MAX_RUN_CHECKPOINT_HEAD_BYTES: usize = 32 * 1024;
const MAX_HEAD_KEY_BYTES: usize = 256;
const MAGIC: &[u8] = b"frankengit-agent-run-checkpoint\0";
const VERSION: u8 = 1;

/// Failure to decode, bind or independently authenticate an original run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunCheckpointRefusal {
    /// Unsupported magic, version, fields or trailing bytes.
    Format,
    /// A declared or observed byte length exceeded this profile.
    Limit,
    /// The complete expected run, authority receipt or selected slot differs.
    Binding,
    /// The ordinary authority store refused the original read receipt.
    Authority(AuthorityFailure),
}

impl fmt::Display for RunCheckpointRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent run checkpoint refused: {self:?}")
    }
}
impl core::error::Error for RunCheckpointRefusal {}

/// Immutable recovery inputs, never authenticated merely by decoding them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCheckpoint {
    run_id: RunId,
    run_commitment: [u8; 32],
    original_read: HeadReadReceipt,
    store_instance: StoreInstanceId,
    observed_at: LogicalTime,
    verifier_profile: [u8; 32],
    scope: ClassSet,
    budget: ResourceVector,
    expiry: LogicalTime,
}

impl RunCheckpoint {
    /// Retains a complete run and the exact backend receipt from which its
    /// authenticated agent receipt was constructed. The native host separately
    /// reauthenticates this receipt before persisting the checkpoint.
    pub fn capture(
        run: &IntentRun,
        authenticated: &AuthenticatedHead,
    ) -> Result<Self, RunCheckpointRefusal> {
        if authenticated.receipt().body().is_empty()
            || authenticated.receipt().body().len() > MAX_RUN_CHECKPOINT_HEAD_BYTES
            || authenticated.receipt().key().as_bytes().len() > MAX_HEAD_KEY_BYTES
        {
            return Err(RunCheckpointRefusal::Limit);
        }
        let receipt = run
            .authority_read_receipt()
            .ok_or(RunCheckpointRefusal::Binding)?;
        let observed = AuthorityReadReceipt::from_authenticated_head(
            authenticated,
            receipt.verified_at_logical_time(),
            receipt.verifier_profile(),
        )
        .map_err(|_| RunCheckpointRefusal::Binding)?;
        if &observed != receipt {
            return Err(RunCheckpointRefusal::Binding);
        }
        let checkpoint = Self {
            run_id: run.run_id(),
            run_commitment: *run
                .commitment()
                .map_err(|_| RunCheckpointRefusal::Binding)?
                .as_bytes(),
            original_read: authenticated.receipt().clone(),
            store_instance: authenticated.verified_against(),
            observed_at: receipt.verified_at_logical_time(),
            verifier_profile: receipt.verifier_profile(),
            scope: run.allowed_operation_classes(),
            budget: run.resource_budget(),
            expiry: run.expiry(),
        };
        checkpoint.check_lengths()?;
        Ok(checkpoint)
    }

    /// Numeric lookup identity; it carries no authority.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Claimed commitment, useful only when compared with an independent pin.
    #[must_use]
    pub const fn claimed_run_commitment(&self) -> &[u8; 32] {
        &self.run_commitment
    }

    /// Strict, versioned local transport bytes. This is a derived recovery
    /// format, not a new canonical repository body or authority database.
    pub fn encode(&self) -> Result<Vec<u8>, RunCheckpointRefusal> {
        self.check_lengths()?;
        let mut out = Vec::with_capacity(self.original_read.body().len() + 512);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.run_id.value().to_be_bytes());
        out.extend_from_slice(&self.run_commitment);
        out.extend_from_slice(&self.store_instance.raw().to_be_bytes());
        let key = self.original_read.key().as_bytes();
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&self.original_read.token().to_opaque_bytes());
        out.extend_from_slice(&self.original_read.generation().get().to_be_bytes());
        let body = self.original_read.body();
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&self.observed_at.value().to_be_bytes());
        out.extend_from_slice(&self.verifier_profile);
        out.extend_from_slice(&self.scope.bits().to_be_bytes());
        for grade in Grade::ALL {
            out.extend_from_slice(&self.budget.get(grade).to_be_bytes());
        }
        out.extend_from_slice(&self.expiry.value().to_be_bytes());
        if out.len() > MAX_RUN_CHECKPOINT_BYTES {
            return Err(RunCheckpointRefusal::Limit);
        }
        Ok(out)
    }

    /// Parses bounded untrusted bytes without creating an IntentRun or an
    /// authenticated receipt. Unknown versions and alternative encodings refuse.
    pub fn decode(bytes: &[u8]) -> Result<Self, RunCheckpointRefusal> {
        if bytes.len() > MAX_RUN_CHECKPOINT_BYTES {
            return Err(RunCheckpointRefusal::Limit);
        }
        let mut input = Input(bytes);
        if input.take(MAGIC.len())? != MAGIC || input.array::<1>()? != [VERSION] {
            return Err(RunCheckpointRefusal::Format);
        }
        let run_id = RunId::new(u128::from_be_bytes(input.array()?));
        let run_commitment = input.array()?;
        let store_instance = StoreInstanceId::from_raw(u64::from_be_bytes(input.array()?));
        let key_length = usize::from(u16::from_be_bytes(input.array()?));
        if key_length == 0 || key_length > MAX_HEAD_KEY_BYTES {
            return Err(RunCheckpointRefusal::Limit);
        }
        let key = HeadKey::new(input.take(key_length)?.to_vec())
            .map_err(|_| RunCheckpointRefusal::Format)?;
        let token = AuthorityVersionToken::from_opaque_bytes(input.array()?);
        let generation = HeadGeneration::try_new(u64::from_be_bytes(input.array()?))
            .map_err(|_| RunCheckpointRefusal::Format)?;
        let body_length = u32::from_be_bytes(input.array()?) as usize;
        if body_length == 0 || body_length > MAX_RUN_CHECKPOINT_HEAD_BYTES {
            return Err(RunCheckpointRefusal::Limit);
        }
        let body = input.take(body_length)?.to_vec();
        let observed_at = LogicalTime::new(u64::from_be_bytes(input.array()?));
        let verifier_profile = input.array()?;
        let scope = ClassSet::from_bits(u16::from_be_bytes(input.array()?))
            .map_err(|_| RunCheckpointRefusal::Format)?;
        if scope.is_empty() {
            return Err(RunCheckpointRefusal::Format);
        }
        let mut budget = ResourceVector::ZERO;
        for grade in Grade::ALL {
            budget = budget.with(grade, u64::from_be_bytes(input.array()?));
        }
        let expiry = LogicalTime::new(u64::from_be_bytes(input.array()?));
        if !input.0.is_empty() {
            return Err(RunCheckpointRefusal::Format);
        }
        let checkpoint = Self {
            run_id,
            run_commitment,
            original_read: HeadReadReceipt::new(key, token, generation, body),
            store_instance,
            observed_at,
            verifier_profile,
            scope,
            budget,
            expiry,
        };
        if checkpoint.encode()? != bytes {
            return Err(RunCheckpointRefusal::Format);
        }
        Ok(checkpoint)
    }

    /// Reauthenticates the ORIGINAL receipt against the selected authority
    /// backend. `expected_run` must come from independently retained run control,
    /// not from this checkpoint. Expired runs may be recovered for cleanup;
    /// expiry, scope and spent-budget history are never reset.
    pub fn restore<S: AuthorityStore + ?Sized>(
        &self,
        store: &S,
        head_key: &HeadKey,
        expected_run: &[u8; 32],
    ) -> Result<IntentRun, RunCheckpointRefusal> {
        self.check_binding(head_key, expected_run)?;
        let authenticated = store
            .authenticate_head_receipt(&self.original_read)
            .map_err(RunCheckpointRefusal::Authority)?;
        self.finish_restore(&authenticated, expected_run)
    }

    /// Production async twin, using the backend's existing owned context and
    /// original issuance record. It does not read or reinterpret the current head.
    pub async fn restore_async<S: AsyncAuthorityStore + ?Sized>(
        &self,
        store: &S,
        cx: &S::Context,
        head_key: &HeadKey,
        expected_run: &[u8; 32],
    ) -> Result<IntentRun, RunCheckpointRefusal> {
        self.check_binding(head_key, expected_run)?;
        let authenticated = store
            .authenticate_head_receipt(cx, &self.original_read)
            .await
            .map_err(RunCheckpointRefusal::Authority)?;
        self.finish_restore(&authenticated, expected_run)
    }

    fn check_lengths(&self) -> Result<(), RunCheckpointRefusal> {
        if self.original_read.body().is_empty()
            || self.original_read.body().len() > MAX_RUN_CHECKPOINT_HEAD_BYTES
            || self.original_read.key().as_bytes().len() > MAX_HEAD_KEY_BYTES
        {
            return Err(RunCheckpointRefusal::Limit);
        }
        Ok(())
    }

    fn check_binding(
        &self,
        head_key: &HeadKey,
        expected_run: &[u8; 32],
    ) -> Result<(), RunCheckpointRefusal> {
        self.check_lengths()?;
        if &self.run_commitment != expected_run || self.original_read.key() != head_key {
            return Err(RunCheckpointRefusal::Binding);
        }
        Ok(())
    }

    fn finish_restore(
        &self,
        authenticated: &AuthenticatedHead,
        expected_run: &[u8; 32],
    ) -> Result<IntentRun, RunCheckpointRefusal> {
        if authenticated.receipt() != &self.original_read
            || authenticated.verified_against() != self.store_instance
        {
            return Err(RunCheckpointRefusal::Binding);
        }
        let authority = AuthorityReadReceipt::from_authenticated_head(
            authenticated,
            self.observed_at,
            self.verifier_profile,
        )
        .map_err(|_| RunCheckpointRefusal::Binding)?;
        let run = IntentRun::new_authenticated(
            self.run_id,
            authority,
            self.scope,
            self.budget,
            self.expiry,
        )
        .map_err(|_| RunCheckpointRefusal::Binding)?;
        if run
            .commitment()
            .map_err(|_| RunCheckpointRefusal::Binding)?
            .as_bytes()
            != expected_run
        {
            return Err(RunCheckpointRefusal::Binding);
        }
        Ok(run)
    }
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], RunCheckpointRefusal> {
        let value = self.0.get(..length).ok_or(RunCheckpointRefusal::Format)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RunCheckpointRefusal> {
        self.take(N)?
            .try_into()
            .map_err(|_| RunCheckpointRefusal::Format)
    }
}
