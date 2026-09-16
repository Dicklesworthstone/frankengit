//! Read-only recovery of an entire non-atomic receive from its original key.
//!
//! A descriptor retains the canonical request and its wire-order permutation.
//! It is an untrusted recovery carrier, not a decision, seal, or new authority:
//! the existing whole-request binding must reproduce its identity, every child
//! binding must match the original admission lowering, and each reported outcome
//! comes from the existing scope/key/seal/outcome verifier. No raw client key,
//! credential, pack, validation basis, or locally inferred outcome is stored.

use fgit_authority::key_recovery::{
    RecoveryFailure, RecoveryScope, RequestRecovery, recover_request_async,
};
use fgit_authority::{
    AsyncAuthorityStore, ExpectedOld, ImmutableKey, ImmutableRead,
    ProposedNew, PutOutcome, SealAttempt, SemanticRequest, idempotency_binding_key,
};
use fgit_codec::{DecodeLimits, Decoder, Encoder, decode_body, encode_body};
use fgit_types::{RefName, RefusalCode, TxId};

use crate::{AdmissionContext, AdmissionError, AdmissionLimits, SessionPlan, seal_attempt};

const PREFIX: &[u8] = b"fg/receive-session/v1/";
const VERSION: u32 = 1;
const MAX_BYTES: usize = 1024 * 1024;
const LIMITS: DecodeLimits = DecodeLimits {
    frame_bytes: MAX_BYTES as u64,
    byte_string_bytes: MAX_BYTES as u64,
    elements: 256,
    depth: 16,
};

/// A descriptor is absent for legacy sessions and interrupted pre-staging work.
/// Absence cannot establish that no command was submitted or committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionRecovery {
    NotObserved,
    Recovered(Box<RecoveredSession>),
}

/// A complete, binding-verified command list with independently observed results.
/// These are not a single atomic snapshot. Terminal decisions are immutable, so
/// all-terminal completion is nevertheless sound once every listed child is
/// authenticated as terminal. Nonterminal observations may immediately change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredSession {
    identity: TxId,
    commands: Vec<RecoveredCommand>,
}
impl RecoveredSession {
    /// Whole-request binding identity; NOT an additional sealed transaction.
    #[must_use]
    pub const fn identity(&self) -> TxId { self.identity }
    #[must_use]
    pub fn commands(&self) -> &[RecoveredCommand] { &self.commands }
    #[must_use]
    pub fn all_terminal(&self) -> bool {
        !self.commands.is_empty() && self.commands.iter().all(|command| command.recovery.terminal().is_some())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredCommand {
    index: usize,
    reference: RefName,
    recovery: RequestRecovery,
}
impl RecoveredCommand {
    #[must_use]
    pub const fn index(&self) -> usize { self.index }
    #[must_use]
    pub const fn reference(&self) -> &RefName { &self.reference }
    #[must_use]
    pub const fn recovery(&self) -> &RequestRecovery { &self.recovery }
}

/// Corruption/unavailability is an error, never an invented absent descriptor.
#[derive(Debug)]
pub enum SessionRecoveryFailure {
    Recovery(Box<RecoveryFailure>),
    Admission(Box<AdmissionError>),
    Integrity(&'static str),
}
impl std::fmt::Display for SessionRecoveryFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recovery(error) => write!(out, "receive session recovery: {error}"),
            Self::Admission(error) => write!(out, "receive session recovery: {error}"),
            Self::Integrity(field) => write!(out, "receive session recovery integrity: {field}"),
        }
    }
}
impl std::error::Error for SessionRecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recovery(error) => Some(error.as_ref()),
            Self::Admission(error) => Some(error.as_ref()),
            Self::Integrity(_) => None,
        }
    }
}
impl From<RecoveryFailure> for SessionRecoveryFailure {
    fn from(error: RecoveryFailure) -> Self { Self::Recovery(Box::new(error)) }
}
impl From<AdmissionError> for SessionRecoveryFailure {
    fn from(error: AdmissionError) -> Self { Self::Admission(Box::new(error)) }
}

struct Descriptor {
    request: SemanticRequest,
    wire_order: Vec<usize>,
}

fn invalid() -> AdmissionError {
    AdmissionError::MaterializationMismatch("receive session descriptor")
}
fn codec(_: fgit_codec::CodecRefusal) -> AdmissionError { invalid() }
fn descriptor_key(context: &AdmissionContext) -> Result<ImmutableKey, AdmissionError> {
    let mut bytes = Vec::with_capacity(PREFIX.len() + 112);
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(context.tenant_id.as_bytes());
    bytes.extend_from_slice(context.repository_id.as_bytes());
    bytes.extend_from_slice(context.principal_id.as_bytes());
    bytes.extend_from_slice(context.idempotency_key.digest().bytes().as_bytes());
    ImmutableKey::new(bytes).map_err(|_| invalid())
}

impl Descriptor {
    fn validate(&self) -> Result<(), AdmissionError> {
        let count = self.request.ref_commands().len();
        if count == 0 || count > AdmissionLimits::default().max_commands
            || self.request.atomic()
            || self.request.request_schema() != fgit_authority::RECEIVE_ADMISSION_SCHEMA
            || !self.request.scoped_entries().is_empty()
            || self.wire_order.len() != count
        { return Err(invalid()); }
        let mut seen = vec![false; count];
        for &index in &self.wire_order {
            let slot = seen.get_mut(index).ok_or_else(invalid)?;
            if *slot { return Err(invalid()); }
            *slot = true;
        }
        // Decode is structural. Rebuild with the authoritative semantic
        // constructor, including push-option bounds, before trusting any field.
        let options = self.request.push_options().iter()
            .map(|option| fgit_authority::PushOption::new(option.as_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let rebuilt = SemanticRequest::build(
            self.request.request_schema(), self.request.object_format(), false,
            self.request.ref_commands().to_vec(), options, Vec::new(),
        )?;
        if rebuilt != self.request { return Err(invalid()); }
        for command in self.request.ref_commands() {
            if command.force
                || matches!(command.expected_old, ExpectedOld::Unspecified)
                || matches!(command.expected_old, ExpectedOld::Exactly(oid) if oid.is_zero())
                || matches!(command.proposed_new, ProposedNew::Update(oid) if oid.is_zero())
                || matches!((command.expected_old, command.proposed_new),
                    (ExpectedOld::Absent, ProposedNew::Delete))
            { return Err(invalid()); }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, AdmissionError> {
        self.validate()?;
        let request = encode_body(&self.request).map_err(codec)?;
        if request.len() > MAX_BYTES - 1024 { return Err(invalid()); }
        let mut out = Encoder::new();
        out.write_scalar(VERSION);
        out.write_bytes("receive-session.request", &request).map_err(codec)?;
        let indices = self.wire_order.iter().map(|index| {
            u16::try_from(*index).map_err(|_| invalid())
        }).collect::<Result<Vec<_>, _>>()?;
        out.write_sequence("receive-session.wire-order", &indices, |out, index| {
            out.write_scalar(*index);
            Ok(())
        }).map_err(codec)?;
        let bytes = out.into_bytes();
        if bytes.len() > MAX_BYTES { return Err(invalid()); }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() > MAX_BYTES { return Err(invalid()); }
        let mut input = Decoder::new(bytes, LIMITS);
        if input.read_scalar::<u32>("receive-session.version").map_err(codec)? != VERSION {
            return Err(invalid());
        }
        let request = decode_body::<SemanticRequest>(
            input.read_bytes("receive-session.request").map_err(codec)?, LIMITS,
        ).map_err(codec)?;
        let wire_order = input.read_sequence("receive-session.wire-order", |input| {
            input.read_scalar::<u16>("receive-session.index").map(usize::from)
        }).map_err(codec)?;
        input.finish().map_err(codec)?;
        let descriptor = Self { request, wire_order };
        descriptor.validate()?;
        if descriptor.encode()? != bytes { return Err(invalid()); }
        Ok(descriptor)
    }

    fn whole_attempt(&self, context: &AdmissionContext) -> Result<SealAttempt, AdmissionError> {
        if self.request.object_format() != context.object_format { return Err(invalid()); }
        Ok(SealAttempt {
            tenant_id: context.tenant_id, repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(), request: self.request.clone(),
        })
    }

    fn child_attempt(&self, context: &AdmissionContext, index: usize) -> Result<SealAttempt, AdmissionError> {
        let position = *self.wire_order.get(index).ok_or_else(invalid)?;
        let command = self.request.ref_commands().get(position).ok_or_else(invalid)?.clone();
        Ok(SealAttempt {
            tenant_id: context.tenant_id, repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: super::non_atomic_command_key(&context.idempotency_key, index)?,
            request: SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                context.object_format, false, vec![command], self.request.push_options().to_vec(), Vec::new())?,
        })
    }
}

/// Stage only after every existing whole/child key binding has been checked,
/// and before the first child can be sealed or published. Failed staging leaves
/// the same command identities retryable; the descriptor never grants admission.
pub(super) async fn stage<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    whole: &SealAttempt, plan: &SessionPlan,
) -> Result<(), AdmissionError> {
    if plan.atomic { return Err(invalid()); }
    let wire_order = plan.lowered.iter().map(|lowered| {
        let [command] = lowered.semantic.ref_commands() else { return Err(invalid()); };
        whole.request.ref_commands().iter().position(|candidate| candidate == command)
            .ok_or_else(invalid)
    }).collect::<Result<Vec<_>, _>>()?;
    let descriptor = Descriptor { request: whole.request.clone(), wire_order };
    // Preserve exactly the established lowerer, including option order and
    // binary child keys; no new per-command identity protocol is introduced.
    for (index, lowered) in plan.lowered.iter().enumerate() {
        if descriptor.child_attempt(context, index)? != seal_attempt(context, lowered) {
            return Err(invalid());
        }
    }
    let bytes = descriptor.encode()?;
    match store.put_if_absent(cx, &descriptor_key(context)?, &bytes).await? {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
        PutOutcome::Conflict => Err(invalid()),
    }
}

async fn require_binding<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, attempt: &SealAttempt,
) -> Result<TxId, SessionRecoveryFailure> {
    let identity = attempt.derive().map_err(AdmissionError::from)?.0;
    let key = idempotency_binding_key(attempt.tenant_id, attempt.repository_id,
        attempt.authenticated_principal_id, &attempt.idempotency_key).map_err(AdmissionError::from)?;
    let mut expected = Encoder::new();
    expected.write_internal_object_id(identity.as_internal_object_id()).map_err(codec)?;
    let found = store.read_immutable(cx, &key).await.map_err(AdmissionError::from)?;
    if !matches!(found, ImmutableRead::Present(ref bytes) if *bytes == expected.into_bytes()) {
        return Err(SessionRecoveryFailure::Integrity("descriptor/key binding"));
    }
    Ok(identity)
}

/// Recover the complete non-atomic command list without reexecuting any command.
/// The caller authenticates the context's principal and repository. Every read
/// remains scoped by that principal's ORIGINAL key. Legacy/missing descriptors
/// return NotObserved, never a fabricated empty or completed session.
pub async fn recover<S, C>(
    store: &S, cx: &S::Context, context: &AdmissionContext, checkpoint: &C,
) -> Result<SessionRecovery, SessionRecoveryFailure>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> Result<(), RefusalCode> + Sync,
{
    let scope = RecoveryScope { tenant_id: context.tenant_id,
        repository_id: context.repository_id, principal_id: context.principal_id };
    // Reuse the authority boundary even for an absent descriptor: this checks
    // the head receipt, repository and original key before reporting absence.
    let _original = recover_request_async(store, cx, &context.head_key, scope,
        &context.idempotency_key, checkpoint).await?;
    checkpoint().map_err(RecoveryFailure::Interrupted)?;
    let stored = store.read_immutable(cx, &descriptor_key(context)?).await
        .map_err(AdmissionError::from)?;
    checkpoint().map_err(RecoveryFailure::Interrupted)?;
    let ImmutableRead::Present(bytes) = stored else { return Ok(SessionRecovery::NotObserved); };
    let descriptor = Descriptor::decode(&bytes)?;
    let whole = descriptor.whole_attempt(context)?;
    let identity = require_binding(store, cx, &whole).await?;
    let mut commands = Vec::with_capacity(descriptor.wire_order.len());
    for index in 0..descriptor.wire_order.len() {
        checkpoint().map_err(RecoveryFailure::Interrupted)?;
        let child = descriptor.child_attempt(context, index)?;
        let child_id = require_binding(store, cx, &child).await?;
        let recovery = recover_request_async(store, cx, &context.head_key, scope,
            &child.idempotency_key, checkpoint).await?;
        match &recovery {
            RequestRecovery::Recovered(known) => {
                let (_, seal) = child.derive().map_err(AdmissionError::from)?;
                if known.tx_id() != child_id || known.seal() != &seal {
                    return Err(SessionRecoveryFailure::Integrity("descriptor/child seal"));
                }
            }
            RequestRecovery::SealNotObserved => {},
            RequestRecovery::KeyNotObserved => {
                return Err(SessionRecoveryFailure::Integrity("verified child binding disappeared"));
            }
        }
        commands.push(RecoveredCommand { index,
            reference: child.request.ref_commands()[0].name.clone(), recovery });
    }
    let result = RecoveredSession { identity, commands };
    // As with one-transaction recovery, final cancellation cannot erase an
    // already authenticated all-terminal result. Partial reads are not final.
    if !result.all_terminal() { checkpoint().map_err(RecoveryFailure::Interrupted)?; }
    Ok(SessionRecovery::Recovered(Box::new(result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_authority::{RefCommand, PushOption};
    use fgit_types::{GitHashAlgorithm, GitOid};

    fn request(atomic: bool) -> SemanticRequest {
        let oid = GitOid::from_hex(GitHashAlgorithm::Sha1, &"1".repeat(40)).unwrap();
        SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            GitHashAlgorithm::Sha1, atomic,
            [b"refs/tags/z".as_slice(), b"refs/tags/a"].into_iter().map(|name| RefCommand {
                name: RefName::try_new(name).unwrap(), expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(oid), force: false,
            }).collect(), vec![PushOption::new(b"ordered-option".to_vec()).unwrap()], Vec::new()).unwrap()
    }

    #[test]
    fn descriptor_roundtrip_preserves_wire_order_separately_from_canonical_order() {
        let descriptor = Descriptor { request: request(false), wire_order: vec![1, 0] };
        let bytes = descriptor.encode().unwrap();
        let decoded = Descriptor::decode(&bytes).unwrap();
        assert_eq!(decoded.wire_order, [1, 0]);
        assert_eq!(decoded.request, descriptor.request);
        assert_eq!(decoded.request.ref_commands()[0].name.as_bytes(), b"refs/tags/a");
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    #[test]
    fn descriptor_cannot_omit_repeat_or_invent_a_wire_command() {
        for order in [vec![], vec![0], vec![0, 0], vec![0, 2], vec![0, 1, 2]] {
            let descriptor = Descriptor { request: request(false), wire_order: order };
            assert!(descriptor.encode().is_err());
        }
        assert!(Descriptor { request: request(false), wire_order: vec![0, 1] }.encode().is_ok());
        assert!(Descriptor { request: request(true), wire_order: vec![0, 1] }.encode().is_err());
    }

    #[test]
    fn truncated_trailing_unknown_version_and_oversized_descriptors_are_errors() {
        let bytes = Descriptor { request: request(false), wire_order: vec![1, 0] }.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(Descriptor::decode(&bytes[..end]).is_err(), "truncated at {end}");
        }
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(Descriptor::decode(&trailing).is_err());
        let mut version = bytes; version[0] ^= 0x40;
        assert!(Descriptor::decode(&version).is_err());
        assert!(Descriptor::decode(&vec![0; MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn empty_results_never_establish_terminal_completion_vacuously() {
        // Completion is an observation over at least one verified child.
        // The production decoder additionally refuses empty command lists.
        let session = RecoveredSession {
            identity: SealAttempt {
                tenant_id: fgit_types::TenantId::from_bytes([1; 16]),
                repository_id: fgit_types::RepositoryId::from_bytes([2; 16]),
                authenticated_principal_id: fgit_types::PrincipalId::from_bytes([3; 16]),
                idempotency_key: fgit_authority::IdempotencyKey::new(b"key".to_vec()).unwrap(),
                request: request(false),
            }.derive().unwrap().0,
            commands: Vec::new(),
        };
        assert!(!session.all_terminal());
    }
}
