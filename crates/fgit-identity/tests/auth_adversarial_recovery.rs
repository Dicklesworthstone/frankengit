//! Adversarial campaign: account-recovery delay, notification, approval,
//! and the strength-downgrade wall (FG-042c).
//!
//! Recovery is the classic takeover path. The controls under attack here:
//! notification evidence is mandatory at initiation; a mandatory delay
//! separates request from unlock; a recovered session is SingleFactor and can
//! never present itself as anything stronger; completion is one-shot.
//! Every refusal is paired with its near-identical permitted twin.

use fgit_identity::{
    AuthenticationStrength, MIN_RECOVERY_DELAY_SECONDS, RecoveryId, RecoveryRefusal,
    RecoveryRequest, RevocationEvidence, SessionId,
};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

const T0: u64 = 10_000;
const UNLOCK: u64 = T0 + MIN_RECOVERY_DELAY_SECONDS;

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN])
}

fn recovery_id(value: u64) -> RecoveryId {
    RecoveryId::try_new(value).expect("nonzero")
}

fn notified_request(id: u64) -> RecoveryRequest {
    RecoveryRequest::initiate(
        recovery_id(id),
        principal(0x33),
        repository(),
        T0,
        UNLOCK,
        true,
    )
    .expect("notified, delay-respecting request")
}

// --- initiation refusals ------------------------------------------------------

#[test]
fn initiation_without_notification_dispatch_is_refused() {
    assert_eq!(
        RecoveryRequest::initiate(
            recovery_id(1),
            principal(0x33),
            repository(),
            T0,
            UNLOCK,
            false
        ),
        Err(RecoveryRefusal::NotificationRequired)
    );
    // Permitted twin: with dispatch recorded, the same request initiates.
    assert!(notified_request(1).id().get() == 1);
}

#[test]
fn initiation_cannot_shrink_the_delay_below_the_floor() {
    let one_second_short = T0 + MIN_RECOVERY_DELAY_SECONDS - 1;
    assert_eq!(
        RecoveryRequest::initiate(
            recovery_id(2),
            principal(0x33),
            repository(),
            T0,
            one_second_short,
            true
        ),
        Err(RecoveryRefusal::DelayTooShort {
            provided: MIN_RECOVERY_DELAY_SECONDS - 1,
            minimum_required: MIN_RECOVERY_DELAY_SECONDS,
        })
    );
    // Boundary twin: exactly the floor unlocks.
    assert!(notified_request(2).id().get() == 2);
}

// --- completion timing ---------------------------------------------------------

#[test]
fn completion_before_unlock_is_refused_with_both_instants_named() {
    let mut request = notified_request(3);
    assert_eq!(
        request.complete(
            SessionId::try_new(9).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK - 1
        ),
        Err(RecoveryRefusal::DelayNotElapsed {
            unlock_at: UNLOCK,
            now: UNLOCK - 1
        })
    );
    // Permitted twin: at the unlock instant completion proceeds.
    let session = request
        .complete(
            SessionId::try_new(9).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK,
        )
        .expect("unlocked");
    assert_eq!(session.strength(), AuthenticationStrength::SingleFactor);
}

// --- downgrade wall -------------------------------------------------------------

#[test]
fn recovered_session_can_never_pass_a_multi_factor_gate() {
    let mut request = notified_request(4);
    let session = request
        .complete(
            SessionId::try_new(10).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK,
        )
        .expect("completed");
    assert_eq!(session.strength(), AuthenticationStrength::SingleFactor);
    // The takeover-fantasy path: walk straight to a privileged operation.
    assert_eq!(
        session.authorize(
            repository(),
            AuthenticationStrength::MultiFactor,
            UNLOCK + 1,
            RevocationEvidence::Live
        ),
        Err(fgit_identity::SessionRefusal::StrengthInsufficient {
            established: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::MultiFactor,
        })
    );
    // Permitted twin: SingleFactor gates admit it.
    assert!(
        session
            .authorize(
                repository(),
                AuthenticationStrength::SingleFactor,
                UNLOCK + 1,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

// --- one-shot lifecycle ------------------------------------------------------------

#[test]
fn completed_recovery_is_terminal_and_cannot_be_recompleted() {
    let mut request = notified_request(5);
    let _ = request
        .complete(
            SessionId::try_new(11).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK,
        )
        .expect("first completion");
    assert_eq!(
        request.complete(
            SessionId::try_new(12).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK + 1
        ),
        Err(RecoveryRefusal::AlreadyCompleted)
    );
}

#[test]
fn holder_cancelled_recovery_stays_cancelled() {
    let mut request = notified_request(6);
    request.cancel(T0 + 60).expect("holder cancels early");
    assert_eq!(
        request.complete(
            SessionId::try_new(13).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK
        ),
        Err(RecoveryRefusal::AlreadyCancelled)
    );
}

#[test]
fn cancellation_is_idempotent_tolerant_or_refuses_but_never_revives() {
    let mut request = notified_request(7);
    request.cancel(T0 + 30).expect("first cancel");
    // A second cancel must not resurrect the request into Pending.
    let _ = request.cancel(T0 + 31);
    assert_eq!(
        request.complete(
            SessionId::try_new(14).expect("nonzero"),
            UNLOCK + 100,
            UNLOCK
        ),
        Err(RecoveryRefusal::AlreadyCancelled)
    );
}
