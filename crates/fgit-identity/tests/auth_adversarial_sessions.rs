//! Adversarial campaign: session fixation, hijack, rotation escalation,
//! expiry, revocation, and cross-repo confinement (FG-042c).
//!
//! Every refusal below is paired with a near-identical permitted case, so a
//! passing suite cannot be satisfied by an `authorize`/`rotate` that simply
//! always refuses. The load-bearing property under attack here: rotation and
//! refresh can never buy strength or time, and a session is useless outside
//! the repository it was established for.

use fgit_identity::{
    AuthenticationStrength, RevocationEvidence, Session, SessionId, SessionRefusal,
};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

const T0: u64 = 1_000;
const EXPIRES: u64 = 2_000;

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn repository(tag: u8) -> RepositoryId {
    RepositoryId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn sid(value: u64) -> SessionId {
    SessionId::try_new(value).expect("nonzero id")
}

fn live_session(principal_tag: u8, repo_tag: u8) -> Session {
    Session::establish(
        sid(42),
        principal(principal_tag),
        repository(repo_tag),
        AuthenticationStrength::MultiFactor,
        EXPIRES,
    )
}

// --- fixation / hijack ------------------------------------------------------

#[test]
fn zero_session_id_cannot_exist_so_zeroed_buffers_name_nothing() {
    assert!(SessionId::try_new(0).is_none(), "zero is the not-a-value");
    assert_eq!(sid(1).get(), 1);
}

#[test]
fn session_is_confined_to_its_repository() {
    let session = live_session(0x33, 0x11);
    // Cross-repo use is refused even with everything else perfect.
    assert_eq!(
        session.authorize(
            repository(0x22),
            AuthenticationStrength::SingleFactor,
            T0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::RepositoryMismatch)
    );
    // Permitted twin: same repository authorizes.
    let permitted = session.authorize(
        repository(0x11),
        AuthenticationStrength::SingleFactor,
        T0,
        RevocationEvidence::Live,
    );
    assert_eq!(permitted, Ok(principal(0x33)));
}

#[test]
fn authorize_hands_back_the_checked_principal_not_a_caller_supplied_one() {
    let session = live_session(0x33, 0x11);
    let who = session
        .authorize(
            repository(0x11),
            AuthenticationStrength::SingleFactor,
            T0,
            RevocationEvidence::Live,
        )
        .expect("live");
    assert_eq!(who, principal(0x33));
    assert_ne!(who, principal(0x44), "permit must not echo attacker input");
}

// --- strength: authorization cannot be downgraded into ---------------------

#[test]
fn single_factor_session_fails_multi_factor_gates() {
    let recovered_style = Session::establish(
        sid(7),
        principal(0x33),
        repository(0x11),
        AuthenticationStrength::SingleFactor,
        EXPIRES,
    );
    assert_eq!(
        recovered_style.authorize(
            repository(0x11),
            AuthenticationStrength::MultiFactor,
            T0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::StrengthInsufficient {
            established: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::MultiFactor,
        })
    );
    // Permitted twin: the same session passes the gate it is entitled to.
    assert!(
        recovered_style
            .authorize(
                repository(0x11),
                AuthenticationStrength::SingleFactor,
                T0,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

// --- rotation cannot buy anything ------------------------------------------

#[test]
fn rotation_cannot_raise_strength() {
    let session = Session::establish(
        sid(42),
        principal(0x33),
        repository(0x11),
        AuthenticationStrength::SingleFactor,
        EXPIRES,
    );
    assert_eq!(
        session.rotate(
            sid(43),
            AuthenticationStrength::MultiFactor,
            EXPIRES - 1,
            T0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::RotationWouldStrengthen {
            established: AuthenticationStrength::SingleFactor,
            requested: AuthenticationStrength::MultiFactor,
        })
    );
    // Permitted twin: lateral rotation to equal-or-weaker strength proceeds.
    let rotated = session
        .rotate(
            sid(43),
            AuthenticationStrength::SingleFactor,
            EXPIRES - 1,
            T0,
            RevocationEvidence::Live,
        )
        .expect("lateral");
    assert_eq!(rotated.strength(), AuthenticationStrength::SingleFactor);
}

#[test]
fn rotation_cannot_extend_deadline() {
    let session = live_session(0x33, 0x11);
    assert_eq!(
        session.rotate(
            sid(43),
            AuthenticationStrength::MultiFactor,
            EXPIRES + 1,
            T0,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::RotationWouldExtend {
            expires_at: EXPIRES,
            requested: EXPIRES + 1,
        })
    );
    // Permitted twin: shortening the deadline is allowed.
    let rotated = session
        .rotate(
            sid(43),
            AuthenticationStrength::MultiFactor,
            EXPIRES - 100,
            T0,
            RevocationEvidence::Live,
        )
        .expect("shorter deadline");
    assert_eq!(rotated.expires_at(), EXPIRES - 100);
}

#[test]
fn expired_session_cannot_be_rotated_back_to_life() {
    let session = live_session(0x33, 0x11);
    assert_eq!(
        session.rotate(
            sid(43),
            AuthenticationStrength::MultiFactor,
            EXPIRES,
            EXPIRES,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::Expired {
            expires_at: EXPIRES,
            now: EXPIRES
        })
    );
    // Permitted twin: strictly before the deadline rotation works.
    assert!(
        session
            .rotate(
                sid(44),
                AuthenticationStrength::MultiFactor,
                EXPIRES - 1,
                EXPIRES - 10,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

// --- revocation evidence is mandatory ---------------------------------------

#[test]
fn skipped_revocation_check_is_itself_a_refusal() {
    let session = live_session(0x33, 0x11);
    assert_eq!(
        session.authorize(
            repository(0x11),
            AuthenticationStrength::SingleFactor,
            T0,
            RevocationEvidence::NotChecked
        ),
        Err(SessionRefusal::RevocationEvidenceRequired)
    );
    assert_eq!(
        session.rotate(
            sid(43),
            AuthenticationStrength::MultiFactor,
            EXPIRES - 1,
            T0,
            RevocationEvidence::NotChecked
        ),
        Err(SessionRefusal::RevocationEvidenceRequired)
    );
    // Permitted twins on both surfaces once the record was consulted.
    assert!(
        session
            .authorize(
                repository(0x11),
                AuthenticationStrength::SingleFactor,
                T0,
                RevocationEvidence::Live
            )
            .is_ok()
    );
    assert!(
        session
            .rotate(
                sid(45),
                AuthenticationStrength::MultiFactor,
                EXPIRES - 1,
                T0,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

#[test]
fn revoked_sessions_are_dead_for_authorize_and_rotate() {
    let session = live_session(0x33, 0x11);
    assert_eq!(
        session.authorize(
            repository(0x11),
            AuthenticationStrength::SingleFactor,
            T0,
            RevocationEvidence::Revoked
        ),
        Err(SessionRefusal::Revoked)
    );
    assert_eq!(
        session.rotate(
            sid(46),
            AuthenticationStrength::SingleFactor,
            EXPIRES - 1,
            T0,
            RevocationEvidence::Revoked
        ),
        Err(SessionRefusal::Revoked)
    );
}

// --- expiry boundary ---------------------------------------------------------

#[test]
fn expiry_is_inclusive_at_the_deadline() {
    let session = live_session(0x33, 0x11);
    assert!(
        session
            .authorize(
                repository(0x11),
                AuthenticationStrength::SingleFactor,
                EXPIRES - 1,
                RevocationEvidence::Live
            )
            .is_ok()
    );
    assert_eq!(
        session.authorize(
            repository(0x11),
            AuthenticationStrength::SingleFactor,
            EXPIRES,
            RevocationEvidence::Live
        ),
        Err(SessionRefusal::Expired {
            expires_at: EXPIRES,
            now: EXPIRES
        })
    );
}

// --- redaction hygiene --------------------------------------------------------

#[test]
fn refusal_debug_output_leaks_no_identity_bytes() {
    // Refusals end up in logs; their Debug must carry scalars and labels, not
    // opaque identity material.
    let session = live_session(0x33, 0x11);
    let refusal = format!(
        "{:?}",
        session.authorize(
            repository(0x22),
            AuthenticationStrength::MultiFactor,
            T0,
            RevocationEvidence::Revoked
        )
    );
    let identity_byte = format!("{:02x}", 0x33);
    assert!(
        !refusal.contains(&identity_byte),
        "refusal debug leaked identity-shaped bytes: {refusal}"
    );
}
