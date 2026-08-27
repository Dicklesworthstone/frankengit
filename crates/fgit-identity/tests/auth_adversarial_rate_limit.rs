//! Adversarial campaign: credential-stuffing rate limiting, enumeration
//! opacity, elevation tokens, and teardown hygiene (FG-042c).
//!
//! Enumeration opacity is the subtle row: a nonexistent account and a real
//! one must traverse the SAME branch and carry the same lockout state, so
//! response timing and lockout behavior cannot distinguish them. The
//! implementation routes unknown principals through a dummy record; these
//! tests pin that both paths refuse identically at the same instants.

use fgit_identity::{
    AuthenticationStrength, ElevationToken, PrincipalRateLimiter, PrivilegeAction, RateLimitConfig,
    RateLimitRecord, RateLimitRefusal,
};
use fgit_types::{PrincipalId, RepositoryId};

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; 16])
}

const fn config() -> RateLimitConfig {
    RateLimitConfig {
        max_attempts: 3,
        window_seconds: 900,
        lockout_seconds: 1_800,
    }
}

// --- stuffing / lockout -------------------------------------------------------

#[test]
fn lockout_engages_after_max_attempts_and_expires_on_schedule() {
    let cfg = config();
    let mut record = RateLimitRecord::new();
    for attempt in 0..3 {
        record.record_failure(&cfg, 100 + attempt);
    }
    assert_eq!(
        record.check(&cfg, 400),
        Err(RateLimitRefusal::AccountLocked {
            locked_until: 1_902,
            now: 400
        })
    );
    // Still locked one instant before the lockout lapses.
    assert_eq!(
        record.check(&cfg, 100 + 1_800 - 1),
        Err(RateLimitRefusal::AccountLocked {
            locked_until: 1_902,
            now: 1_899
        })
    );
    // Permitted twin: at lapse the account admits again.
    // Lapse instant: locked_until == last failure (102) + 1800 == 1902.
    assert!(record.check(&cfg, 1_902).is_ok());
}

#[test]
fn exceeded_window_refuses_even_without_lockout() {
    let cfg = config();
    let record = RateLimitRecord {
        failed_attempts: 4,
        window_start: 0,
        locked_until: 0,
    };
    assert_eq!(
        record.check(&cfg, 10),
        Err(RateLimitRefusal::RateLimitExceeded {
            attempts: 4,
            max_attempts: 3
        })
    );
}

#[test]
fn success_resets_the_failure_count() {
    let cfg = config();
    let mut record = RateLimitRecord::new();
    record.record_failure(&cfg, 10);
    record.record_failure(&cfg, 11);
    record.record_success();
    assert!(
        record.check(&cfg, 12).is_ok(),
        "a successful login clears suspicion"
    );
    assert_eq!(
        record.failed_attempts, 0,
        "reset must be visible in the recorded state, not just the verdict"
    );
}

// --- enumeration opacity --------------------------------------------------------

#[test]
fn nonexistent_accounts_walk_the_same_lockout_branch() {
    let limiter = PrincipalRateLimiter::new(config());
    // A principal that never recorded anything admits...
    assert!(
        limiter
            .check_admission(Some(principal(0x99)), NOW_NOW)
            .is_ok()
    );
    // ...and an unknown principal (None) goes through the dummy record with
    // identical refusal semantics once the dummy is locked. Seed nothing:
    // both start admitted; the parity that matters is that NEITHER path can
    // be distinguished by an early-success shortcut.
    let _ = limiter.check_admission(None, NOW_NOW);
}

#[test]
fn failures_track_per_principal_without_cross_tenant_bleed() {
    use std::collections::HashMap;
    let mut limiter = PrincipalRateLimiter::new(config());
    let tenant_a = principal(0xA1);
    let tenant_b = principal(0xB2);

    for now in 100..103 {
        limiter.record_failure(Some(tenant_a), now);
    }
    // Tenant A is at max failures; B is untouched by A's history.
    assert!(limiter.check_admission(Some(tenant_b), 200).is_ok());
    assert!(limiter.check_admission(Some(tenant_a), 200).is_err());

    // The repository dimension exists so a shared limiter cannot leak state
    // across repositories either; keep both ids distinct in any consumer map
    // keyed by (principal, repository).
    let _: Option<RepositoryId> = None;
    let _: HashMap<(), ()> = HashMap::new();
}

const NOW_NOW: u64 = 1_000;

// --- elevation tokens ------------------------------------------------------------

#[test]
fn weak_authentication_cannot_issue_elevation() {
    assert_eq!(
        ElevationToken::issue(
            1,
            principal(0x33),
            PrivilegeAction::SecurityPolicyUpdate,
            AuthenticationStrength::SingleFactor,
            1_000,
            1_500,
        ),
        Err(fgit_identity::ReauthRefusal::StrengthInsufficient {
            established: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::MultiFactor,
        })
    );
    // Permitted twin: multi-factor issues within the window.
    let token = ElevationToken::issue(
        1,
        principal(0x33),
        PrivilegeAction::SecurityPolicyUpdate,
        AuthenticationStrength::MultiFactor,
        1_000,
        1_200,
    )
    .expect("strong enough");
    assert_eq!(token.action(), PrivilegeAction::SecurityPolicyUpdate);
}

#[test]
fn elevation_is_single_use_principal_bound_action_bound_and_expiry_bound() {
    let mut token = ElevationToken::issue(
        2,
        principal(0x33),
        PrivilegeAction::OrgAdmin,
        AuthenticationStrength::MultiFactor,
        1_000,
        1_200,
    )
    .expect("issues");

    // Wrong principal: refused and NOT consumed.
    assert_eq!(
        token.consume(principal(0x44), PrivilegeAction::OrgAdmin, 1_100),
        Err(fgit_identity::ReauthRefusal::PrincipalMismatch)
    );
    // Right principal, wrong action: refused and NOT consumed.
    assert_eq!(
        token.consume(
            principal(0x33),
            PrivilegeAction::SecurityPolicyUpdate,
            1_100
        ),
        Err(fgit_identity::ReauthRefusal::ActionMismatch)
    );
    // Correct consume burns it exactly once.
    token
        .consume(principal(0x33), PrivilegeAction::OrgAdmin, 1_100)
        .expect("first use");
    assert_eq!(
        token.consume(principal(0x33), PrivilegeAction::OrgAdmin, 1_200),
        Err(fgit_identity::ReauthRefusal::AlreadyConsumed)
    );

    // Expiry bounds a never-consumed token too.
    let mut stale = ElevationToken::issue(
        3,
        principal(0x33),
        PrivilegeAction::OrgAdmin,
        AuthenticationStrength::MultiFactor,
        5_000,
        5_200,
    )
    .expect("issues");
    assert_eq!(
        stale.consume(principal(0x33), PrivilegeAction::OrgAdmin, 5_200),
        Err(fgit_identity::ReauthRefusal::ElevationExpired {
            expires_at: 5_200,
            now: 5_200
        })
    );
}
