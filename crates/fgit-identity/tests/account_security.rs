#![forbid(unsafe_code)]
//! Comprehensive test suite for FG-042b: Account-takeover prevention controls.
//!
//! Covers:
//! 1. Passkey registration, assertion, RP binding, UV/UP, and monotonic counter clone defense.
//! 2. OAuth PKCE S256, exact redirect URI matching, and single-use redemption replay defense.
//! 3. Rate limiting and lockout with non-existence oracle defense.
//! 4. Delay-and-notify account recovery with honest single-factor strength binding.
//! 5. Privilege elevation / step-up reauth with action binding and narrow validity window.

use ed25519_dalek::{Signer, SigningKey};
use fgit_identity::oauth::{
    AuthorizationCode, OAuthRefusal, PkceMethod, derive_s256_challenge, validate_redirect_uri,
    verify_pkce,
};
use fgit_identity::passkey::{
    PasskeyAlgorithm, PasskeyAssertion, PasskeyAssertionChallenge, PasskeyCredential, PasskeyId,
    PasskeyRefusal, UserVerificationRequirement,
};
use fgit_identity::rate_limit::{PrincipalRateLimiter, RateLimitConfig, RateLimitRefusal};
use fgit_identity::reauth::{
    ElevationToken, MAX_ELEVATION_WINDOW_SECONDS, PrivilegeAction, ReauthRefusal,
};
use fgit_identity::recovery::{
    MIN_RECOVERY_DELAY_SECONDS, RecoveryId, RecoveryRefusal, RecoveryRequest, RecoveryState,
};
use fgit_identity::revocation::RevocationEvidence;
use fgit_identity::session::{AuthenticationStrength, SessionId};
use fgit_types::{PrincipalId, RepositoryId};

fn test_principal() -> PrincipalId {
    PrincipalId::from_bytes([1u8; 16])
}

fn other_principal() -> PrincipalId {
    PrincipalId::from_bytes([2u8; 16])
}

fn test_repo() -> RepositoryId {
    RepositoryId::from_bytes([9u8; 16])
}

/// Crafts an assertion whose client data honestly carries the challenge's
/// canonical token and whose signature covers `auth_data || client_data_hash`
/// — the shape a real authenticator produces.
fn bound_assertion(
    challenge: &PasskeyAssertionChallenge,
    signing_key: &SigningKey,
    credential_id: PasskeyId,
    auth_data: Vec<u8>,
    sign_count: u32,
    user_present: bool,
    user_verified: bool,
) -> PasskeyAssertion {
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}",
        challenge.challenge_token()
    )
    .into_bytes();
    let client_data_hash = PasskeyAssertionChallenge::client_data_hash(&client_data_json);
    let mut payload = auth_data.clone();
    payload.extend_from_slice(&client_data_hash);
    let signature = signing_key.sign(&payload).to_bytes().to_vec();
    PasskeyAssertion {
        credential_id,
        client_data_hash,
        client_data_json,
        auth_data,
        signature,
        sign_count,
        user_present,
        user_verified,
    }
}

// -----------------------------------------------------------------------------
// Passkey / WebAuthn Tests
// -----------------------------------------------------------------------------

#[test]
fn passkey_registration_and_assertion_roundtrip() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let vk = signing_key.verifying_key();
    let vk_bytes = vk.to_bytes();

    let cred_id = PasskeyId::try_new(101).unwrap();
    let principal = test_principal();
    let rp_id = "forge.example.com";

    let mut credential = PasskeyCredential::register(
        cred_id,
        principal,
        rp_id,
        PasskeyAlgorithm::Ed25519,
        &vk_bytes,
        10, // initial sign_count
        1000,
    )
    .expect("registration succeeds");

    assert_eq!(credential.id(), cred_id);
    assert_eq!(credential.principal(), principal);
    assert_eq!(credential.rp_id(), rp_id);
    assert_eq!(credential.sign_count(), 10);

    // Issue challenge
    let challenge_bytes = [7u8; 32];
    let challenge = PasskeyAssertionChallenge::new(challenge_bytes, rp_id, principal, 2000);

    // Client data carrying the canonical challenge token, hash recomputed
    // from the exact bytes the signature will cover.
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}",
        challenge.challenge_token()
    )
    .into_bytes();
    let client_data_hash = PasskeyAssertionChallenge::client_data_hash(&client_data_json);

    let auth_data = vec![1, 2, 3, 4];
    let mut payload = Vec::new();
    payload.extend_from_slice(&auth_data);
    payload.extend_from_slice(&client_data_hash);

    let signature = signing_key.sign(&payload).to_bytes().to_vec();

    let assertion = PasskeyAssertion {
        credential_id: cred_id,
        client_data_hash,
        client_data_json,
        auth_data,
        signature,
        sign_count: 15, // advance counter
        user_present: true,
        user_verified: true,
    };

    // Verify assertion at now = 1500
    let strength = credential
        .verify_assertion(
            &challenge,
            &assertion,
            UserVerificationRequirement::Required,
            1500,
            RevocationEvidence::Live,
        )
        .expect("assertion must succeed");

    assert_eq!(strength, AuthenticationStrength::MultiFactor);
    assert_eq!(credential.sign_count(), 15);
}

#[test]
fn passkey_counter_regression_refused() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let vk = signing_key.verifying_key();

    let cred_id = PasskeyId::try_new(102).unwrap();
    let mut credential = PasskeyCredential::register(
        cred_id,
        test_principal(),
        "forge.example.com",
        PasskeyAlgorithm::Ed25519,
        &vk.to_bytes(),
        50, // current sign_count is 50
        1000,
    )
    .unwrap();

    let challenge =
        PasskeyAssertionChallenge::new([0u8; 32], "forge.example.com", test_principal(), 2000);

    // Replay / clone with regression (received 50 <= recorded 50). The client
    // data is honestly bound to this challenge so the refusal lands on the
    // counter rather than on an earlier gate.
    let assertion = bound_assertion(
        &challenge,
        &signing_key,
        cred_id,
        vec![0x49],
        50,
        true,
        true,
    );

    let err = credential
        .verify_assertion(
            &challenge,
            &assertion,
            UserVerificationRequirement::Preferred,
            1100,
            RevocationEvidence::Live,
        )
        .expect_err("must refuse counter regression");

    assert_eq!(
        err,
        PasskeyRefusal::CounterRegression {
            recorded: 50,
            received: 50
        }
    );
}

#[test]
fn passkey_expired_challenge_and_rp_mismatch_refused() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let vk = signing_key.verifying_key();
    let cred_id = PasskeyId::try_new(103).unwrap();
    let mut credential = PasskeyCredential::register(
        cred_id,
        test_principal(),
        "forge.example.com",
        PasskeyAlgorithm::Ed25519,
        &vk.to_bytes(),
        1,
        1000,
    )
    .unwrap();

    // Expired challenge
    let challenge =
        PasskeyAssertionChallenge::new([0u8; 32], "forge.example.com", test_principal(), 1500);

    let assertion = PasskeyAssertion {
        credential_id: cred_id,
        client_data_hash: [0u8; 32],
        client_data_json: vec![],
        auth_data: vec![],
        signature: vec![],
        sign_count: 5,
        user_present: true,
        user_verified: true,
    };

    let err = credential
        .verify_assertion(
            &challenge,
            &assertion,
            UserVerificationRequirement::Discouraged,
            1600, // now > expires_at (1500)
            RevocationEvidence::Live,
        )
        .expect_err("expired challenge must be refused");

    assert_eq!(
        err,
        PasskeyRefusal::ChallengeExpired {
            expires_at: 1500,
            now: 1600
        }
    );

    // RP ID mismatch
    let bad_rp_challenge =
        PasskeyAssertionChallenge::new([0u8; 32], "evil.attacker.com", test_principal(), 2000);
    let err_rp = credential
        .verify_assertion(
            &bad_rp_challenge,
            &assertion,
            UserVerificationRequirement::Discouraged,
            1200,
            RevocationEvidence::Live,
        )
        .expect_err("RP mismatch must be refused");

    assert_eq!(err_rp, PasskeyRefusal::RelyingPartyMismatch);
}

#[test]
fn passkey_user_verification_and_presence_enforced() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cred_id = PasskeyId::try_new(104).unwrap();
    let mut credential = PasskeyCredential::register(
        cred_id,
        test_principal(),
        "forge.example.com",
        PasskeyAlgorithm::Ed25519,
        &signing_key.verifying_key().to_bytes(),
        1,
        1000,
    )
    .unwrap();

    let challenge =
        PasskeyAssertionChallenge::new([0u8; 32], "forge.example.com", test_principal(), 2000);

    // Missing user presence
    let no_up = bound_assertion(&challenge, &signing_key, cred_id, vec![], 2, false, true);
    assert_eq!(
        credential
            .verify_assertion(
                &challenge,
                &no_up,
                UserVerificationRequirement::Discouraged,
                1100,
                RevocationEvidence::Live
            )
            .unwrap_err(),
        PasskeyRefusal::UserPresenceRequired
    );

    // Missing user verification when required
    let no_uv = bound_assertion(&challenge, &signing_key, cred_id, vec![], 2, true, false);
    assert_eq!(
        credential
            .verify_assertion(
                &challenge,
                &no_uv,
                UserVerificationRequirement::Required,
                1100,
                RevocationEvidence::Live
            )
            .unwrap_err(),
        PasskeyRefusal::UserVerificationRequired
    );
}

// -----------------------------------------------------------------------------
// OAuth 2.0 PKCE and Exact Redirect URI Tests
// -----------------------------------------------------------------------------

#[test]
fn pkce_s256_derivation_and_verification() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = derive_s256_challenge(verifier).expect("valid verifier");

    // Must verify successfully with correct verifier
    assert!(verify_pkce(verifier, &challenge, PkceMethod::S256).is_ok());

    // Mismatched verifier fails
    let wrong_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXy";
    assert_eq!(
        verify_pkce(wrong_verifier, &challenge, PkceMethod::S256).unwrap_err(),
        OAuthRefusal::PkceVerificationFailed
    );

    // Short verifier fails (<43 chars)
    let short_verifier = "too_short_verifier_string";
    assert!(derive_s256_challenge(short_verifier).is_err());
}

#[test]
fn redirect_uri_validation_rules() {
    // Valid URIs
    assert!(validate_redirect_uri("https://forge.example.com/oauth/callback").is_ok());
    assert!(validate_redirect_uri("http://localhost:8080/callback").is_ok());
    assert!(validate_redirect_uri("http://127.0.0.1:3000/callback").is_ok());

    // Insecure non-localhost HTTP
    assert_eq!(
        validate_redirect_uri("http://insecure.example.com/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );

    // Fragments (#) forbidden
    assert_eq!(
        validate_redirect_uri("https://forge.example.com/callback#token").unwrap_err(),
        OAuthRefusal::FragmentInRedirectUri
    );

    // Wildcards (*) forbidden
    assert_eq!(
        validate_redirect_uri("https://*.example.com/callback").unwrap_err(),
        OAuthRefusal::WildcardInRedirectUri
    );
    // Loopback prefix must never widen into a different host: longer
    // hostnames, userinfo tricks, and port-then-userinfo tricks all name a
    // remote authority and are refused.
    assert_eq!(
        validate_redirect_uri("http://localhost.evil.com/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );
    assert_eq!(
        validate_redirect_uri("http://127.0.0.1.evil.com/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );
    assert_eq!(
        validate_redirect_uri("http://localhost@evil.com/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );
    assert_eq!(
        validate_redirect_uri("http://localhost:8080@evil.com/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );
    assert_eq!(
        validate_redirect_uri("http://localhostly/callback").unwrap_err(),
        OAuthRefusal::InsecureRedirectUri
    );
}

#[test]
fn authorization_code_redemption_and_single_use() {
    let verifier = "E9Melhoa2OwvFrGMTJguCH5rtx64LxU4kWbZUU-1na_w";
    let challenge = derive_s256_challenge(verifier).unwrap();

    let mut code = AuthorizationCode::issue(
        901,
        "client-app-123",
        test_principal(),
        test_repo(),
        "https://client.example.com/callback",
        "repo:read repo:write",
        &challenge,
        PkceMethod::S256,
        "state-xyz-456",
        Some("nonce-789".to_string()),
        AuthenticationStrength::MultiFactor,
        2000,
    )
    .expect("valid code issuance");

    assert!(!code.is_used());

    // First redemption succeeds
    let session_id = SessionId::try_new(501).unwrap();
    let session = code
        .redeem(
            session_id,
            "client-app-123",
            "https://client.example.com/callback",
            verifier,
            5000,
            1500,
        )
        .expect("redemption succeeds");

    assert_eq!(session.id(), session_id);
    assert_eq!(session.principal(), test_principal());
    assert_eq!(session.strength(), AuthenticationStrength::MultiFactor);
    assert!(code.is_used());

    // Re-redemption attempt immediately rejected with CodeAlreadyUsed (replay attack!)
    let replay_err = code
        .redeem(
            SessionId::try_new(502).unwrap(),
            "client-app-123",
            "https://client.example.com/callback",
            verifier,
            5000,
            1501,
        )
        .expect_err("replay must be refused");

    assert_eq!(replay_err, OAuthRefusal::CodeAlreadyUsed { code_id: 901 });
}

#[test]
fn authorization_code_exact_redirect_uri_enforced() {
    let verifier = "E9Melhoa2OwvFrGMTJguCH5rtx64LxU4kWbZUU-1na_w";
    let challenge = derive_s256_challenge(verifier).unwrap();

    let mut code = AuthorizationCode::issue(
        902,
        "client-app-123",
        test_principal(),
        test_repo(),
        "https://client.example.com/callback",
        "repo:read",
        &challenge,
        PkceMethod::S256,
        "state-1",
        None,
        AuthenticationStrength::SingleFactor,
        2000,
    )
    .unwrap();

    // Mismatched redirect URI (e.g. path traversal or attacker redirect)
    let err = code
        .redeem(
            SessionId::try_new(503).unwrap(),
            "client-app-123",
            "https://client.example.com/callback/extra",
            verifier,
            5000,
            1500,
        )
        .expect_err("must refuse redirect URI mismatch");

    assert_eq!(err, OAuthRefusal::RedirectUriMismatch);
}

// -----------------------------------------------------------------------------
// Rate Limiting & Non-Existence Oracle Tests (Invariant 17)
// -----------------------------------------------------------------------------

#[test]
fn rate_limiting_lockout_and_oracle_defense() {
    let config = RateLimitConfig {
        max_attempts: 3,
        window_seconds: 60,
        lockout_seconds: 300,
    };
    let mut limiter = PrincipalRateLimiter::new(config);

    let principal = test_principal();

    // First 3 attempts permitted
    assert!(limiter.check_admission(Some(principal), 1000).is_ok());
    limiter.record_failure(Some(principal), 1000);

    assert!(limiter.check_admission(Some(principal), 1010).is_ok());
    limiter.record_failure(Some(principal), 1010);

    assert!(limiter.check_admission(Some(principal), 1020).is_ok());
    limiter.record_failure(Some(principal), 1020);

    // 4th attempt refused with AccountLocked
    let err = limiter.check_admission(Some(principal), 1025).unwrap_err();
    assert_eq!(
        err,
        RateLimitRefusal::AccountLocked {
            locked_until: 1320, // 1020 + 300
            now: 1025
        }
    );

    // After lockout lifts at 1321
    assert!(limiter.check_admission(Some(principal), 1321).is_ok());

    // Nonexistent principal (None) uses dummy record with identical shape
    assert!(limiter.check_admission(None, 1000).is_ok());
    limiter.record_failure(None, 1000);
    limiter.record_failure(None, 1010);
    limiter.record_failure(None, 1020);
    let dummy_err = limiter.check_admission(None, 1025).unwrap_err();
    assert_eq!(
        dummy_err,
        RateLimitRefusal::AccountLocked {
            locked_until: 1320,
            now: 1025
        }
    );
}

// -----------------------------------------------------------------------------
// Delay-and-Notify Account Recovery Tests
// -----------------------------------------------------------------------------

#[test]
fn account_recovery_delay_and_cancellation_flow() {
    let rec_id = RecoveryId::try_new(701).unwrap();
    let principal = test_principal();
    let requested_at = 10_000;
    let unlock_at = requested_at + MIN_RECOVERY_DELAY_SECONDS; // exactly 24h

    // Rejects if notification not dispatched
    assert_eq!(
        RecoveryRequest::initiate(
            rec_id,
            principal,
            test_repo(),
            requested_at,
            unlock_at,
            false
        )
        .unwrap_err(),
        RecoveryRefusal::NotificationRequired
    );

    // Rejects if delay too short
    assert!(matches!(
        RecoveryRequest::initiate(
            rec_id,
            principal,
            test_repo(),
            requested_at,
            requested_at + 3600, // 1 hour is too short!
            true
        )
        .unwrap_err(),
        RecoveryRefusal::DelayTooShort { .. }
    ));

    let mut recovery = RecoveryRequest::initiate(
        rec_id,
        principal,
        test_repo(),
        requested_at,
        unlock_at,
        true,
    )
    .expect("valid recovery initiation");

    assert_eq!(recovery.state(), RecoveryState::Pending);

    // Attempting completion before unlock_at fails
    let early_err = recovery
        .complete(
            SessionId::try_new(801).unwrap(),
            100_000,
            requested_at + 1000,
        )
        .unwrap_err();
    assert_eq!(
        early_err,
        RecoveryRefusal::DelayNotElapsed {
            unlock_at,
            now: requested_at + 1000
        }
    );

    // Legitimate account holder cancels upon receiving notification
    recovery
        .cancel(requested_at + 2000)
        .expect("cancel succeeds");
    assert_eq!(
        recovery.state(),
        RecoveryState::Cancelled {
            cancelled_at: requested_at + 2000
        }
    );

    // Once cancelled, completion is refused
    assert_eq!(
        recovery
            .complete(SessionId::try_new(802).unwrap(), 100_000, unlock_at + 10)
            .unwrap_err(),
        RecoveryRefusal::AlreadyCancelled
    );
}

#[test]
fn account_recovery_yields_honest_single_factor_strength() {
    let rec_id = RecoveryId::try_new(702).unwrap();
    let principal = test_principal();
    let requested_at = 10_000;
    let unlock_at = requested_at + MIN_RECOVERY_DELAY_SECONDS;

    let mut recovery = RecoveryRequest::initiate(
        rec_id,
        principal,
        test_repo(),
        requested_at,
        unlock_at,
        true,
    )
    .unwrap();

    // Complete after delay elapsed
    let session = recovery
        .complete(SessionId::try_new(803).unwrap(), 200_000, unlock_at + 50)
        .expect("recovery completion succeeds");

    // CRITICAL: Recovery establishes SingleFactor, NEVER MultiFactor!
    assert_eq!(session.strength(), AuthenticationStrength::SingleFactor);
    assert_eq!(session.principal(), principal);
}

// -----------------------------------------------------------------------------
// Privilege Elevation / Step-Up Re-Authentication Tests
// -----------------------------------------------------------------------------

#[test]
fn privilege_elevation_lifecycle_and_strength_bounds() {
    let principal = test_principal();

    // Insufficient strength for ProtectedRefMutation (requires MultiFactor)
    let low_strength_err = ElevationToken::issue(
        301,
        principal,
        PrivilegeAction::ProtectedRefMutation,
        AuthenticationStrength::SingleFactor, // insufficient!
        1000,
        1200,
    )
    .unwrap_err();

    assert_eq!(
        low_strength_err,
        ReauthRefusal::StrengthInsufficient {
            established: AuthenticationStrength::SingleFactor,
            required: AuthenticationStrength::MultiFactor
        }
    );

    // Window exceeded (> MAX_ELEVATION_WINDOW_SECONDS = 300s)
    let window_err = ElevationToken::issue(
        302,
        principal,
        PrivilegeAction::ProtectedRefMutation,
        AuthenticationStrength::MultiFactor,
        1000,
        1000 + MAX_ELEVATION_WINDOW_SECONDS + 10,
    )
    .unwrap_err();

    assert!(matches!(window_err, ReauthRefusal::WindowExceeded { .. }));

    // Valid elevation token
    let mut token = ElevationToken::issue(
        303,
        principal,
        PrivilegeAction::ProtectedRefMutation,
        AuthenticationStrength::MultiFactor,
        1000,
        1000 + 200,
    )
    .expect("valid elevation issuance");

    // Action mismatch rejected
    assert_eq!(
        token
            .consume(principal, PrivilegeAction::ReleaseSigning, 1050)
            .unwrap_err(),
        ReauthRefusal::ActionMismatch
    );

    // Principal mismatch rejected
    assert_eq!(
        token
            .consume(
                other_principal(),
                PrivilegeAction::ProtectedRefMutation,
                1050
            )
            .unwrap_err(),
        ReauthRefusal::PrincipalMismatch
    );

    // Consumption succeeds
    token
        .consume(principal, PrivilegeAction::ProtectedRefMutation, 1050)
        .expect("consumption succeeds");

    // Reuse rejected
    assert_eq!(
        token
            .consume(principal, PrivilegeAction::ProtectedRefMutation, 1060)
            .unwrap_err(),
        ReauthRefusal::AlreadyConsumed
    );
}

#[test]
fn passkey_replay_against_a_fresh_challenge_is_refused() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cred_id = PasskeyId::try_new(105).unwrap();
    let mut credential = PasskeyCredential::register(
        cred_id,
        test_principal(),
        "forge.example.com",
        PasskeyAlgorithm::Ed25519,
        &signing_key.verifying_key().to_bytes(),
        0, // zero-counter authenticator: the counter check never fires
        1000,
    )
    .unwrap();

    // A first, entirely legitimate assertion.
    let first =
        PasskeyAssertionChallenge::new([1u8; 32], "forge.example.com", test_principal(), 2000);
    let captured = bound_assertion(&first, &signing_key, cred_id, vec![7], 0, true, true);
    credential
        .verify_assertion(
            &first,
            &captured,
            UserVerificationRequirement::Preferred,
            1100,
            RevocationEvidence::Live,
        )
        .expect("the original assertion is genuine");

    // Replaying the identical bytes against a brand-new challenge must not
    // authenticate: nothing in the signed data speaks for the new challenge.
    let second =
        PasskeyAssertionChallenge::new([2u8; 32], "forge.example.com", test_principal(), 4000);
    let err = credential
        .verify_assertion(
            &second,
            &captured,
            UserVerificationRequirement::Preferred,
            3000,
            RevocationEvidence::Live,
        )
        .expect_err("a captured assertion must not satisfy a fresh challenge");
    assert_eq!(err, PasskeyRefusal::ChallengeNotBound);
}

#[test]
fn passkey_client_data_hash_mismatch_is_refused() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cred_id = PasskeyId::try_new(106).unwrap();
    let mut credential = PasskeyCredential::register(
        cred_id,
        test_principal(),
        "forge.example.com",
        PasskeyAlgorithm::Ed25519,
        &signing_key.verifying_key().to_bytes(),
        0,
        1000,
    )
    .unwrap();

    let challenge =
        PasskeyAssertionChallenge::new([3u8; 32], "forge.example.com", test_principal(), 2000);
    let mut tampered = bound_assertion(&challenge, &signing_key, cred_id, vec![9], 1, true, true);
    // Swap in client data that no longer hashes to the asserted digest.
    tampered.client_data_json = b"{\"type\":\"webauthn.get\",\"challenge\":\"nope\"}".to_vec();

    let err = credential
        .verify_assertion(
            &challenge,
            &tampered,
            UserVerificationRequirement::Preferred,
            1100,
            RevocationEvidence::Live,
        )
        .expect_err("client data that fails its own hash must be refused");
    assert_eq!(err, PasskeyRefusal::ClientDataHashMismatch);
}
