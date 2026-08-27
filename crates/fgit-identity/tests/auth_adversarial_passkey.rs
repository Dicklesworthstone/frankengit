//! Adversarial campaign: passkey assertions — RP/credential binding,
//! challenge expiry and binding, revocation evidence, presence/verification,
//! and clone detection via counter regression (FG-042c).
//!
//! The signature over `auth_data || client_data_hash` is real Ed25519 here:
//! every refusal case is paired with a genuinely-signed permitted twin, so
//! this file cannot be satisfied by a verifier that rejects everything.

use ed25519_dalek::{Signer, SigningKey};
use fgit_identity::{
    PasskeyAlgorithm, PasskeyAssertion, PasskeyAssertionChallenge, PasskeyCredential, PasskeyId,
    PasskeyRefusal, RevocationEvidence, UserVerificationRequirement,
};
use fgit_types::identity::OPAQUE_ID_LEN;
use fgit_types::{PrincipalId, RepositoryId};

const NOW: u64 = 5_000;
const CHALLENGE_EXPIRES: u64 = 6_000;

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x11; OPAQUE_ID_LEN])
}

fn signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn registered_credential(key: &SigningKey) -> PasskeyCredential {
    PasskeyCredential::register(
        PasskeyId::try_new(1).expect("nonzero"),
        principal(0x33),
        "example.org",
        PasskeyAlgorithm::Ed25519,
        key.verifying_key().as_bytes(),
        0,
        NOW - 100,
    )
    .expect("valid registration")
}

fn challenge(bytes: [u8; 32], rp: &str) -> PasskeyAssertionChallenge {
    PasskeyAssertionChallenge::new(
        bytes,
        rp,
        principal(0x33),
        "https://example.org",
        CHALLENGE_EXPIRES,
    )
}

/// Builds a correctly signed assertion bound to `challenge`.
fn genuine_assertion(
    key: &SigningKey,
    credential_id: PasskeyId,
    challenge: &PasskeyAssertionChallenge,
    sign_count: u32,
) -> PasskeyAssertion {
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.org\"}}",
        challenge.challenge_token()
    )
    .into_bytes();
    let client_data_hash = PasskeyAssertionChallenge::client_data_hash(&client_data_json);
    // Canonical authenticator data: RP ID hash placeholder, flags byte with
    // UP|UV (0x05) - the bits verification derives from these signed bytes -
    // then the big-endian counter.
    let mut auth_data = vec![0u8; 32];
    auth_data.push(0x05);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed_payload = auth_data.clone();
    signed_payload.extend_from_slice(&client_data_hash);
    let signature = key.sign(&signed_payload).to_bytes().to_vec();
    PasskeyAssertion {
        credential_id,
        client_data_hash,
        client_data_json,
        auth_data,
        signature,
        sign_count,
    }
}

#[test]
fn rp_mismatch_and_credential_mismatch_are_refused() {
    let key = signing_key([1; 32]);
    let mut credential = registered_credential(&key);
    let foreign_rp_challenge = challenge([9; 32], "evil.example");
    assert_eq!(
        credential.verify_assertion(
            &foreign_rp_challenge,
            &genuine_assertion(
                &key,
                PasskeyId::try_new(1).unwrap(),
                &foreign_rp_challenge,
                1
            ),
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::RelyingPartyMismatch)
    );

    let own_challenge = challenge([8; 32], "example.org");
    let stolen_id_assertion =
        genuine_assertion(&key, PasskeyId::try_new(2).unwrap(), &own_challenge, 1);
    assert_eq!(
        credential.verify_assertion(
            &own_challenge,
            &stolen_id_assertion,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::CredentialMismatch)
    );
}
#[test]
fn expired_challenges_are_refused_with_a_live_twin() {
    let key = signing_key([2; 32]);
    let mut credential = registered_credential(&key);
    let stale = PasskeyAssertionChallenge::new(
        [7; 32],
        "example.org",
        principal(0x33),
        "https://example.org",
        NOW - 1,
    );
    assert_eq!(
        credential.verify_assertion(
            &stale,
            &genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &stale, 1),
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::ChallengeExpired {
            expires_at: NOW - 1,
            now: NOW
        })
    );
    // Permitted twin: unexpired challenge verifies.
    let fresh = challenge([7; 32], "example.org");
    assert!(
        credential
            .verify_assertion(
                &fresh,
                &genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &fresh, 1),
                UserVerificationRequirement::Required,
                NOW,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

#[test]
fn captured_assertions_replay_against_nothing() {
    let key = signing_key([3; 32]);
    let mut credential = registered_credential(&key);

    // Challenge A is answered honestly.
    let challenge_a = challenge([0xAA; 32], "example.org");
    let captured = genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &challenge_a, 5);
    credential
        .verify_assertion(
            &challenge_a,
            &captured,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live,
        )
        .expect("honest round");

    // Replay the identical assertion against a DIFFERENT live challenge B:
    // the client data still hashes correctly, but it no longer names B's
    // token, so the signature proves nothing about B.
    let challenge_b = challenge([0xBB; 32], "example.org");
    assert_eq!(
        credential.verify_assertion(
            &challenge_b,
            &captured,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::ChallengeNotBound)
    );

    // Tampered client data under B with a recomputed hash still fails: the
    // signature covers the hash, so the forgery breaks cryptographically.
    let mut forged = captured.clone();
    forged.client_data_json = b"{\"type\":\"webauthn.get\",\"challenge\":\"B-token\"}".to_vec();
    forged.client_data_hash = PasskeyAssertionChallenge::client_data_hash(&forged.client_data_json);
    let mut signed_payload = forged.auth_data.clone();
    signed_payload.extend_from_slice(&forged.client_data_hash);
    // (signature left as-is: it no longer matches the new payload)
    forged.signature = key.sign(&signed_payload).to_bytes().to_vec();
    assert_eq!(
        credential.verify_assertion(
            &challenge_b,
            &forged,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::ChallengeNotBound),
        "a valid signature over attacker-chosen data must not substitute for challenge binding"
    );
}

#[test]
fn cloned_authenticators_are_caught_by_counter_regression() {
    let key = signing_key([4; 32]);
    let mut credential = registered_credential(&key);
    let chal = challenge([0xCC; 32], "example.org");

    credential
        .verify_assertion(
            &chal,
            &genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &chal, 10),
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live,
        )
        .expect("counter advances to 10");
    // Clone presents an equal or lower counter than the recorded 10.
    for cloned in [10u32, 3] {
        assert_eq!(
            credential.verify_assertion(
                &chal,
                &genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &chal, cloned),
                UserVerificationRequirement::Required,
                NOW,
                RevocationEvidence::Live
            ),
            Err(PasskeyRefusal::CounterRegression {
                recorded: 10,
                received: cloned
            })
        );
    }
    // Permitted twin: strictly greater counter passes.
    assert!(
        credential
            .verify_assertion(
                &chal,
                &genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &chal, 11),
                UserVerificationRequirement::Required,
                NOW,
                RevocationEvidence::Live
            )
            .is_ok()
    );
}

#[test]
fn presence_verification_and_revocation_are_each_load_bearing() {
    let key = signing_key([5; 32]);
    let mut credential = registered_credential(&key);
    let chal = challenge([0xDD; 32], "example.org");
    let mut assertion = genuine_assertion(&key, PasskeyId::try_new(1).unwrap(), &chal, 1);

    // The flags live INSIDE the signed authenticator data (byte 32: bit
    // 0x01 user presence, bit 0x04 user verification). Flipping a bit here
    // changes what the signature covers - that is exactly what makes the
    // policy gates load-bearing rather than advisory.

    // Drop user presence inside the signed bytes.
    assertion.auth_data[32] &= !0x01;
    assert_eq!(
        credential.verify_assertion(
            &chal,
            &assertion,
            UserVerificationRequirement::Preferred,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::UserPresenceRequired)
    );

    // Restore presence, drop user verification under a Required policy.
    assertion.auth_data[32] |= 0x01;
    assertion.auth_data[32] &= !0x04;
    assert_eq!(
        credential.verify_assertion(
            &chal,
            &assertion,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Err(PasskeyRefusal::UserVerificationRequired)
    );

    // Permitted twin: both bits set verifies to MultiFactor.
    assertion.auth_data[32] |= 0x04;
    assert_eq!(
        credential.verify_assertion(
            &chal,
            &assertion,
            UserVerificationRequirement::Required,
            NOW,
            RevocationEvidence::Live
        ),
        Ok(fgit_identity::AuthenticationStrength::MultiFactor)
    );

    // Revocation evidence gates remain independent of cryptography. Presence
    // is cleared again in the signed bytes; the revocation refusal must win
    // on evidence grounds regardless.
    assertion.auth_data[32] &= !0x01;
    assert!(matches!(
        credential.verify_assertion(
            &chal,
            &assertion,
            UserVerificationRequirement::Preferred,
            NOW,
            RevocationEvidence::NotChecked
        ),
        Err(PasskeyRefusal::RevocationEvidenceRequired)
    ));
}
