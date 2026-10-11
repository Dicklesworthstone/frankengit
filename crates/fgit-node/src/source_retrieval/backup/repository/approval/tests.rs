use super::super::profile::Profile;
use super::*;
use fgit_authority_fsqlite::{ExportBundle, ExportedHead, SCHEMA_VERSION};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

// Generated with the existing scripts/lib/repository-backup-approval.mjs issuer.
// The public RFC 8032 test seed was used only during fixture generation.
// Malformed statement fixtures below also have real, valid DSSE signatures;
// their refusal therefore exercises policy/canonicality after authentication.
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const ENVELOPE: &str = "{\"payloadType\":\"application/vnd.frankengit.repository-backup-approval.v1+json\",\"payload\":\"eyJ0eXBlIjoiZnJhbmtlbmdpdC1yZXBvc2l0b3J5LWJhY2t1cC1hcHByb3ZhbC12MSIsInRlbmFudF9pZCI6IjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwicmVwb3NpdG9yeV9pZCI6IjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwiaW5jYXJuYXRpb25faWQiOiIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyIsIm9iamVjdF9mb3JtYXQiOiJzaGExIiwiaGVhZF9nZW5lcmF0aW9uIjoiMTg0NDY3NDQwNzM3MDk1NTE2MTUiLCJpc3N1ZWRfYXQiOiIyMDI2LTEwLTA4VDEyOjAwOjAwWiIsImV4cGlyZXNfYXQiOiIyMDI2LTEwLTA5VDEyOjAwOjAwWiIsImFydGlmYWN0Ijp7ImJ5dGVzIjoiMzAiLCJzaGEyNTYiOiI4ODc3MzBiYTY0NzAxZjRkMTI3MWQ2Y2FiZmQzNThhZjMxZWZiM2UwMzNiMzkxZmViNTRjOWQwYjAzY2ZmOTdiIn0sInNjb3BlIjoiYXV0aG9yaXR5X2FuZF9zZWxlY3RlZF9naXRfb2JqZWN0cyJ9\",\"signatures\":[{\"keyid\":\"sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9\",\"sig\":\"HK2b1h3HCtlKRpY9QBJYlYUgXm2F1UdSla3ATtod95kyqEuarUKkCj906fAwv8Ep7aKVK7HRDpwKcQorR4r2Cg==\"}]}\n";
const PAYLOAD: &str = "{\"type\":\"frankengit-repository-backup-approval-v1\",\"tenant_id\":\"11111111111111111111111111111111\",\"repository_id\":\"22222222222222222222222222222222\",\"incarnation_id\":\"33333333333333333333333333333333\",\"object_format\":\"sha1\",\"head_generation\":\"18446744073709551615\",\"issued_at\":\"2026-10-08T12:00:00Z\",\"expires_at\":\"2026-10-09T12:00:00Z\",\"artifact\":{\"bytes\":\"30\",\"sha256\":\"887730ba64701f4d1271d6cabfd358af31efb3e033b391feb54c9d0b03cff97b\"},\"scope\":\"authority_and_selected_git_objects\"}";
const SIGNATURE: &str = "1cad9bd61dc70ad94a46963d4012589585205e6d85d5475295adc04eda1df79932a84b9aad42a40a3f74e9f030bfc129eda2952bb1d10e9c0a710a2b478af60a";
const KEY_ID: &str = "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";
const DIGEST: &str = "887730ba64701f4d1271d6cabfd358af31efb3e033b391feb54c9d0b03cff97b";
const NOW: i64 = 1791460800000;
const EXPIRES: i64 = 1791547200000;
const SIG_LEADING_SPACE: &str = "0ac4d6d7f6235c404b2c8ff020cf15755466e107ac154e4e7846d6ef40ded1d79cdacf78f1447d5efc4c224ad1e8c2c63372a2bd1699432268fe3d9053695406";
const SIG_DUPLICATE: &str = "7c8ad11737d3ad7b047bc17cd0dc27a7ff00f39f417b784b727c60087917c02a29f6fa0c20ca3d35636b7524b3c132d2389514b7f723a03d9f27ddd7b8918f0c";
const SIG_SCOPE: &str = "ac2e3dad16030ff2a290986bd61b528ace9d418522f8cd93195db6d37ba015ed7c7e38abef2d0e050e486dcf6eebe706767d9a6056a249305389e26763c42206";
const SIG_LEADING_ZERO: &str = "64f89dd34fb0e1e617af0627c96950700db716168a4aae9af3b2f4dae3df5c87be1dcc16eb14eb5a2165e2a84b289065d505a41778f51f6365053194d8078801";
const SIG_WRONG_TIME: &str = "c4b523ab2f69f44939d096c6b3d5075c989c1977d75838c7397b64e192c1b06f66d608790ae0cd0038d217df83db2d33733acc21d15e7004036f875e8e662103";
const SIG_NULL_EXPIRY: &str = "6f08f86949a146d3e38702863f3d05a8bf6f03af71104aa3f3685a6908e4e3ae863c2435ba0f3b33d58c5c3efb467c345956b4b129450e3ffc62fdd2c3f00a06";
const SIG_LOWER_GENERATION: &str = "250ab500b1e353516bcc324209d3fe6cc8be74df281c92894b93f5e1c303ab289430a3dc7173cfc6aae498109db6e2280fac2988b7b7233974fc825377913b0f";
const SIG_SHA256: &str = "feae00ec598502715210c1cf3babf4f90b57a4eff83312cd268687072b38c95263062426f6892c0d57282b03ffb54872bacf6cf190d7041d446e6fefca6e5607";
const SIG_ESCAPED_FIELD: &str = "3e33cbc9ab9e300a995196e7a8989924d59fad28473f42687f5996d7c37a06bb66c6d489aaed4042d8fb0b71adc29e0cf2518a90aa0905df33439f1a12b4ac00";
const CROSS_TYPE_SIGNATURE: &str = "c7c3f1d6b7af8fc1938a4317441e77496edc9c318c36fb81dfd973af2170948464d9990567ef65c60830687805619858b98fd6336f5230ead32f2b23a2d8a008";

fn identity() -> Identity {
    Identity {
        tenant: TenantId::from_bytes([0x11; 16]),
        repository: RepositoryId::from_bytes([0x22; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([0x33; 16]),
        format: GitHashAlgorithm::Sha1,
    }
}

fn options(minimum_generation: u64) -> ApprovalOptions {
    ApprovalOptions {
        approval: "unused-unit-approval".into(),
        trust_key: "unused-unit-trust-key".into(),
        policy: Policy {
            identity: identity(),
            minimum_generation,
        },
        clock: Some(Arc::new(AtomicI64::new(NOW))),
    }
}

fn authenticate(options: &ApprovalOptions, envelope: &str) -> Result<VerifiedApproval, String> {
    options.authenticate_bytes(
        envelope.as_bytes(),
        PUBLIC_PEM.as_bytes(),
        unhex(DIGEST).unwrap(),
        1 << 30,
        Profile::default().start(),
    )
}

// Encoding is used only to package fixed signatures from the external issuer.
// The unmodified positive envelope above does not use this helper.
fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(DIGITS[usize::from(first >> 2)]));
        encoded.push(char::from(
            DIGITS[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        encoded.push(if chunk.len() > 1 {
            char::from(DIGITS[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(DIGITS[usize::from(third & 63)])
        } else {
            '='
        });
    }
    encoded
}

fn signature_entry(signature: &str) -> String {
    format!(
        "{{\"keyid\":\"{KEY_ID}\",\"sig\":\"{}\"}}",
        encode_base64(&unhex::<64>(signature).unwrap())
    )
}

fn envelope(payload: &str, signature: &str) -> String {
    format!(
        "{{\"payloadType\":\"{PAYLOAD_TYPE}\",\"payload\":\"{}\",\"signatures\":[{}]}}",
        encode_base64(payload.as_bytes()),
        signature_entry(signature)
    )
}

fn assert_refuses(options: &ApprovalOptions, encoded: &str, expected: &str) {
    let error = authenticate(options, encoded).unwrap_err();
    assert!(
        error.contains(expected),
        "expected {expected:?}, got {error:?}"
    );
}

#[test]
fn existing_javascript_issuer_authenticates_exact_original_statement() {
    let approved = authenticate(&options(u64::MAX), ENVELOPE).unwrap();
    assert_eq!(approved.statement.canonical(), PAYLOAD);
    assert_eq!(approved.statement.generation, u64::MAX);
    assert_eq!(approved.statement.archive_bytes, 30);
    assert_eq!(approved.statement.digest, unhex::<32>(DIGEST).unwrap());
    assert_eq!(approved.trusted_key_id, KEY_ID);
    assert_eq!(approved.statement.issued_millis, NOW);
    assert_eq!(approved.statement.expires_millis, Some(EXPIRES));
    let receipt = approved.receipt_json();
    assert!(receipt.contains("\"signature_verified\":true"));
    assert!(receipt.contains("\"minimum_head_generation\":\"18446744073709551615\""));
    assert!(receipt.contains("\"newest_checkpoint_verified\":false"));
    assert!(receipt.contains("\"complete_capsule_verified\":false"));
    assert!(receipt.contains(PAYLOAD));
}

#[test]
fn valid_signatures_do_not_make_noncanonical_or_cross_scope_statements_admissible() {
    let cases = [
        (
            format!(" {PAYLOAD}"),
            SIG_LEADING_SPACE,
            "canonical original JSON",
        ),
        (
            PAYLOAD.replace("\"type\":", "\"type\":\"ignored\",\"type\":"),
            SIG_DUPLICATE,
            "duplicate",
        ),
        (PAYLOAD.replace(SCOPE, "full-capsule"), SIG_SCOPE, "scope"),
        (
            PAYLOAD.replace(
                "\"head_generation\":\"18446744073709551615\"",
                "\"head_generation\":\"01\"",
            ),
            SIG_LEADING_ZERO,
            "canonical positive",
        ),
        (
            PAYLOAD.replace("2026-10-08T12:00:00Z", "2026-02-30T12:00:00Z"),
            SIG_WRONG_TIME,
            "real UTC",
        ),
        (
            PAYLOAD.replace("\"tenant_id\"", "\"tenant_\\u0069d\""),
            SIG_ESCAPED_FIELD,
            "canonical original JSON",
        ),
    ];
    for (payload, signature, reason) in cases {
        // Demonstrate the signed malformed payload passes the cryptographic
        // boundary; its later native refusal is not merely a bad-signature test.
        let (key, _) = public_key(PUBLIC_PEM.as_bytes()).unwrap();
        verify_dsse_ed25519(
            &key,
            PAYLOAD_TYPE,
            payload.as_bytes(),
            &unhex(signature).unwrap(),
        )
        .unwrap();
        assert_refuses(&options(1), &envelope(&payload, signature), reason);
    }
}

#[test]
fn trust_key_and_dsse_type_are_independent_non_discoverable_inputs() {
    let other_type = "application/vnd.frankengit.source-backup-attestation.v1+json";
    assert_refuses(
        &options(1),
        &ENVELOPE.replace(PAYLOAD_TYPE, other_type),
        "payload type",
    );
    assert_refuses(
        &options(1),
        &envelope(PAYLOAD, CROSS_TYPE_SIGNATURE),
        "signature refused",
    );
    assert_refuses(
        &options(1),
        &ENVELOPE.replace(KEY_ID, "sha256:untrusted"),
        "independently trusted key",
    );
    assert_refuses(
        &options(1),
        &envelope(
            &PAYLOAD.replace("\"bytes\":\"30\"", "\"bytes\":\"31\""),
            SIGNATURE,
        ),
        "signature refused",
    );

    // Second public key from RFC 8032's test vectors, supplied outside the envelope.
    let mut der = [0_u8; 44];
    der[..12].copy_from_slice(ED25519_SPKI_PREFIX);
    der[12..].copy_from_slice(
        &unhex::<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").unwrap(),
    );
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(&der)
    );
    let other_key_id = format!("sha256:{}", hex(&sha256(&der)));
    for (encoded, expected) in [
        (ENVELOPE.to_owned(), "independently trusted key"),
        (ENVELOPE.replace(KEY_ID, &other_key_id), "signature refused"),
    ] {
        let error = options(1)
            .authenticate_bytes(
                encoded.as_bytes(),
                pem.as_bytes(),
                unhex(DIGEST).unwrap(),
                1 << 30,
                Profile::default().start(),
            )
            .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn independent_identity_floor_checksum_and_size_budget_all_apply() {
    let mut mismatches = [identity(), identity(), identity(), identity()];
    mismatches[0].tenant = TenantId::from_bytes([0x44; 16]);
    mismatches[1].repository = RepositoryId::from_bytes([0x44; 16]);
    mismatches[2].incarnation = RepositoryIncarnationId::from_bytes([0x44; 16]);
    mismatches[3].format = GitHashAlgorithm::Sha256;
    for identity in mismatches {
        let mut policy = options(1);
        policy.policy.identity = identity;
        assert_refuses(&policy, ENVELOPE, "independent policy");
    }

    // Adjacent generations above JSON's exact-number range must stay distinct.
    let payload = PAYLOAD.replace("18446744073709551615", "9007199254740992");
    let encoded = envelope(&payload, SIG_LOWER_GENERATION);
    let approved = authenticate(&options(9_007_199_254_740_992), &encoded).unwrap();
    assert_eq!(approved.statement.generation, 9_007_199_254_740_992);
    assert_refuses(
        &options(9_007_199_254_740_993),
        &encoded,
        "generation floor",
    );

    let mut sha256_policy = options(1);
    sha256_policy.policy.identity.format = GitHashAlgorithm::Sha256;
    authenticate(
        &sha256_policy,
        &envelope(
            &PAYLOAD.replace("\"object_format\":\"sha1\"", "\"object_format\":\"sha256\""),
            SIG_SHA256,
        ),
    )
    .unwrap();

    let error = options(1)
        .authenticate_bytes(
            ENVELOPE.as_bytes(),
            PUBLIC_PEM.as_bytes(),
            [0xff; 32],
            1 << 30,
            Profile::default().start(),
        )
        .unwrap_err();
    assert!(error.contains("--expected-sha256"));
    for maximum in [0, 29, (1 << 40) + 1] {
        assert!(
            options(1)
                .authenticate_bytes(
                    ENVELOPE.as_bytes(),
                    PUBLIC_PEM.as_bytes(),
                    unhex(DIGEST).unwrap(),
                    maximum,
                    Profile::default().start(),
                )
                .is_err()
        );
    }
    options(1)
        .authenticate_bytes(
            ENVELOPE.as_bytes(),
            PUBLIC_PEM.as_bytes(),
            unhex(DIGEST).unwrap(),
            30,
            Profile::default().start(),
        )
        .unwrap();
}

#[test]
fn receipt_and_resume_binding_own_exact_envelope_and_normalized_trust_policy() {
    let mut policy = options(1);
    let mut encoded = ENVELOPE.to_owned();
    let approved = authenticate(&policy, &encoded).unwrap();
    let original_binding = approved.binding_digest();
    encoded.push('\n');
    let whitespace_changed = authenticate(&policy, &encoded).unwrap();
    assert_ne!(original_binding, whitespace_changed.binding_digest());
    assert_eq!(
        approved.statement.canonical(),
        whitespace_changed.statement.canonical()
    );
    policy.policy.minimum_generation = 2;
    assert_ne!(
        original_binding,
        authenticate(&policy, ENVELOPE).unwrap().binding_digest()
    );
    assert_eq!(approved.policy.minimum_generation, 1);
    assert_eq!(approved.binding_digest(), original_binding);

    let (_, mut der) = public_key(PUBLIC_PEM.as_bytes()).unwrap();
    let original = binding(ENVELOPE.as_bytes(), &der, options(1).policy);
    der[43] ^= 1;
    assert_ne!(
        original,
        binding(ENVELOPE.as_bytes(), &der, options(1).policy)
    );
    for change in 0..4 {
        let mut changed = options(1).policy;
        match change {
            0 => changed.identity.tenant = TenantId::from_bytes([0x44; 16]),
            1 => changed.identity.repository = RepositoryId::from_bytes([0x44; 16]),
            2 => changed.identity.incarnation = RepositoryIncarnationId::from_bytes([0x44; 16]),
            _ => changed.identity.format = GitHashAlgorithm::Sha256,
        }
        let (_, der) = public_key(PUBLIC_PEM.as_bytes()).unwrap();
        assert_ne!(original, binding(ENVELOPE.as_bytes(), &der, changed));
    }

    // PEM line-ending changes preserve the independently supplied DER policy.
    let approved_crlf = options(1)
        .authenticate_bytes(
            ENVELOPE.as_bytes(),
            PUBLIC_PEM.replace('\n', "\r\n").as_bytes(),
            unhex(DIGEST).unwrap(),
            1 << 30,
            Profile::default().start(),
        )
        .unwrap();
    assert_eq!(original_binding, approved_crlf.binding_digest());
}

#[test]
fn lifetime_boundaries_are_checked_again_without_reauthenticating_paths() {
    let clock = Arc::new(AtomicI64::new(NOW - 300_000));
    let mut policy = options(1);
    policy.set_test_clock(clock.clone());
    let approved = authenticate(&policy, ENVELOPE).unwrap();
    clock.store(NOW - 300_001, Ordering::SeqCst);
    assert!(approved.check_current().unwrap_err().contains("future"));
    assert_refuses(&policy, ENVELOPE, "future");
    clock.store(EXPIRES - 1, Ordering::SeqCst);
    approved.check_current().unwrap();
    clock.store(EXPIRES, Ordering::SeqCst);
    assert!(approved.check_current().unwrap_err().contains("expired"));
    assert_refuses(&policy, ENVELOPE, "expired");

    // A committed publication's receipt remains available if output is delayed.
    assert!(
        approved
            .receipt_json()
            .contains("\"signature_verified\":true")
    );
    let no_expiry = PAYLOAD.replace(
        "\"expires_at\":\"2026-10-09T12:00:00Z\"",
        "\"expires_at\":null",
    );
    let encoded = envelope(&no_expiry, SIG_NULL_EXPIRY);
    authenticate(&policy, &encoded).unwrap();
    clock.store(MAX_TIME_MILLIS, Ordering::SeqCst);
    authenticate(&policy, &encoded).unwrap();
    clock.store(MAX_TIME_MILLIS + 1, Ordering::SeqCst);
    assert_refuses(&policy, &encoded, "supported UTC");
    clock.store(-1, Ordering::SeqCst);
    assert_refuses(&policy, &encoded, "supported UTC");
}

#[test]
fn original_monotonic_deadline_is_required_even_with_a_valid_signature() {
    let deadline = Profile {
        timeout: Duration::ZERO,
        ..Profile::default()
    }
    .start();
    let error = options(1)
        .authenticate_bytes(
            ENVELOPE.as_bytes(),
            PUBLIC_PEM.as_bytes(),
            unhex(DIGEST).unwrap(),
            1 << 30,
            deadline,
        )
        .unwrap_err();
    assert!(error.contains("deadline"));
    let mut approved = authenticate(&options(1), ENVELOPE).unwrap();
    approved.deadline = deadline;
    assert!(approved.check_current().unwrap_err().contains("deadline"));
}

fn header_and_seal() -> (StreamHeader, Seal) {
    // This tests the authenticated-header boundary only. It is deliberately not
    // presented as a real archive, authority replay, or native restore fixture.
    (
        StreamHeader {
            identity: identity(),
            authority: ExportBundle {
                schema_version: SCHEMA_VERSION,
                instance: 1,
                bodies: Vec::new(),
                head: Some(ExportedHead {
                    key: Vec::new(),
                    token: Vec::new(),
                    generation: u64::MAX,
                    body: Vec::new(),
                }),
                issuance: Vec::new(),
            },
            objects: 0,
        },
        Seal {
            digest: unhex(DIGEST).unwrap(),
            bytes: 30,
        },
    )
}

#[test]
fn signed_metadata_must_match_the_verified_stream_header_and_complete_seal() {
    let approved = authenticate(&options(1), ENVELOPE).unwrap();
    let (header, seal) = header_and_seal();
    approved.match_archive(&header, seal).unwrap();
    for change in 0..8 {
        let (mut header, mut seal) = header_and_seal();
        match change {
            0 => header.identity.tenant = TenantId::from_bytes([0x44; 16]),
            1 => header.identity.repository = RepositoryId::from_bytes([0x44; 16]),
            2 => header.identity.incarnation = RepositoryIncarnationId::from_bytes([0x44; 16]),
            3 => header.identity.format = GitHashAlgorithm::Sha256,
            4 => header.authority.head.as_mut().unwrap().generation -= 1,
            5 => header.authority.head = None,
            6 => seal.digest[0] ^= 1,
            _ => seal.bytes += 1,
        }
        assert!(approved.match_archive(&header, seal).is_err());
    }
}

#[test]
fn bounded_envelope_requires_one_signature_and_closed_unambiguous_json() {
    let entry = signature_entry(SIGNATURE);
    let payload = encode_base64(PAYLOAD.as_bytes());
    for signatures in [String::new(), format!("{entry},{entry}")] {
        let encoded = format!(
            "{{\"payloadType\":\"{PAYLOAD_TYPE}\",\"payload\":\"{payload}\",\"signatures\":[{signatures}]}}"
        );
        assert_refuses(&options(1), &encoded, "exactly one signature");
    }
    for encoded in [
        ENVELOPE.replacen('{', "{\"extra\":null,", 1),
        ENVELOPE.replace(
            "\"payloadType\":",
            "\"payloadType\":\"ignored\",\"payloadType\":",
        ),
        ENVELOPE.replace(
            "\"payloadType\":",
            "\"payload\\u0054ype\":\"ignored\",\"payloadType\":",
        ),
        ENVELOPE.replace("\"keyid\":", "\"keyid\":\"ignored\",\"keyid\":"),
        ENVELOPE.replace("\"keyid\":", "\"extra\":null,\"keyid\":"),
        format!("{ENVELOPE}null"),
    ] {
        assert!(authenticate(&options(1), &encoded).is_err(), "{encoded}");
    }
    assert_refuses(
        &options(1),
        &" ".repeat(MAX_ENVELOPE_BYTES + 1),
        "byte limit",
    );
    assert_refuses(
        &options(1),
        &envelope(&"x".repeat(MAX_PAYLOAD_BYTES + 1), SIGNATURE),
        "noncanonical base64",
    );
    assert_refuses(
        &options(1),
        &ENVELOPE.replace(
            &encode_base64(&unhex::<64>(SIGNATURE).unwrap()),
            &encode_base64(&[0; 65]),
        ),
        "noncanonical base64",
    );

    // Every strict prefix before the final closing brace is incomplete JSON.
    for prefix in 0..ENVELOPE.len() - 1 {
        assert!(
            parse_json(&ENVELOPE.as_bytes()[..prefix], MAX_ENVELOPE_BYTES).is_err(),
            "{prefix}"
        );
    }
    for bad in [
        b"{\"x\":\"\\ud800\"}".as_slice(),
        b"{\"x\":\"\\udc00\"}",
        b"{\"x\":\"\\ud800\\u0041\"}",
        b"{\"x\":\"\\q\"}",
        b"{\"x\":\"\x01\"}",
        b"{\"x\":\"\xff\"}",
        b"[[[[[[null]]]]]]",
        b"{\"x\":1}",
        b"{\"x\":true}",
    ] {
        assert!(parse_json(bad, MAX_ENVELOPE_BYTES).is_err());
    }
}

#[test]
fn public_keys_and_base64_keep_the_existing_canonical_wire_profile() {
    let (_, der) = public_key(PUBLIC_PEM.as_bytes()).unwrap();
    assert_eq!(&der[..12], ED25519_SPKI_PREFIX);
    for (text, expected) in [
        ("Zg==", b"f".as_slice()),
        ("Zm8=", b"fo"),
        ("Zm9v", b"foo"),
        ("AAEC/w==", b"\0\x01\x02\xff"),
    ] {
        assert_eq!(base64(text, 8).unwrap(), expected);
    }
    for text in [
        "", "Zg", "Zg=", "Zh==", "Zm9=", "Zg==AAAA", "=AAA", "AA=A", "AA-_", "Zg==\n", "Zm9v====",
    ] {
        assert!(base64(text, 64).is_err(), "{text}");
    }
    assert!(base64("Zm9v", 2).is_err());
    assert!(base64("Zg==", 0).is_err());

    let mut wrong_oid = der;
    wrong_oid[8] ^= 1;
    let wrong_oid = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(&wrong_oid)
    );
    let mut extra_der = der.to_vec();
    extra_der.push(0);
    let extra_der = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        encode_base64(&extra_der)
    );
    for pem in [
        String::new(),
        "x".repeat(MAX_KEY_BYTES + 1),
        PUBLIC_PEM.replace("PUBLIC", "PRIVATE"),
        format!(" {PUBLIC_PEM}"),
        format!("{PUBLIC_PEM}trailing"),
        wrong_oid,
        extra_der,
        PUBLIC_PEM.replace("MCow", "MC w"),
    ] {
        assert!(public_key(pem.as_bytes()).is_err());
    }
}

#[test]
fn calendar_and_decimal_rules_preserve_full_wire_ranges_without_aliases() {
    for (text, millis) in [
        ("1970-01-01T00:00:00Z", 0),
        ("1969-12-31T23:59:59Z", -1000),
        ("2000-02-29T00:00:00Z", 951_782_400_000),
        ("0000-01-01T00:00:00Z", -62_167_219_200_000),
        ("9999-12-31T23:59:59Z", 253_402_300_799_000),
        ("2026-10-08T12:00:00Z", NOW),
    ] {
        assert_eq!(instant(text).unwrap(), millis, "{text}");
    }
    for text in [
        "1900-02-29T00:00:00Z",
        "2000-02-30T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-01-00T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "2026-1-01T00:00:00Z",
        "2026-01-01t00:00:00Z",
        "2026-01-01T00:00:00z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00+00:00",
    ] {
        assert!(instant(text).is_err(), "{text}");
    }
    assert_eq!(decimal("18446744073709551615", u64::MAX).unwrap(), u64::MAX);
    for text in [
        "",
        "0",
        "01",
        "+1",
        "-1",
        " 1",
        "1 ",
        "1.0",
        "1e1",
        "18446744073709551616",
    ] {
        assert!(decimal(text, u64::MAX).is_err(), "{text}");
    }
    for expires in ["2026-10-08T12:00:00Z", "2026-10-07T12:00:00Z"] {
        assert!(
            Statement::parse(
                PAYLOAD.replace("2026-10-09T12:00:00Z", expires).as_bytes(),
                1 << 30
            )
            .is_err()
        );
    }
}

#[test]
fn signed_mode_flags_are_explicit_complete_and_not_last_value_wins() {
    let values = [
        ("--approval", "approval.json"),
        ("--trust-key", "trusted.pem"),
        ("--tenant-id", "11111111111111111111111111111111"),
        ("--repository-id", "22222222222222222222222222222222"),
        ("--incarnation-id", "33333333333333333333333333333333"),
        ("--object-format", "sha1"),
        ("--minimum-head-generation", "18446744073709551615"),
    ];
    assert!(ApprovalFlags::default().finish().unwrap().is_none());
    for omitted in 0..values.len() {
        let mut flags = ApprovalFlags::default();
        for (i, (flag, value)) in values.iter().enumerate() {
            assert!(ApprovalFlags::accepts(flag));
            if i != omitted {
                flags.set(flag, value).unwrap();
            }
        }
        assert!(flags.finish().is_err());
    }
    let mut flags = ApprovalFlags::default();
    for (flag, value) in values {
        flags.set(flag, value).unwrap();
        assert!(flags.set(flag, value).unwrap_err().contains("duplicate"));
    }
    let options = flags.finish().unwrap().unwrap();
    assert_eq!(options.policy.identity, identity());
    assert_eq!(options.policy.minimum_generation, u64::MAX);
    assert!(!ApprovalFlags::accepts("--key-discovery"));
    assert!(
        ApprovalFlags::default()
            .set("--key-discovery", "key")
            .is_err()
    );
    for (flag, value) in [
        ("--tenant-id", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("--repository-id", "22"),
        ("--incarnation-id", "0x33333333333333333333333333333333"),
        ("--object-format", "SHA1"),
        ("--minimum-head-generation", "01"),
        ("--approval", ""),
        ("--trust-key", "x\0y"),
    ] {
        assert!(ApprovalFlags::default().set(flag, value).is_err());
    }
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-approval-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn authentication_snapshots_bounded_control_files_and_never_reopens_them() {
    let directory = Directory::new();
    let mut policy = options(1);
    policy.approval = directory.0.join("approval.json");
    policy.trust_key = directory.0.join("trusted.pem");
    fs::write(&policy.approval, ENVELOPE).unwrap();
    fs::write(&policy.trust_key, PUBLIC_PEM).unwrap();
    let approved = policy
        .authenticate(unhex(DIGEST).unwrap(), 1 << 30, Profile::default().start())
        .unwrap();
    let binding = approved.binding_digest();
    fs::write(&policy.approval, b"changed").unwrap();
    fs::write(&policy.trust_key, b"changed").unwrap();
    approved.check_current().unwrap();
    assert_eq!(approved.binding_digest(), binding);
    assert!(
        policy
            .authenticate(unhex(DIGEST).unwrap(), 1 << 30, Profile::default().start())
            .is_err()
    );
    fs::write(&policy.approval, vec![b' '; MAX_ENVELOPE_BYTES + 1]).unwrap();
    assert!(
        read_control(
            &policy.approval,
            MAX_ENVELOPE_BYTES,
            Profile::default().start()
        )
        .is_err()
    );
    assert!(read_control(&directory.0, MAX_ENVELOPE_BYTES, Profile::default().start()).is_err());
    #[cfg(unix)]
    {
        let link = directory.0.join("approval-link");
        std::os::unix::fs::symlink(&policy.approval, &link).unwrap();
        assert!(read_control(&link, MAX_ENVELOPE_BYTES, Profile::default().start()).is_err());
    }
}
