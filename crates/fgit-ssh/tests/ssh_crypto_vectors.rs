#![forbid(unsafe_code)]

use fgit_identity::deploy_key::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};
use fgit_identity::revocation::RevocationEvidence;
use fgit_ssh::auth::{AuthRefusal, authorize_deploy_key};
use fgit_ssh::command::SshGitService;
use fgit_ssh::crypto::{
    CryptoError, Curve25519Kex, OpenSshChaCha20Poly1305, encode_ed25519_public_key,
    parse_ed25519_public_key, sign_ed25519, verify_ed25519,
};
use fgit_types::{PrincipalId, RepositoryId};

#[test]
fn test_rfc7748_curve25519_test_vectors() {
    // RFC 7748 Section 6.1 Diffie-Hellman test vectors
    let alice_priv = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let expected_alice_pub = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    let bob_priv = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0x47, 0x70, 0x1e, 0xbf, 0xb4, 0x5d,
        0x52, 0xd2, 0xf5, 0xb2, 0xf5, 0xe9, 0xda, 0x61, 0xf1, 0x6c, 0x42, 0xa9, 0xdb, 0x36, 0x25,
        0x70, 0x4b,
    ];
    let expected_bob_pub = [
        0xc6, 0xb8, 0xec, 0xf4, 0x90, 0xcf, 0x1b, 0xae, 0x17, 0x77, 0x9e, 0x9c, 0x07, 0x8a, 0x5c,
        0xd1, 0xa5, 0xee, 0x2b, 0x89, 0x27, 0xea, 0xc9, 0xf7, 0x4a, 0xf1, 0x26, 0x29, 0x53, 0x32,
        0xbc, 0x38,
    ];

    let expected_shared = [
        0x39, 0x57, 0x74, 0xa5, 0x47, 0x01, 0xbd, 0x94, 0x12, 0x67, 0x56, 0xd5, 0x12, 0x71, 0x32,
        0x66, 0x15, 0x90, 0x72, 0xcb, 0x52, 0xc3, 0xd3, 0x42, 0x4c, 0xa5, 0xe8, 0x8a, 0xff, 0x8b,
        0x44, 0x6e,
    ];

    let alice = Curve25519Kex::from_private_bytes(alice_priv);
    assert_eq!(alice.public_key(), &expected_alice_pub);

    let bob = Curve25519Kex::from_private_bytes(bob_priv);
    assert_eq!(bob.public_key(), &expected_bob_pub);

    let shared_alice = alice.compute_shared_secret(&expected_bob_pub).unwrap();
    let shared_bob = bob.compute_shared_secret(&expected_alice_pub).unwrap();

    assert_eq!(shared_alice, expected_shared);
    assert_eq!(shared_bob, expected_shared);
}

#[test]
fn test_curve25519_weak_shared_secret_refusal() {
    let alice = Curve25519Kex::from_private_bytes([0x42; 32]);
    // Point 0 produces all-zero shared secret
    let low_order_point = [0u8; 32];
    let err = alice.compute_shared_secret(&low_order_point).unwrap_err();
    assert_eq!(err, CryptoError::WeakKeyExchange);
}

#[test]
fn test_chacha20_poly1305_roundtrip_and_tampering() {
    let key_material = [0x55u8; 64];
    let mut encryptor = OpenSshChaCha20Poly1305::new(&key_material);
    let mut decryptor = OpenSshChaCha20Poly1305::new(&key_material);

    let payloads = [
        b"hello, OpenSSH chacha20-poly1305".to_vec(),
        vec![],
        vec![0xAA; 1024],
        vec![0xBB; 4096],
    ];

    for payload in &payloads {
        let encrypted = encryptor.encrypt_packet(payload, &[0x01; 16]);
        assert!(encrypted.len() >= 4 + payload.len() + 4 + 16);

        let decrypted = decryptor
            .decrypt_packet(&encrypted)
            .expect("decryption failed");
        assert_eq!(&decrypted, payload);
    }

    // Tampering tests:
    let payload = b"critical git command payload";
    let encrypted = encryptor.encrypt_packet(payload, &[0x02; 16]);

    // 1. Tamper length byte
    let mut tampered_len = encrypted.clone();
    tampered_len[0] ^= 0xFF;
    assert!(decryptor.decrypt_packet(&tampered_len).is_err());

    // 2. Tamper payload byte
    let mut tampered_payload = encrypted.clone();
    tampered_payload[6] ^= 0x01;
    let err = decryptor.decrypt_packet(&tampered_payload).unwrap_err();
    assert_eq!(err, CryptoError::MacVerificationFailed);

    // 3. Tamper MAC tag byte
    let mut tampered_tag = encrypted;
    let tag_idx = tampered_tag.len() - 1;
    tampered_tag[tag_idx] ^= 0x40;
    let err = decryptor.decrypt_packet(&tampered_tag).unwrap_err();
    assert_eq!(err, CryptoError::MacVerificationFailed);
}

#[test]
fn test_ed25519_key_and_signature_operations() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();

    let blob = encode_ed25519_public_key(&pub_bytes);
    let parsed_pub = parse_ed25519_public_key(&blob).expect("parse public key blob failed");
    assert_eq!(parsed_pub, pub_bytes);

    let data = b"preimage to be signed over ssh";
    let sig_blob = sign_ed25519(&signing_key, data);

    verify_ed25519(&pub_bytes, data, &sig_blob).expect("signature verify failed");

    // Tamper data
    let err = verify_ed25519(&pub_bytes, b"tampered", &sig_blob).unwrap_err();
    assert_eq!(err, CryptoError::SignatureVerificationFailed);
}

#[test]
fn test_deploy_key_authorization_seam() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();
    let fgit_verifying_key = fgit_crypto::VerifyingKey::from_bytes(pub_bytes);

    let repo_id = RepositoryId::from_bytes([0x88; 16]);
    let principal = PrincipalId::from_bytes([0x01; 16]);

    // Create binding with Read only
    let read_only_binding = DeployKeyBinding::register(
        repo_id,
        principal,
        fgit_verifying_key,
        &[DeployKeyScope::Read],
    )
    .expect("register binding failed");

    let bindings = vec![read_only_binding];

    // UploadPack (Read) should succeed
    let auth_principal = authorize_deploy_key(
        &bindings,
        &pub_bytes,
        repo_id,
        SshGitService::UploadPack,
        RevocationEvidence::Live,
    )
    .expect("authorize read failed");
    assert_eq!(auth_principal, principal);

    // ReceivePack (Write) on read-only key should be refused
    let err = authorize_deploy_key(
        &bindings,
        &pub_bytes,
        repo_id,
        SshGitService::ReceivePack,
        RevocationEvidence::Live,
    )
    .unwrap_err();

    assert_eq!(
        err,
        AuthRefusal::DeployKey(DeployKeyRefusal::ScopeNotGranted {
            requested: DeployKeyScope::Write
        })
    );

    // Wrong repository should be refused
    let other_repo = RepositoryId::from_bytes([0x99; 16]);
    let err = authorize_deploy_key(
        &bindings,
        &pub_bytes,
        other_repo,
        SshGitService::UploadPack,
        RevocationEvidence::Live,
    )
    .unwrap_err();
    assert_eq!(
        err,
        AuthRefusal::DeployKey(DeployKeyRefusal::NoBindingForKey)
    );
}

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (at, pair) in text.as_bytes().chunks(2).enumerate() {
        out[at] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn rfc7748_section_5_2_scalar_multiplication_vectors() {
    use fgit_ssh::x25519::x25519;
    // The two single-shot vectors of RFC 7748 section 5.2. The second input
    // u-coordinate has its top bit set, which X25519 must mask.
    for (scalar, u, expected) in [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ] {
        assert_eq!(x25519(&hex32(scalar), &hex32(u)), hex32(expected));
    }
}

#[test]
fn rfc7748_section_5_2_iterated_vectors_after_one_and_one_thousand_rounds() {
    use fgit_ssh::x25519::x25519;
    // k = u = 9; each round computes k' = X25519(k, u) and sets u = k, k = k'.
    let mut k = hex32("0900000000000000000000000000000000000000000000000000000000000000");
    let mut u = k;
    for round in 1..=1_000 {
        let next = x25519(&k, &u);
        u = k;
        k = next;
        if round == 1 {
            assert_eq!(
                k,
                hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            );
        }
    }
    assert_eq!(
        k,
        hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    );
}

#[test]
fn x25519_matches_the_admitted_dalek_curve_on_derived_keys() {
    use fgit_ssh::x25519::{x25519, x25519_base};
    // Differential against the admitted curve implementation reached through
    // ed25519-dalek (DEP-051, curve25519-dalek transitively, DEP-044): an
    // Ed25519 key's Montgomery form is the X25519 public key of its clamped
    // scalar, and dalek's clamped Montgomery multiplication is the reference
    // for arbitrary points.
    let keys: Vec<_> = (0_u8..=127)
        .map(|seed| {
            let mut bytes = [seed; 32];
            bytes[0] = seed.wrapping_mul(37).wrapping_add(11);
            bytes[31] = !seed;
            ed25519_dalek::SigningKey::from_bytes(&bytes)
        })
        .collect();
    for pair in keys.windows(2) {
        let (ours, theirs) = (&pair[0], &pair[1]);
        let scalar = ours.to_scalar_bytes();
        let own_public = ours.verifying_key().to_montgomery();
        assert_eq!(x25519_base(&scalar), own_public.to_bytes());
        let peer = theirs.verifying_key().to_montgomery();
        assert_eq!(
            x25519(&scalar, &peer.to_bytes()),
            peer.mul_clamped(scalar).to_bytes()
        );
    }
}
