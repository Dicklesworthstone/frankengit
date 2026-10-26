//! Complete-table validation for the live SSH authorization source. These
//! tests need neither a filesystem nor a runtime.

use ed25519_dalek::SigningKey;
use fgit_crypto::VerifyingKey;
use fgit_identity::RevocationEvidence;
use fgit_identity::deploy_key::{
    DeployKeyBinding, DeployKeyRefusal, DeployKeyScope, DeployKeyTableRefusal,
    MAX_DEPLOY_KEY_TABLE_BYTES, MAX_DEPLOY_KEY_TABLE_ROWS, parse_deploy_key_table,
};
use fgit_types::{PrincipalId, RepositoryId};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x11; 16]);
const ROUTE: RepositoryId = RepositoryId::from_bytes([0x22; 16]);

fn public_key(index: u64) -> [u8; 32] {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&index.to_le_bytes());
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

fn row(index: u64, principal: u8, scopes: &str) -> String {
    format!(
        "{} {} {scopes}",
        hex(&public_key(index)),
        hex(&[principal; 16])
    )
}

fn parse(text: &str) -> Result<Vec<DeployKeyBinding>, DeployKeyTableRefusal> {
    parse_deploy_key_table(text.as_bytes(), REPOSITORY, ROUTE)
}

#[test]
fn valid_table_keeps_each_key_principal_scope_and_repository_alias_exact() {
    let text = format!(
        " \t# Déploy keys\r\n\r\n{} # read only\r\n\t{}\r\n{} #write and read\r\n",
        row(1, 1, "read"),
        row(2, 2, "write"),
        row(3, 3, "write,read"),
    );
    let bindings = parse(&text).unwrap();
    assert_eq!(bindings.len(), 6);
    for (index, scopes) in [
        (1, vec![DeployKeyScope::Read]),
        (2, vec![DeployKeyScope::Write]),
        (3, vec![DeployKeyScope::Read, DeployKeyScope::Write]),
    ] {
        let key = VerifyingKey::from_bytes(public_key(index));
        for repository in [REPOSITORY, ROUTE] {
            let binding = DeployKeyBinding::resolve(&bindings, &key, repository).unwrap();
            assert_eq!(
                binding.principal(),
                PrincipalId::from_bytes([index as u8; 16])
            );
            assert_eq!(binding.scopes(), scopes);
            for scope in [DeployKeyScope::Read, DeployKeyScope::Write] {
                let result = binding.authorize(&key, repository, scope, RevocationEvidence::Live);
                if scopes.contains(&scope) {
                    assert_eq!(result.unwrap(), binding.principal());
                } else {
                    assert_eq!(
                        result,
                        Err(DeployKeyRefusal::ScopeNotGranted { requested: scope }),
                    );
                }
            }
        }
        assert_eq!(
            DeployKeyBinding::resolve(&bindings, &key, RepositoryId::from_bytes([0x33; 16])),
            Err(DeployKeyRefusal::NoBindingForKey),
        );
    }
}

#[test]
fn an_alias_equal_to_the_repository_does_not_create_ambiguous_bindings() {
    let bindings =
        parse_deploy_key_table(row(1, 1, "read,write").as_bytes(), REPOSITORY, REPOSITORY).unwrap();
    assert_eq!(bindings.len(), 1);
    DeployKeyBinding::resolve(
        &bindings,
        &VerifyingKey::from_bytes(public_key(1)),
        REPOSITORY,
    )
    .unwrap();
}

#[test]
fn empty_and_comment_only_tables_revoke_every_key() {
    for text in ["", " \t\r\n\n", "# revoked\n  # no registrations remain\n"] {
        let bindings = parse(text).unwrap();
        assert!(bindings.is_empty());
        assert_eq!(
            DeployKeyBinding::resolve(
                &bindings,
                &VerifyingKey::from_bytes(public_key(1)),
                REPOSITORY,
            ),
            Err(DeployKeyRefusal::NoBindingForKey),
        );
    }
}

#[test]
fn hexadecimal_case_and_unambiguous_scope_repetition_have_canonical_meaning() {
    let ordinary = parse(&row(1, 0xab, "read,write")).unwrap();
    let alternate = format!(
        "{} {} write,read,write,read",
        hex(&public_key(1)).to_ascii_uppercase(),
        hex(&[0xab; 16]).to_ascii_uppercase(),
    );
    assert_eq!(parse(&alternate).unwrap(), ordinary);
    assert_eq!(
        parse(&row(1, 1, "read,read")).unwrap(),
        parse(&row(1, 1, "read")).unwrap(),
    );
    for scopes in [
        "admin",
        "READ",
        "read,",
        ",write",
        "read,,write",
        "read,admin",
    ] {
        assert_eq!(
            parse(&row(1, 1, scopes)),
            Err(DeployKeyTableRefusal::InvalidScopes { line: 1 }),
        );
    }
}

#[test]
fn a_repeated_logical_key_refuses_identical_and_conflicting_rows_before_aliases() {
    for second in [
        row(1, 1, "read"),
        row(1, 2, "read"),
        row(1, 1, "write"),
        format!(
            "{} {} read",
            hex(&public_key(1)).to_ascii_uppercase(),
            hex(&[1; 16]),
        ),
    ] {
        assert_eq!(
            parse(&format!("# table\n{}\n\n{second}", row(1, 1, "read"))),
            Err(DeployKeyTableRefusal::DuplicateKey {
                first_line: 2,
                line: 4,
            }),
        );
    }
    assert_eq!(
        parse(&format!("{}\n{}", row(1, 1, "read"), row(2, 1, "read")))
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn only_explicit_trailing_comments_may_follow_the_three_columns() {
    for suffix in ["", " \t", " # comment text", " \t#comment text 日本語"] {
        assert_eq!(
            parse(&format!("{}{suffix}", row(1, 1, "read"))).unwrap(),
            parse(&row(1, 1, "read")).unwrap(),
        );
    }
    for suffix in [" ignored", " write", " ignored # comment"] {
        assert_eq!(
            parse(&format!(
                "{}\n{}{suffix}",
                row(2, 2, "write"),
                row(1, 1, "read")
            )),
            Err(DeployKeyTableRefusal::UnexpectedField { line: 2 }),
        );
    }
    assert_eq!(
        parse(&row(1, 1, "read#comment")),
        Err(DeployKeyTableRefusal::InvalidScopes { line: 1 }),
    );
}

#[test]
fn invalid_utf8_anywhere_refuses_the_entire_table() {
    for prefix in [
        row(1, 1, "read"),
        format!("{}\n# comment", row(1, 1, "read")),
    ] {
        let mut bytes = prefix.into_bytes();
        bytes.push(0xff);
        assert_eq!(
            parse_deploy_key_table(&bytes, REPOSITORY, ROUTE),
            Err(DeployKeyTableRefusal::InvalidUtf8),
        );
    }
}

#[test]
fn malformed_or_non_ascii_hex_is_a_typed_refusal_and_never_a_slicing_panic() {
    let principal = hex(&[1; 16]);
    for key in [
        "00".repeat(31),
        "00".repeat(33),
        "gg".repeat(32),
        "€".repeat(21) + "0",
        "é".repeat(32),
    ] {
        assert_eq!(
            parse(&format!("{key} {principal} read")),
            Err(DeployKeyTableRefusal::InvalidPublicKey { line: 1 }),
        );
    }
    let key = hex(&public_key(1));
    for principal in [
        "00".repeat(15),
        "00".repeat(17),
        "gg".repeat(16),
        "€".repeat(10) + "00",
        "é".repeat(16),
    ] {
        assert_eq!(
            parse(&format!("{key} {principal} read")),
            Err(DeployKeyTableRefusal::InvalidPrincipal { line: 1 }),
        );
    }
    for text in [key.clone(), format!("{key} {}", hex(&[1; 16]))] {
        assert_eq!(
            parse(&text),
            Err(DeployKeyTableRefusal::MissingFields { line: 1 })
        );
    }
}

#[test]
fn unusable_ed25519_encodings_refuse_the_whole_table() {
    let undecodable = (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("the compressed Edwards encoding rejects non-points");
    let mut identity = [0; 32];
    identity[0] = 1;
    for key in [undecodable, [0; 32], identity] {
        let text = format!(
            "{}\n{} {} read",
            row(1, 1, "read"),
            hex(&key),
            hex(&[2; 16])
        );
        assert_eq!(
            parse(&text),
            Err(DeployKeyTableRefusal::InvalidPublicKey { line: 2 })
        );
    }
}

#[test]
fn byte_and_logical_row_limits_have_exact_accepted_boundaries() {
    let exact_bytes = format!("#{}", "x".repeat(MAX_DEPLOY_KEY_TABLE_BYTES - 1));
    assert!(parse(&exact_bytes).unwrap().is_empty());
    let mut oversized = exact_bytes.into_bytes();
    oversized.push(0xff);
    assert_eq!(
        parse_deploy_key_table(&oversized, REPOSITORY, ROUTE),
        Err(DeployKeyTableRefusal::ByteLimitExceeded {
            observed: MAX_DEPLOY_KEY_TABLE_BYTES + 1,
            limit: MAX_DEPLOY_KEY_TABLE_BYTES,
        }),
    );
    let table = (0..MAX_DEPLOY_KEY_TABLE_ROWS)
        .map(|index| row(index as u64, 1, "read"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(parse(&table).unwrap().len(), MAX_DEPLOY_KEY_TABLE_ROWS * 2);
    let oversized = format!(
        "{table}\n{}",
        row(MAX_DEPLOY_KEY_TABLE_ROWS as u64, 1, "read")
    );
    assert_eq!(
        parse(&oversized),
        Err(DeployKeyTableRefusal::RowLimitExceeded {
            line: MAX_DEPLOY_KEY_TABLE_ROWS + 1,
            limit: MAX_DEPLOY_KEY_TABLE_ROWS,
        }),
    );
}
