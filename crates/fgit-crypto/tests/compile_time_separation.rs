//! The algorithm boundary is a compile error, and this test proves it under
//! the lane that actually runs.
//!
//! `fgit-crypto` documents the boundary with `compile_fail` doc tests, but
//! `verify.sh fast` runs `cargo test --workspace --all-targets`, and
//! `--all-targets` excludes doc tests. A property that only a lane nobody runs
//! can check is not a gated property, so this harness invokes `rustc` directly
//! on small programs and asserts each one is rejected — and, just as
//! importantly, that the near-identical permitted program is accepted. A
//! harness that only ever saw rejections could be passing because the compiler
//! invocation itself is broken.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A program that must not compile, and the reason it must not.
struct ForbiddenCase {
    name: &'static str,
    reason: &'static str,
    body: &'static str,
}

/// A program that must compile, paired with a forbidden case above.
struct PermittedCase {
    name: &'static str,
    body: &'static str,
}

const FORBIDDEN: &[ForbiddenCase] = &[
    ForbiddenCase {
        name: "cross_format_equality",
        reason: "a SHA-1 identity and a SHA-256 identity are different types",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
            fn main() {
                let narrow = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
                let wide = GitOid::<Sha256>::of_object(GitObjectKind::Blob, b"");
                let _ = narrow == wide;
            }
        "#,
    },
    ForbiddenCase {
        name: "cross_format_substitution",
        reason: "one format cannot be passed where the other is required",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
            fn requires_wide(_oid: GitOid<Sha256>) {}
            fn main() {
                requires_wide(GitOid::<Sha1>::of_object(GitObjectKind::Blob, b""));
            }
        "#,
    },
    ForbiddenCase {
        name: "cross_format_hasher",
        reason: "a hasher for one format cannot finish into the other format's identity",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
            fn main() {
                let hasher = GitOid::<Sha1>::object_hasher(GitObjectKind::Blob, 0);
                let _wide: GitOid<Sha256> = hasher.finish().unwrap();
            }
        "#,
    },
    ForbiddenCase {
        name: "hex_without_algorithm_context",
        reason: "hexadecimal parsing never infers the algorithm from the input",
        body: r#"
            fn main() {
                let _ = fgit_crypto::parse_git_oid("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
            }
        "#,
    },
    ForbiddenCase {
        name: "internal_identity_without_a_domain",
        reason: "an internal identity cannot be computed without naming a domain",
        body: r#"
            use fgit_crypto::{internal_object_id, CodecVersion, SchemaFamily, SchemaId};
            fn main() {
                let family = SchemaFamily::from_static("frankengit.canonical-body");
                let _ = internal_object_id(SchemaId::new(family, 1, 0), CodecVersion::new(1, 0), b"body");
            }
        "#,
    },
    ForbiddenCase {
        name: "third_party_algorithm_marker",
        reason: "the algorithm set is sealed against downstream extension",
        body: r#"
            use fgit_crypto::{DigestAlgorithm, GitHashAlgorithm};
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            struct Md5;
            impl GitHashAlgorithm for Md5 {
                const ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha1;
                const OBJECT_FORMAT: fgit_crypto::GitObjectFormat = fgit_crypto::GitObjectFormat::Sha1;
                const DIGEST_LEN: usize = 16;
                const HEX_LEN: usize = 32;
                type Digest = [u8; 16];
                type Hasher = fgit_crypto::Sha1Hasher;
                type Oid = fgit_crypto::GitOidSha1;
                fn oid_from_digest(_digest: Self::Digest) -> Self::Oid {
                    fgit_crypto::GitOidSha1::from_bytes([0; 20])
                }
                fn parse_hex(_text: &str) -> Result<Self::Oid, fgit_types::TypeRefusal> {
                    Ok(fgit_crypto::GitOidSha1::from_bytes([0; 20]))
                }
            }
            fn main() {}
        "#,
    },
];

const PERMITTED: &[PermittedCase] = &[
    PermittedCase {
        name: "same_format_equality",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
            fn main() {
                let first = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
                let second = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"");
                assert!(first == second);
            }
        "#,
    },
    PermittedCase {
        name: "same_format_substitution",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha256};
            fn requires_wide(_oid: GitOid<Sha256>) {}
            fn main() {
                requires_wide(GitOid::<Sha256>::of_object(GitObjectKind::Blob, b""));
            }
        "#,
    },
    PermittedCase {
        name: "same_format_hasher",
        body: r#"
            use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
            fn main() {
                let hasher = GitOid::<Sha1>::object_hasher(GitObjectKind::Blob, 0);
                let _narrow: GitOid<Sha1> = hasher.finish().unwrap();
            }
        "#,
    },
    PermittedCase {
        name: "hex_with_algorithm_context",
        body: r#"
            use fgit_crypto::{parse_git_oid, Sha1};
            fn main() {
                let _ = parse_git_oid::<Sha1>("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391").unwrap();
            }
        "#,
    },
    PermittedCase {
        name: "internal_identity_with_a_domain",
        body: r#"
            use fgit_crypto::{internal_object_id, CodecVersion, IdentityDomain, SchemaFamily, SchemaId};
            fn main() {
                let family = SchemaFamily::from_static("frankengit.canonical-body");
                let _ = internal_object_id(
                    IdentityDomain::RefTransaction,
                    SchemaId::new(family, 1, 0),
                    CodecVersion::new(1, 0),
                    b"body",
                );
            }
        "#,
    },
];

/// Directory cargo placed this test binary in; its sibling `.rlib` files are
/// the crate under test and its dependencies.
fn dependency_dir() -> PathBuf {
    let mut path = std::env::current_exe().expect("the test binary knows its own path");
    path.pop();
    if path.ends_with("deps") {
        path
    } else {
        path.join("deps")
    }
}

/// Locate the most recently built `.rlib` whose file name starts with `prefix`.
fn newest_rlib(directory: &Path, prefix: &str) -> PathBuf {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(prefix) || !name.ends_with(".rlib") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if best
            .as_ref()
            .is_none_or(|(best_time, _)| modified >= *best_time)
        {
            best = Some((modified, path));
        }
    }
    best.map(|(_, path)| path).unwrap_or_else(|| {
        panic!(
            "no `{prefix}*.rlib` in {}; the compile-time boundary cannot be checked",
            directory.display()
        )
    })
}

struct Harness {
    scratch: PathBuf,
    deps: PathBuf,
    crypto: PathBuf,
    types: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let deps = dependency_dir();
        let scratch = deps.join("fgit-crypto-compile-fail");
        std::fs::create_dir_all(&scratch).expect("a scratch directory for generated sources");
        let crypto = newest_rlib(&deps, "libfgit_crypto-");
        let types = newest_rlib(&deps, "libfgit_types-");
        Self {
            scratch,
            deps,
            crypto,
            types,
        }
    }

    /// Compile one program and report whether `rustc` accepted it.
    fn compiles(&self, name: &str, body: &str) -> (bool, String) {
        let source = self.scratch.join(format!("{name}.rs"));
        std::fs::write(&source, body).expect("the generated source is writable");
        let output = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()))
            .arg("--edition=2024")
            .arg("--crate-type=bin")
            .arg("--emit=metadata")
            .arg("-o")
            .arg(self.scratch.join(format!("{name}.meta")))
            .arg("-L")
            .arg(format!("dependency={}", self.deps.display()))
            .arg("--extern")
            .arg(format!("fgit_crypto={}", self.crypto.display()))
            .arg("--extern")
            .arg(format!("fgit_types={}", self.types.display()))
            .arg(&source)
            .output()
            .expect("rustc is on PATH inside a cargo test");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

#[test]
fn permitted_programs_compile() {
    let harness = Harness::new();
    for case in PERMITTED {
        let (compiled, diagnostics) = harness.compiles(case.name, case.body);
        assert!(
            compiled,
            "the permitted case `{}` must compile, but rustc rejected it:\n{diagnostics}",
            case.name
        );
    }
}

#[test]
fn forbidden_programs_do_not_compile() {
    let harness = Harness::new();
    for case in FORBIDDEN {
        let (compiled, _) = harness.compiles(case.name, case.body);
        assert!(
            !compiled,
            "the forbidden case `{}` compiled, so the boundary is gone: {}",
            case.name, case.reason
        );
    }
}
