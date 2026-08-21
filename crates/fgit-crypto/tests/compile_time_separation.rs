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

use std::ffi::OsStr;
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

/// Locate a build artifact for `prefix`, searching outward from this binary.
///
/// Two assumptions in the first version of this harness were wrong, and batch
/// verify found both. It assumed the test binary sits in
/// `<target>/<profile>/deps` alongside the crate's `.rlib`; in this
/// environment cargo writes artifacts to
/// `<target>/<profile>/build/<package>/<hash>/out/`, the `deps` directory is
/// empty, and each build unit gets its own `out` directory — so the test
/// binary's own directory does not contain the library it linked against, a
/// sibling one does. It also assumed `.rlib`; `cargo check` emits only
/// `.rmeta`, which is sufficient here because this harness only ever asks
/// rustc for `--emit=metadata`.
///
/// So: walk ancestors, and at each one do a depth-limited recursive scan for
/// `prefix*.rlib` or `prefix*.rmeta`, newest wins. Verified against the exact
/// layout that broke the first version.
fn locate_artifact(prefix: &str) -> PathBuf {
    /// How deep to look below each ancestor. Four levels reaches
    /// `build/<package>/<hash>/out/<file>`.
    const SCAN_DEPTH: usize = 4;
    /// How far up to walk. Eight levels reaches the target root from a binary
    /// nested inside a build-unit output directory.
    const ANCESTOR_LIMIT: usize = 8;

    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let mut searched = Vec::new();
    for ancestor in exe.ancestors().take(ANCESTOR_LIMIT) {
        let mut best = None;
        scan_for_artifact(ancestor, prefix, SCAN_DEPTH, &mut best);
        if let Some((_, path)) = best {
            return path;
        }
        searched.push(ancestor.display().to_string());
    }
    // Deliberately a hard failure, never a skip: a compile-time boundary that
    // has quietly stopped being checked is worse than one that fails the lane.
    let searched = searched.join("\n  ");
    panic!(
        "no `{prefix}*.rlib` or `{prefix}*.rmeta` found; the compile-time boundary cannot be checked. Searched below:\n  {searched}"
    );
}

/// Depth-limited search for the newest matching artifact.
fn scan_for_artifact(
    directory: &Path,
    prefix: &str,
    depth: usize,
    best: &mut Option<(std::time::SystemTime, PathBuf)>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // `file_type` does not follow symlinks, so this cannot loop.
        if file_type.is_dir() {
            scan_for_artifact(&path, prefix, depth - 1, best);
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let extension = path.extension().and_then(OsStr::to_str);
        if !name.starts_with(prefix) || !matches!(extension, Some("rlib" | "rmeta")) {
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
            *best = Some((modified, path));
        }
    }
}

struct Harness {
    scratch: PathBuf,
    crypto: PathBuf,
    types: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let crypto = locate_artifact("libfgit_crypto-");
        let types = locate_artifact("libfgit_types-");
        let scratch = crypto
            .parent()
            .expect("an artifact always has a parent directory")
            .join("fgit-crypto-compile-fail");
        std::fs::create_dir_all(&scratch).expect("a scratch directory for generated sources");
        Self {
            scratch,
            crypto,
            types,
        }
    }

    /// `-L dependency=` for each directory holding an artifact. The two crates
    /// land in different build-unit directories, so one search path is not
    /// enough.
    fn link_dirs(&self) -> Vec<&Path> {
        let mut dirs: Vec<&Path> = Vec::new();
        for artifact in [&self.crypto, &self.types] {
            if let Some(parent) = artifact.parent()
                && !dirs.contains(&parent)
            {
                dirs.push(parent);
            }
        }
        dirs
    }

    /// Compile one program and report whether `rustc` accepted it.
    fn compiles(&self, name: &str, body: &str) -> (bool, String) {
        let source = self.scratch.join(format!("{name}.rs"));
        std::fs::write(&source, body).expect("the generated source is writable");
        let mut command =
            Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()));
        command
            .arg("--edition=2024")
            .arg("--crate-type=bin")
            .arg("--emit=metadata")
            .arg("-o")
            .arg(self.scratch.join(format!("{name}.meta")));
        for directory in self.link_dirs() {
            command
                .arg("-L")
                .arg(format!("dependency={}", directory.display()));
        }
        let output = command
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
