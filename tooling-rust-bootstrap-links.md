# Pinned Rust bootstrap links

Temporary transport-only links for the repository's exact `nightly-2026-08-31` toolchain, matching [`rust-toolchain.toml`](rust-toolchain.toml):

- [SHA-256 manifest](https://static.rust-lang.org/dist/2026-08-31/rust-nightly-x86_64-unknown-linux-gnu.tar.xz.sha256)
- [Toolchain archive](https://static.rust-lang.org/dist/2026-08-31/rust-nightly-x86_64-unknown-linux-gnu.tar.xz)

Treat `rust-toolchain.toml` as the authority. This note exists only for environments that must bootstrap the pinned distribution without `rustup`; it must move in the same commit whenever the pin changes.

Validate this coupling locally with `scripts/check_toolchain_bootstrap_links.sh`; its fixture suite also rejects rolling channels, stale URLs, and mixed dates.
