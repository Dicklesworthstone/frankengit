# Pinned Rust bootstrap links

Temporary transport-only links for the repository's exact `nightly-2026-08-31` toolchain, matching [`rust-toolchain.toml`](rust-toolchain.toml):

- [SHA-256 manifest](https://static.rust-lang.org/dist/2026-08-31/rust-nightly-x86_64-unknown-linux-gnu.tar.xz.sha256)
- [Toolchain archive](https://static.rust-lang.org/dist/2026-08-31/rust-nightly-x86_64-unknown-linux-gnu.tar.xz)

Treat `rust-toolchain.toml` as the authority. This note exists only for environments that must bootstrap the pinned distribution without `rustup`; it must move in the same commit whenever the pin changes.

Run the read-only preflight before downloading or invoking Cargo:

```bash
scripts/check_toolchain_bootstrap_links.sh
scripts/tests/check_toolchain_bootstrap_links.sh
```

The preflight uses Bash and Python 3.11+ from the local machine, with no
third-party Python or Cargo dependencies. `PYTHON_BIN` may name an explicit
interpreter. The `docs` verification lane runs it before the registry checker.
A consistent dated pin and exactly one archive/checksum URL pair return exit
0; malformed, missing, stale, duplicated, or mixed metadata return exit 3;
usage errors and an unavailable interpreter return exit 2. It never downloads
anything or rewrites either input.

This checks transport metadata only. It does not authenticate an archive,
prove distribution availability, install Rust, establish compiler identity,
or authorize a nightly advancement. The fixture suite tests this command's
contract and its ordering before Cargo, not the Rust workspace. Advancement
still follows [ADR-0010](docs/ADR-0010-NIGHTLY-ADVANCEMENT-CADENCE.md), including
revision-bound verification; the pin and this mechanically coupled transport
metadata move together, separately from implementation or lint fallout.
