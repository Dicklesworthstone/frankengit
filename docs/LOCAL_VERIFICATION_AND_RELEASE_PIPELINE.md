# Local Verification and Release Pipeline

**Status:** normative operations profile  
**Version:** 1.0  
**Last revised:** 2026-08-19

FrankenGit does not depend on GitHub-hosted Actions for correctness, release availability, or evidence. Repository workflows are portable lane descriptions consumed locally by Doodlestein Self-Releaser (`dsr`) and `act` where appropriate. The canonical commands, schemas, and evidence generation live inside the repository.

## 1. Source of truth

The hierarchy is:

1. repository-owned Rust tools and shell entrypoints;
2. checked-in lane manifests and expected artifacts;
3. `.github/workflows/*.yml` as a dispatch-only portable adapter for DSR/`act`;
4. GitHub Releases as one distribution endpoint.

No verification or release behavior may exist only in GitHub expression syntax, hosted runner state, Marketplace action internals, or an untracked repository secret.

## 2. Canonical local commands

The initial lanes are:

```bash
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
./scripts/verify.sh full
./scripts/verify.sh release
```

- `docs`: links, fences, required status/contract phrases, registries, workflow portability.
- `constitution`: dependency, unsafe/FFI, layer, crate-admission, license, and claim checks.
- `fast`: fmt, check, focused unit/model tests, registry checker.
- `full`: future workspace/conformance/deterministic-lab/fuzz/corpus/artifact gate.
- `release`: future full lane plus target-native binaries, packaging, checksums, SBOM, signatures, installer smoke, reproducibility, and root-last manifest.

In the pre-implementation repository, `docs`, `constitution`, and `fast` are runnable. `full` and `release` deliberately return exit code 3 with a typed dormant-gate refusal; they must not produce a false green status. As implementation grows, each lane delegates to Rust `xtask`/checker subcommands; shell remains a thin portable dispatcher.

## 3. Workflow YAML rules

Workflow files:

- call only repository-owned lane commands except checkout/setup primitives;
- pin every action to an immutable commit SHA;
- declare timeouts and least permissions;
- avoid service-specific artifact discovery;
- keep Linux jobs compatible with DSR/`act`;
- mark macOS/Windows/hardware lanes as native-host lanes;
- never make remote queue completion a release precondition;
- never mint canonical claims from a badge or workflow status alone.

Workflow manifests are dispatch-only by default and are intended for local DSR/`act` execution. If an operator deliberately enables remote execution, its result has no stronger status than the equivalent repository-owned local lane receipt.

## 4. DSR target matrix

The current example DSR config declares only the runnable Linux documentation/constitution bootstrap. It intentionally cannot release a FrankenGit binary. When implementation artifacts exist, the config expands to:

- Linux x86_64 and aarch64;
- macOS Apple Silicon and Intel where supported;
- Windows x86_64 and arm64 where supported;
- WebAssembly/browser packages where relevant;
- source archive and verification bundle;
- target-to-job/native-host mapping;
- exact primary assets and checksum sidecars;
- required companion files;
- toolchain and environment constraints.

Linux may run through `act` or native local execution. macOS and Windows run on native hosts through SSH. Cross-compiled artifacts never substitute for target-native smoke/conformance where the release contract requires it.

## 5. Attempt and resume semantics

Each release run has a stable `ReleaseRunId` and immutable per-target attempts. A completed target can be reused on resume only if all of the following match:

- source commit/tree;
- Cargo.lock and constellation lock;
- pinned nightly/compiler fingerprint;
- target triple and CPU contract;
- feature/profile set;
- workflow/lane digest;
- environment/input manifest;
- artifact and test receipt roots.

Incomplete or mismatched targets rerun. Verified completed artifacts are never silently overwritten by a later attempt; a new attempt has a new identity.

## 6. Root-last release publication

A partial matrix is not a release.

1. Build/test each target into an attempt-scoped staging directory.
2. Verify primary binaries and exact companion files.
3. Produce deterministic archives.
4. Generate per-asset SHA-256/strong digests.
5. Generate SBOM and provenance records.
6. Run installer/extraction/version/smoke tests against staged assets.
7. Produce signatures according to policy.
8. Verify all requested targets and assets against the exact contract.
9. Construct the unsigned release-manifest body.
10. Sign the manifest and checksum collection.
11. Atomically publish the authoritative local manifest.
12. Upload exactly those immutable assets to GitHub Releases and other mirrors.
13. Verify remote asset name/size/digest against the local manifest.

The local signed manifest is the release authority. A GitHub release page cannot make an incomplete or altered asset set legitimate.

## 7. Release manifest

```rust
struct ReleaseManifestBody {
    project: String,
    version: SemVer,
    source_commit: GitObjectId,
    source_tree: GitObjectId,
    cargo_lock_digest: Digest,
    constellation_digest: Digest,
    toolchain_fingerprint: ToolchainFingerprint,
    lane_profile: VerificationProfileId,
    targets: Vec<TargetReleaseRecord>,
    sbom_root: Digest,
    provenance_root: Digest,
    verification_root: Digest,
    negative_evidence_root: Digest,
    created_logical_time: LogicalTime,
}
```

Each target record binds host identity class, target triple, enabled CPU contract, build profile/features, binary/archive/assets, checksums, signatures, tests, installer smoke, and resource/performance receipts.

## 8. Exact asset contract

Each configured target maps to exactly one primary asset basename. Every primary asset has a checksum sidecar. Additional assets are enumerated by exact name. The packager refuses:

- symlinks or path traversal;
- missing or duplicate files;
- basename collisions;
- unlisted directory discovery;
- stale assets from another attempt;
- non-regular companion files;
- archive members outside the intended root;
- mismatched executable names/version output;
- unsigned/checksumless assets when policy requires them.

## 9. Reproducibility and equivalence

Two target builds are reproducibility-comparable only when their manifest inputs match. The lane records:

- exact versus semantic reproducibility class;
- `SOURCE_DATE_EPOCH`/timestamps;
- archive ordering/metadata normalization;
- embedded build ID policy;
- binary and section digests;
- known unavoidable target differences;
- A/A control and A/B comparison.

A remote and local build are “the same” only if the declared reproducibility class verifies—not because they ran nominally similar YAML.

## 10. Evidence pack

Every full/release lane emits a bounded replay pack containing:

- manifest and source fingerprints;
- commands and environment whitelist;
- structured per-step results;
- raw test/conformance/benchmark samples;
- deterministic lab seeds/crashpacks;
- dependency/unsafe/layer/claim reports;
- artifact inventory and digests;
- failure/skip/refusal records;
- replay command;
- completeness class.

Large artifacts may be separately stored and RaptorQ-protected; the evidence pack contains their immutable IDs and availability policy.

## 11. Hosted-service dogfooding

Once FrankenGit can host its own repository, the release pipeline should be mirrored through FrankenGit-native CI/artifact/release APIs while retaining DSR as an independent local recovery path. Neither system becomes the sole route to rebuild or verify the other.

## 12. Security

- Build hosts are registered capabilities with target/toolchain scope.
- SSH host identity and source checkout are verified before execution.
- Secrets are delivered per attempt and revoked at region close.
- Host outputs are untrusted until local digest/structure/signature verification.
- Release credentials cannot modify source or authority records.
- Upload uses idempotent exact-asset reconciliation.
- SBOM/signatures are generated from staged immutable assets, not mutable build directories.
- A compromised GitHub account cannot alter already published local signed manifests without detection.

## 13. Failure semantics

- Target failure: release remains unpublished; successful target attempts remain resumable evidence.
- Host unavailable: typed unavailable result; no target substitution unless contract permits it.
- Upload partial failure: retry exact missing/mismatched assets; do not rebuild.
- Remote asset mismatch: fail closed and quarantine/recreate draft release according to policy.
- Signing failure: no authoritative manifest.
- Cancellation: stop new targets, drain active jobs, preserve complete attempt receipts, publish no release root.

## 14. Required local tooling gates

The repository must remain verifiable on the user’s own machines with:

- pinned Rust nightly and Cargo;
- standard shell/core utilities used only by thin scripts;
- DSR/`act` for workflow reuse;
- native target hosts where required;
- minisign/cosign/SBOM tools according to final policy.

No test requires a hosted Actions token merely to run. Network-dependent conformance lanes are separately marked and have offline replay artifacts.
