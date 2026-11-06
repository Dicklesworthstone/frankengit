# Local Verification and Release Pipeline

**Status:** normative operations profile  
**Version:** 1.2
**Last revised:** 2026-11-02

FrankenGit uses Doodlestein Self-Releaser (`dsr`) directly. The GitHub Actions service must never be used, including hosted and self-hosted runners. Repository workflow definitions remain portable lane descriptions for local DSR/`act` execution. The canonical commands, schemas, and evidence generation live inside the repository.

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
# Choose a durable target directory unique to this verification pane.
export CARGO_TARGET_DIR=/data/frankengit-targets/verify-my-pane
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
./scripts/verify.sh e2e
./scripts/verify.sh operator
./scripts/verify.sh full
./scripts/verify.sh release
```

Build-backed lanes require `CARGO_TARGET_DIR`. Compilation follows the caller's
Cargo/RCH routing under AGENTS.md §16.2; the verifier does not force local
compilation. Repository-inspecting tools are built for the caller's native
host and executed on the caller against explicit checkout paths. This keeps
documentation, tracker and generated-schema checks on the real input tree,
including files excluded from a worker's source projection. The configured
`CARGO_BUILD_TARGET` still selects constitutional dependency/linkage inspection
and workspace compilation; it does not select the host that runs these tools.
Python 3.11+ is required by the bootstrap preflight; Python also parses Cargo's
target metadata without losing spaces, quotes or backslashes in paths.
When `CARGO_BUILD_JOBS` is set, native tool builds pass it explicitly as Cargo
`--jobs`, so remote compilation and scheduler admission use the same bound.

- `docs`: Markdown links, fences, required status/contract phrases, registry schemas/rows, and workflow portability.
- `constitution`: required files, first-party unsafe/FFI/foreign-Git source scan, manifest and Cargo.lock closed-world dependency checks, toolchain pin, and forbidden artifacts. Layering, license-compatibility, and claim-registry checks join this lane as the corresponding machinery lands; they are not implemented yet.
- `fast`: the `docs` and `constitution` lanes plus verifier command-contract tests, `cargo fmt --check`, `cargo check`, generated-schema checks, full workspace tests, and `cargo clippy -D warnings`.
- `operator`: the currently implemented live operator campaigns and operator/script module suites, using one native `fg` build and the shared pinned Node identity. This is not the complete every-entrypoint qualification required by `x2mv.4.59`.
- `full`: future workspace/conformance/deterministic-lab/fuzz/corpus/artifact gate.
- `release`: future full lane plus target-native binaries, packaging, checksums, SBOM, signatures, installer smoke, reproducibility, and root-last manifest.

The product `e2e` lane also discovers the operator module suite at
[`scripts/e2e/suites/operator/contract_tests.sh`](../scripts/e2e/suites/operator/contract_tests.sh).
It reuses the [pinned JavaScript verifier](LOCAL_JS_VERIFICATION.md) for both
operator and script tests and forwards the prebuilt `fg` to their existing
native child cases. This is module coverage with explicitly identified native
cells; it does not establish the full live-server operator matrix in
`x2mv.4.59`. Missing prerequisites, failed profiles and empty TAP are non-pass;
optional oracle skips remain skips rather than native compatibility evidence.

The dedicated `operator` command checks the existing
[`verify_js.mjs runtime`](../scripts/verify_js.mjs) identity before native
compilation. `FGE_NODE` selects that executable; otherwise it uses Node on PATH.
An unavailable runtime returns a typed exit-3 refusal, and a mismatched version
retains the shared verifier's typed refusal. There is no second version pin.
The command builds `fg` once with the existing Cargo `release` profile through
the native-host/private-target/Cargo/RCH
functions above, installs an identical private executable snapshot, then supplies
it and the same Node to
[`run_all.sh`](../scripts/e2e/run_all.sh). A supplied `FG_BIN` cannot bypass the
build. Source must be clean before compilation; a changed revision or dirty
checkout afterwards prevents campaign dispatch. After the campaigns finish, the
launcher checks the revision and checkout again: changed or unreadable source
cannot produce a successful lane result. An existing campaign failure keeps its
original exit code even if the final source diagnostic cannot be written. These
checks do not establish isolation from hostile concurrent writers or detect a
temporary change that was restored before inspection. The selected
source revision overrides a stale `FG_SIGNED_BUNDLE_SOURCE_CUT` for the signed
campaign.
Campaign receipts record `FGE_PROFILE=release`. The optimized, stripped artifact
serves the operators' existing executable-size and execution-time budgets;
those production guards are retained. This profile selection applies only to
`operator`; it is not evidence for the default-profile `fast` lane or the dormant
`release` gate.
The [native installer](../scripts/prepare_operator_native.py) leaves the Cargo/RCH
delivery unchanged, checks stable source identity and matching SHA-256 bytes,
and retains a canonical path under a private target subdirectory with mode
`0500`. Its streaming copy bounds an executable to 2 GiB. This accommodates a
worker's group-writable build output while retaining
the operator's executable ownership checks. Incomplete copies stay non-executable;
an installation failure prevents dispatch and retains its files for inspection.
The build remains the trust boundary;
installation does not authenticate an arbitrary executable. Retained snapshots
support replay and stay outside source control.

Selection includes every regular `.sh` recursively under
`scripts/e2e/suites/operator/`, in deterministic order, followed by the required
[`recovery/native_signed_bundle.sh`](../scripts/e2e/suites/recovery/native_signed_bundle.sh).
Empty discovery, non-executable campaigns and a missing signed campaign refuse
rather than narrowing the run. The existing `FGE_E2E_TIMEOUT` is forwarded;
build and runner failures preserve their exit status. LANE-008 records this
implemented command; LANE-007 retains its narrower module-only entrypoint.
Command-contract tests use explicit fake build/runner tools and establish
dispatch behavior only. They do not establish a native build, complete
entrypoint coverage, independent batch verification or a passing operator lane.
The [retained large signed-bundle deadline failure](NATIVE_BUNDLE_OPERATOR_VERIFICATION.md)
and all original `.4.59` acceptance conditions remain open until qualified.

The same discovery includes
[`operator/backup.sh`](../scripts/e2e/suites/operator/backup.sh), which drives seven
actual signed-backup CLIs through real native verification, local replica health,
retained checkpoint refusals, Git/forge restoration and exact cached resume in
both hash domains. It reuses the sole Node pin and supplied prebuilt `fg`; it
does not build another executable or substitute schema peers. The
[revision-bound result and missing-restore-route control](LOCAL_JS_VERIFICATION.md)
do not activate the full/release gates or complete `.4.59`'s original matrix.

The `docs`, `constitution`, `fast`, `e2e` and `operator` commands are implemented; their existence is not revision-bound evidence that they pass. `full` returns exit code 3 with a typed dormant-gate refusal. `release` first runs its mandatory license and runner-probe checks, preserving their failures, then returns the dormant refusal. Neither may produce a false green status. As implementation grows, each lane delegates to Rust `xtask`/checker subcommands; shell remains a thin portable dispatcher.

Activation is controlled by FG-091's exact suite manifest, not by a minimum script count. For the selected profile, the independent expected IDs must equal the scripts discovered, started, completed, and passed. Each required ID also names exactly one active owning Bead, and FG-091 must reach the complete owner set through blocking dependencies; dependency rewiring cannot silently detach a campaign. Missing, duplicate, unregistered, zero-run, skipped, unsupported, filtered, ignored, timed-out, malformed-log, stale-revision, wrong-profile, or unreachable-owner required entries keep the lane non-green, and first-attempt failures remain in the evidence.

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

Workflow manifests are dispatch-only and intended solely for local DSR/`act` execution. Their presence never authorizes use of the GitHub Actions service.

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
