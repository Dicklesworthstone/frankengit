# FrankenGit Dependency and Memory-Safety Constitution

**Status:** normative pre-implementation constitution  
**Version:** 1.0  
**Last revised:** 2026-08-19

FrankenGit is a clean-room, pure-Rust implementation of Git hosting and forge semantics. It does not wrap the C Git implementation, `libgit2`, JGit, Dulwich, or another production Git engine. It does not link C/C++ libraries through FFI to obtain protocol, packfile, diff, compression, storage, TLS, database, or sandbox behavior. Existing Git implementations are permitted only as separately executed differential oracles inside conformance lanes; they never enter a FrankenGit production process or define an internal data structure by ABI accident.

This constitution makes dependency restraint and memory safety architectural properties rather than aspirations.

## 1. Non-negotiable rules

1. Every first-party Rust crate MUST declare `#![forbid(unsafe_code)]`.
2. No first-party crate may relax that lint through a local override.
3. No production feature may depend on a C or C++ library, a system `libgit2`, a dynamically loaded Git implementation, or a subprocess invocation of `git`.
4. Git’s observable formats and protocols are implemented from public specifications, source-derived behavioral analysis, and differential conformance—not by translating C control flow line by line.
5. Asupersync is the only async runtime. Tokio, async-std, smol, glommio, monoio, and hidden Tokio-bearing SDKs are prohibited from the production graph.
6. FrankenSuite crates are preferred over parallel local substitutes when their contract and evidence level fit the need.
7. A dependency is admitted for a capability, not for convenience. Every admitted non-Franken dependency has one registry row, one owner, one removal cost, one security review, and one reason a smaller in-tree implementation is not superior.
8. Empty crates, placeholder modules, and abstractions that merely rename an external dependency are prohibited.
9. The scalar, portable, safe-Rust implementation is the correctness oracle for every optimized path.
10. Performance work may alter representation or algorithm, but never memory-safety posture or the declared observable contract.

## 2. Dependency classes

### 2.1 Constitutional first-party dependencies

The preferred dependency universe is:

- `asupersync` for structured concurrency, capability-bearing contexts, obligations, deterministic lab execution, ATP, native transport, cancellation, and resource budgets;
- FrankenKernel / FrankenEvidence / FrankenDecision components where their versioned contracts are suitable;
- FrankenSQLite for embedded MVCC materializations, derived indexes, local queues, and single-node authority storage;
- FrankenFS for safe filesystem/materialization machinery and optional FUSE-backed workspaces;
- FrankenSearch for progressive lexical/semantic retrieval and immutable generation discipline;
- FrankenNetworkX for deterministic graph storage and graph algorithms;
- FrankenGraphDB for temporal graph projections, append-only graph state, evidence/claim machinery, and graph query execution;
- franken_markdown for source-spanned parsing and safe deterministic rendering;
- other FrankenSuite crates only through an explicit, pinned constellation.

A sibling dependency is not automatically trusted because it is in the family. Before the first release-facing build that consumes a sibling, its exact revision, feature set, public contract, unsafe inventory, and claim level must be pinned in a checked-in `constellation.lock` evidence manifest and verified by the registry checker; no such manifest exists yet because no sibling dependency has been admitted.

### 2.2 Fundamental pure-Rust dependencies

A small number of foundational crates may be admitted when implementing them in-tree would increase risk or create a cryptographic/protocol maintenance burden. Examples include:

- `serde` and narrowly scoped serialization adapters;
- audited cryptographic primitives and signature implementations;
- `zeroize`-class secret-memory hygiene;
- pure-Rust Unicode tables or normalization data;
- standards-compliant compression primitives when no FrankenSuite implementation is ready;
- platform bindings that expose safe Rust APIs without linking foreign runtime code.

“Fundamental” is not a catch-all. HTTP frameworks, ORMs, generic object-store SDKs, Git libraries, graph libraries, search engines, templating engines, task schedulers, cloud SDKs, and broad utility crates do not qualify merely because they are popular.

### 2.3 Tooling-only dependencies

Fuzzers, coverage tools, mutation testers, benchmark harnesses, and conformance oracles may use a wider development-only universe if they are quarantined from all production feature graphs. Tooling dependencies still receive license, supply-chain, and execution-boundary review.

The upstream `git` executable is allowed only in this class. A differential test starts it as an untrusted external oracle with pinned version, bounded resources, controlled environment, and captured transcript. A production binary must build and run correctly on a system with no Git installation.

### 2.4 Prohibited classes

The following are prohibited in production:

- C/C++ Git engines or bindings;
- OpenSSL, libcurl, zlib, PCRE, ICU, libssh2, or other native libraries reached through FFI;
- database servers or clients needed to establish repository truth;
- cloud-provider SDKs that pull broad async/runtime stacks;
- ambient global executors;
- dependencies that perform network access in `build.rs`;
- proc-macro frameworks that generate opaque authority-sensitive code without a checked expansion artifact;
- crates whose default features silently add native code, Tokio, telemetry exporters, or network clients;
- crates with unresolved soundness advisories in an enabled path;
- dynamically loaded plugins inside the truth plane.

## 3. Latest-nightly policy without unreproducible releases

Development targets the latest Rust nightly because FrankenGit expects to use edition 2024, portable SIMD, strict linting, and rapidly improving compiler optimization. “Latest” does not mean “unrecorded.”

- `rust-toolchain.toml` pins one nightly date for the repository.
- A local toolchain-refresh lane proposes the next nightly, runs the complete gate matrix, and records compiler/LLVM fingerprints.
- Release artifacts bind the exact `rustc -vV`, Cargo version, target spec, enabled CPU contract, lockfile digest, constellation digest, and build profile.
- The pinned nightly is refreshed frequently, but only by an explicit commit whose evidence pack proves behavior and performance did not regress.
- A developer may experiment with a newer nightly locally; evidence from an unpinned compiler cannot promote a release claim.

## 4. Safe performance doctrine

FrankenGit rejects the false choice between safety and performance. Its main performance levers are architectural:

- immutable append-oriented records instead of in-place mutation;
- content-addressed deduplication;
- object-aware and graph-aware segmentation;
- per-core preparation lanes and flat-combined publication;
- integer-indexed hot graph structures with stable external identities;
- columnar ingest and sort-based index construction;
- bounded arena reuse through safe ownership APIs;
- copy-on-write tree overlays;
- zero-copy *logical* slicing over owned byte buffers rather than unchecked pointers;
- portable SIMD through safe FrankenSuite facades;
- cache-aware layouts and explicit working-set budgets;
- precomputed deterministic plans and witnesses;
- batch, swarm, and fountain-coded transport;
- progressive results instead of latency-amplifying all-or-nothing pipelines.

No optimization is admitted solely because a benchmark is faster. It must carry:

1. an exact behavior-isomorphism or accepted-divergence proof;
2. scalar-oracle comparison;
3. deterministic repeated-run evidence;
4. memory and cancellation bounds;
5. target-family measurements;
6. a rollback artifact;
7. a negative-result entry if the hypothesis fails.

## 5. Unsafe transitive code

Rust dependencies may internally contain `unsafe` while still exposing a sound memory-safe API. FrankenGit nevertheless treats transitive unsafe as a cost, not as invisible implementation detail.

Every admitted dependency records:

- whether enabled code contains `unsafe`;
- why the capability cannot currently be obtained from safe FrankenSuite code;
- audit status and soundness history;
- fuzz/Miri/sanitizer coverage where available;
- the exact feature graph that keeps unrelated unsafe modules disabled;
- a replacement or containment plan.

The V1 target is zero first-party unsafe, zero foreign-language runtime code, and a sharply minimized, ledgered transitive unsafe surface. Cryptographic or platform primitives do not receive blanket exemptions.

## 6. Build-script and proc-macro policy

A dependency with `build.rs` or proc macros expands the trusted build surface.

- Build scripts may not access the network, execute downloaded binaries, inspect undeclared host secrets, or vary output by wall clock.
- Generated source and schemas must be reproducible from tracked inputs.
- Authority-sensitive generated code has a checked-in schema fingerprint and golden expansion test.
- Proc macros are not used to hide transaction state machines, authorization decisions, canonical encodings, or cancellation boundaries.
- The local verifier enumerates every enabled build script and proc macro and compares it with the dependency registry.

## 7. Dependency admission procedure

A proposed dependency must answer:

1. What exact capability is missing?
2. Which FrankenSuite crates were evaluated?
3. What is the smallest viable feature set?
4. Does it add an async runtime, FFI, build script, proc macro, native binary, or network acquisition?
5. What unsafe code becomes reachable?
6. What canonical bytes or behavior could it influence?
7. What is the conformance oracle?
8. What is the supply-chain and license history?
9. Can it be replaced without changing durable formats?
10. What evidence closes the admission gate?

The registry checker fails when a manifest dependency lacks an accepted row, when a prohibited crate appears transitively, or when a dependency’s enabled feature set drifts from its declared contract.

## 8. Git implementation boundary

FrankenGit owns:

- object header and object-ID calculation;
- blob, tree, commit, and tag parsing/encoding;
- SHA-1 and SHA-256 repository formats;
- pack parsing, delta resolution, indexing, bitmap/MIDX/commit-graph materializations;
- pkt-line and sideband framing;
- upload-pack and receive-pack negotiation;
- shallow and partial-clone semantics;
- refs, namespaces, atomic pushes, symrefs, notes, tags, and hidden refs;
- diff/merge algorithms and deterministic tie-break policies;
- quarantine, reachability, collision defense, and resource limits.

The C Git project remains a behavioral oracle and interoperability peer. It is never a linked library, embedded process, or hidden fallback. An unsupported FrankenGit operation returns a typed refusal; it does not shell out to Git and pretend the feature is native.

## 9. Memory-safety release gate

A release is blocked unless:

- every first-party crate contains `#![forbid(unsafe_code)]`;
- the workspace lint also forbids unsafe;
- no production binary links a non-Rust object or shared library beyond the operating system ABI allowed by the target contract;
- no production feature invokes `git` or another foreign engine;
- the dependency graph matches `registries/dependency_policy.tsv`;
- all enabled transitive unsafe is acknowledged in the generated dependency evidence report;
- malformed/adversarial Git, archive, Markdown, workflow, package, webhook, and object-store inputs remain within declared memory/time/decompression bounds;
- cancellation and panic campaigns leave no orphan process, task, lock, reservation, or partially published root.

## 10. Constitutional non-claims

This document does not claim that Rust alone prevents logic errors, that `forbid(unsafe_code)` audits dependencies, that pure Rust makes cryptography correct, or that a clean-room implementation automatically matches Git. It establishes the minimum construction rules under which the later evidence can be meaningful.
