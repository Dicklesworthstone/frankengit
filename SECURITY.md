# Security Policy

FrankenGit is currently a pre-implementation architecture and constitutional bootstrap project. Security reports may concern documentation defects that would produce an unsafe implementation, repository verification/release automation, or future code.

## Reporting a vulnerability

Use GitHub's private security-advisory flow for this repository. Do not open a public issue containing exploit details, credentials, private repository data, or a working proof of concept against a deployed system.

Include:

- affected document, commit, component, protocol/format version, or registry row;
- threat actor and required access;
- exact invariant, capability, trust boundary, or authority primitive violated;
- reproduction steps, minimal model, packet/object corpus, or deterministic trace;
- impact and whether it crosses tenants, repositories, regions, or release hosts;
- suggested mitigation, if known;
- disclosure constraints.

## Highest-priority areas

- pure-Rust Git object, pack, pkt-line, archive, diff, and signature parsing;
- authority-head compare-and-exchange, ABA prevention, transaction seals, terminal outcomes, and decision-batch replay;
- ref plus forge-event atomicity and policy-snapshot TOCTOU;
- object-store conditional semantics and stale/malicious backend receipts;
- authentication, capability attenuation, revocation, and confused-deputy attacks;
- hidden/private refs, forks, LFS, packages, artifacts, indexes, and Context Packet disclosure;
- TreeFS path resolution, symlink/reparse/hardlink escape, and workspace secret isolation;
- Asupersync cancellation, obligation leaks, and orphaned external effects;
- ATP-Git peer/path spoofing, symbol mixing, resource amplification, and cache-trust confusion;
- CI runner escape, cache poisoning, provenance forgery, and fork secret exposure;
- webhooks/importers SSRF, replay, redirect, decompression, and archive traversal;
- Markdown/SVG/rendered active content and source-span confusion;
- graph/search mixed-generation authorization or unreceipted decision ordering;
- RaptorQ decode acceptance without original commitments or repair overwriting newer state;
- GC, legal hold, active seal, migration, restore, and deletion-root omission;
- local DSR release resume, symlink/path collision, target substitution, signing, SBOM, and root-last manifest errors;
- dependency-policy, transitive unsafe, build-script, proc-macro, and supply-chain violations.

## Non-claims

No production support window or security SLA exists before an implementation release. Canonical semantics are defined in [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md), and the full threat model is [`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md).
