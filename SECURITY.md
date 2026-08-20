# Security Policy

FrankenGit is currently a pre-implementation architecture project. Security reports may still concern documentation defects that would produce an unsafe implementation, repository automation, or future code.

## Reporting a vulnerability

Use GitHub's private security-advisory flow for this repository. Do not open a public issue containing exploit details, credentials, private repository data, or a working proof of concept against a deployed system.

Include:

- affected document, commit, component, or protocol version;
- threat actor and required access;
- exact invariant or trust boundary violated;
- reproduction steps or a minimal model/trace;
- impact and whether it crosses tenants/repositories;
- suggested mitigation, if known;
- any disclosure constraints.

## Scope priorities

Highest priority areas include:

- Git pack/object parsing and resource exhaustion;
- ref/forge transaction atomicity and idempotency;
- writer fencing and failover;
- authentication, authorization, token attenuation, and revocation;
- hidden/private ref or fork disclosure;
- CI runner isolation, cache poisoning, and secret exposure;
- agent prompt injection and effect-broker bypass;
- webhook SSRF/signature/replay issues;
- archive/rendering path traversal or active-content injection;
- package/LFS/artifact cross-tenant access;
- GC, legal hold, backup, and deletion-root failures;
- RaptorQ decode acceptance without original commitments;
- projection lag being used as current authorization state.

## Non-claims

No security-support window or production SLA exists before an implementation release. The full architecture threat model is in `SECURITY_THREAT_MODEL.md`; canonical semantics are in `docs/NORMATIVE_PROTOCOL_CONTRACTS.md`.