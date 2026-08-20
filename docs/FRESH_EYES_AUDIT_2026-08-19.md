# Historical Fresh-Eyes Audit

**Date:** 2026-08-19  
**Status:** historical v2 audit, superseded for current architecture by [`FRANKENSUITE_DEEP_AUDIT_2026-08-19.md`](FRANKENSUITE_DEEP_AUDIT_2026-08-19.md)

This file preserves the disposition of the first publication audit without keeping a second live architecture in the repository.

The v2 audit corrected the initial upload and several foundational ambiguities:

- restored the intended repository tree and documentation links;
- separated `git-upload-pack` fetch negotiation from `git-receive-pack` push semantics;
- established one stable logical `TxId` derivation and immutable terminal outcome lookup;
- made ref and forge publication one atomic repository decision;
- separated current forge position from periodic checkpoint capsules;
- constrained RaptorQ to registered immutable byte objects with post-decode verification;
- clarified agent capability attenuation, cancellation ambiguity, and licensing truthfulness;
- added Git compatibility, security, retention, CI, LFS, and recovery surfaces.

The subsequent FrankenSuite deep dive found that the v2 architecture still imported too many ideas only at slogan level and retained a conventional external metadata/sequencer shape. The live v3 contracts now use an immutable repository decision stream plus a conditional authenticated authority head; pure-Rust Git semantics; Asupersync obligations and ATP; FrankenSQLite-style preparation and witness refinement; FrankenFS-style repair/publication discipline; immutable search and graph generations; Git TreeFS workspaces; deterministic graph witnesses; a closed dependency constitution; and local DSR-owned verification and release evidence.

For current normative semantics, read:

1. [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md)
2. [`OBJECT_STORE_DECISION_LOG.md`](OBJECT_STORE_DECISION_LOG.md)
3. [`FRANKENSUITE_DEEP_AUDIT_2026-08-19.md`](FRANKENSUITE_DEEP_AUDIT_2026-08-19.md)
4. [`../VERIFY_SPEC.md`](../VERIFY_SPEC.md)

Nothing in this historical note overrides those documents.
