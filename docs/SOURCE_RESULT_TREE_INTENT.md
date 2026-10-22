# Independently constrained source preparation

A valid patch is not necessarily the intended change. A caller can constrain the
complete native result tree without trusting a preparation receipt to choose that
expectation. This binds every path, blob identity, executable bit, nested tree and
unchanged sibling. The expected tree must come from the caller's reviewed intent;
copying the server's result back into this field supplies no independent check.

## HTTP

`POST /api/v1/source/prepare` accepts optional `expected_result_tree` in the existing
multipart `command` form alongside `ref`, `object_format`, `expected_commit`,
`author`, `committer`, `timestamp` and `message`. It is a nonzero, full lowercase
native tree ID in the repository's SHA-1 or SHA-256 domain. Empty, malformed,
wrong-width and duplicate fields refuse. The command field-count allowance is
eight for preparation; all byte, patch, decoding, response and source-read budgets
are unchanged. Inspection and publication refuse this preparation-only field.

The existing native planner validates the entire patch and produces its candidate.
Before framing or sending a candidate response, the server compares the actual
root to the expectation. A mismatch is HTTP 409 `patch_result_tree_mismatch` with
`outcome_unknown:false`, not a canonical transaction refusal. The response contains
no candidate identity or bundle. Preparation neither imports objects nor publishes
repository state. Authentication, deployment grants, source freshness and native
patch/rename/binary verification remain independent requirements.

A matching expectation adds `expected_result_tree` to the metadata part of the
response. It does not change the candidate or bundle bytes. Omitting the optional
field preserves existing successful response bytes. Exact text edits, native binary
literal/delta edits and explicit supported file relocations use the same planner;
this feature adds no parser, fallback, fuzzy matching or privilege.

Save and independently inspect the returned bundle. Publication still consumes that
exact bundle with the reviewed commit, expected-old base, authenticated principal
and original idempotency key. A tree expectation cannot replace commit review or
admission; matching a tree says nothing about author/message approval. Missing
output never proves non-commit, and original terminal retries remain recoverable.

## Evidence boundary

The discovered `scripts/e2e/suites/smokes/source_result_tree.sh` campaign starts the
actual prebuilt `fg serve-http` on loopback and tests both object formats. Python
constructs expected native trees and commits before preparation and decodes the
returned bundle independently. A valid unintended sibling mode change is paired
with a permitted expectation, along with exact multi-file moves, raw binary names,
chunked intake, malformed pins, restart, stale-source refusal and original-key
publication recovery. The native HTTP tests also retain symlink/gitlink siblings
without following them. These are trusted-local functionality checks, not remote
production deployment, hostile isolation, full-workspace or power-loss qualification.
