# Native tag lifecycle

`fg tag` composes the existing native tag contracts with the real node, verified
object fabric, production receive quarantine and exact-basis publication. There
is no tag database, external Git subprocess, force fallback or new dependency.

## Commands

```sh
fg tag create ROOT TENANT REPOSITORY --trusted-local \
  --ref refs/tags/v1 --target NATIVE_COMMIT \
  --principal PRINCIPAL --key-stdin

fg tag annotate ROOT TENANT REPOSITORY --trusted-local \
  --ref refs/tags/v1-annotated --target NATIVE_COMMIT --target-kind commit \
  --tagger 'Release Author <release@example.invalid>' --timestamp 7 \
  --message-file release-message.txt --principal PRINCIPAL --key-stdin

fg tag show ROOT TENANT REPOSITORY --trusted-local --ref refs/tags/v1-annotated
fg tag list ROOT TENANT REPOSITORY --trusted-local --limit 50

fg tag delete ROOT TENANT REPOSITORY --trusted-local \
  --ref refs/tags/v1-annotated --expected-tip NATIVE_TAG_OBJECT \
  --principal PRINCIPAL --key-stdin
```

All names are complete `refs/tags/*` references. `--ref-hex` and `--after-hex`
accept exact lowercase hexadecimal bytes, including non-UTF-8 names. Select
`--object-format sha256` for a SHA-256 repository; there is no hash-domain
coercion. Annotation target kinds are commit, tree, blob or tag. The declared
kind is independently verified by quarantine, not accepted as evidence.

Creation is absent-destination only. Deletion compares the exact **unpeeled**
tag tip. No action overwrites an existing tag or guesses the current tip.
Messages come from an explicitly selected, bounded regular file: empty messages,
non-UTF-8, CRLF and missing final newlines are retained exactly; NUL refuses.
The limit is 65,536 bytes. Metadata is explicit UTC, never ambient Git config.
The file must remain stable under the trusted local operator's control; this is
not a hostile host-filesystem sandbox.

Keys are either `--idempotency-key` or `--key-stdin`, never both. Standard-input
keys preserve all bytes, including a newline, and contain 1..256 bytes. They are
never written in receipts. The underlying library retains the existing native
key domain; this CLI profile does not change native transaction identities.

## Durable mutation and recovery

`OneNode::admit_tag_durable_in` accepts an authenticated local session and the
existing `TagCommand`. Generated annotations pass real pack construction and
production quarantine, just like incoming native objects. Existing targets must
be reachable through the current visible ref frontier; objects merely retained
from deleted refs cannot be resurrected by this API. Hidden-name and original
object checks precede disclosure of target kinds.

Canonical publication uses ordinary receive admission, exact expected-old
conditions and one authority-head CAS. Repository policy remains authoritative.
A successful write leaves HEAD configuration, forge metadata and existing outbox
obligations unchanged. It does not create a release, sign an object or grant a
permission.

An exact previously decided request recovers its original committed/refused
outcome before gates for a new publication, including serving state and quota.
Replay does not recreate a tag subsequently deleted. Reusing the key with a
different command fails seal binding. Transport, storage or shutdown failure is
not evidence of non-commit: retry identical inputs/key or use `fg outcome`.
CLI JSON receipts retain known terminal decisions even if cleanup or output
fails. Exit 0 means a completed read or committed mutation, 3 a canonical
refusal, and 2 an input/infrastructure/cleanup/output failure.

## Reads, peeling and disclosure

`OneNode::list_tag_refs_in` shares the existing ref pagination implementation.
Visibility filtering precedes page limits and continuation calculation. A
continuation requires the initial `snapshot_token` as `--expected-head`; an
authority movement refuses instead of mixing snapshots. Page tips are unpeeled.

`OneNode::read_tag_in` starts from a currently visible tag name, not an arbitrary
caller-supplied object ID. Each annotation and followed target is identity-
verified and type-checked through the selected immutable native closure. Nested
tags are returned outermost-first, with exact original `body_hex`, target and
native identity. The final `peeled` identity can be a commit, tree or blob.
Lightweight aliases of an annotation expose that underlying annotation chain.

Read limits are 64 annotations, 1 MiB per decoded object and 4 MiB in aggregate,
including the final non-tag object. The remaining byte allowance is enforced
before decoding. Existing node and request budgets may be stricter. Cycles,
missing/wrong-kind objects, oversized data, cancellation and stale snapshots
refuse; none is a successful empty result. The page/peel result is derived
information and never changes repository state.

Signature armor is only classified as absent or opaque/unverifiable. No
cryptographic verification is performed and no signing key or trust authority is
inferred from embedded text. A `signature_verification` receipt always says
`not_performed`. This API does not offer cryptographic signing/verification,
remote authentication, regex/wildcard tag selection or full `git tag` parity.

## Verification

```sh
CARGO_TARGET_DIR=/tmp/fg-native-tags bash scripts/verify_native_tags.sh check
CARGO_TARGET_DIR=/tmp/fg-native-tags bash scripts/verify_native_tags.sh test
```

The campaign covers the actual tag contract, file-backed both-hash nodes,
exact terminal retries after deletion/reopen/quota changes, collision and
expected-old refusals, deleted-only target prevention, wrong declared kinds,
visibility, cancellation and read budgets. CLI tests cover exact inputs and
terminal/read receipt failure semantics. The fresh-process campaign uses the
actual `fg` binary for tag creation, nested peeling, pagination, refusal, replay,
empty messages and complete native bundle transfer into a newly initialized
node. Test presence alone does not establish a passing run or full conformance;
execution evidence must identify the exact source revision.
