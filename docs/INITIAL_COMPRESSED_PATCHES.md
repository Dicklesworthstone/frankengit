# Compressed binary creation in initial commits

The existing `OneNode::prepare_trusted_initial_patch_in` now accepts creation-only
patches containing native `GIT binary patch` literals or deltas, mixed with
ordinary literal creation records. This fills the difference between existing-
branch compressed authoring and a branch with no parent history. It is not a
new publication endpoint, a checkout, a second decoder, or a new source of truth.

## Construction and validation

Every record must create a regular or executable file. Each compressed record
must carry a full-width all-zero old index and a full nonzero new blob identity
in the repository's SHA-1 or SHA-256 domain. The complete record set, path policy
and hash widths are checked before the first decompression. Modifications,
deletions, renames, symlinks, gitlinks and copies cannot be smuggled into an
initial plan, including after an earlier otherwise valid creation.

An empty source is not an existing empty blob: the native decoder receives
`old: None` and an empty byte slice. A delta can insert content from that absent
source but cannot depend on repository objects. `delta N` still means the
inflated delta program length, not its output length. Every supplied reverse
member must reconstruct the empty source exactly. A reverse member is optional;
an invalid supplied member is never ignored. Empty created files retain the
ordinary nonzero empty-blob identity and their file mode.

The node uses the existing `BinaryPatchBatch`, with one input/line/expanded-byte
allowance for all compressed records and nontransferable shares of the existing
inflate/delta work ceilings. Failed decoding poisons that batch; no replacement
budget is allocated. Expanded accounting includes inflated programs, reconstructed
results and reverse images. Ordinary aggregate file-output and complete-object
closure budgets remain separate. These work ceilings do not claim a bound on
all fixed hashing/allocation/setup overhead or a performance improvement.

The forge's new `prepare_initial_commit_with_binary_decoder` keeps the layering
boundary: the forge owns tree/root construction; the node supplies the existing
pack/DEFLATE decoder. It independently checks result blob identities and emits
all blobs, directories and exactly one zero-parent commit. The existing
`prepare_initial_commit` API remains literal-only. No dependency was added.
The node performs a bounded structural counting pass, drops its parsed records,
and lets the forge independently parse and validate the same immutable bytes.
This deliberately trades a second bounded parse for unchanged decoder ownership.

## Publication and unsupported surfaces

Canonical metadata selection, hidden-ref checks, expected preparation head and
absent destination remain enforced before construction. Preparation stages no
objects and publishes no repository decision. All files must succeed before a
complete candidate can be returned.

The entire initial bundle publication/recovery method is unchanged. It still
requires independent branch/commit expectations, verifies complete reachable
closure and a root commit, applies current authorization/policy and performs an
expected-absent admission. Original-key recovery precedes new intake and does not
recreate a branch or weaken protection. Compressed patch deltas are decoded into
ordinary blobs; this does not enable delta entries in initial publication bundles.

This batch does not add an arbitrary-patch upload widget to the initial-history
browser or widen that editor's local text/binary input rules. Native consumers
use the existing preparation method; existing HTTP callers of that method inherit
its decoding behavior, not new grants. Directory moves, existing-history rewrites
and a complete forge release remain outside this change.

## Evidence and unexecuted gates

Seven new forge builder tests explicitly use decoder doubles. Nine new node tests
exercise the real native decoder/builder and include a file-backed OneNode
prepare/publish/reopen/original-key recovery scenario in both hash domains.
They cover mixed text/binary/empty files, exact object identities, literal/delta
equivalence, creation-only preflight, wrong widths, invalid targets and reverse
images, aggregate limits, cancellation and late failure.

Rust/Cargo is unavailable in this implementation environment. These 16 Rust test
functions, native compilation, live HTTP/browser execution, durable-runtime
behavior, Clippy, full-workspace and release gates were NOT executed. The tests
are definitions, not passed evidence. The batch verification lane should include
`initial_commit` in the forge and node packages under AGENTS.md's offload rules.

The independent input-fixture check can be run with an explicitly pinned Git:

```sh
python3 scripts/verify_initial_compressed_oracle.py \
  /absolute/path/to/git 'git version <exact-version>' <executable-sha256>
```

Git 2.47.3 with executable SHA-256
`356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60`
accepted four initial-creation scenarios: literal and empty-base delta in SHA-1
and SHA-256. Each uses a fresh receiver without the expected blob installed,
checks content, path, executable mode, blob/tree/root-commit identities and strict
`git fsck`. The literal is Git-produced; the delta is independently authored.
This validates interoperable test input, NOT execution of the Rust implementation,
reverse-image enforcement, authorization, a release gate, or Git performance.
