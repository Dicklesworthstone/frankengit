# Native source browsing

`fg tree` and `fg show` complete the read side of the native read/edit/review loop.
They use `OneNode` and the verified immutable TreeFS object source, not a host
checkout, a Git subprocess, an independently authoritative index, or arbitrary
OID lookup. A repository ref must select a commit. Both SHA-1 and SHA-256 retain
their native identity domains.

## Commands

```sh
fg tree /data/repository TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --limit 100

fg tree /data/repository TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --path src --expected-head SNAPSHOT_TOKEN

fg show /data/repository TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --path src/lib.rs --max-bytes 65536 \
  --expected-head SNAPSHOT_TOKEN --expected-commit NATIVE_COMMIT_ID
```

Set `--object-format sha256` for a SHA-256 repository. `--ref-hex` and
`--path-hex` accept exact lowercase hex bytes instead of text. Paths are always
repository-relative. Omit the path to list the root; an empty path is not an
alternative spelling of the root.

Tree output is one JSON `source_tree` record. Every immediate child has
`name_hex`, `kind`, and `object_id`. Order is raw byte order, not locale order
or Git's special directory comparison. Continue using `next_after_hex` as
`--after-hex`, retaining the first page's `snapshot_token` as `--expected-head`.
A non-null cursor is returned only when another authorized entry exists.

File output is one JSON `source_file` record. `bytes_hex` is exact, including
NUL, non-UTF-8, CRLF, and a missing final newline. `text_utf8` is a convenience
only when the returned range is independently valid UTF-8. A byte-range boundary
may split a Unicode character: clients needing decoded text should first join
`bytes_hex` ranges. `offset`, `returned_bytes`, `total_bytes`, and `next_offset`
state the range without pretending it is the whole file. Use `next_offset` as
`--offset` and retain the snapshot token. A range starting exactly at EOF is an
empty complete result; a range starting beyond EOF refuses.

Both outputs include the repository, reference bytes, authority head, RCR,
selected native commit, root tree, selected object, and requested path. An
optional `--expected-commit` independently pins the reviewed native commit;
it never selects historical state. Continuations require an authority-head
identity. If any canonical operation changes that head, continuation refuses,
even when this branch tip stayed unchanged. Restart the read rather than mixing
snapshots. Changing the ref/path/query is a new read, not an opaque continuation
claim; callers must retain the original request alongside its cursor.

A symlink is listed as a symlink and its target bytes can be read as data.
Nothing follows the target into another repository path or the host filesystem.
Gitlinks are opaque external commit IDs in listings; file reads and traversal
through them refuse. Executable files are distinguished from ordinary files.
Directories cannot be read as blobs and files cannot be listed as directories.

## Embedding and authority

`fgit_forge::source_browse` owns the typed request/result contracts.
`OneNode::browse_source_in<A>` consumes the embedding's existing `TreeCapability`,
current authenticated disclosure policy, and clock. It does not mint a wider
capability. Canonical hidden-ref policy and caller visibility are conjunctive.
Path preauthorization happens before source-object reads. Expiry, revocation,
byte budget, object budget, and symlink policy remain those of the capability.
Directory classification and continuation computation use authorized entries.

`OneNode::browse_source_local_in` is an explicit trusted-local-owner boundary,
not authentication for remote clients or an agent capability broker. Its
read-only temporary path grants derive from caller-selected paths or verified
root entries. It refuses a root with more than 4,096 immediate grant scopes
rather than minting a fake wildcard path. Empty trees are genuine empty results.

The profile caps returned directory entries at 1,000, file range output at
1 MiB, individual decoded source objects at 16 MiB, and traversal object reads
at 132 with an aggregate 64 MiB bound. Existing node, parser, path, and capability
limits may be lower. Range output does not imply range-only storage I/O: the
entire native blob is verified before slicing. An oversized blob refuses even
when the requested output range would be small. Canonical authority selection
retains the node's existing independent read bounds.

All reads use one authenticated current snapshot and selected native closure.
They never move refs, alter policy, issue delivery receipts, or publish candidate
objects. Cancellation or any read, cleanup, or output failure is distinct from
an empty successful page. The CLI writes its JSON only after node shutdown;
write/flush failure returns exit 2 and marks output incomplete. Successful
complete pages return exit 0. No mutation keys or force options are accepted.

## Verification

```sh
bash scripts/verify_source_browse.sh check
bash scripts/verify_source_browse.sh test
```

The tests include real file-backed both-hash nodes, binary and raw-name handling,
permission/expiry/revocation/budget refusals, symlink data and gitlink boundaries,
empty files/trees, cancellation, stale snapshots, and restart. CLI tests cover
parsing, receipt fidelity, and read/cleanup/output failures. The fresh-process
campaign reads source, prepares an exact patch from the observed base, publishes
its independently checked candidate through existing admission, verifies new
bytes, and requires old read continuations to fail. Test presence alone is not
a passing native gate; execution must be tied to the actual source revision.
