# Selected context membership under an independent commit

The source search page now offers **Prove selected paths under an independent
commit** after combined Initial search with source excerpts enabled. It fills a
specific gap in FG-032 and plan section 27: hashing a complete blob does not by
itself establish that its path and mode occur beneath the intended commit.

## Browser workflow

Enter a commit ID obtained independently of the server. The field is deliberately
blank, and neither a search result nor an imported proof populates it. It must
match the context's retained source commit. Review the metadata limits and consent,
then choose **Acquire and verify selected membership**.

The existing authenticated `source/log` and `source/tree` read APIs provide the
original commit bytes and the complete parent trees needed for the selected
paths. Every request carries the original reference, commit and snapshot. The
client hashes the commit, reconstructs each tree's native Git byte ordering,
hashes every parent, and joins each selected raw path, regular-file mode and blob
identity through that hierarchy. Both SHA-1 and SHA-256 are supported. Complete
parent trees include sibling names and IDs, but unrelated subtrees are not
traversed and no blob body is downloaded by this operation.

A missing page, omitted sibling, changed source, detached parent, wrong blob,
unknown mode or selected symlink/gitlink fails the whole operation. There is no
successful prefix, source refresh, alternate root, network retry or fallback.
Noncanonical tree modes that cannot be reconstructed from the API's kind field
also fail by hash mismatch; they are not normalized into a different proof.

## Portable proof and offline replay

**Download replayable membership proof** exports the original commit bytes,
needed complete tree bytes, and exact selected path/blob/mode inventory in the
closed `frankengit-context-membership-proof-v1` schema. No ambient bearer token,
source-head assertion or permission grant is included. Commit messages, sibling
names and IDs can still be private: protect the proof accordingly.

To check a saved proof in the page, retain the intended search context, enter its
independently selected commit, choose one JSON file, confirm, and press **Verify
saved proof locally — no network**. Import is bounded before and after the file
read. It never calls the acquisition function, imports a new source selection,
or accepts a summary flag instead of hashing the evidence. The page requires the
retained context as its expected file inventory; it does not reconstruct that
inventory from the imported proof. Disconnect clears the page's current context.

The exported `verifyMembershipProof(proof, expected, crypto, check, limits)`
function can also run entirely offline without a connection or DOM. `expected`
is an independent `{ format, commit, files: [{ pathHex, blob }] }` selection.
Supplying those values from the proof itself would discard the independent trust
anchor. The function verifies exact file membership, hashes all supplied parents,
and refuses extra or unreachable trees. Caller-owned evidence and expected IDs
are copied before asynchronous hashing.

## Independent claims and resource limits

Membership means **these path/mode/blob identities belong under this commit**,
subject to the selected native hash algorithm. It does not prove the commit's
signature, current repository authority, branch freshness, access rights, source
search completeness or declaration semantics. It does not verify blob contents.
The existing **Verify all selected context files** operation separately hashes
complete blob bodies and checks the retained excerpt and match witnesses. Neither
operation automatically upgrades or relabels the other's receipt.

The membership operation admits 1–32 selected files and at most 32 KiB of their
raw path bytes. Metadata limits are independently configurable up to 512 requests,
128 parent trees, 16,384 entries and 4 MiB of encoded tree bytes. Every request is
charged before dispatch; all siblings in each needed parent count toward the
entry and byte limits. The existing transport has separate per-response bounds.
These bounds are not a claim about total server work or HTTP wire bytes.

The browser proof file limit is 12 MiB. The page's operation owns acquisition,
local file reads and re-verification through one bounded lifetime. Changed input,
cancellation, disconnect or replaced context invalidates pending results. File
read cancellation observes eventual promise rejection without selecting late
bytes. Exports revoke previous object URLs, and page cleanup revokes remaining
URLs. No filesystem extraction, Git subprocess, write API or dependency is added.

## Executable evidence boundary

`node --test tests/browser/search-context-membership*.test.mjs` exercises the
complete membership module, actual shared Transport, real Fetch/WebCrypto and
HTTP sockets with the repository's independently defined source-archive native
schema fixture. Git `mktree` and `hash-object` in isolated test repositories also
check raw-name and directory ordering in both object formats. Production does not
invoke Git. View tests use a small DOM adapter, real hashing, actual acquisition
for positive network cases, and explicit delayed/error hosts for lifecycle cases.

The fixture responses are not a live Rust server. The tests do not establish
native authorization, real-browser behavior, full Initial/CodeSearch integration,
a pinned Git conformance lane, hardware-failure safety or full-workspace success.
The legacy isolated context tests remain useful regression checks but are not
promoted to those stronger claim classes. No bead closure follows from this slice.
