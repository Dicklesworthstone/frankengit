# Verified representation reuse for streaming bundles

Full and incremental streaming exports can preserve eligible native pack
compression and deltas already held by the node. This is an explicit option:

```sh
fg bundle export STORAGE TENANT REPOSITORY source.bundle \
  --streaming --trusted-local --reuse-verified-packs

fg bundle sync-export STORAGE TENANT REPOSITORY next.bundle \
  --streaming --trusted-local --reuse-verified-packs \
  --ref refs/heads/main --prerequisite BASE_COMMIT
```

Add `--object-format sha256` for a SHA-256 repository. The existing independent
output, expanded-byte, object, blob, graph, reference, compression-work and
timeout options still apply. The option is accepted only by these streaming
export commands. It adds no import permission, hidden-ref exception or cache
size override.

Without this option, export keeps its existing deterministic OID-ordered,
whole-object compression profile and JSON receipt. The option may select a
different valid representation when custody differs. Its purpose is to avoid
re-reading and recompressing the expanded selected payloads on a warm hit.
Exact bytes across different cache histories are not promised.

## What can be reused

The same bounded received-pack cache serves upload-pack and this export path.
Custody originates from successful native receive or native packed-directory
import, after full native validation, canonical collision checks and activation.
Disk cache records are untrusted hints until independently revalidated.

An eligible export can use one complete original pack, compose complete disjoint
entry runs, or select exact entry spans from retained packs. Compressed members
are copied without re-encoding. Selective output may change pack entry headers
and OFS references, then recompute the pack count, native checksum and strong
digest. It does not retain a complete joined output buffer.

The copied set must equal the exact currently selected object set, with verified
kinds and expanded lengths. Extra entries cannot disclose hidden, deleted-only
or unrelated history. A full bundle contains every delta base it needs. An
incremental bundle may use an external REF base only when that object's kind
and membership are proved in the complete closure of the caller's explicitly
declared, currently visible commit prerequisites. Cache membership never proves
that the receiver holds a base. The receiver must already possess the declared
prerequisite history, as for the existing incremental export profile.

## Selection and completion evidence

Export first authenticates one immutable authority snapshot and selects visible
ref roots. Caller visibility only narrows the canonical hidden-ref policy.
Before asking for reuse, the node independently constructs the bounded native
typed graph, verifies branch/root kinds, and derives the exact selected and
omitted inventories. Blob discovery reads checked envelopes; metadata discovery
reads and verifies the native commit, tree and tag bodies.

Full opt-in selection retains the existing full stream's object, index and edge
ceilings. It does not acquire the incremental path's additional omitted-closure
caps. Incremental export retains its existing bounds on the whole visible
graph and prerequisite proof. Neither mode makes metadata discovery proportional
to compressed output bytes.

The low-level `fgit_pack::full_bundle::stream::existing` module checks a bounded
bundle envelope and copies the pack while validating its exact byte count,
object count, native trailer, SHA-256 and EOF. Its
`ExistingPackBundleReceipt` is **framing evidence only**: it does not decompress
objects or prove their native identities, kinds, graph edges or authorization.
The node combines that receipt with its private verified received-pack custody
and its independently selected typed graph. It never manufactures a
`StreamFullBundleReceipt` from copied pack bytes.

The public node query enables the option with
`StreamBundleExportQuery::default().with_verified_pack_reuse(true)`.
`SelectedStreamBundleExport::receipt()` exposes the common
`StreamBundleExportReceipt` view. Its `encoded()` accessor returns the original
encoder receipt on a default export or miss; `received()` and `framing()` return
the distinct proofs on a hit. `SelectedStreamBundleExport::reuse()` reports
`NotRequested`, `Miss` or `Reused`.

## Receipts

An opted-in miss preserves the ordinary full or incremental encoder profile and
adds `"representation_reuse":"miss"` to the CLI receipt. A hit reports:

| Field | Meaning |
| --- | --- |
| `profile` | `git-bundle-received-pack-v1` or `git-bundle-incremental-received-pack-v1` |
| `representation_reuse` | `reused` |
| `received_pack_profile` | Original, concatenated, selective or thin cache representation profile |
| `source_pack_count` | Number of retained source allocations contributing entries |
| `external_base_count` | Distinct prerequisite objects actually used as external delta bases |
| `ofs_delta_count`, `ref_delta_count` | Delta entries in the emitted pack |
| `maximum_delta_depth` | Verified dependency depth of the emitted representation |
| `compression_work` | Zero: this export did not invoke the compressor |

The ordinary native pack checksum, bundle SHA-256, selected object/expanded-byte
counts, output sizes, source head and generation remain available. An incremental
receipt's `external_object_count` counts the complete omitted prerequisite
closure; it is separate from `external_base_count`.

Zero compression work does not mean zero CPU or I/O. Selection, representation
validation, copying and hashing consume work. The selected source head identifies
the snapshot authenticated at the start; it does not assert that no subsequent
transaction changed the repository.

## Bounds, restart and fallback

Cache custody remains optional and finite. Disabled, absent, corrupt,
over-budget, incomplete or ineligible representations fall back to the existing
encoder **before output starts**. The exact header-plus-pack envelope is checked
before choosing a representation: a large retained pack cannot prevent a
smaller deterministic encoding from fitting the requested output bound.

The optional cache path retains the buffered per-object limit. Increasing the
separate streamed-blob limit does not permit a larger resident cache parser
allocation; an otherwise legal large blob can use the existing streaming
encoder on a miss. The same selected expanded-byte, object/index, graph,
native delta and cache bounds remain enforced.

A fresh node configuration can restore persisted custody by re-reading the
bounded raw pack, resolving its native objects and verifying their exact strong
payload commitments against canonical storage. The first cold export therefore
still performs expanded-object validation. This feature does not claim
pack-proportional cold-open performance, nor does it make the cache authoritative
or allow a damaged canonical source to pass cold revalidation. Subsequent warm
exports can reuse the verified compression without repeating that restoration.

Cancellation remains sticky across authority selection, optional restore,
hashing and output. Cache lookup never converts cancellation into a miss. After
framing starts, an I/O, integrity or cancellation failure is terminal; the node
does not append a second encoder's output to the partial artifact. Library
callers retain ownership of the tentative sink and cleanup. The CLI keeps the
existing private-file protocol: complete native output, node shutdown, file
sync, create-only publication and parent sync. It never replaces an existing
destination.

## Focused verification targets

The pack component tests `full_bundle::stream::existing::tests` exercise both
hash domains, malformed framing coordinates, exact resource boundaries,
prerequisite envelopes, sticky cancellation and interrupted/short I/O. They also
make explicit that framing is not native-object evidence.

The public node integration target `stream_bundle_reuse` covers full OFS and
forward-REF reuse, disjoint pack composition, fresh-configuration restoration,
incremental prerequisite-scoped thin reuse, hidden members and prerequisites,
cache and representation misses, envelope fallback, corruption, selected bounds
and cancellation. The CLI `bundle_stream_export` integration target covers
actual separate-process cold reuse and fallback receipts. These targets use the
production implementations and native fixtures; no external Git executable is
part of the production path.

For the underlying deterministic encoder and local publication contract, see
[Native streaming full-bundle export](NATIVE_GIT_BUNDLE_STREAMING_EXPORT.md).
