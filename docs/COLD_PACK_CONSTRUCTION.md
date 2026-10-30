# Cold pack construction: exact lazy deltas

Owning work: `frankengit-1tl9`. The consumer is the selected-pack writer used by
clone/fetch/export. This slice removes repeated allocation and byte comparisons
while constructing a cold pack; the first-clone and retained-pack-reuse work
remains open. Replace this synthetic workload when a real-repository cold-clone
lane covers these shapes with exact output comparison and resource measurements.

## Mechanism and preserved contract

`writer/prefix_suffix.rs` measures the exact encoded length of the existing
copy-prefix / insert-middle / copy-suffix program without copying the middle.
The cost includes both size varints, literal opcodes, copy-offset bytes and
Git's implicit 64 KiB copy length. Indexed search receives the same
`min(current_best_bound, prefix_suffix_length)` as before. Only a fallback that
wins that comparison is allocated and encoded. Long matching prefixes and
suffixes use safe 64-byte comparisons followed by the scalar mismatch tail;
indexed match extension uses the same exact prefix function.

No profile, ordering, emitted instruction, tie-break, delta-window, depth,
fanout, byte limit, logical work charge or cancellation checkpoint is changed.
The historical planner explicitly retains scalar prefix/suffix construction
and scalar match extension. Focused tests compare encoded bytes, strict bounds,
equal-length choices, live-position skips, copy/varint boundaries, typed
overflow refusals and cancellation checkpoint counts. Native delta decoding
checks reconstruction independently of the sizing helper. Allocation behavior
intentionally changes: losing fallbacks allocate nothing, and winners reserve
the encoded length. Allocation-failure timing and requested allocation sizes
are therefore not promised identical; explicit byte and work limits remain.

## Measurement source and method

These samples use the final writer implementation, including the fixed-array
forward comparison. Binary identities bind the measurements below; timings
must not be silently rebound to a different source or compiler.

- A1/A2: `07587ad2cf5581b41790f2ce80802c67ba4672ec`, with the same example added.
- B: `59b2b411aa55de91fb2c2a29acb517e829f43153` plus this pack-only writer change.
  Both arms retain the original `fgit-deflate`; these results do not include
  the separate compression-matcher optimization.
- Host: AMD EPYC 9V74, x86_64, Linux 6.18.55. Toolchain:
  `nightly-2026-08-31`. Cargo `--release`: opt-level 3, LTO enabled,
  codegen-units 1; no additional `RUSTFLAGS`.
- [`cold_pack.rs`](../crates/fgit-pack/examples/cold_pack.rs) invokes the public
  `PackPlanner::stream_selected_thin` pipeline with SHA-1, `COMPRESSED_V5`, no
  thin bases and no computation cache. Every source object has zero recency
  and path hints. Later `main` adds basename-derived ordering hints; this
  experiment exercises none of them and measures only the stated mechanism.
- Each input has twelve 1 MiB blobs. `similar` edits eight bytes in one common
  pseudorandom body; `shifted` shifts that body by 17 bytes per version;
  `unrelated` uses different deterministic noise seeds; `text` repeats a JSONL
  record with an eight-byte edit per version.
- Five trials per shape, each in a new process: A1/A2/B on even trials and
  B/A2/A1 on odd trials. A1 and A2 are repeated baseline controls.
  `elapsed_ns` includes owned source copies, native identity verification,
  delta selection, compression, the memory sink and trailer hashing. Corpus
  generation is outside that timer. CPU and peak RSS describe the whole
  process, including corpus generation, initial hashing and JSON output.

Final benchmark executables (SHA-256):

| Arm | Binary SHA-256 |
| --- | --- |
| A1/A2 | `9ea2ca9670d0530a551f2d5ed0702114f9c1364595e1780ab3bde48df114d3d2` |
| B | `082cbad785ab186292634e44ac2dcda9410356c05b192e67f3e4fc1f050c7f9c` |

## Observations

Elapsed samples below are in trial order, rounded to microseconds. CPU is the
median sum of user and system time. RSS is the median of process peak RSS.

| Shape | Arm | Median elapsed, ms | Five elapsed samples, ms | CPU, ms | Peak RSS, KiB |
| --- | --- | ---: | --- | ---: | ---: |
| similar | A1 | 148.905 | 157.477, 148.905, 191.379, 148.148, 142.211 | 178.496 | 40964 |
| similar | A2 | 167.752 | 142.305, 150.337, 190.644, 167.752, 275.697 | 195.568 | 40960 |
| similar | B | 108.751 | 106.371, 110.551, 134.388, 102.688, 108.751 | 137.701 | 38724 |
| shifted | A1 | 131.780 | 127.345, 131.780, 140.507, 117.293, 135.923 | 167.006 | 40752 |
| shifted | A2 | 134.737 | 156.015, 133.171, 158.656, 134.737, 116.585 | 164.876 | 40752 |
| shifted | B | 117.448 | 113.647, 123.559, 146.307, 117.448, 105.778 | 146.705 | 39868 |
| unrelated | A1 | 562.457 | 562.457, 642.176, 649.704, 523.095, 538.975 | 621.854 | 50476 |
| unrelated | A2 | 556.035 | 538.928, 583.899, 574.461, 526.963, 556.035 | 609.073 | 50480 |
| unrelated | B | 550.443 | 554.920, 550.443, 569.615, 544.465, 538.041 | 604.586 | 50368 |
| text | A1 | 500.399 | 475.545, 603.314, 523.277, 500.399, 474.417 | 539.225 | 40320 |
| text | A2 | 497.067 | 525.630, 690.031, 485.802, 477.187, 497.067 | 534.059 | 40324 |
| text | B | 131.714 | 132.898, 139.401, 131.714, 121.956, 122.702 | 171.647 | 37696 |

Against the pooled ten baseline samples, median elapsed time fell from
153.907 to 108.751 ms for `similar` (29.3%) and from 498.733 to 131.714 ms
for `text` (73.6%). Shifted and unrelated differences remain inside the
observed baseline range and are sensitive to host variability; neither
receives an improvement claim. An earlier complete run measured 22.2% and
76.5% for similar and text, respectively, so these percentages are observations,
not fixed speedup factors. Twelve MiB of synthetic input on one host does not
establish real-repository clone speed, tail latency, storage cost or another
target family's performance.

All fifteen timed runs of each shape reported the same length, delta count and
native pack checksum. The experiment did not retain raw packs for a direct
cross-process byte comparison; exact-byte equivalence is covered separately
by the scalar-oracle and streamed/planned writer tests.

| Shape | Pack bytes | Deltas | SHA-1 pack checksum |
| --- | ---: | ---: | --- |
| similar | 1049723 | 11 | `41bb0b43f92a9d4ebf81aca0f8edd40f741749a9` |
| shifted | 1049587 | 11 | `b909684d69c86b4108613935d9248e783cdf67b8` |
| unrelated | 12585008 | 0 | `993a9ef078d28ad1ecd509afffa2a54ac11bf201` |
| text | 10307 | 11 | `ca68787c629774c0bba7c9358c4723d0d5272053` |

## Reproduction and verification scope

Use separate baseline and candidate checkouts and targets, with the identical
example in each. To isolate this mechanism, retain the same original deflater
in both and apply only the writer change to the candidate. Record the exact
commit/diff, binary hashes and compiler identity before interpreting a rerun.

```bash
CARGO_TARGET_DIR=/tmp/fgit-cold-target-a cargo +nightly-2026-08-31 build --locked --release -p fgit-pack --example cold_pack --manifest-path /tmp/fgit-cold-baseline/Cargo.toml
CARGO_TARGET_DIR=/tmp/fgit-cold-target-b cargo +nightly-2026-08-31 build --locked --release -p fgit-pack --example cold_pack --manifest-path /tmp/fgit-cold-candidate/Cargo.toml
FGIT_COLD_A=/tmp/fgit-cold-target-a/release/examples/cold_pack
FGIT_COLD_B=/tmp/fgit-cold-target-b/release/examples/cold_pack
for trial in 0 1 2 3 4; do
  if (( trial % 2 == 0 )); then arms=(A1 A2 B); else arms=(B A2 A1); fi
  for shape in similar shifted unrelated text; do
    for arm in "${arms[@]}"; do
      binary="$FGIT_COLD_A"
      if [[ "$arm" == B ]]; then binary="$FGIT_COLD_B"; fi
      /usr/bin/time -f "$shape $trial $arm user=%U system=%S rss_kib=%M" "$binary" "$shape" 1048576 12 1
    done
  done
done
CARGO_TARGET_DIR=/tmp/fgit-cold-tests cargo +nightly-2026-08-31 test --locked -p fgit-pack --all-targets
```

At the final composite candidate source specified above, the author-run pack
suite completed across 34 targets: 283 passed, 0 failed, 9 ignored. Ignored
measurement tests are not passes. Strict scoped Clippy also completed:
`cargo clippy --offline --locked -p fgit-pack --lib --example cold_pack -- -D warnings`.
The separate all-target Clippy run remains blocked by two upstream lints in
`tests/path_grouping.rs` (constant assertion at line 129 and `int_plus_one` at
line 153); this is not an all-target lint-clean claim. Full-node execution,
transport round trips, the reported large repository's clone, persistent pack
reuse and completion of `frankengit-1tl9` are not established by this result.
Rollback is the prior scalar/eager writer implementation; no stored object,
pack profile or migration changes.
