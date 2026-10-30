# Rejected experiment: rolling DEFLATE match index

**Disposition: rejected and unshipped.** The final pruned-index prototype
improved a repetitive-text codec microbenchmark but materially regressed the
public pack writer. The original per-block deflater was retained. This record
preserves the experiment for `frankengit-1tl9` and the related matcher work
`frankengit-g4a9`; it does not describe deployed architecture.

For twelve unrelated 1 MiB objects, pooled baseline elapsed was 563.245 ms
versus 704.536 ms for the prototype (**25.09% slower**), with **23.69% more
process CPU** and 1.74% A/A wall spread. Two unrelated 8 MiB objects were
**12.84% slower**, with **10.14% more CPU** and 1.97% A/A wall spread.
The text-specific gains below did not justify those regressions. The earlier
u32-link failure is retained separately in
[NEG-041](NEGATIVE_EVIDENCE_LEDGER.md#neg-041--retained-u32-back-distance-links-regress-small-member-compression-frankengit-1tl9--frankengit-g4a9).
The successful [lazy-delta pack change](COLD_PACK_CONSTRUCTION.md) was already
in both controls and candidates throughout this final comparison.

## Prototype mechanism and bounds

The production matcher rebuilt its hash heads and predecessor table and
rehashed retained history for each fixed-Huffman block. The final prototype
kept one encoder-local index across blocks. Heads and links held absolute
`usize` positions in a bounded ring. When the history origin advanced, one
pass pruned expired heads and predecessor links in the retained history,
addressed as at most two contiguous ring slices. Every reachable position was
then at or above the validated origin. Lookup could add/subtract that origin
without repeated checked arithmetic on every chain step; all access remained
safe Rust. Pruning still scanned the heads and retained links each advancing
block, although it no longer rehashed history bytes.

Only the last two history positions could acquire new three-byte lookahead at
a boundary. The prototype recorded those triples and emitted positions in
order. Each run validated bounds and advanced the indexed frontier once. A
one-position literal path hashed one triple and wrote its link/head directly;
longer runs used `windows(3)`. Absolute predecessors removed the first
prototype's per-position u32 back-distance conversion.

The equivalence obligations were unchanged hash/bucket count, nearest-first
chain order, chain/window bounds, greedy choices and ties, exact tokens and
member bytes, and public work totals/refusals. Candidates becoming too distant
within a block still counted toward chain work. `FixedOrStored` still made
matcher decisions before selecting the strictly smaller stored representation.
The prototype changed `Fixed` and `FixedOrStored`; it introduced no new codec
or pack profile, persistent index or authority.

A non-final first block allocated
`next_power_of_two(window_bytes + block_bytes)` links once: 65,536 links,
**512 KiB on this 64-bit host**, plus 32,768 heads (256 KiB). A custom positive
span rounded to less than twice its requested length. A first-final block
instead used exactly its actual length, with one slot for empty input, an
all-ones addressing mask and origin zero. It could not grow or accept a shifted
origin. Allocation sizes/timing differed from the production implementation;
identical allocator-failure behavior was not claimed.

Checked span/absolute-position overflow returned `InvalidProfile`. The last
two incomplete triples were not indexed, preserving the `usize::MAX` sentinel.
Existing work charges and cancellation probes remained. Cancellation at a
later streaming call or during matching discarded the retained index, pending
input, history and unpublished writer output; a refused encoder had no receipt
or further output and refused subsequent push/finish calls. Previously drained
tentative bytes still had to be discarded by the caller.

## Prototype verification, not shipped test coverage

The unpublished final prototype's `crates/fgit-deflate/src/lib.rs` SHA-256 was
`76226eb40ec770991fe53f0ffef2f749c14f1b8cd21f7e131b5964764267a239`.
This is an artifact identity, **not a published source commit**.

At that prototype source, author-run deflate tests completed across six
targets: **64 passed, 0 failed, 1 ignored**; strict all-target deflate Clippy
also passed. These counts belong to rejected prototype tests, not the shipped
tree. The ignored measurement was not a pass.

The historical scalar `reference_matcher` retained independent hash and chain
traversal. Comparisons covered both affected block kinds, eight block/window/
chain configurations, blocks from 1 to 65,535 bytes, mixed repetitive/random/
periodic data, history eviction, ring wraps and boundary triples. They checked
per-block work, exact member bytes, one-shot and 997-byte streaming input,
native inflation and stable allocation addresses/capacities.

Focused cases checked post-wrap work ceilings (`observed = limit + 1`),
exact final-block allocation, shifted-origin refusal, absolute overflow,
sentinel handling, expired heads/links across wrapped history, and cancellation
both at call entry and during matching. Conformance passing did not establish
the performance hypothesis. No new full-node or stock-Git transport verification
was performed for this prototype.

## Sources and measurement method

- Final pack A1/A2 control: `6aff7387e91c277e76b658aee6a4bfb0406f097b`.
  B was that source with the unpublished final prototype identified above.
  Earlier experiments used `d98eb110a9fce6306627302f7561f3c3986294c1`;
  they are not silently rebound to this control. The original deflater used
  for the codec control was unchanged between those commits.
- Host: AMD EPYC 9V74, x86_64 Linux 6.18.55; pinned
  `nightly-2026-08-31`. Pack executables used Cargo `--release`:
  opt-level 3, fat LTO, codegen-units 1, panic abort and symbol stripping;
  no extra `RUSTFLAGS`.
- The final standalone codec executables also used opt-level 3,
  codegen-units 1, `lto=fat`, `panic=abort`, `strip=symbols` and debuginfo 0.
  Source rlibs were built with `embed-bitcode=yes` for that LTO link.
  This final LTO experiment is distinct from NEG-041's first u32 experiment,
  which used direct rustc with default codegen settings and no explicit LTO.
- The public [cold_pack example](../crates/fgit-pack/examples/cold_pack.rs)
  used `PackPlanner::stream_selected_thin`, SHA-1, `COMPRESSED_V5`, zero
  recency/path hints, no thin bases and no computation cache. Shapes and the
  timer follow [cold pack construction](COLD_PACK_CONSTRUCTION.md#measurement-source-and-method).
  Cases were four shapes at twelve 1 MiB objects, then similar/unrelated/text
  at two 8 MiB objects. Both sizes are reported.
- There were five trials, trial outermost, in the case order shown below.
  Each arm ran in a fresh process: A1/A2/B on even trials and B/A2/A1 on odd
  trials. A1 and A2 were repeated controls. Pack `elapsed_ns` included owned
  source copies, native identity verification, delta selection, compression,
  memory sink and trailer hashing; corpus generation was excluded.
- CPU means process user + system time; peak RSS covers the entire process,
  including corpus generation, initial hashing and reporting outside the
  internal timer. No request-cost, storage-cost or service-tail measurement was
  made. The raw elapsed arrays expose this campaign's observed spread.

Final executable identities (SHA-256):

| Executable | SHA-256 |
| --- | --- |
| Pack control A1/A2 | `082cbad785ab186292634e44ac2dcda9410356c05b192e67f3e4fc1f050c7f9c` |
| Pack prototype B | `a1bdad9debb107000d101e81aee2c787ef553976121f16ae84993afad07c378e` |
| LTO codec control A1/A2 | `b4ee1ecdda02a6295722758bf60defc527432787faed6eb989037799efc1a32e` |
| LTO codec prototype B | `ab5dc2770df489b2d486607a1d35da55ccb716655e396c897a3edc4eba45767b` |

## Final public pack-writer results: all 105 samples

A pooled control median uses all ten A1/A2 observations; B uses five. A/A spread
is the difference between A1 and A2 medians divided by the pooled baseline
median. It is a noise indicator, not a confidence interval. Positive changes
mean higher cost.

| Case | Pooled A, ms | B, ms | Wall change | A/A spread | CPU change | RSS change, KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| similar, 12 x 1 MiB | 110.866 | 124.419 | +12.23% | 2.56% | +11.24% | +122 |
| shifted, 12 x 1 MiB | 114.763 | 120.981 | +5.42% | 15.06% | +4.43% | +124 |
| unrelated, 12 x 1 MiB | 563.245 | 704.536 | +25.09% | 1.74% | +23.69% | +2 |
| text, 12 x 1 MiB | 128.503 | 135.693 | +5.60% | 6.69% | +4.34% | +254 |
| similar, 2 x 8 MiB | 382.400 | 422.536 | +10.50% | 10.49% | +12.06% | -4 |
| unrelated, 2 x 8 MiB | 883.450 | 996.877 | +12.84% | 1.97% | +10.14% | +0 |
| text, 2 x 8 MiB | 96.713 | 76.932 | -20.45% | 8.84% | -13.64% | -4 |

The two unrelated cases regressed substantially beyond their A/A median
spread. Similar 12 x 1 MiB also regressed; shifted and 12 x 1 MiB text differences
were inside A/A spread. The similar 2 x 8 MiB increase was about its A/A spread.
The 2 x 8 MiB text improvement is retained as a positive shape-specific result,
not evidence that the prototype improved the complete workload.

Elapsed arrays are in trial order and retain nanosecond precision in
milliseconds. CPU and RSS columns are medians of process measurements.

| Case | Arm | Median elapsed, ms | Five elapsed samples, ms | Process CPU, ms | Peak RSS, KiB |
| --- | --- | ---: | --- | ---: | ---: |
| similar, 12 x 1 MiB | A1 | 112.284 | 125.383378, 112.283742, 102.327177, 125.488936, 102.835043 | 139.053 | 38664 |
| similar, 12 x 1 MiB | A2 | 109.448 | 133.687743, 106.375317, 106.052483, 123.460789, 109.448402 | 137.307 | 38660 |
| similar, 12 x 1 MiB | B | 124.419 | 150.215013, 113.600049, 116.254119, 124.419485, 139.839355 | 153.712 | 38784 |
| shifted, 12 x 1 MiB | A1 | 114.635 | 114.635496, 106.179341, 116.851897, 112.087918, 114.889978 | 142.810 | 39944 |
| shifted, 12 x 1 MiB | A2 | 131.916 | 141.156446, 111.352112, 131.916206, 132.760831, 110.497043 | 161.411 | 39940 |
| shifted, 12 x 1 MiB | B | 120.981 | 155.638191, 119.985741, 121.383477, 120.981226, 117.021269 | 149.304 | 40064 |
| unrelated, 12 x 1 MiB | A1 | 566.340 | 663.830028, 560.150022, 544.597951, 566.340220, 579.405778 | 623.438 | 50432 |
| unrelated, 12 x 1 MiB | A2 | 556.551 | 630.713769, 556.550756, 646.742564, 518.651277, 553.091927 | 614.536 | 50440 |
| unrelated, 12 x 1 MiB | B | 704.536 | 772.542337, 633.925358, 704.535738, 635.443070, 721.125797 | 766.709 | 50436 |
| text, 12 x 1 MiB | A1 | 132.799 | 161.669249, 132.799419, 133.206963, 121.405120, 121.755487 | 172.526 | 37764 |
| text, 12 x 1 MiB | A2 | 124.206 | 155.467251, 122.560410, 123.559323, 124.206165, 165.146954 | 160.994 | 37768 |
| text, 12 x 1 MiB | B | 135.693 | 166.759250, 139.843192, 135.692784, 127.896332, 131.160570 | 174.001 | 38020 |
| similar, 2 x 8 MiB | A1 | 392.551 | 483.857818, 392.550612, 372.249213, 402.523966, 355.749878 | 448.788 | 50524 |
| similar, 2 x 8 MiB | A2 | 352.454 | 431.479078, 454.137291, 332.999470, 352.454454, 349.944116 | 411.136 | 50528 |
| similar, 2 x 8 MiB | B | 422.536 | 509.008032, 422.535619, 404.806711, 491.474083, 402.776007 | 490.296 | 50524 |
| unrelated, 2 x 8 MiB | A1 | 892.162 | 1003.500291, 892.161895, 863.758236, 908.388601, 871.002105 | 989.961 | 59604 |
| unrelated, 2 x 8 MiB | A2 | 874.738 | 999.015930, 829.390154, 874.737735, 834.058449, 907.981033 | 982.831 | 59612 |
| unrelated, 2 x 8 MiB | B | 996.877 | 981.979226, 1018.796608, 996.877418, 965.728987, 1047.805296 | 1086.391 | 59612 |
| text, 2 x 8 MiB | A1 | 92.436 | 92.436487, 126.760096, 92.322407, 87.850007, 111.568498 | 167.075 | 50272 |
| text, 2 x 8 MiB | A2 | 100.990 | 84.769891, 100.990001, 102.960794, 86.883499, 118.940328 | 181.181 | 50268 |
| text, 2 x 8 MiB | B | 76.932 | 91.291999, 80.157950, 76.931765, 71.113205, 72.572994 | 150.374 | 50268 |

All fifteen timed samples in each case reported the same length, delta count
and native pack checksum. Raw packs were not retained for a direct cross-process
byte comparison; exact bytes were checked separately by the prototype oracles.

| Case | Pack bytes | Deltas | SHA-1 pack checksum |
| --- | ---: | ---: | --- |
| similar, 12 x 1 MiB | 1049723 | 11 | `41bb0b43f92a9d4ebf81aca0f8edd40f741749a9` |
| shifted, 12 x 1 MiB | 1049587 | 11 | `b909684d69c86b4108613935d9248e783cdf67b8` |
| unrelated, 12 x 1 MiB | 12585008 | 0 | `993a9ef078d28ad1ecd509afffa2a54ac11bf201` |
| text, 12 x 1 MiB | 10307 | 11 | `ca68787c629774c0bba7c9358c4723d0d5272053` |
| similar, 2 x 8 MiB | 8390295 | 1 | `a7000d50f2641c0bd898e52512cfd8ba6050cf7f` |
| unrelated, 2 x 8 MiB | 16779832 | 0 | `fd0409ff087d2ffa0ea0fc43c1798994057ee071` |
| text, 2 x 8 MiB | 74477 | 1 | `3d0bded2e4f7d46b34442d55a813872aad8315a6` |

## Final LTO codec results: all 45 samples

The public probe repeated a fixed text pattern to the requested length before
starting its timer. Each iteration created a fresh `Deflater` with
`GIT_OBJECT` and `FIXED_OR_STORED`, pushed through `black_box`, finished,
counted public work and drained output. Setup/allocation was timed; corpus
generation was excluded. CPU/RSS were whole-process measurements.

| Input x repeats | Pooled A, ms | B, ms | Wall change | A/A spread | Process CPU A / B, ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 64 B x 20000 | 75.908 | 71.956 | -5.21% | 7.97% | 76.691 / 73.182 |
| 4096 B x 2000 | 29.703 | 27.453 | -7.57% | 16.21% | 31.008 / 29.213 |
| 1048576 B x 20 | 87.583 | 54.680 | -37.57% | 5.54% | 89.700 / 56.410 |

All 45 samples had 10,368 KiB peak RSS. The 64 B and 4 KiB wall differences were
inside A/A spread. The 1 MiB codec improved 37.57% in wall time and 37.11% in
process CPU, but the public pack pipeline regressed on unrelated data. A
repetitive-text codec result was therefore insufficient for adoption.

| Input | A1: five elapsed samples, ms | A2: five elapsed samples, ms | B: five elapsed samples, ms |
| --- | --- | --- | --- |
| 64 B | 65.445898, 86.991140, 78.934180, 82.304220, 67.229483 | 68.771897, 68.493129, 72.881571, 100.325117, 82.973919 | 70.276083, 85.809889, 81.049183, 71.956083, 69.227369 |
| 4096 B | 27.179189, 32.719720, 25.802162, 32.110910, 37.818577 | 23.819810, 37.543475, 26.881001, 27.295433, 41.557125 | 24.412468, 27.453310, 24.762984, 36.234070, 30.786620 |
| 1048576 B | 81.004791, 75.909178, 90.007024, 115.523689, 94.356663 | 85.158146, 81.291245, 81.712909, 100.608512, 100.996001 | 61.298652, 54.680230, 51.840120, 50.345668, 67.552858 |

Every arm preserved cumulative output length and public work for each case:
64 B: 920,000 output bytes / 2,640,000 work units; 4096 B: 156,000 output bytes / 16,422,000 work units; 1048576 B: 175,640 output bytes / 42,025,320 work units. These fields supplement the exact-byte oracle checks.

## Reproduction and retained negative evidence

The immutable control can be rebuilt using the separate-checkout/target commands
in [COLD_PACK_CONSTRUCTION.md](COLD_PACK_CONSTRUCTION.md#reproduction-and-verification-scope).
For each trial, invoke the selected executable with `SHAPE 1048576 12 1`
for similar, shifted, unrelated and text, then `SHAPE 8388608 2 1` for similar,
unrelated and text, with the same alternating arm order above. Record process
CPU/RSS with `os.wait4` or `/usr/bin/time`.

The codec probe was:

```rust
use std::hint::black_box;
use std::time::Instant;
use fgit_deflate::{DeflateLimits, DeflateProfile, Deflater};
fn main() {
    let n: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let repeats: usize = std::env::args().nth(2).unwrap().parse().unwrap();
    let pattern = b"the quick bounded repository object\n";
    let data: Vec<u8> = (0..n).map(|i| pattern[i % pattern.len()]).collect();
    let start = Instant::now();
    let mut sum = 0usize;
    let mut work = 0u64;
    for _ in 0..repeats {
        let mut encoder = Deflater::new(DeflateLimits::GIT_OBJECT, DeflateProfile::FIXED_OR_STORED).unwrap();
        encoder.push(black_box(&data)).unwrap();
        encoder.finish().unwrap();
        work += encoder.work_units();
        sum += black_box(encoder.take_output()).len();
    }
    println!("bytes={n} repeats={repeats} elapsed_ns={} output_bytes={sum} work_units={work}", start.elapsed().as_nanos());
}
```

Compile each source rlib with pinned rustc, edition 2024, opt-level 3,
codegen-units 1, debuginfo 0, panic abort and embedded bitcode; link its probe
with the same settings plus fat LTO and symbol stripping. Run `64 20000`,
`4096 2000`, and `1048576 20` with the five-trial A/A/B order. The original
raw files were `frankengit-8810-pack-pruned-raw.jsonl` and
`frankengit-8810-codec-lto-pruned-raw.jsonl`; all elapsed observations are
preserved above.

The candidate source and added tests were deliberately not committed. Its
hashes identify an unpublished experiment; checking out the control or current
main does not recreate it. A future revisit must identify a changed mechanism
and demonstrate both small-member behavior and the complete public writer
against A/A controls. The earlier u32 failure and this pruned-usize failure
remain in NEG-041 regardless of any later result.

The original deflater was retained, so no object rewrite, profile migration or
stored-state cleanup was needed. After restoration, the shipped-source pack and
deflate suites at `6aff7387e91c277e76b658aee6a4bfb0406f097b` completed across
40 targets: **341 passed, 0 failed, 10 ignored**. That result is distinct from
the 64-test rejected-prototype result above. This experiment establishes no full-node,
transport, production-concurrency or large-repository clone improvement, and
does not complete `frankengit-1tl9` or persisted-pack reuse.
