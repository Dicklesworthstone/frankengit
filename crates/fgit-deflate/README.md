# fgit-deflate

`fgit-deflate` is FrankenGit's owned, safe-Rust zlib/DEFLATE codec. It is the
D4 slice selected for loose-object/pack quarantine and deterministic pack
writing: RFC 1950 framing (including Adler-32) plus RFC 1951 stored,
fixed-Huffman, and dynamic-Huffman blocks, with no native compression library,
FFI, subprocess, or dependency edge.

The public decoder is streaming: `Inflater::push` may make output available
after each supplied compressed chunk, while `Inflater::finish` authenticates
the zlib Adler-32 trailer. Output obtained before a successful `finish` is
tentative and callers must discard it after any refusal. `inflate_zlib` is the
one-shot convenience API and returns bytes only after the trailer verifies.

## Admission and resource boundary

An `Inflater` accepts exactly one zlib member. It checks the advertised window
before allocating it; bounds retained input before copying it; bounds Huffman
tables and dynamic code-length collections before construction; and reserves
output before emitting a literal or match. Every profile must set a nonzero
ratio ceiling as well as input, pending-input, output, window, collection,
table, and deterministic work ceilings. `InflateLimits::GIT_OBJECT` is the
conservative object/pack-admission profile. Concatenated members and any bytes
after the Adler-32 trailer are a refusal, not a hidden multi-member mode.

The decoder has no ambient runtime, clock, or I/O authority. A caller supplies
deadline cancellation through `CancellationProbe`; `push_with_control` checks
that control between bounded decoding steps and returns `Cancelled`. This
crate neither commits decoded bytes nor decides an object's identity: callers
keep the stream in quarantine and verify the enclosing Git commitments.

## Deterministic encoding

`Deflater` and `deflate_zlib` emit one RFC 1950 member. The streaming encoder
accepts input incrementally and emits every full profile-sized non-final block;
`finish` or `finish_with_control` emits the final remainder, an empty final
block when needed, then the Adler-32 trailer. Bytes returned by `take_output`
remain tentative until `finish` succeeds. After any refusal, the encoder
discards its private remainder, exposes no further bytes, and has no receipt.

The frozen policies are recorded verbatim in `DeflateReceipt`:

- `DeflateProfile::FAST_STORED` emits 32 KiB stored blocks and retains no
  match history;
- `DeflateProfile::DEFAULT` (also `FIXED`) emits 32 KiB fixed-Huffman blocks
  using a 32 KiB window, nearest-first greedy matching, a 64-candidate direct
  backward search, and no lazy matching;
- `DeflateProfile::DYNAMIC` emits RFC 1951 dynamic-Huffman blocks with a
  frozen literal codebook and no match history in this slice.

The split boundary is profile-constant, so identical bytes and profile produce
byte-identical members regardless of streaming chunk boundaries. The encoder
checks input, pending-input, output, window, Huffman-symbol,
dynamic-code-length, allocation, and deterministic-work ceilings before the
corresponding work or allocation. It has no ambient runtime, clock, I/O, or
commit authority; `CancellationProbe` is the sole cancellation input.

## Exact refusal vocabulary

`InflateRefusal` is the entire non-success vocabulary:

- `ResourceLimit` for invalid limits and for input, retained input, output,
  expansion-ratio, window, Huffman-symbol, dynamic-collection, work, or
  allocation budgets;
- `Cancelled` for caller-provided cancellation checks;
- `InvalidZlibHeader`, `PresetDictionaryUnsupported`, and `Adler32Mismatch`;
- `UnexpectedEnd`, `TrailingGarbage`, and `StoredLengthMismatch`;
- `ReservedBlockType`, `InvalidHuffmanCode`, `IncompleteHuffmanSet`, and
  `OversubscribedHuffmanSet` for malformed DEFLATE coding structure;
- `InvalidCodeLength`, `InvalidLengthOrDistanceCode`, and `DistanceTooFar`.

These refusals are deterministic and never silently truncate output. The
encoder's `DeflateRefusal` vocabulary is `ResourceLimit`, `Cancelled`,
`AlreadyFinished`, `RefusedAfterFailure`, and `InvalidProfile`. It never falls
back to a system codec or silently changes a selected profile.

Encoder fingerprint tests use checked-in FNV-1a regression constants for fixed
input bytes under every frozen profile. They were derived offline with a small
separately written RFC bit-packing reference that did not call zlib; FNV-1a is
only a compact regression sentinel, not an integrity or object-identity
commitment. This crate makes **no claim** that its compressed bytes are
bit-compatible with zlib or upstream Git, nor any ratio or throughput claim.
The checked-in inflate fixtures remain external reference inputs for decoder
conformance rather than evidence of encoder compatibility.
