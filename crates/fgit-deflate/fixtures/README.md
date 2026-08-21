# `fgit-deflate` offline inflate fixtures

These are immutable hex encodings of complete RFC 1950 zlib members.  Tests
decode them with the owned decoder; they never invoke Python, system `zlib`,
or any external codec at test time.

They were generated once on 2026-08-21 using CPython 3.13.7 and zlib 1.3.1:

- `stored_hello.zlib.hex`: `zlib.compress(b"hello", level=0)`;
- `fixed_repetition.zlib.hex`: a `zlib.compressobj` at level 9 with
  `strategy=zlib.Z_FIXED`, over the literal text reconstructed in
  `offline_reference_vectors_decode`;
- `dynamic_text.zlib.hex`: a level-9 default-strategy `zlib.compressobj`,
  over the deterministic text-and-byte corpus reconstructed in that same
  test.

The files are deliberately hex text so their exact input bytes are reviewable
without a binary tool.  Their block-type assertions ensure this corpus covers
stored, fixed-Huffman, and dynamic-Huffman decoding.  These are external
reference fixtures for the decoder; they are not encoder-output goldens and do
not claim that this crate's deterministic encoder is byte-compatible with
zlib.
