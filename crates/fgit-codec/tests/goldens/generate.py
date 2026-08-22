#!/usr/bin/env python3
"""Independent derivation of the fgit-codec golden corpus.

This is the second implementation behind every byte checked in next to it. It
reads ONLY the written format specification -- the `crates/fgit-codec/src/wire.rs`
module doc plus ADR-0002 -- and re-implements the frame layout from scratch in
another language. So the committed goldens are not the Rust encoder's own output
echoed back at it: the Rust tests compare the encoder against bytes something
else produced.

It is never invoked by the Rust tests, and nothing in this directory imports it.
Regenerating a vector from fgit-codec's own output would make those tests
tautological, so this script is the only thing permitted to write them. Same
arrangement, and for the same reason, as `crates/fgit-crypto/goldens/derive.py`.

**What preserves the independence is what this file DOES, not where it lives.**
It must never call into fgit-codec, never be ported to Rust, and never be made a
`cargo` target. An earlier version of the README kept it out of the repository
altogether on the theory that distance was the safeguard; the practical effect
was that the corpus's central claim became unverifiable the moment the only copy
went stale, because the control step in the README needs this file to run at all.

Usage, from anywhere:  python3 crates/fgit-codec/tests/goldens/generate.py
It rewrites `*.golden` in its own directory and leaves everything else alone.
"""
import os, struct

# Its own directory, so the control step works from any working directory and
# cannot be pointed at the wrong tree by a stale absolute path.
OUT = os.path.dirname(os.path.abspath(__file__))

def u16(v): return struct.pack(">H", v)
def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def lp(b):  return u32(len(b)) + b            # length-prefixed bytes

CODEC_MAJOR, CODEC_MINOR = 1, 0
MAGIC = b"FGC1"
ALG = 1                                       # DigestAlgorithmId used in fixtures

def internal_id(domain, digest, alg=ALG, major=CODEC_MAJOR, minor=CODEC_MINOR):
    return u16(alg) + lp(domain.encode()) + u16(major) + u16(minor) + lp(digest)

def digest(alg, body):
    return u16(alg) + lp(body)

def schema_id(family, major, minor):
    return lp(family.encode()) + u16(major) + u16(minor)

def frame(domain, family, smaj, smin, payload, codec_minor=CODEC_MINOR, codec_major=CODEC_MAJOR):
    return (MAGIC + u16(codec_major) + u16(codec_minor)
            + lp(domain.encode()) + schema_id(family, smaj, smin) + lp(payload))

def opt(v):
    return b"\x00" if v is None else b"\x01" + v

def canonical_set(elements):
    e = sorted(elements)
    assert len(set(e)) == len(e), "duplicate element in canonical set"
    return u32(len(e)) + b"".join(e)

def sequence(elements):
    return u32(len(elements)) + b"".join(elements)

FNV_OFFSET, FNV_PRIME, MASK = 0xcbf29ce484222325, 0x100000001b3, (1 << 64) - 1
def fnv1a64(data):
    h = FNV_OFFSET
    for byte in data:
        h = ((h ^ byte) * FNV_PRIME) & MASK
    return h

CORPUS_ALG = 0xfff1
# Fixture signature scheme. Production code point 1 is Ed25519 under ADR-0003;
# 0xfff0..=0xffff is reserved for harness use. Folded back from the 740a253
# re-bless, which changed the corpus without updating this generator.
FIXTURE_SIG_SCHEME = 0xfff1
def corpus_digest(data):
    """corpus-fnv1a64x2: fnv1a64(bytes) || fnv1a64(reversed bytes), big-endian."""
    return u64(fnv1a64(data)) + u64(fnv1a64(bytes(reversed(data))))

def identity_preimage(domain, family, smaj, smin, canonical_body):
    """fgit-crypto's frozen preimage framing (CloudyTiger, v1.1)."""
    d, f = domain.encode(), family.encode()
    assert len(d) < 256 and len(f) < 256
    return (bytes([len(d)]) + d + bytes([len(f)]) + f
            + u16(smaj) + u16(smin) + u64(len(canonical_body)) + canonical_body)

def corpus_body_id(domain, family, smaj, smin, canonical_body):
    pre = identity_preimage(domain, family, smaj, smin, canonical_body)
    return "%s/v%d.%d/alg:%d/%s" % (domain, CODEC_MAJOR, CODEC_MINOR, CORPUS_ALG,
                                    corpus_digest(pre).hex())

# ---------------------------------------------------------------- fixtures
D_TX      = "frankengit/ref-txn/v2"
D_SEAL    = "frankengit/txn-seal/v1"
D_RCR     = "frankengit/rcr/v1"
D_BATCH   = "frankengit/decision-batch/v1"
D_HEAD    = "frankengit/authority-head/v1"
D_REFUSAL = "frankengit/refusal-record/v1"
D_SNAP    = "frankengit/principal-snapshot/v1"
D_CAPSULE = "frankengit/repository-capsule/v1"
D_ENV     = "frankengit/signed-envelope/v1"

def fill(byte, n=32): return bytes([byte]) * n

TX_ID    = internal_id(D_TX,      bytes(range(32)))
SEAL_ID  = internal_id(D_SEAL,    fill(0x51))
RCR_ID   = internal_id(D_RCR,     fill(0x52))
BATCH_ID = internal_id(D_BATCH,   fill(0x53))
HEAD_ID  = internal_id(D_HEAD,    fill(0x54))
REF_ID   = internal_id(D_REFUSAL, fill(0x55))
SNAP_ID  = internal_id(D_SNAP,    fill(0x56))
CAP_ID   = internal_id(D_CAPSULE, fill(0x57))

TENANT = bytes([0x11]) * 16
REPO   = bytes([0x22]) * 16
PRINC  = bytes([0x33]) * 16

def dg(byte): return digest(ALG, fill(byte))

# ---------------------------------------------------------------- bodies
seal_payload = (TX_ID + TENANT + REPO + PRINC
                + dg(0x44) + dg(0x55) + schema_id("ref-txn", 2, 0))
SEAL = frame(D_SEAL, "txn-seal", 1, 0, seal_payload)

rcr_payload = (REPO + u64(7) + opt(RCR_ID) + TX_ID + SNAP_ID
               + dg(0x60) + dg(0x61) + dg(0x62) + dg(0x63) + dg(0x64) + dg(0x65)
               + u64(3)
               + dg(0x66) + dg(0x67) + dg(0x68) + dg(0x69))
RCR = frame(D_RCR, "rcr", 1, 0, rcr_payload)

decision_committed = TX_ID + u64(9) + b"\x01" + RCR_ID
decision_refused   = TX_ID + u64(10) + b"\x02" + u16(0x0201) + REF_ID
batch_payload = (REPO + HEAD_ID + u64(4) + u64(9)
                 + sequence([decision_committed, decision_refused])
                 + sequence([rcr_payload])
                 + dg(0x70) + dg(0x71) + dg(0x72) + dg(0x73) + dg(0x74)
                 + u64(3) + dg(0x75))
BATCH = frame(D_BATCH, "decision-batch", 1, 0, batch_payload)

genesis_head_payload = (REPO + u64(1) + opt(None) + opt(None) + opt(None)
                        + opt(None) + opt(None)
                        + dg(0x80) + dg(0x81) + dg(0x82) + dg(0x83) + dg(0x84) + dg(0x85)
                        + u64(1) + u64(1) + opt(None))
HEAD_GENESIS = frame(D_HEAD, "authority-head", 1, 0, genesis_head_payload)

advanced_head_payload = (REPO + u64(5) + opt(HEAD_ID) + opt(BATCH_ID) + opt(u64(10))
                         + opt(RCR_ID) + opt(u64(7))
                         + dg(0x80) + dg(0x81) + dg(0x82) + dg(0x83) + dg(0x84) + dg(0x85)
                         + u64(3) + u64(2) + opt(CAP_ID))
HEAD_ADVANCED = frame(D_HEAD, "authority-head", 1, 0, advanced_head_payload)

detail = b"expected-old ref did not match the basis"
refusal_payload = (TX_ID + SEAL_ID + u64(10) + u16(0x0201) + u64(3)
                   + lp(detail) + dg(0x90))
REFUSAL = frame(D_REFUSAL, "refusal-record", 1, 0, refusal_payload)

# signed envelopes: same carried body, zero / one / two signatures
def signature(scheme, key_id, body_id_bytes, sig):
    return u16(scheme) + lp(key_id) + body_id_bytes + lp(sig)

SEAL_BODY_ID_FOR_SIG = internal_id(
    D_SEAL, corpus_digest(identity_preimage(D_SEAL, "txn-seal", 1, 0, seal_payload)))
sig_a = signature(FIXTURE_SIG_SCHEME, b"key-a", SEAL_BODY_ID_FOR_SIG, bytes([0xa0]) * 64)
sig_b = signature(FIXTURE_SIG_SCHEME, b"key-b", SEAL_BODY_ID_FOR_SIG, bytes([0xb0]) * 64)

ENV_0 = frame(D_ENV, "signed-envelope", 1, 0, lp(SEAL) + canonical_set([]))
ENV_1 = frame(D_ENV, "signed-envelope", 1, 0, lp(SEAL) + canonical_set([sig_a]))
ENV_2 = frame(D_ENV, "signed-envelope", 1, 0, lp(SEAL) + canonical_set([sig_b, sig_a]))

VALID = [
    ("txn-seal", "canonical", D_SEAL, SEAL, seal_payload,
     "One transaction seal with every field populated."),
    ("rcr", "canonical", D_RCR, RCR, rcr_payload,
     "One Repository Commit Record with a parent, at repository sequence 7."),
    ("decision-batch", "canonical", D_BATCH, BATCH, batch_payload,
     "One decision batch carrying a commit and a refusal plus one commit record."),
    ("authority-head", "genesis", D_HEAD, HEAD_GENESIS, genesis_head_payload,
     "The genesis authority head: generation 1, every optional position absent."),
    ("authority-head", "advanced", D_HEAD, HEAD_ADVANCED, advanced_head_payload,
     "An advanced authority head: generation 5, every optional position present."),
    ("refusal-record", "canonical", D_REFUSAL, REFUSAL, refusal_payload,
     "One refusal record for an expected-old mismatch."),
    ("signed-envelope", "unsigned", D_ENV, ENV_0, lp(SEAL) + canonical_set([]),
     "A signed envelope carrying the txn-seal body with no signatures yet."),
    ("signed-envelope", "one-signature", D_ENV, ENV_1, lp(SEAL) + canonical_set([sig_a]),
     "The same carried body with one detached signature."),
    ("signed-envelope", "two-signatures", D_ENV, ENV_2, lp(SEAL) + canonical_set([sig_b, sig_a]),
     "The same carried body with two detached signatures, supplied out of order."),
]

# ---------------------------------------------------------------- mutations
def mutate_magic(b):        return b"FGC0" + b[4:]
def mutate_codec_major(b):  return b[:4] + u16(2) + b[6:]
def with_schema_major(b, domain, family, new_major):
    off = 4 + 2 + 2 + 4 + len(domain) + 4 + len(family)
    assert b[off:off+2] == u16(1), b[off:off+2].hex()
    return b[:off] + u16(new_major) + b[off+2:]
def with_domain(b, domain, replacement):
    assert len(domain) == len(replacement)
    off = 4 + 2 + 2 + 4
    assert b[off:off+len(domain)] == domain.encode()
    return b[:off] + replacement.encode() + b[off+len(domain):]
def truncate(b, n=1):       return b[:-n]
def append_trailing(b):     return b + b"\x00"

def family_of(domain):
    return {D_SEAL: "txn-seal", D_RCR: "rcr", D_BATCH: "decision-batch",
            D_HEAD: "authority-head", D_REFUSAL: "refusal-record",
            D_ENV: "signed-envelope"}[domain]

# Equal length so every later offset is unchanged, and lowercase so the label
# validator accepts the tag and the DOMAIN check is what actually refuses.
SWAP = {D_SEAL: "frankengit/txn-seaz/v1", D_RCR: "frankengit/rcz/v1",
        D_BATCH: "frankengit/decision-batcz/v1", D_HEAD: "frankengit/authority-heaz/v1",
        D_REFUSAL: "frankengit/refusal-recorz/v1", D_ENV: "frankengit/signed-envelopz/v1"}

os.makedirs(OUT, exist_ok=True)
# Only the generated vectors. The earlier scratchpad version of this script
# cleared the whole directory, which was harmless while it wrote to a temp dir
# and would have deleted README.md -- the file documenting the procedure that
# invokes it -- the first time anyone pointed it at the real corpus.
for f in os.listdir(OUT):
    if f.endswith(".golden"):
        os.remove(os.path.join(OUT, f))

def write(name, lines):
    with open(os.path.join(OUT, name), "w") as handle:
        handle.write("\n".join(lines) + "\n")

count_valid = count_invalid = 0
for schema, case, domain, data, payload, description in VALID:
    stem = "%s__%s" % (schema, case)
    write(stem + ".golden", [
        "# frankengit-codec-golden v1",
        "# " + description,
        "# Bytes derived independently from the written format specification,",
        "# not emitted by the encoder under test.",
        "schema = " + schema,
        "kind = valid",
        "frame_len = %d" % len(data),
        "body_id = " + corpus_body_id(domain, family_of(domain), 1, 0, payload),
        "canonical_body_len = %d" % len(payload),
        "bytes = " + data.hex(),
    ])
    count_valid += 1
    family = family_of(domain)
    variants = [
        ("magic_corrupted", "magic_unrecognized", mutate_magic(data)),
        ("codec_major_bumped", "codec_major_unsupported", mutate_codec_major(data)),
        ("schema_major_bumped", "schema_major_unsupported",
         with_schema_major(data, domain, family, 2)),
        ("domain_swapped", "domain_unexpected", with_domain(data, domain, SWAP[domain])),
        ("payload_truncated", "input_truncated", truncate(data, 1)),
        ("trailing_byte_appended", "trailing_bytes", append_trailing(data)),
    ]
    for mutation, expect, mutated in variants:
        write("%s__%s.golden" % (stem, mutation), [
            "# frankengit-codec-golden v1",
            "# Planted defect: %s" % mutation,
            "schema = " + schema,
            "kind = invalid",
            "mutation = " + mutation,
            "expect = " + expect,
            "bytes = " + mutated.hex(),
        ])
        count_invalid += 1

print("valid=%d invalid=%d total=%d" % (count_valid, count_invalid, count_valid + count_invalid))
print("SEAL body id:", corpus_body_id(D_SEAL, "txn-seal", 1, 0, seal_payload))
