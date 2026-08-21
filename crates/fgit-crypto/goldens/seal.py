#!/usr/bin/env python3
"""Derive the envelope-sealing golden corpus from outside this crate.

The same discipline as `derive.py`: nothing here calls into fgit-crypto, and
the Rust tests only ever *read* the .tsv this writes. Regenerating the vectors
from Rust output would make the test tautological.

Independence has two layers here. HKDF-SHA-256 and HMAC-SHA-256 come from
Python's `hashlib`/`hmac`. ChaCha20-Poly1305 comes from `cryptography`, which
is OpenSSL-backed. Only HChaCha20 is written out longhand, because neither
library exposes it -- and it is validated against the published
draft-irtf-cfrg-xchacha section 2.2.1 vector before it is used for anything,
so a mistake in it fails loudly here rather than agreeing with a matching
mistake in Rust.

Usage: python3 seal.py
"""

import hashlib
import hmac
import pathlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HERE = pathlib.Path(__file__).resolve().parent
MARKER = "# franken-registry-v1"

# --- HChaCha20, the only primitive written longhand -------------------------

MASK = 0xFFFFFFFF


def rotl(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & MASK


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK
    state[d] = rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK
    state[d] = rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotl(state[b] ^ state[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    assert len(key) == 32 and len(nonce16) == 16
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)
    # No feed-forward addition: that is what makes it HChaCha20 rather than
    # a ChaCha20 block.
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def _self_check_hchacha20() -> None:
    """draft-irtf-cfrg-xchacha section 2.2.1."""
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    expected = bytes.fromhex(
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    )
    actual = hchacha20(key, nonce)
    if actual != expected:
        raise SystemExit(
            f"HChaCha20 self-check FAILED\n  expected {expected.hex()}\n  actual   {actual.hex()}"
        )


def xchacha20poly1305_seal(
    key: bytes, nonce24: bytes, aad: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    subkey = hchacha20(key, nonce24[:16])
    inner_nonce = b"\x00\x00\x00\x00" + nonce24[16:]
    sealed = ChaCha20Poly1305(subkey).encrypt(inner_nonce, plaintext, aad)
    return sealed[:-16], sealed[-16:]


# --- HKDF-SHA-256, RFC 5869 -------------------------------------------------


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# --- The fgit-crypto key pipeline, re-derived from the documented layout ----

PURPOSE_SALT = {
    "identity": b"frankengit/key-salt/identity/v1",
    "authority-admin": b"frankengit/key-salt/authority-admin/v1",
    "capsule": b"frankengit/key-salt/capsule/v1",
    "evidence": b"frankengit/key-salt/evidence/v1",
    "package-release": b"frankengit/key-salt/package-release/v1",
    "webhook": b"frankengit/key-salt/webhook/v1",
    "tenant-encryption": b"frankengit/key-salt/tenant-encryption/v1",
    "recovery": b"frankengit/key-salt/recovery/v1",
}
PURPOSE_CODE_POINT = {
    "identity": 1,
    "authority-admin": 2,
    "capsule": 3,
    "evidence": 4,
    "package-release": 5,
    "webhook": 6,
    "tenant-encryption": 7,
    "recovery": 8,
}
COMMITMENT_LABEL = b"frankengit/key-commitment/v1"
SEALING_KEY_SALT = b"frankengit/sealing-key/xchacha20-poly1305/v1"
SEALING_KEY_INFO = b"xchacha20-poly1305 sealing key"
XCHACHA_CODE_POINT = 1


PURPOSE_TAG = {name: f"frankengit/key/{name}/v1" for name in PURPOSE_CODE_POINT}


def derivation_info(purpose: str, epoch: int, tenant: bytes, repository: bytes) -> bytes:
    # The framed field is the full purpose TAG, not the bare purpose name.
    # Getting this wrong is what the first run of this oracle did, and the
    # disagreement is what caught it -- read from src/keys.rs::tag.
    tag = PURPOSE_TAG[purpose].encode("ascii")
    out = bytes([len(tag)]) + tag
    out += struct.pack(">H", PURPOSE_CODE_POINT[purpose])
    out += struct.pack(">I", epoch)
    out += struct.pack(">Q", len(tenant)) + tenant
    out += struct.pack(">Q", len(repository)) + repository
    return out


def key_material(root: bytes, purpose: str, epoch: int, tenant: bytes, repository: bytes) -> bytes:
    info = derivation_info(purpose, epoch, tenant, repository)
    return hkdf_sha256(PURPOSE_SALT[purpose], root, info, 32)


def domain_associated_data(
    purpose: str, epoch: int, commitment: bytes, caller: bytes
) -> bytes:
    out = struct.pack(">H", XCHACHA_CODE_POINT)
    out += struct.pack(">H", PURPOSE_CODE_POINT[purpose])
    out += struct.pack(">I", epoch)
    out += commitment
    out += struct.pack(">Q", len(caller)) + caller
    return out


# --- Vector grid ------------------------------------------------------------
# One purpose only: tenant-encryption is the sole EncryptionCapable purpose,
# so any other row would describe a program that does not compile.

CASES = [
    # label, root byte, epoch, tenant, repository, nonce byte, aad, plaintext
    ("empty-plaintext", 0x5A, 1, b"", b"", 0x00, b"", b""),
    ("operator-scope", 0x5A, 1, b"", b"", 0x11, b"", b"one canonical tenant body"),
    ("tenant-scope", 0x5A, 1, b"tenant-a", b"", 0x22, b"", b"one canonical tenant body"),
    ("other-tenant", 0x5A, 1, b"tenant-b", b"", 0x22, b"", b"one canonical tenant body"),
    ("repository-scope", 0x5A, 1, b"tenant-a", b"repo-1", 0x33, b"", b"one canonical tenant body"),
    ("second-epoch", 0x5A, 2, b"tenant-a", b"", 0x44, b"", b"one canonical tenant body"),
    ("with-associated-data", 0x5A, 1, b"tenant-a", b"", 0x55, b"segment-7", b"one canonical tenant body"),
    ("block-boundary-64", 0x5A, 1, b"", b"", 0x66, b"", bytes(range(64))),
    ("block-boundary-65", 0x5A, 1, b"", b"", 0x77, b"", bytes(range(65))),
    ("other-root", 0xA5, 1, b"", b"", 0x88, b"", b"one canonical tenant body"),
]


def main() -> None:
    _self_check_hchacha20()
    rows = []
    for label, root_byte, epoch, tenant, repository, nonce_byte, aad, plaintext in CASES:
        root = bytes([root_byte]) * 32
        material = key_material(root, "tenant-encryption", epoch, tenant, repository)
        commitment = hmac.new(material, COMMITMENT_LABEL, hashlib.sha256).digest()
        sealing_key = hkdf_sha256(SEALING_KEY_SALT, material, SEALING_KEY_INFO, 32)
        nonce = bytes([nonce_byte]) * 24
        full_aad = domain_associated_data("tenant-encryption", epoch, commitment, aad)
        ciphertext, tag = xchacha20poly1305_seal(sealing_key, nonce, full_aad, plaintext)
        rows.append(
            "\t".join(
                [
                    label,
                    f"{root_byte:02x}",
                    str(epoch),
                    tenant.hex(),
                    repository.hex(),
                    f"{nonce_byte:02x}",
                    aad.hex(),
                    plaintext.hex(),
                    commitment.hex(),
                    ciphertext.hex(),
                    tag.hex(),
                ]
            )
        )
    header = (
        "label\troot_byte\tepoch\ttenant_hex\trepository_hex\tnonce_byte\t"
        "aad_hex\tplaintext_hex\tkey_commitment_hex\tciphertext_hex\ttag_hex"
    )
    text = MARKER + "\n" + header + "\n" + "".join(row + "\n" for row in rows)
    (HERE / "seal_vectors.tsv").write_text(text, encoding="ascii")
    print(f"wrote seal_vectors.tsv with {len(rows)} rows")


if __name__ == "__main__":
    main()
