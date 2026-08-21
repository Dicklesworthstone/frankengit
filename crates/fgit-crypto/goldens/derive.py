#!/usr/bin/env python3
"""Derive the fgit-crypto golden corpus from an implementation outside this crate.

This script is the independent oracle behind every expected digest checked in
next to it. It uses Python's `hashlib` (an OpenSSL-backed SHA-1/SHA-256
implementation with no relationship to the Rust in `src/`) and re-derives the
internal-identity preimage framing directly from the documented layout in
`src/body_identity.rs`, rather than calling into the crate.

It is never invoked by the Rust tests. The tests read the checked-in .tsv files
and assert that fgit-crypto reproduces them; regenerating a vector file from
fgit-crypto's own output would make those tests tautological, so this script is
the only thing permitted to write them.

Usage:  python3 derive.py            # rewrite the vector .tsv files in place
Verify: sha1sum / sha256sum agree with hashlib on every message spec below.
"""

import hashlib
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
MARKER = "# franken-registry-v1"


def spec_bytes(spec: str) -> bytes:
    kind, _, rest = spec.partition(":")
    if kind == "hex":
        return bytes.fromhex(rest)
    if kind == "repeat":
        byte_hex, _, count = rest.partition(":")
        return bytes.fromhex(byte_hex) * int(count)
    raise ValueError(f"unknown message spec: {spec}")


def write(name: str, header: str, rows: list[str]) -> None:
    text = MARKER + "\n" + header + "\n" + "".join(row + "\n" for row in rows)
    (HERE / name).write_text(text, encoding="ascii")


# --- FIPS 180-4 known-answer and block-boundary vectors ---------------------
# The first five are the published FIPS 180-4 / NIST CAVP examples. The rest
# walk the padding transitions: 55 bytes is the last single-block message, 56
# forces a second block, 63/64/65 straddle the block width, and 119/120 do the
# same one block later.
DIGEST_SPECS = [
    ("DV-001", "hex:", "empty message"),
    ("DV-002", "hex:616263", "abc"),
    ("DV-003", "hex:" + b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".hex(), "FIPS 56-byte"),
    (
        "DV-004",
        "hex:"
        + b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".hex(),
        "FIPS 112-byte",
    ),
    ("DV-005", "repeat:61:1000000", "one million a"),
    ("DV-006", "repeat:61:55", "last single-block length"),
    ("DV-007", "repeat:61:56", "first two-block length"),
    ("DV-008", "repeat:61:63", "one below the block width"),
    ("DV-009", "repeat:61:64", "exactly the block width"),
    ("DV-010", "repeat:61:65", "one above the block width"),
    ("DV-011", "repeat:61:119", "one below two blocks plus length"),
    ("DV-012", "repeat:61:120", "two blocks plus length"),
    ("DV-013", "hex:00", "a single zero byte"),
    ("DV-014", "hex:" + bytes(range(256)).hex(), "every byte value"),
]


def derive_digest_vectors() -> None:
    rows = []
    for row_id, spec, note in DIGEST_SPECS:
        message = spec_bytes(spec)
        rows.append(
            "\t".join(
                [
                    row_id,
                    spec,
                    hashlib.sha1(message).hexdigest(),
                    hashlib.sha256(message).hexdigest(),
                    note,
                ]
            )
        )
    write("digest_vectors.tsv", "id\tmessage\tsha1\tsha256\tnote", rows)


# --- Native Git object identities -------------------------------------------
# The Git preimage is `<type> <decimal length>\0<content>`. DV/GV-001 and
# GV-002 are the empty blob and empty tree, whose SHA-1 identities are the
# most widely published constants in Git.
GIT_SPECS = [
    ("GV-001", "blob", "hex:", "empty blob"),
    ("GV-002", "tree", "hex:", "empty tree"),
    ("GV-003", "blob", "hex:" + b"hello world\n".hex(), "hello world blob"),
    ("GV-004", "blob", "hex:" + b"hello world".hex(), "blob without trailing newline"),
    ("GV-005", "blob", "repeat:61:1000", "a thousand a"),
    ("GV-006", "commit", "hex:" + b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@example.invalid> 0 +0000\ncommitter A <a@example.invalid> 0 +0000\n\nempty tree commit\n".hex(), "commit over the empty tree"),
    ("GV-007", "tag", "hex:" + b"object e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\ntype blob\ntag empty\ntagger A <a@example.invalid> 0 +0000\n\nannotated empty blob\n".hex(), "annotated tag"),
    ("GV-008", "blob", "hex:00010203fffefdfc", "binary blob"),
]


def git_preimage(object_type: str, content: bytes) -> bytes:
    return object_type.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content


def derive_git_oid_vectors() -> None:
    rows = []
    for row_id, object_type, spec, note in GIT_SPECS:
        content = spec_bytes(spec)
        preimage = git_preimage(object_type, content)
        rows.append(
            "\t".join(
                [
                    row_id,
                    object_type,
                    spec,
                    hashlib.sha1(preimage).hexdigest(),
                    hashlib.sha256(preimage).hexdigest(),
                    note,
                ]
            )
        )
    write("git_oid_vectors.tsv", "id\tobject_type\tcontent\tsha1_oid\tsha256_oid\tnote", rows)


# --- Internal domain-separated identities ------------------------------------
# Framing re-derived from the documented layout, not from the Rust:
#   u8 domain length | domain | u8 family length | family
#   | u16be major | u16be minor | u64be body length | body
INTERNAL_SPECS = [
    ("IV-001", "frankengit/ref-txn/v2", "frankengit.canonical-body", 1, 0, "hex:", "empty body"),
    ("IV-002", "frankengit/ref-txn/v2", "frankengit.canonical-body", 1, 0, "hex:" + b"identical body bytes".hex(), "shared body, first domain"),
    ("IV-003", "frankengit/txn-seal/v1", "frankengit.canonical-body", 1, 0, "hex:" + b"identical body bytes".hex(), "shared body, second domain"),
    ("IV-004", "frankengit/rcr/v1", "frankengit.canonical-body", 1, 0, "hex:" + b"identical body bytes".hex(), "shared body, third domain"),
    ("IV-005", "frankengit/git-object-microsegment/v1", "frankengit.microsegment", 1, 0, "hex:" + b"microsegment body".hex(), "microsegment domain"),
    ("IV-006", "frankengit/ref-txn/v2", "frankengit.canonical-body", 2, 0, "hex:" + b"identical body bytes".hex(), "schema major bumped"),
    ("IV-007", "frankengit/ref-txn/v2", "frankengit.canonical-body", 1, 1, "hex:" + b"identical body bytes".hex(), "schema minor bumped"),
    ("IV-008", "frankengit/ref-txn/v2", "frankengit.canonical-bod", 1, 0, "hex:" + b"yidentical body bytes".hex(), "framing shift: one byte moved from family to body"),
    ("IV-009", "frankengit/git-payload-commitment/v1", "frankengit.git-payload-commitment", 1, 0, "hex:" + git_preimage("blob", b"").hex(), "payload commitment over the empty blob"),
    ("IV-010", "frankengit/git-payload-commitment/v1", "frankengit.git-payload-commitment", 1, 0, "hex:" + git_preimage("blob", b"hello world\n").hex(), "payload commitment over a blob"),
    ("IV-011", "frankengit/generation/v1", "frankengit.generation", 3, 7, "repeat:5a:300", "long body, non-trivial versions"),
    ("IV-012", "frankengit/merkle-leaf/v1", "frankengit.microsegment", 1, 0, "hex:" + b"record bytes".hex(), "Merkle leaf"),
    ("IV-013", "frankengit/merkle-node/v1", "frankengit.microsegment", 1, 0, "hex:" + b"record bytes".hex(), "Merkle node over identical bytes: must differ from IV-012"),
    ("IV-014", "frankengit/merkle-node/v1", "frankengit.microsegment", 1, 0, "hex:" + ("11" * 32) + ("22" * 32), "Merkle node over two child digests"),
]


def internal_preimage(domain: str, family: str, major: int, minor: int, body: bytes) -> bytes:
    domain_bytes = domain.encode("ascii")
    family_bytes = family.encode("ascii")
    return (
        len(domain_bytes).to_bytes(1, "big")
        + domain_bytes
        + len(family_bytes).to_bytes(1, "big")
        + family_bytes
        + major.to_bytes(2, "big")
        + minor.to_bytes(2, "big")
        + len(body).to_bytes(8, "big")
        + body
    )


def derive_internal_id_vectors() -> None:
    rows = []
    for row_id, domain, family, major, minor, spec, note in INTERNAL_SPECS:
        body = spec_bytes(spec)
        preimage = internal_preimage(domain, family, major, minor, body)
        rows.append(
            "\t".join(
                [
                    row_id,
                    domain,
                    family,
                    str(major),
                    str(minor),
                    spec,
                    preimage.hex(),
                    hashlib.sha256(preimage).hexdigest(),
                    note,
                ]
            )
        )
    write(
        "internal_id_vectors.tsv",
        "id\tdomain_tag\tschema_family\tschema_major\tschema_minor\tbody\tpreimage\tdigest\tnote",
        rows,
    )


if __name__ == "__main__":
    derive_digest_vectors()
    derive_git_oid_vectors()
    derive_internal_id_vectors()
    print("derived digest_vectors.tsv, git_oid_vectors.tsv, internal_id_vectors.tsv")
