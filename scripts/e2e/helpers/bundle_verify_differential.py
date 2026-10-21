#!/usr/bin/env python3
"""Differential corpus: the JavaScript bundle verifier against `fg bundle verify`.

frankengit-root-doctrine-x2mv.4.44. FrankenGit owns pack, delta and DEFLATE
semantics in Rust (AGENTS.md 3.1, 6), yet scripts/verify_git_bundle.mjs (and
the served transfers-protocol.mjs it shares) still decodes bundles in
JavaScript by default. While both exist, they must agree. Every bundle here is
run through:

- the JavaScript verifier (node scripts/verify_git_bundle.mjs PATH);
- the Rust verifier (fg bundle verify PATH);
- upstream Git as the validity oracle (`git clone --mirror` of the bundle with
  transfer.fsckObjects), for the format the case uses.

Valid bundles come from stock Git (v2 and v3, SHA-1 and SHA-256, deltas, tags,
several refs). Invalid ones are derived from them or assembled byte by byte
(truncations, corrupted DEFLATE, a wrong pack trailer, a missing ref target, a
wrong object-format capability, an object-count overrun, a REF_DELTA cycle, an
OFS_DELTA before the pack, a delta whose result size lies). Each case records
the three verdicts and, for accepted bundles, the references and object count
both verifiers report. Assembled packs carry a correct trailer, so each defect
is the only one.

Every check lands in one JSON summary as {"checks": {id: {"ok", "detail"}}};
scripts/e2e/suites/recovery/bundle_verify_differential.sh asserts each id.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import zlib
from pathlib import Path

TIMEOUT = 300
HASHES = {"sha1": hashlib.sha1, "sha256": hashlib.sha256}
# Known divergences between the two verifiers, pending the owner's ruling on the JavaScript engine
# (x2mv.4.14 D2/D10). A listed check that fails is reported as unsupported, never as a pass; a listed
# check that starts passing fails the suite so the entry is removed.
UNSORTED = ("Rust parses trees with GitCompatibleImport, which tolerates historically unsorted entries; "
            "the JavaScript verifier and upstream fsck (treeNotSorted) refuse")
BAD_MODE = ("the JavaScript verifier refuses tree mode 100645; Rust (GitCompatibleImport) and upstream "
            "(badFilemode is a warning) accept")


class Git:
    def __init__(self, home: Path, git_bin: str | None, exec_path: str | None) -> None:
        home.mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
                   GIT_AUTHOR_NAME="Bundle", GIT_AUTHOR_EMAIL="bundle@example.invalid",
                   GIT_COMMITTER_NAME="Bundle", GIT_COMMITTER_EMAIL="bundle@example.invalid",
                   GIT_AUTHOR_DATE="2001-01-01T00:00:00+0000",
                   GIT_COMMITTER_DATE="2001-01-01T00:00:00+0000")
        if git_bin:
            env["PATH"] = f"{git_bin}{os.pathsep}{env.get('PATH', '')}"
        if exec_path:
            env["GIT_EXEC_PATH"] = exec_path
        self.env = env

    def run(self, *args, check: bool = False) -> subprocess.CompletedProcess:
        result = subprocess.run(["git", *map(str, args)], env=self.env, capture_output=True, timeout=TIMEOUT)
        if check and result.returncode != 0:
            raise RuntimeError(f"git {args[:3]} failed: {result.stderr.decode(errors='replace')[-800:]}")
        return result


def source_repository(git: Git, root: Path, fmt: str) -> Path:
    """Thirty revisions of a 24 KiB text file (so packs carry deltas), two branches and two tags."""
    repo = root / f"src-{fmt}"
    git.run("init", "-q", f"--object-format={fmt}", "-b", "main", repo, check=True)
    lines = [f"line {n:05d} " + "x" * 40 + "\n" for n in range(500)]
    for revision in range(30):
        lines[revision * 7 % 500] = f"line changed in revision {revision}\n"
        (repo / "big.txt").write_text("".join(lines))
        (repo / "small.txt").write_text(f"revision {revision}\n")
        git.run("-C", repo, "add", ".", check=True)
        git.run("-C", repo, "commit", "-qm", f"revision {revision}", check=True)
        if revision == 10:
            git.run("-C", repo, "branch", "side", check=True)
    git.run("-C", repo, "tag", "-a", "v1", "-m", "annotated", "main~5", check=True)
    git.run("-C", repo, "tag", "light", "main~2", check=True)
    return repo


def split_bundle(data: bytes) -> tuple[bytes, bytes]:
    index = data.index(b"\n\n")
    return data[: index + 2], data[index + 2:]


def with_trailer(pack_body: bytes, fmt: str) -> bytes:
    return pack_body + HASHES[fmt](pack_body).digest()


def varint_header(kind: int, size: int) -> bytes:
    first = (kind << 4) | (size & 0x0F)
    size >>= 4
    out = bytearray()
    while size:
        out.append(first | 0x80)
        first = size & 0x7F
        size >>= 7
    out.append(first)
    return bytes(out)


def size_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def object_id(fmt: str, kind: str, body: bytes) -> str:
    return HASHES[fmt](f"{kind} {len(body)}\0".encode() + body).hexdigest()


def assembled(fmt: str, refs: list[tuple[str, str]], entries: list[bytes], count: int | None = None) -> bytes:
    # v2 bundles are SHA-1 only; SHA-256 needs the v3 object-format capability.
    header = b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=%s\n" % fmt.encode()
    header += b"".join(f"{oid} {name}\n".encode() for oid, name in refs) + b"\n"
    body = b"PACK" + (2).to_bytes(4, "big") + (count if count is not None else len(entries)).to_bytes(4, "big")
    return header + with_trailer(body + b"".join(entries), fmt)


def blob_entry(body: bytes) -> bytes:
    return varint_header(3, len(body)) + zlib.compress(body)


def ref_delta_entry(fmt: str, base_hex: str, delta: bytes) -> bytes:
    return varint_header(7, len(delta)) + bytes.fromhex(base_hex) + zlib.compress(delta)


def ofs_delta_entry(distance: int, delta: bytes) -> bytes:
    offset = bytearray([distance & 0x7F])
    distance >>= 7
    while distance:
        distance -= 1
        offset.insert(0, 0x80 | (distance & 0x7F))
        distance >>= 7
    return varint_header(6, len(delta)) + bytes(offset) + zlib.compress(delta)


def build_corpus(git: Git, root: Path) -> list[dict]:
    """[{name, fmt, path, expect: accept|refuse, oracle: bool}]"""
    cases: list[dict] = []

    def add(name, fmt, data, expect, oracle=True, known=None):
        path = root / f"{name}.bundle"
        path.write_bytes(data)
        cases.append({"name": name, "fmt": fmt, "path": path, "expect": expect, "oracle": oracle,
                      "known": known or {}})

    for fmt in ("sha1", "sha256"):
        repo = source_repository(git, root, fmt)
        full = root / f"full-{fmt}.bundle"
        git.run("-C", repo, "bundle", "create", "-q", full, "--all", check=True)
        data = full.read_bytes()
        add(f"{fmt}-all-refs", fmt, data, "accept")
        single = root / f"single-{fmt}.bundle"
        git.run("-C", repo, "bundle", "create", "-q", single, "main", check=True)
        add(f"{fmt}-single-ref", fmt, single.read_bytes(), "accept")
        if fmt == "sha1":
            v3 = root / "v3-sha1.bundle"
            git.run("-C", repo, "bundle", "create", "-q", "--version=3", v3, "--all", check=True)
            add("sha1-v3-header", fmt, v3.read_bytes(), "accept")
        header, pack = split_bundle(data)
        # Truncations: header only, inside the first object, mid-pack, and without the trailer.
        add(f"{fmt}-truncated-header-only", fmt, header, "refuse")
        add(f"{fmt}-truncated-first-object", fmt, header + pack[:20], "refuse")
        add(f"{fmt}-truncated-mid-pack", fmt, header + pack[: len(pack) // 2], "refuse")
        digest = len(HASHES[fmt]().digest())
        add(f"{fmt}-missing-trailer", fmt, header + pack[:-digest], "refuse")
        # One flipped bit in the pack trailer, and one inside a DEFLATE stream with the trailer recomputed.
        flipped = bytearray(pack)
        flipped[-1] ^= 0x01
        add(f"{fmt}-wrong-trailer", fmt, header + bytes(flipped), "refuse")
        corrupt = bytearray(pack[:-digest])
        corrupt[len(corrupt) // 3] ^= 0x40
        add(f"{fmt}-corrupt-deflate", fmt, header + with_trailer(bytes(corrupt), fmt), "refuse")
        # A header ref whose object is not in the pack.
        lines = header.split(b"\n")
        for position, line in enumerate(lines):
            if line and not line.startswith(b"#") and not line.startswith(b"@") and b" " in line:
                oid, name = line.split(b" ", 1)
                replacement = (b"0" if oid[:1] != b"0" else b"1") + oid[1:]
                lines[position] = replacement + b" " + name
                break
        add(f"{fmt}-ref-target-missing", fmt, b"\n".join(lines) + pack, "refuse")
        # The pack header promises one more object than it carries (trailer recomputed).
        body = bytearray(pack[:-digest])
        body[8:12] = (int.from_bytes(body[8:12], "big") + 1).to_bytes(4, "big")
        add(f"{fmt}-object-count-overrun", fmt, header + with_trailer(bytes(body), fmt), "refuse")
        # Hand-assembled packs, each with exactly one defect.
        base = b"delta base content\n" * 8
        base_id = object_id(fmt, "blob", base)
        # Copy opcode 0x90 (offset 0, one size byte) then insert two literal bytes, so the result is a
        # distinct object; copying the whole base alone would rebuild a duplicate, which both refuse.
        extra = b"!\n"
        result_id = object_id(fmt, "blob", base + extra)
        instructions = bytes([0x90, len(base), len(extra)]) + extra
        good_delta = size_varint(len(base)) + size_varint(len(base) + len(extra)) + instructions
        # A complete commit whose tree holds the base blob and the delta-built result blob.
        tree_body = (b"100644 base.txt\0" + bytes.fromhex(base_id)
                     + b"100644 result.txt\0" + bytes.fromhex(result_id))
        tree_id = object_id(fmt, "tree", tree_body)
        commit_body = (f"tree {tree_id}\nauthor A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000\n\nassembled\n").encode()
        commit_id = object_id(fmt, "commit", commit_body)
        add(f"{fmt}-assembled-ref-delta-ok", fmt,
            assembled(fmt, [(commit_id, "refs/heads/main")],
                      [varint_header(1, len(commit_body)) + zlib.compress(commit_body),
                       varint_header(2, len(tree_body)) + zlib.compress(tree_body),
                       blob_entry(base), ref_delta_entry(fmt, base_id, good_delta)]),
            "accept")
        lying = size_varint(len(base)) + size_varint(len(base) + len(extra) + 7) + instructions
        add(f"{fmt}-delta-result-size-lies", fmt,
            assembled(fmt, [(base_id, "refs/heads/main")], [blob_entry(base), ref_delta_entry(fmt, base_id, lying)]),
            "refuse")
        x, y = "a" * (digest * 2), "b" * (digest * 2)
        cycle = size_varint(4) + size_varint(4) + bytes([0x90, 4])
        add(f"{fmt}-ref-delta-cycle", fmt,
            assembled(fmt, [(x, "refs/heads/main")], [ref_delta_entry(fmt, y, cycle), ref_delta_entry(fmt, x, cycle)]),
            "refuse")
        add(f"{fmt}-ofs-delta-before-pack", fmt,
            assembled(fmt, [(base_id, "refs/heads/main")], [blob_entry(base), ofs_delta_entry(4096, good_delta)]),
            "refuse")
        # Where independent decoders tend to diverge. Each case is one commit over one tree, so only the
        # named defect differs from the accepted twin above.
        def single_commit(entries_tree: bytes, extra_entries: list[bytes], commit_text: str | None = None,
                          tree_text_override: bytes | None = None, ref: str = "refs/heads/main",
                          pack_version: int = 2) -> bytes:
            tree = tree_text_override if tree_text_override is not None else entries_tree
            tid = object_id(fmt, "tree", tree)
            body = (commit_text or f"tree {tid}\nauthor A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000\n\nedge\n").encode()
            cid = object_id(fmt, "commit", body)
            entries = [varint_header(1, len(body)) + zlib.compress(body),
                       varint_header(2, len(tree)) + zlib.compress(tree)] + extra_entries
            data = assembled(fmt, [(cid, ref)], entries)
            if pack_version != 2:
                head, pack_bytes = split_bundle(data)
                body_bytes = bytearray(pack_bytes[:-digest])
                body_bytes[4:8] = pack_version.to_bytes(4, "big")
                data = head + with_trailer(bytes(body_bytes), fmt)
            return data

        one_blob_tree = b"100644 base.txt\0" + bytes.fromhex(base_id)
        # Git also reads pack version 3; FrankenGit declares pack v2 only (GIT_COMPATIBILITY_MATRIX), so both
        # verifiers refusing it is the declared profile and upstream is not consulted.
        add(f"{fmt}-pack-version-3", fmt, single_commit(one_blob_tree, [blob_entry(base)], pack_version=3), "refuse",
            oracle=False)
        add(f"{fmt}-pack-version-4", fmt, single_commit(one_blob_tree, [blob_entry(base)], pack_version=4), "refuse")
        two_tree = b"100644 base.txt\0" + bytes.fromhex(base_id) + b"100644 result.txt\0" + bytes.fromhex(result_id)
        # Copy opcode 0x91 (one offset byte, one size byte): offset 8 for len(base) bytes overruns the base.
        past_base = size_varint(len(base)) + size_varint(len(base) + 2) + bytes([0x91, 8, len(base)]) + bytes([2]) + extra
        add(f"{fmt}-delta-copy-past-base", fmt,
            single_commit(two_tree, [blob_entry(base), ref_delta_entry(fmt, base_id, past_base)]), "refuse")
        # Copy opcode with no size bytes means 0x10000 bytes, far past this base.
        size_zero = size_varint(len(base)) + size_varint(0x10000) + bytes([0x80])
        add(f"{fmt}-delta-copy-size-zero-means-64k", fmt,
            single_commit(two_tree, [blob_entry(base), ref_delta_entry(fmt, base_id, size_zero)]), "refuse")
        reserved = size_varint(len(base)) + size_varint(len(base) + 2) + bytes([0x90, len(base), 0x00]) + extra
        add(f"{fmt}-delta-reserved-opcode-zero", fmt,
            single_commit(two_tree, [blob_entry(base), ref_delta_entry(fmt, base_id, reserved)]), "refuse")
        short_header = varint_header(3, len(base) - 1) + zlib.compress(base)
        add(f"{fmt}-object-size-understated", fmt, single_commit(one_blob_tree, [short_header]), "refuse")
        unsorted = b"100644 z.txt\0" + bytes.fromhex(base_id) + b"100644 a.txt\0" + bytes.fromhex(base_id)
        add(f"{fmt}-tree-unsorted", fmt, single_commit(unsorted, [blob_entry(base)]), "refuse",
            known={"agree": UNSORTED, "rust-verdict": UNSORTED})
        bad_mode = b"100645 base.txt\0" + bytes.fromhex(base_id)
        add(f"{fmt}-tree-bad-mode", fmt, single_commit(bad_mode, [blob_entry(base)]), "accept",
            known={"agree": BAD_MODE, "js-verdict": BAD_MODE})
        no_tree = "author A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000\n\nno tree\n"
        add(f"{fmt}-commit-without-tree", fmt, single_commit(one_blob_tree, [blob_entry(base)], commit_text=no_tree), "refuse")
        # Deep but valid delta chain: each link appends one line to the previous result.
        chain_entries, chain_tree, previous, previous_id = [blob_entry(base)], [], base, base_id
        for depth in range(60):
            line = f"chain {depth}\n".encode()
            delta = size_varint(len(previous)) + size_varint(len(previous) + len(line))
            delta += (bytes([0x90, len(previous)]) if len(previous) < 256 else bytes([0xb0, len(previous) & 0xFF, len(previous) >> 8]))
            delta += bytes([len(line)]) + line
            chain_entries.append(ref_delta_entry(fmt, previous_id, delta))
            previous = previous + line
            previous_id = object_id(fmt, "blob", previous)
        deep_tree = b"100644 base.txt\0" + bytes.fromhex(base_id) + b"100644 deep.txt\0" + bytes.fromhex(previous_id)
        add(f"{fmt}-delta-chain-depth-60", fmt, single_commit(deep_tree, chain_entries), "accept")
        # Header-only defects on the stock bundle.
        header_lines = header.split(b"\n")
        first_ref = next(line for line in header_lines if line and line[:1] not in (b"#", b"@"))
        add(f"{fmt}-duplicate-ref-line", fmt,
            header.replace(first_ref + b"\n", first_ref + b"\n" + first_ref + b"\n", 1) + pack, "refuse")
        oid_text = first_ref.split(b" ", 1)[0]
        # Upstream's mirror clone tolerates this ref name; FrankenGit refuses invalid ref names by policy.
        add(f"{fmt}-invalid-ref-name", fmt,
            header.replace(first_ref + b"\n", first_ref + b"\n" + oid_text + b" refs/heads/a..b\n", 1) + pack, "refuse",
            oracle=False)
        incremental = root / f"incremental-{fmt}.bundle"
        git.run("-C", repo, "bundle", "create", "-q", incremental, "main~3..main", check=True)
        add(f"{fmt}-incremental-with-prerequisites", fmt, incremental.read_bytes(), "refuse")
    # A SHA-1 pack under a v3 header that claims SHA-256.
    sha1_full = (root / "full-sha1.bundle").read_bytes()
    header, pack = split_bundle(sha1_full)
    claimed = b"# v3 git bundle\n@object-format=sha256\n" + header.split(b"\n", 1)[1]
    add("sha1-pack-under-sha256-header", "sha256", claimed + pack, "refuse")
    add("garbage-signature", "sha1", b"# v9 git bundle\n" + header.split(b"\n", 1)[1] + pack, "refuse")
    return cases


def js_verify(node: str, script: Path, bundle: Path) -> dict:
    result = subprocess.run([node, str(script), str(bundle)], capture_output=True, text=True, timeout=TIMEOUT)
    report = {}
    if result.returncode == 0:
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {"accepted": result.returncode == 0, "rc": result.returncode,
            "objects": report.get("pack_objects"), "refs": report.get("refs"), "head": report.get("advertised_head"),
            "said": (result.stderr or result.stdout).strip()[-300:]}


def rust_verify(fg: str, bundle: Path, extra: tuple[str, ...] = ()) -> dict:
    result = subprocess.run([fg, "bundle", "verify", str(bundle), *extra], capture_output=True, text=True,
                            timeout=TIMEOUT)
    report = {}
    if result.returncode == 0:
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {"accepted": result.returncode == 0, "rc": result.returncode,
            "objects": report.get("object_count"), "refs": report.get("references"), "head": report.get("advertised_head"),
            "said": (result.stderr or result.stdout).strip()[-300:]}


def oracle_verify(git: Git, root: Path, case: dict) -> bool:
    target = root / f"oracle-{case['name']}"
    result = git.run("-c", "transfer.fsckObjects=true", "clone", "-q", "--mirror", case["path"], target)
    return result.returncode == 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--js-verifier", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--git-bin")
    parser.add_argument("--git-exec-path")
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-bundle-differential-"))
    checks: dict[str, dict] = {}
    summary: dict = {"type": "bundle_verify_differential_summary", "artifacts": str(root)}
    try:
        git = Git(root / "home", options.git_bin, options.git_exec_path)
        summary["git"] = git.run("--version", check=True).stdout.decode().strip()
        summary["node"] = subprocess.run([options.node, "--version"], capture_output=True, text=True).stdout.strip()
        cases = build_corpus(git, root)
        summary["cases"] = []
        for case in cases:
            js = js_verify(options.node, options.js_verifier, case["path"])
            rs = rust_verify(options.fg, case["path"])
            upstream = oracle_verify(git, root, case) if case["oracle"] else None
            expect_accept = case["expect"] == "accept"
            name = case["name"]
            checks[f"{name}-agree"] = {"ok": js["accepted"] == rs["accepted"],
                                       "detail": f"js={js['accepted']} ({js['said'][-160:]}) rust={rs['accepted']} ({rs['said'][-160:]})"}
            checks[f"{name}-rust-verdict"] = {"ok": rs["accepted"] == expect_accept,
                                              "detail": f"expected {case['expect']}; rust rc={rs['rc']} {rs['said'][-200:]}"}
            checks[f"{name}-js-verdict"] = {"ok": js["accepted"] == expect_accept,
                                            "detail": f"expected {case['expect']}; js rc={js['rc']} {js['said'][-200:]}"}
            if upstream is not None:
                checks[f"{name}-upstream-verdict"] = {"ok": upstream == expect_accept,
                                                      "detail": f"expected {case['expect']}; git clone --mirror accepted={upstream}"}
            if expect_accept and js["accepted"] and rs["accepted"]:
                checks[f"{name}-facts"] = {"ok": js["objects"] == rs["objects"] and js["refs"] == rs["refs"]
                                           and js["head"] == rs["head"],
                                           "detail": f"objects js={js['objects']} rust={rs['objects']}; refs equal={js['refs'] == rs['refs']}; head js={js['head']} rust={rs['head']}"}
            for suffix, reason in case["known"].items():
                checks[f"{name}-{suffix}"]["known"] = reason
            if name.endswith("-all-refs"):
                # Over budget: the same valid bundle under a two-object ceiling is a typed refusal; the
                # default-limits verdict above is its accepted twin.
                capped = rust_verify(options.fg, case["path"], ("--max-objects", "2"))
                checks[f"{name}-rust-over-budget-refused"] = {
                    "ok": not capped["accepted"] and rs["accepted"] and "limit" in capped["said"].lower(),
                    "detail": f"--max-objects 2: rc={capped['rc']} {capped['said'][-200:]}; default accepted={rs['accepted']}"}
            summary["cases"].append({"name": name, "format": case["fmt"], "expect": case["expect"],
                                     "js": js["accepted"], "rust": rs["accepted"], "upstream": upstream})
    except Exception as error:  # recorded, never swallowed: the id fails the suite
        checks["campaign"] = {"ok": False, "detail": f"{type(error).__name__}: {error}"}
    else:
        checks["campaign"] = {"ok": True, "detail": f"{len(summary.get('cases', []))} cases"}
    finally:
        summary["checks"] = checks
        options.summary.write_text(json.dumps(summary, sort_keys=True) + "\n")
        print(json.dumps({"type": summary["type"], "artifacts": str(root),
                          "failed": sorted(k for k, v in checks.items() if not v["ok"])}), flush=True)


if __name__ == "__main__":
    main()
