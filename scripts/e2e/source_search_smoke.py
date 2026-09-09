#!/usr/bin/env python3
"""Real fg search campaign; --self-test checks only fixtures and the checker."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = "c1" * 16, "c2" * 16, "c3" * 16
REF = "refs/heads/main"
FILES = {b"binary": b"\0needle\xff", b"empty": b"", b"escape": b"needle\x1b[2Jcontrol\rline\n",
         b"overlap": b"aaaa\n", b"src/file.rs": "éneedle\r\nNEEDLE needle\n".encode(),
         b"src2/secret.rs": b"private needle\n", b"utf8/\xff.rs": b"needle without newline"}


def require(test, message):
    if not test:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def fixture(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {REF}\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
                                ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"))
    def store(kind, body):
        oid = identity(algorithm, kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid
    hierarchy = {}
    for name, body in FILES.items():
        parent = hierarchy
        parts = name.split(b"/")
        for component in parts[:-1]:
            parent = parent.setdefault(component, {})
        parent[parts[-1]] = (b"100644", store("blob", body))
    hierarchy[b"link"] = (b"120000", store("blob", b"src/file.rs"))
    def directory(entries):
        objects = []
        for name, entry in entries.items():
            mode, oid = (b"40000", directory(entry)) if isinstance(entry, dict) else entry
            objects.append((name, mode, oid))
        objects.sort(key=lambda x: x[0] + (b"/" if x[1] == b"40000" else b"\0"))
        return store("tree", b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                                     for name, mode, oid in objects))
    tree = directory(hierarchy)
    commit = store("commit", (f"tree {tree}\nauthor Test <test@example.invalid> 1 +0000\n"
                              "committer Test <test@example.invalid> 1 +0000\n\nsearch fixture\n").encode())
    (root / REF).write_text(commit + "\n")
    return commit, tree


def selected(prefixes):
    return {path: body for path, body in FILES.items()
            if not prefixes or any(path == p or path.startswith(p + b"/") for p in prefixes)}


def expected_hits(algorithm, needle, insensitive=False, prefixes=()):
    expected = []
    for path, body in sorted(selected(prefixes).items()):
        haystack, target = (body.lower(), needle.lower()) if insensitive else (body, needle)
        start = 0
        while True:
            at = haystack.find(target, start)
            if at < 0:
                break
            expected.append({"path_hex": path.hex(), "blob": identity(algorithm, "blob", body),
                             "byte_offset": at, "line": body.count(b"\n", 0, at) + 1,
                             "byte_column": at - body.rfind(b"\n", 0, at), "match_length": len(needle)})
            start = at + 1
    return expected


def validate(report, algorithm, commit, tree, needle, insensitive=False, prefixes=(), limit=200):
    expected = expected_hits(algorithm, needle, insensitive, prefixes)
    complete = len(expected) <= limit
    require(report["type"] == "source_search" and report["profile"] == "literal-bytes-v1", "search profile")
    require(report["scope"] == "selected_regular_files", "search scope")
    require(report["repository_id"] == REPOSITORY, "repository binding")
    require(report["source_commit"] == commit and report["source_tree"] == tree, "native source binding")
    require(isinstance(report["source_rcr"], str) and report["source_rcr"], "RCR binding")
    require(report["reference_hex"] == REF.encode().hex(), "reference binding")
    require(report["query_hex"] == needle.hex(), "query binding")
    require(report["case"] == ("ascii_insensitive" if insensitive else "exact"), "case profile")
    require(report["path_prefixes_hex"] == [p.hex() for p in sorted(set(prefixes))], "prefix binding")
    require(report["complete"] is complete, "false completeness")
    require(report["truncated_reason"] == (None if complete else "match_limit"), "truncation reason")
    require(report["node_closed"] is True, "node close")
    require(report["match_count"] == len(expected[:limit]) and report["max_matches"] == limit, "match count")
    require(len(report["matches"]) == len(expected[:limit]), "match list count")
    for actual, wanted in zip(report["matches"], expected[:limit]):
        for key, value in wanted.items():
            require(actual[key] == value and type(actual[key]) is type(value), f"match {key}")
        data = FILES[bytes.fromhex(actual["path_hex"])]
        snippet = bytes.fromhex(actual["excerpt_hex"])
        begin = actual["excerpt_offset"]
        require(type(begin) is int and 0 <= begin <= actual["byte_offset"], "excerpt offset")
        require(len(snippet) <= 416 and data[begin:begin + len(snippet)] == snippet, "original excerpt bytes")
        require(begin + len(snippet) >= actual["byte_offset"] + len(needle), "excerpt covers match")
    subset = selected(prefixes)
    require(report["files_selected"] == len(subset), "file selection")
    require(0 <= report["files_read"] <= len(subset), "file reads")
    require(0 <= report["bytes_searched"] <= report["bytes_read"] <= sum(map(len, subset.values())), "byte accounting")
    if complete:
        require(report["files_read"] == len(subset), "complete scan file count")
        require(report["bytes_searched"] == report["bytes_read"] == sum(map(len, subset.values())), "complete scan byte count")
    excluded = int(not prefixes or any(b"link" == p or b"link".startswith(p + b"/") for p in prefixes))
    require(report["non_regular_entries"] == excluded, "symlink exclusion")


def invoke(binary, arguments, code=0):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, timeout=120)
    require(result.returncode == code, f"fg exit {result.returncode}, wanted {code}: {result.stderr!r}; {result.stdout!r}")
    return result


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-source-search-") as temporary:
        root = Path(temporary)
        node, source = root / "node", root / "source"
        commit, tree = fixture(source, algorithm)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "search-source", source])
        state_args = ["at", node, TENANT, REPOSITORY, "latest"]
        before = invoke(binary, state_args).stdout
        cases = [(b"needle", False, (), 200), (b"needle", True, (), 200),
                 (b"needle", True, (b"src",), 2), (b"needle", True, (b"src",), 3),
                 (b"aa", False, (b"overlap",), 200), (b"\0", False, (), 200),
                 (b"absent", False, (), 200), (b"needle", False, (b"missing",), 200),
                 (b"needle", False, (b"utf8/\xff.rs",), 200)]
        rcr = None
        for needle, insensitive, prefixes, limit in cases:
            args = ["search", node, TENANT, REPOSITORY, REF, "--trusted-local", "--object-format", algorithm,
                    "--literal-hex", needle.hex(), "--max-matches", str(limit)]
            if insensitive:
                args.append("--ignore-ascii-case")
            for prefix in prefixes:
                args += ["--path-hex", prefix.hex()]
            count = len(expected_hits(algorithm, needle, insensitive, prefixes))
            response = invoke(binary, args, 0 if count <= limit else 3)
            require(b"\x1b" not in response.stdout and b"\xff" not in response.stdout, "raw terminal/invalid bytes leaked")
            report = json.loads(response.stdout)
            validate(report, algorithm, commit, tree, needle, insensitive, prefixes, limit)
            require(rcr is None or report["source_rcr"] == rcr, "source selection changed during read-only queries")
            rcr = report["source_rcr"]
            require(invoke(binary, args, 0 if count <= limit else 3).stdout == response.stdout, "nondeterministic search output")
        base = ["search", node, TENANT, REPOSITORY, REF, "--trusted-local", "--object-format", algorithm,
                "--literal", "needle"]
        no_trust = base.copy()
        no_trust.remove("--trusted-local")
        for args in [no_trust, base + ["--max-bytes", "1"], base + ["--max-files", "1"],
                     base + ["--regex", ".*"], base + ["--max-matches", "0"],
                     base + ["--path", "../secret"], base + ["--literal-hex", "ff"]]:
            require(not invoke(binary, args, 2).stdout, "error masquerades as a successful search result")
        require(invoke(binary, state_args).stdout == before, "source search changed canonical repository state")
        print(json.dumps({"type": "source_search_smoke", "format": algorithm, "queries": len(cases),
                          "negative_queries": 7, "passed": True, "rust_executed": True}))


def self_test():
    negatives = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as temporary:
            commit, tree = fixture(Path(temporary), algorithm)
            for path in Path(temporary).glob("objects/*/*"):
                raw = zlib.decompress(path.read_bytes())
                header, body = raw.split(b"\0", 1)
                kind, size = header.split(b" ", 1)
                require(int(size) == len(body), "fixture object framing")
                require(identity(algorithm, kind.decode(), body) == path.parent.name + path.name, "fixture identity")
            needle = b"needle"
            hits = expected_hits(algorithm, needle, True)
            for hit in hits:
                hit["excerpt_offset"] = hit["byte_offset"]
                body = FILES[bytes.fromhex(hit["path_hex"])]
                hit["excerpt_hex"] = body[hit["byte_offset"]:hit["byte_offset"] + len(needle)].hex()
            report = dict(type="source_search", profile="literal-bytes-v1", scope="selected_regular_files",
                          repository_id=REPOSITORY, source_rcr="synthetic-checker-input", source_commit=commit,
                          source_tree=tree, reference_hex=REF.encode().hex(), query_hex=needle.hex(),
                          case="ascii_insensitive", path_prefixes_hex=[], complete=True, truncated_reason=None,
                          node_closed=True, match_count=len(hits), max_matches=200, matches=hits,
                          files_selected=len(FILES), files_read=len(FILES), bytes_read=sum(map(len, FILES.values())),
                          bytes_searched=sum(map(len, FILES.values())), non_regular_entries=1)
            validate(report, algorithm, commit, tree, needle, True)
            for field, value in [("complete", False), ("repository_id", "wrong"), ("source_commit", tree),
                                 ("match_count", 0), ("query_hex", "00"), ("non_regular_entries", 0)]:
                bad = copy.deepcopy(report)
                bad[field] = value
                try:
                    validate(bad, algorithm, commit, tree, needle, True)
                except AssertionError:
                    negatives += 1
                else:
                    raise AssertionError(f"checker accepted damaged {field}")
            for field, value in [("byte_offset", 999), ("blob", commit), ("path_hex", b"unknown".hex()),
                                 ("excerpt_hex", "00"), ("line", 0), ("byte_column", 0)]:
                bad = copy.deepcopy(report)
                bad["matches"][0][field] = value
                try:
                    validate(bad, algorithm, commit, tree, needle, True)
                except AssertionError:
                    negatives += 1
                else:
                    raise AssertionError(f"checker accepted damaged match {field}")
    print(json.dumps({"type": "source_search_checker_self_test", "negative_cases": negatives,
                      "passed": True, "rust_executed": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path)
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    binary = args.fg.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK), "an executable built fg is required")
    print(json.dumps({"type": "binary_identity", "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
    for algorithm in ["sha1", "sha256"]:
        run_format(binary, algorithm)


if __name__ == "__main__":
    main()
