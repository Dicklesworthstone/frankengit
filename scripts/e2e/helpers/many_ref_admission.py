#!/usr/bin/env python3
"""Exercise many-ref import, atomic push and mirror push with stock Git.

The corpus mixes branches, lightweight tags and annotated tags. Every run uses
a fresh node and compares every resulting reference, not only a success code.
Use --counts 64,256,1024,4096 for the command-boundary cost campaign. Timings
are observations of the supplied binary and host, not a release performance
claim. The transport helper owns and drains every server it starts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

from stock_transport_capabilities import (
    Git, PRINCIPAL, REPOSITORY, TENANT, TIMEOUT, ref_map, served, text,
)


def corpus(git: Git, root: Path, fmt: str, count: int) -> tuple[Path, dict[str, str]]:
    source = root / f"source-{fmt}-{count}"
    git.run("init", "-q", f"--object-format={fmt}", "-b", "main", source, check=True)
    (source / "README").write_text("many-ref admission corpus\n")
    git.run("-C", source, "add", "README", check=True)
    git.run("-C", source, "commit", "-qm", "base", check=True)
    tip = git.out("-C", source, "rev-parse", "HEAD")
    tag = git.run(
        "-C", source, "mktag", check=True,
        input_bytes=(f"object {tip}\ntype commit\ntag annotated\n"
                     "tagger Admission <admission@example.invalid> 0 +0000\n\n"
                     "annotated tag body\n").encode(),
    ).stdout.decode().strip()
    refs = {"refs/heads/main": tip}
    for index in range(count - 1):
        kind = index % 3
        prefix = ("refs/heads/branch", "refs/tags/light", "refs/tags/annotated")[kind]
        refs[f"{prefix}-{index:05}"] = tag if kind == 2 else tip
    commands = "".join(f"update {name} {oid}\n" for name, oid in refs.items())
    git.run("-C", source, "update-ref", "--stdin", input_bytes=commands.encode(), check=True)
    actual = git.out("-C", source, "for-each-ref", "--format=%(refname) %(objectname)")
    assert dict(line.split() for line in actual.splitlines()) == refs
    return source, refs


def run_case(fg: str, git: Git, root: Path, fmt: str, count: int,
             operation: str, transport: str, source: Path,
             expected: dict[str, str]) -> dict:
    label = f"{fmt}-{count}-{operation}-{transport}"
    node = root / f"node-{label}"
    subprocess.run([fg, "init", str(node), TENANT, REPOSITORY, fmt],
                   check=True, capture_output=True, timeout=TIMEOUT)
    elapsed = None
    import_retry = None
    if operation == "import":
        start = time.monotonic()
        result = subprocess.run(
            [fg, "import", str(node), TENANT, REPOSITORY, PRINCIPAL,
             f"import-{label}", str(source / ".git")],
            capture_output=True, timeout=TIMEOUT,
        )
        elapsed = time.monotonic() - start
        # Finish the durable retry before opening a server on the same node.
        if result.returncode == 0:
            import_retry = subprocess.run(
                [fg, "import", str(node), TENANT, REPOSITORY, PRINCIPAL,
                 f"import-{label}", str(source / ".git")],
                capture_output=True, timeout=TIMEOUT,
            )
    with served(fg, transport, node, root) as (url, env):
        if operation != "import":
            args = ["-C", source, "push", "--porcelain"]
            if operation == "atomic":
                args.append("--atomic")
            args.extend(["--mirror", url])
            start = time.monotonic()
            result = git.run(*args, env=env)
            elapsed = time.monotonic() - start
        remote = {name: oid for name, oid in ref_map(git, url, env).items()
                  if name != "HEAD" and not name.endswith("^{}")}
        equal = remote == expected
        # A second identical operation must neither reject nor change refs.
        retry_ok = False
        if result.returncode == 0 and equal:
            if operation == "import":
                assert import_retry is not None
                retry = import_retry
            else:
                retry = git.run(*args, env=env)
            again = {name: oid for name, oid in ref_map(git, url, env).items()
                     if name != "HEAD" and not name.endswith("^{}")}
            retry_ok = retry.returncode == 0 and again == expected
        return {
            "id": label, "ok": result.returncode == 0 and equal and retry_ok,
            "format": fmt, "commands": count, "operation": operation,
            "transport": transport, "seconds": elapsed,
            "exit": result.returncode, "expected_refs": len(expected),
            "observed_refs": len(remote), "refs_equal": equal,
            "retry_ok": retry_ok, "detail": text(result)[-1200:],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--counts", default="1000")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--transports", default="git,http,ssh")
    parser.add_argument("--operations", default="import,atomic,mirror")
    parser.add_argument("--git-bin")
    parser.add_argument("--git-exec-path")
    options = parser.parse_args()
    counts = [int(value) for value in options.counts.split(",")]
    formats, transports = options.formats.split(","), options.transports.split(",")
    operations = options.operations.split(",")
    if (not counts or any(count < 1 or count > 4096 for count in counts)
            or not set(formats) <= {"sha1", "sha256"}
            or not set(transports) <= {"git", "http", "ssh"}
            or not set(operations) <= {"import", "atomic", "mirror"}):
        parser.error("invalid bounded campaign selection")
    options.summary.parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="fg-many-ref-admission-"))
    git = Git(root / "git-home", options.git_bin, options.git_exec_path)
    summary = {"type": "many_ref_admission", "artifacts": str(root),
               "git": git.out("--version"), "cases": []}
    try:
        for fmt in formats:
            for count in counts:
                source, expected = corpus(git, root, fmt, count)
                for operation in operations:
                    # Import has no transport; one serving read verifies its result.
                    selected = transports[:1] if operation == "import" else transports
                    for transport in selected:
                        try:
                            row = run_case(options.fg, git, root, fmt, count,
                                           operation, transport, source, expected)
                        except Exception as error:
                            row = {"id": f"{fmt}-{count}-{operation}-{transport}",
                                   "ok": False, "detail": f"{type(error).__name__}: {error}"}
                        summary["cases"].append(row)
                        print(json.dumps(row, sort_keys=True), flush=True)
                        options.summary.write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        options.summary.write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["cases"] and all(row["ok"] for row in summary["cases"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
