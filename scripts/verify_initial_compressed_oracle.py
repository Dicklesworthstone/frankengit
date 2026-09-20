#!/usr/bin/env python3
"""Non-production Git input oracle, not execution of the native Rust builder.

Requires an exact executable path, version and SHA-256. Uses new disposable
repositories, no inherited Git configuration, no remote, and no target blobs
preinstalled in the receiving object store. Failure never prints a pass report.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BODY = b"\0\x01\x02\r\n\xffA"
LITERAL = "literal 7\nOcmZQzWa8!e?+5?_r~z95\n\n"
DELTA = "delta 10\nRc${NkXJ=q!;^q492mk{j0cijL\n\n"
EMPTY = "literal 0\nHcmV?d00001\n\n"


def oid(kind, body, algorithm):
    framed = f"{kind} {len(body)}\0".encode() + body
    return hashlib.new(algorithm, framed).hexdigest()


def main():
    if len(sys.argv) != 4:
        raise ValueError("usage: script ABSOLUTE_GIT_PATH EXACT_VERSION EXECUTABLE_SHA256")
    executable = Path(sys.argv[1])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("an existing absolute Git executable is required")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if digest != sys.argv[3]:
        raise ValueError("Git executable SHA-256 mismatch")
    clean = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    clean.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                 GIT_ATTR_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="", LC_ALL="C")
    version = subprocess.check_output([str(executable), "--version"], env=clean, timeout=10).decode().strip()
    if version != sys.argv[2]:
        raise ValueError("Git version mismatch")
    cases = []
    for algorithm in ("sha1", "sha256"):
        for name, forward in (("git-literal", LITERAL), ("empty-base-delta", DELTA)):
            with tempfile.TemporaryDirectory(prefix="fg-initial-compressed-oracle-") as directory:
                root = Path(directory); repository = root / "repo"; repository.mkdir()
                home = root / "home"; home.mkdir(); template = root / "template"; template.mkdir()
                env = dict(clean, HOME=str(home), XDG_CONFIG_HOME=str(home))

                def git(*args, data=None, success=True):
                    completed = subprocess.run([str(executable), "-C", str(repository), *args],
                        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=15)
                    if completed.stderr:
                        sys.stderr.buffer.write(completed.stderr)
                    if (completed.returncode == 0) != success:
                        raise RuntimeError(f"unexpected Git exit {completed.returncode}: {args!r}")
                    return completed.stdout

                git("init", "-q", "--initial-branch=main", f"--object-format={algorithm}", f"--template={template}")
                blob = oid("blob", BODY, algorithm)
                patch = (f"diff --git a/asset.bin b/asset.bin\nnew file mode 100755\n"
                         f"index {'0' * len(blob)}..{blob}\nGIT binary patch\n{forward}{EMPTY}").encode()
                # This object is absent, so apply cannot reuse the expected blob.
                if (repository / ".git" / "objects" / blob[:2] / blob[2:]).exists():
                    raise AssertionError("target blob was installed before decoding")
                git("apply", "--cached", "--binary", "-", data=patch)
                if git("show", ":asset.bin") != BODY:
                    raise AssertionError("decoded content differs")
                index = git("ls-files", "--stage").decode()
                if index != f"100755 {blob} 0\tasset.bin\n":
                    raise AssertionError("mode/path/blob mismatch")
                tree_body = b"100755 asset.bin\0" + bytes.fromhex(blob)
                tree = git("write-tree").decode().strip()
                if tree != oid("tree", tree_body, algorithm):
                    raise AssertionError("tree identity mismatch")
                raw_commit = (f"tree {tree}\nauthor A <a@example.invalid> 1 +0000\n"
                              "committer C <c@example.invalid> 1 +0000\n\ninitial\n").encode()
                commit = git("hash-object", "-t", "commit", "-w", "--stdin", data=raw_commit).decode().strip()
                if commit != oid("commit", raw_commit, algorithm):
                    raise AssertionError("root commit identity mismatch")
                git("update-ref", "refs/heads/main", commit)
                git("fsck", "--strict")
                cases.append(dict(format=algorithm, member=name, blob=blob, tree=tree, commit=commit))
    print(json.dumps(dict(profile="initial-compressed-input-git-oracle-v1", git_version=version,
        git_sha256=digest, passed=len(cases), cases=cases, native_rust_executed=False,
        native_authority_tested=False), indent=2))


if __name__ == "__main__":
    main()
