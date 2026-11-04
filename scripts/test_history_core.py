#!/usr/bin/env python3
"""Run the actual native-history core modules without node/transport dependencies.

Requires a caller-selected private target directory. Artifact paths come from
this successful Cargo build, including fresh artifacts; no target-tree glob or
substitute production API is used. This is core evidence, not node integration.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
DIRECT = ("fgit_types", "fgit_crypto", "fgit_diff")
HARNESS = ROOT / "crates/fgit-forge/src/history_core_harness.rs"


def build_artifacts(target):
    command = [
        "cargo", "build", "--locked", "--offline", "--jobs", "1", "--lib",
        "--message-format=json", "--target-dir", str(target),
        "-p", "fgit-types", "-p", "fgit-crypto", "-p", "fgit-diff",
    ]
    artifacts = []
    finished = False
    env = {**os.environ, "CARGO_TARGET_DIR": str(target), "RCH_CARGO_JSON_STDOUT": "1"}
    # stderr stays attached. Rust diagnostics carried inside JSON are rendered
    # below, so compiler errors are never swallowed with the artifact receipt.
    with subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                          text=True, encoding="utf-8") as child:
        for line in child.stdout:
            record = json.loads(line)
            reason = record.get("reason")
            if reason == "compiler-message":
                rendered = record.get("message", {}).get("rendered")
                if rendered:
                    print(rendered, end="", file=sys.stderr, flush=True)
            elif reason == "build-finished":
                finished = record.get("success") is True
            elif reason == "compiler-artifact":
                artifacts.append(record)
        status = child.wait()
    if status:
        raise subprocess.CalledProcessError(status, command)
    direct = {}
    directories = set()
    for record in artifacts:
        files = [Path(name).resolve() for name in record.get("filenames", [])]
        directories.update(path.parent for path in files)
        name = record.get("target", {}).get("name")
        if name in DIRECT:
            manifest = Path(record["manifest_path"]).resolve()
            expected = ROOT / "crates" / name.replace("_", "-") / "Cargo.toml"
            if manifest != expected or name in direct:
                raise ValueError(f"ambiguous or foreign artifact for {name}")
            pair = []
            for suffix in (".rlib", ".rmeta"):
                matching = [path for path in files if path.suffix == suffix]
                if len(matching) != 1 or not matching[0].is_file():
                    raise ValueError(f"missing or ambiguous {suffix} artifact for {name}")
                pair.append(matching[0])
            direct[name] = pair
    if not finished or set(direct) != set(DIRECT):
        raise ValueError("Cargo did not provide a completed build with all three libraries")
    return direct, sorted(directories)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", help="private build directory; defaults to CARGO_TARGET_DIR")
    args = parser.parse_args()
    selected = args.target_dir or os.environ.get("CARGO_TARGET_DIR")
    if not selected:
        parser.error("set CARGO_TARGET_DIR or --target-dir to a private build directory")
    target = Path(selected).expanduser().resolve()
    if target == (ROOT / "target").resolve():
        parser.error("the shared repository target is not a private build directory")
    print("history-core: building real types, crypto and diff dependencies", file=sys.stderr)
    direct, directories = build_artifacts(target)
    executable = target / ("history-core-tests.exe" if os.name == "nt" else "history-core-tests")
    command = [os.environ.get("RUSTC", "rustc"), "--edition=2024", "--test", str(HARNESS)]
    for name in DIRECT:
        for artifact in direct[name]:
            # This pinned compiler needs linked code AND separate metadata.
            command += ["--extern", f"{name}={artifact}"]
    for directory in directories:
        command += ["-L", f"dependency={directory}"]
    command += ["-o", str(executable)]
    print("history-core: compiling the actual production history modules", file=sys.stderr)
    subprocess.run(command, cwd=ROOT, check=True)
    print("history-core: running isolated core tests (not node integration)", file=sys.stderr)
    subprocess.run([str(executable), "--test-threads=1"], cwd=ROOT, check=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode >= 0 else 128 - error.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"history-core: refused: {error}", file=sys.stderr)
        sys.exit(2)
