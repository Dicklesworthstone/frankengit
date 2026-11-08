"""Real CLI/OS-pipe error-delivery probe. No native workflow is executed.

The unit test supplies its own trusted Node process.execPath, not external input.
The selected repository script/arguments are closed and no shell is invoked.
"""
from pathlib import Path
import json
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/e2e"))
from operator_output_smoke import output_sink

def stop_probe(number, _frame):
    raise SystemExit(128 + number)

signal.signal(signal.SIGTERM, stop_probe)
signal.signal(signal.SIGINT, stop_probe)

node, selected, mode = sys.argv[1:]
if selected not in ("watch", "checks") or mode not in ("draining", "blocked"):
    raise ValueError("closed workflow CLI probe selection required")

with tempfile.TemporaryDirectory(prefix="fg-workflow-cli-output-") as temporary:
    root = Path(temporary)
    missing = root / "missing.json"
    args = (["once", "--config", str(missing), "--trusted-local"] if selected == "watch" else
            ["once", "--watch-config", str(missing), "--state", str(root / "publisher"),
             "--principal-id", "5" * 32, "--trusted-local"])
    command = [node, str(ROOT / f"scripts/fg_workflow_{selected}.mjs"), *args]
    interrupted = False
    with (root / "stdout").open("wb") as out, (root / "stderr").open("wb") as err, \
            output_sink(err, mode == "blocked") as (sink, prefilled):
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=sink)
        try:
            try:
                child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                interrupted = True
        finally:
            # These commands cannot pass configuration loading or start native
            # work. Reap their Node child on timeout or parent interruption.
            if child.poll() is None:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                child.terminate()
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=1)
        code = child.returncode
    print(json.dumps(dict(exit=code, parent_intervened=interrupted, prefilled_bytes=prefilled,
                         stdout=(root / "stdout").read_text(), stderr=(root / "stderr").read_text(),
                         missing_config_absent=not missing.exists(), publisher_absent=not (root / "publisher").exists())))
