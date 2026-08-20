#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    ".gitignore",
    "LICENSE",
    "README.md",
    "ARCHITECTURE.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md",
    "VERIFY_SPEC.md",
    "SECURITY_THREAT_MODEL.md",
    "docs/ADR-0001-CANONICAL-STATE.md",
    "docs/AGENT_PROTOCOL.md",
    "docs/INITIAL_ISSUE_BACKLOG.md",
    "docs/RAPTORQ_PERMEATION_MAP.md",
    "docs/RESEARCH_PROVENANCE.md",
    "docs/NORMATIVE_PROTOCOL_CONTRACTS.md",
    "docs/FRESH_EYES_AUDIT_2026-08-19.md",
    "docs/LICENSING_DECISION.md",
    "docs/GIT_COMPATIBILITY_MATRIX.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/architecture-proposal.yml",
    ".github/ISSUE_TEMPLATE/implementation-slice.yml",
    ".github/workflows/docs-integrity.yml",
]

FORBIDDEN_BASENAMES = {".DS_Store", "Thumbs.db", "Desktop.ini"}
FORBIDDEN_ROOT = {
    "ADR-0001-CANONICAL-STATE.md",
    "AGENT_PROTOCOL.md",
    "INITIAL_ISSUE_BACKLOG.md",
    "RAPTORQ_PERMEATION_MAP.md",
    "RESEARCH_PROVENANCE.md",
    "bootstrap_github_repo.sh",
    "frankengit-artifacts-SHA256SUMS.txt",
}

MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
FENCE = re.compile(r"^\s*(```+|~~~+)")
ACTION_USE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
SHA_PIN = re.compile(r"^[^@]+@[0-9a-f]{40}$")

errors: list[str] = []

for rel in REQUIRED:
    if not (ROOT / rel).is_file():
        errors.append(f"missing required file: {rel}")

for path in ROOT.rglob("*"):
    if path.is_file() and path.name in FORBIDDEN_BASENAMES:
        errors.append(f"forbidden platform artifact: {path.relative_to(ROOT)}")

for name in FORBIDDEN_ROOT:
    if (ROOT / name).exists():
        errors.append(f"forbidden/flattened root artifact: {name}")

markdown = sorted(ROOT.rglob("*.md"))
for path in markdown:
    text = path.read_text(encoding="utf-8")
    open_fence: tuple[str, int] | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if not match:
            continue
        family = match.group(1)[0]
        if open_fence is None:
            open_fence = (family, lineno)
        elif open_fence[0] == family:
            open_fence = None
    if open_fence is not None:
        errors.append(f"unbalanced code fence: {path.relative_to(ROOT)}:{open_fence[1]}")

    for match in MD_LINK.finditer(text):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("#", "mailto:", "data:")):
            continue
        target = raw.split()[0].strip("<>")
        parsed = urlparse(target)
        if parsed.scheme or target.startswith("//"):
            continue
        file_part = unquote(target.split("#", 1)[0])
        if not file_part:
            continue
        resolved = (path.parent / file_part).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"link escapes repository: {path.relative_to(ROOT)} -> {target}")
            continue
        if not resolved.exists():
            errors.append(f"broken relative link: {path.relative_to(ROOT)} -> {target}")

workflow = ROOT / ".github/workflows/docs-integrity.yml"
if workflow.exists():
    wf = workflow.read_text(encoding="utf-8")
    for action in ACTION_USE.findall(wf):
        if not SHA_PIN.match(action):
            errors.append(f"GitHub Action is not pinned to a full commit SHA: {action}")

normative = ROOT / "docs/NORMATIVE_PROTOCOL_CONTRACTS.md"
if normative.exists():
    text = normative.read_text(encoding="utf-8")
    for phrase in [
        "There is exactly one normative derivation",
        "TxnOutcomeRecord",
        "resulting_forge_position_root",
        "push negotiates with `git-receive-pack`",
        "RaptorQ is an erasure-recovery mechanism",
        "The mutation linearizes at the serializable metadata commit",
    ]:
        if phrase not in text:
            errors.append(f"normative contract missing phrase: {phrase}")

readme = ROOT / "README.md"
if readme.exists():
    text = readme.read_text(encoding="utf-8").lower()
    if "pre-implementation" not in text and "spec-first" not in text:
        errors.append("README must state that FrankenGit is pre-implementation/spec-first")
    if "source-available" not in text:
        errors.append("README must describe the current source-available licensing status")

plan = ROOT / "COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md"
if plan.exists() and "docs/NORMATIVE_PROTOCOL_CONTRACTS.md" not in plan.read_text(encoding="utf-8"):
    errors.append("comprehensive plan must declare the normative protocol contract")

# Catch the exact stale misconception while allowing text that explains why it is wrong.
for path in markdown:
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        low = line.lower()
        if "protocol v2 push" in low and not any(
            word in low for word in ("not", "fictional", "out-of-scope", "incorrect")
        ):
            errors.append(f"stale protocol-v2 push claim: {path.relative_to(ROOT)}:{lineno}")

# One canonical formula, in one file.
formula_locations: list[str] = []
for path in markdown:
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if re.search(r"\bTxId\s*=\s*H\s*\(", line):
            formula_locations.append(f"{path.relative_to(ROOT)}:{lineno}")
if len(formula_locations) != 1:
    errors.append(f"expected exactly one canonical TxId formula, found {formula_locations}")

if errors:
    print("FrankenGit documentation verification FAILED:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"FrankenGit documentation verification passed ({len(markdown)} Markdown files).")