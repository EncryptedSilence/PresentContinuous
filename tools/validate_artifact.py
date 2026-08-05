#!/usr/bin/env python3
"""Validate the committed reproducibility artifact without rerunning long jobs."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "CITATION.cff",
    "LICENSE-TODO.md",
    "artifact-manifest.json",
    "docs/ARCHIVAL.md",
    "docs/ARCHIVAL_REVIEW.md",
    "docs/measurement-environment.md",
    "docs/speed-at-equal-security.md",
    "results/avalanche.csv",
    "results/rounds-at-64.csv",
]

REQUIRED_DIRS = [
    "results/bound-search",
]


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check)


def load_manifest() -> dict:
    path = ROOT / "artifact-manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"cannot parse artifact-manifest.json: {exc}")


def validate_citation() -> None:
    path = ROOT / "CITATION.cff"
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
        except Exception as exc:
            fail(f"CITATION.cff is not valid YAML: {exc}")
        if not isinstance(data, dict):
            fail("CITATION.cff did not parse as a mapping")
    required = [
        "cff-version: 1.2.0",
        "type: software",
        "repository-code: \"https://github.com/EncryptedSilence/PresentContinuous\"",
        "family-names: Gorlov",
        "family-names: Ibrayev",
        "family-names: Seilova",
        "AFFILIATION TO BE CONFIRMED",
    ]
    for needle in required:
        if needle not in text:
            fail(f"CITATION.cff missing {needle!r}")
    if re.search(r"^license:", text, re.MULTILINE):
        fail("CITATION.cff must not include a license field until LICENSE is selected")

    cffconvert = run(["bash", "-lc", "command -v cffconvert"])
    if cffconvert.returncode == 0:
        check = run(["cffconvert", "--validate"])
        if check.returncode != 0:
            fail("cffconvert validation failed:\n" + check.stderr)
        print("CITATION.cff: valid by cffconvert")
    else:
        print("CITATION.cff: cffconvert not installed; completed built-in structural checks")


def check_required_paths(manifest: dict) -> None:
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        if not path.is_file():
            fail(f"required file missing: {rel}")
        if path.stat().st_size == 0:
            fail(f"required file is empty: {rel}")
    for rel in REQUIRED_DIRS:
        path = ROOT / rel
        if not path.is_dir():
            fail(f"required directory missing: {rel}")
        if not any(path.iterdir()):
            fail(f"required directory is empty: {rel}")

    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("artifact-manifest.json has no entries")
    for entry in entries:
        rel = entry.get("path")
        if not rel:
            fail("manifest entry without path")
        for field in ("role", "classification", "required"):
            if field not in entry:
                fail(f"manifest path {rel} missing {field}")
        if entry.get("required") and not (ROOT / rel).exists():
            fail(f"manifest path does not exist: {rel}")


def markdown_files() -> list[Path]:
    roots = [ROOT / "README.md", ROOT / "LICENSE-TODO.md", ROOT / "docs", ROOT / "paper"]
    out: list[Path] = []
    for root in roots:
        if root.is_file():
            out.append(root)
        elif root.is_dir():
            out.extend(sorted(root.rglob("*.md")))
    return out


def validate_links() -> None:
    link_re = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for md in markdown_files():
        text = md.read_text(encoding="utf-8")
        for match in link_re.finditer(text):
            target = match.group(1).strip()
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            if "://" in target:
                continue
            candidate = (md.parent / target).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                fail(f"{md.relative_to(ROOT)} links outside repository: {target}")
            if not candidate.exists():
                fail(f"{md.relative_to(ROOT)} has broken link: {target}")
    print("documentation links: ok")


def check_ignored_required(manifest: dict) -> None:
    paths = [entry["path"] for entry in manifest["entries"] if entry.get("required")]
    ignored: list[str] = []
    for rel in paths:
        check = run(["git", "check-ignore", "-q", "--no-index", "--", rel])
        if check.returncode == 0:
            ignored.append(rel)
        elif check.returncode != 1:
            fail(f"git check-ignore failed for {rel}:\n{check.stderr}")
    if ignored:
        fail("required artifact path is ignored:\n" + "\n".join(ignored))


def print_commit() -> None:
    commit = run(["git", "rev-parse", "HEAD"], check=True).stdout.strip()
    print(f"git commit: {commit}")


def check_no_tracked_docx() -> None:
    tracked = run(["git", "ls-files", "*.docx", "*.DOCX"]).stdout.strip()
    if tracked:
        fail("tracked DOCX files are not allowed in the public artifact:\n" + tracked)


def main() -> int:
    manifest = load_manifest()
    check_required_paths(manifest)
    validate_citation()
    validate_links()
    check_ignored_required(manifest)
    check_no_tracked_docx()
    print_commit()
    print("artifact validation: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
