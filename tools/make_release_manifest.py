#!/usr/bin/env python3
"""Generate results/release-manifest.json for a tagged archival release."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> str:
    return subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, check=True).stdout.strip()


def optional_run(args: list[str]) -> str | None:
    try:
        return run(args)
    except Exception:
        return None


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def required_files() -> list[Path]:
    manifest = json.loads((ROOT / "artifact-manifest.json").read_text(encoding="utf-8"))
    files: set[Path] = set()
    for entry in manifest["entries"]:
        if not entry.get("required"):
            continue
        path = ROOT / entry["path"]
        if path.is_file():
            files.add(path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and ".git" not in child.parts:
                    files.add(child)
    return sorted(files)


def solver_versions() -> dict[str, str | None]:
    return {
        "cadical": "3.0.1, third_party/cadical @ c607304 (see docs/measurement-environment.md)",
        "kissat": "4.0.4, third_party/kissat @ 8af8e56 (see docs/measurement-environment.md)",
        "cryptominisat": "5.11.15 tag (see docs/measurement-environment.md)",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--output", default="results/release-manifest.json")
    ap.add_argument("--concept-doi")
    ap.add_argument("--version-doi")
    args = ap.parse_args()

    artifacts = []
    for path in required_files():
        artifacts.append({
            "path": str(path.relative_to(ROOT)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })

    data = {
        "release_tag": args.tag,
        "git_commit": run(["git", "rev-parse", "HEAD"]),
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repository_url": "https://github.com/EncryptedSilence/PresentContinuous",
        "compiler_version": optional_run(["cc", "--version"]),
        "python_version": platform.python_version(),
        "solver_versions": solver_versions(),
        "artifacts": artifacts,
    }
    if args.concept_doi:
        data["concept_doi"] = args.concept_doi
    if args.version_doi:
        data["version_doi"] = args.version_doi

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        shown = out.relative_to(ROOT)
    except ValueError:
        shown = out
    print(f"wrote {shown} with {len(artifacts)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
