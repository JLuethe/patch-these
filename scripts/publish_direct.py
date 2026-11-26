#!/usr/bin/env python3
"""Publish an ordinary edition update straight to main.

Usage:
  python scripts/publish_direct.py data/2026-11-26.json
  python scripts/publish_direct.py --dry-run data/2026-11-26.json

Run this from a checkout of main. The script regenerates the site, runs the
tests, checks generated files, then link-checks. A confirmed dead link that
was already in the repository stops the push. A dead link on a non-social
source added in this edit is printed and does not stop the push. Inconclusive
results never stop the push.

Authentication uses GITHUB_TOKEN and never prints it. --dry-run runs the same
checks and prints the commit it would make, then stops before git add.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from patchthese.common import social_platform  # noqa: E402

GENERATED = ("README.md", "data/products.json")


def commit_message(paths: list[Path], when: datetime) -> str:
    dates = sorted({path.stem for path in paths})
    if len(dates) == 1:
        subject = f"Update {dates[0]} edition"
    else:
        subject = "Update " + " and ".join(dates) + " editions"
    local = when.astimezone(ZoneInfo("America/Los_Angeles"))
    return f"{subject} ({local.strftime('%H:%M')} PT run)"


def edition_urls(payload: dict) -> set[str]:
    urls = set()
    for item in payload.get("items") or []:
        for source in item.get("sources") or []:
            url = source.get("url")
            if isinstance(url, str):
                urls.add(url)
    return urls


def new_source_urls(root: Path, paths: list[Path]) -> set[str]:
    """HTTPS sources that were not in these edition files at HEAD."""
    added = set()
    for path in paths:
        relative = path.relative_to(root).as_posix()
        current = json.loads(path.read_text(encoding="utf-8"))
        previous: set[str] = set()
        show = subprocess.run(
            ["git", "show", f"HEAD:{relative}"],
            cwd=root, capture_output=True, text=True,
        )
        if show.returncode == 0:
            previous = edition_urls(json.loads(show.stdout))
        added.update(edition_urls(current) - previous)
    return added


def blocking_dead(results: list[dict], new_urls: set[str]) -> list[dict]:
    """Dead links that must stop a push.

    A newly added non-social URL is reported by the caller and does not block.
    """
    blocking = []
    for result in results:
        if result.get("status") != "dead":
            continue
        target = result.get("target") or ""
        if result.get("kind") != "local" and target in new_urls and social_platform(target) is None:
            continue
        blocking.append(result)
    return blocking


def reported_new_dead(results: list[dict], new_urls: set[str]) -> list[dict]:
    return [
        result for result in results
        if result.get("status") == "dead"
        and result.get("kind") != "local"
        and (result.get("target") or "") in new_urls
        and social_platform(result.get("target") or "") is None
    ]


def _run(command: list[str], *, cwd: Path, token: str = "") -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    if token:
        printable = printable.replace(token, "***")
    print("+", printable, flush=True)
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    output = (completed.stdout + completed.stderr)
    if token:
        output = output.replace(token, "***")
    if output.strip():
        print(output.rstrip())
    return completed


def _fail(message: str, code: int = 1) -> int:
    print(message, file=sys.stderr)
    return code


def _allowed_paths(edition_paths: list[Path]) -> set[str]:
    allowed = set(GENERATED)
    for path in edition_paths:
        allowed.add(path.relative_to(ROOT).as_posix())
        allowed.add(f"digests/{path.stem}.md")
    return allowed


def _unexpected_changes(allowed: set[str]) -> list[str]:
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True)
    unexpected = []
    for line in status.stdout.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip()
        if path not in allowed:
            unexpected.append(path)
    return unexpected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, help="Edition JSON files to publish, such as data/2026-11-26.json")
    parser.add_argument("--dry-run", action="store_true", help="Run the checks and print the commit, but do not commit or push.")
    args = parser.parse_args(argv)
    python = sys.executable
    edition_paths = []
    for path in args.files:
        candidate = path if path.is_absolute() else ROOT / path
        relative = candidate.resolve().relative_to(ROOT)
        if relative.parts[0] != "data" or len(relative.parts) != 2 or not relative.name.endswith(".json"):
            return _fail(f"Not an edition file: {path}")
        if not candidate.is_file():
            return _fail(f"Missing edition file: {path}")
        edition_paths.append(candidate)

    steps = [
        [python, "scripts/build_site.py", "--write-generated"],
        [python, "-m", "pytest", "-q"],
        [python, "scripts/build_site.py", "--check"],
    ]
    for command in steps:
        completed = _run(command, cwd=ROOT)
        if completed.returncode != 0:
            return completed.returncode

    new_urls = new_source_urls(ROOT, edition_paths)
    link = _run([python, "scripts/check_links.py", "--report", "_reports/link-check.json"], cwd=ROOT)
    report_path = ROOT / "_reports" / "link-check.json"
    if link.returncode == 2 or not report_path.is_file():
        return link.returncode or 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    warned = reported_new_dead(report.get("results") or [], new_urls)
    for result in warned:
        print(f"link check warning (new non-social source, not blocking): {result['target']} — {result.get('detail')}")
    blocking = blocking_dead(report.get("results") or [], new_urls)
    if blocking or link.returncode not in {0, 1}:
        for result in blocking:
            print(f"link check blocked the push: {result['target']} — {result.get('detail')}", file=sys.stderr)
        return 1

    when = datetime.now(timezone.utc)
    message = commit_message(edition_paths, when)
    allowed = _allowed_paths(edition_paths)
    unexpected = _unexpected_changes(allowed)
    if unexpected:
        return _fail("Refusing to publish because unrelated files changed: " + ", ".join(unexpected))
    if args.dry_run:
        print(f"dry run: would commit {message}")
        print("dry run: would add " + ", ".join(sorted(allowed)))
        print("dry run: no commit and no push")
        return 0

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token.strip() or any(char.isspace() for char in token):
        return _fail("GITHUB_TOKEN is required to push, and it must not contain whitespace.")
    branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
    if branch.stdout.strip() != "main":
        return _fail("publish_direct.py must be run from main.")

    add = ["git", "add", "--", *sorted(allowed)]
    completed = _run(add, cwd=ROOT)
    if completed.returncode != 0:
        return completed.returncode
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
    if staged.returncode == 0:
        print("Nothing to publish.")
        return 0
    completed = _run(["git", "commit", "-m", message], cwd=ROOT)
    if completed.returncode != 0:
        return completed.returncode

    auth_remote = f"https://x-access-token:{token}@github.com/JLuethe/patch-these.git"
    pull = _run(["git", "pull", "--rebase", auth_remote, "main"], cwd=ROOT, token=token)
    if pull.returncode != 0:
        _run(["git", "rebase", "--abort"], cwd=ROOT)
        return pull.returncode
    push = _run(["git", "push", auth_remote, "HEAD:main"], cwd=ROOT, token=token)
    if push.returncode != 0:
        return push.returncode
    print(f"Pushed {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
