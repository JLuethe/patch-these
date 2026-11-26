#!/usr/bin/env python3
"""Check public source URLs and literal Markdown links without authenticating.

A zero exit status means no confirmed dead links were found. It does not mean
every source was accessible, current, or verified: see the inconclusive results.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urldefrag, urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "_site", "_reports", ".pytest_cache"}
AUTH_GATED_HOSTS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"}
USER_AGENT = "patch-these-link-checker/1.0 (+https://github.com/JLuethe/patch-these)"


def markdown_targets(text: str) -> list[str]:
    """Extract inline/reference link destinations and autolinks, excluding code."""
    lines = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = run
                continue
            if run[0] == fence[0] and len(run) >= len(fence):
                fence = None
                continue
        if fence is None:
            lines.append(line)
    body = "\n".join(lines)
    body = re.sub(r"(`+)[^\n]*?\1", "", body)
    targets = re.findall(r"<(https?://[^<>\s]+)>", body)
    for match in re.finditer(r"^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))", body, re.MULTILINE):
        targets.append(match.group(1) or match.group(2))
    # Balance parentheses so a valid URL such as /advisory_(v2) is not truncated.
    for match in re.finditer(r"!?\[[^\]\n]*\]\(\s*", body):
        start = match.end()
        if start >= len(body):
            continue
        if body[start] == "<":
            end = body.find(">", start + 1)
            if end != -1:
                targets.append(body[start + 1:end])
            continue
        cursor, depth, value = start, 0, []
        while cursor < len(body):
            char = body[cursor]
            if char == "\\" and cursor + 1 < len(body):
                cursor += 1
                value.append(body[cursor])
            elif char == "(":
                depth += 1
                value.append(char)
            elif char == ")":
                if depth == 0:
                    break
                depth -= 1
                value.append(char)
            elif char.isspace() and depth == 0:
                break
            else:
                value.append(char)
            cursor += 1
        if value:
            targets.append("".join(value))
    return targets


def collect_links(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    external: dict[str, set[str]] = defaultdict(set)
    local: dict[str, set[str]] = defaultdict(set)
    root = root.resolve()

    def add(target: str, origin: Path) -> None:
        target, _ = urldefrag(target.strip())
        if not target:
            return
        parsed = urlsplit(target)
        origin_name = origin.relative_to(root).as_posix()
        if parsed.scheme in {"http", "https"}:
            external[target].add(origin_name)
        elif parsed.scheme or parsed.netloc:
            # mailto and other non-HTTP schemes are not public advisory pages.
            return
        else:
            path = (origin.parent / unquote(parsed.path)).resolve()
            try:
                name = path.relative_to(root).as_posix()
            except ValueError:
                name = os.path.relpath(path, root)
            local[name].add(origin_name)

    for path in sorted((root / "data").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for item in payload.get("items", []):
            for source in item.get("sources", []):
                add(source["url"], path)
            # Also support checking the original schema during migration.
            for field in ("advisory_url", "x_post_urls"):
                for target in item.get(field, []):
                    add(target, path)
    for path in sorted(root.rglob("*.md")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        for target in markdown_targets(path.read_text(encoding="utf-8")):
            add(target, path)
    return dict(external), dict(local)


def classify_http(status_code: int, hostname: str) -> str:
    if hostname.lower() in AUTH_GATED_HOSTS:
        return "inconclusive"
    if 200 <= status_code < 300:
        return "available"
    if status_code in {404, 410}:
        return "dead"
    return "inconclusive"


def check_external(
    url: str,
    *,
    timeout: float = 10,
    attempts: int = 3,
    opener: Callable | None = None,
    sleeper: Callable = time.sleep,
) -> dict:
    opener = opener or urlopen
    host = urlsplit(url).hostname or ""
    result = {"target": url, "kind": "external"}
    for attempt in range(1, attempts + 1):
        retry = False
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT})
            with opener(request, timeout=timeout) as response:
                status_code = response.status
                final_url = response.geturl()
            result.update(
                status=classify_http(status_code, host),
                status_code=status_code,
                final_url=final_url,
                detail=(
                    "An unauthenticated social page may be a login screen; the post was not verified."
                    if host.lower() in AUTH_GATED_HOSTS
                    else "HTTP response received; source claims were not verified."
                ),
            )
        except HTTPError as error:
            status_code = error.code
            error.close()
            retry = status_code in {408, 425, 429} or status_code >= 500
            result.update(
                status=classify_http(status_code, host),
                status_code=status_code,
                detail=(
                    "An unauthenticated social-post response cannot establish whether the post exists."
                    if host.lower() in AUTH_GATED_HOSTS
                    else "Authentication, throttling, or server failure is inconclusive."
                    if status_code not in {404, 410}
                    else f"The public server returned HTTP {status_code}."
                ),
            )
        except (URLError, OSError, ValueError) as error:
            retry = True
            result.update(status="inconclusive", status_code=None, detail=f"Network check failed: {str(error)[:240]}")
        result["attempts"] = attempt
        if not retry or attempt == attempts:
            return result
        sleeper(min(2 ** (attempt - 1), 4))
    raise AssertionError("attempts must be positive")


def run_checks(root: Path, *, workers: int = 4, timeout: float = 10, attempts: int = 3) -> list[dict]:
    root = root.resolve()
    external, local = collect_links(root)
    results = []
    for target, origins in local.items():
        path = (root / target).resolve()
        within_root = path.is_relative_to(root)
        exists = within_root and path.exists()
        results.append({
            "target": target,
            "kind": "local",
            "status": "available" if exists else "dead",
            "detail": "Local target exists." if exists else "Local target is missing or outside the repository.",
            "origins": sorted(origins),
        })
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check_external, url, timeout=timeout, attempts=attempts): url
            for url in external
        }
        for future in as_completed(futures):
            url = futures[future]
            result = future.result()
            result["origins"] = sorted(external[url])
            results.append(result)
    return sorted(results, key=lambda result: (result["kind"], result["target"]))


def report_summary(results: list[dict]) -> str:
    counts = Counter(result["status"] for result in results)
    lines = [
        "## Source link check",
        "",
        f"Checked {len(results)} unique targets: {counts['available']} available, "
        f"{counts['dead']} confirmed dead or missing, {counts['inconclusive']} inconclusive.",
        "",
        "An available URL does not verify the advisory's claims. Inconclusive responses "
        "need manual review; a successful job means no confirmed dead links were found.",
    ]
    for result in results:
        if result["status"] != "available":
            lines.append(f"- {result['status']}: `{result['target']}` — {result['detail']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path, default=ROOT / "_reports/link-check.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args(argv)
    if args.workers < 1 or args.timeout <= 0 or args.attempts < 1:
        parser.error("workers, timeout, and attempts must be positive")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "results": []}
    try:
        report["results"] = run_checks(args.root, workers=args.workers, timeout=args.timeout, attempts=args.attempts)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["error"] = str(error)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Link check could not complete: {error}", file=sys.stderr)
        return 2
    report["counts"] = dict(Counter(result["status"] for result in report["results"]))
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = report_summary(report["results"])
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(summary)
    if report["counts"].get("inconclusive") and os.environ.get("GITHUB_ACTIONS") == "true":
        print("::warning::Some sources could not be checked. Review the link-check report; those links were not verified.")
    return 1 if report["counts"].get("dead") else 0


if __name__ == "__main__":
    raise SystemExit(main())
