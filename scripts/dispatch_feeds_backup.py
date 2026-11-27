#!/usr/bin/env python3
"""Backup trigger for the Discovery feeds workflow, run from cron on the bot's box.

GitHub's own schedule (:13 and :43) is best effort and often skipped. Every 30
minutes between 6 AM and 11 PM Pacific this script asks the GitHub API whether
a feeds run is already queued or running, or started in the last 20 minutes.
If not, it dispatches feeds.yml on main (workflow_dispatch). It costs no
editorial routine run: it is a single API call from cron.

Token: GITHUB_TOKEN from the environment, otherwise the token already stored in
the clone's origin URL (https://x-access-token:<token>@github.com/...). It needs
Actions read and write. The token is never printed or logged.

Usage:
  python3 scripts/dispatch_feeds_backup.py              # decide, maybe dispatch, log
  python3 scripts/dispatch_feeds_backup.py --dry-run    # decide and log, never dispatch
  python3 scripts/dispatch_feeds_backup.py --force      # ignore the time window and recent runs

Log: $PT_STATE_DIR/feed-backup.log (default /workspace/pt-state/feed-backup.log).
Install the cron entry with scripts/install_feed_backup_cron.sh.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

REPO = "JLuethe/patch-these"
WORKFLOW = "feeds.yml"
API = f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}"
PACIFIC = ZoneInfo("America/Los_Angeles")
FIRST_HOUR, LAST_HOUR = 6, 23  # 06:00 through 23:00 Pacific
RECENT = timedelta(minutes=20)
ACTIVE = {"queued", "in_progress", "waiting", "requested", "pending"}
CLONE = Path(__file__).resolve().parents[1]
LOG_LIMIT = 1_000_000


def in_window(now: datetime) -> bool:
    """06:00 to 23:00 Pacific, inclusive of 23:00 exactly."""
    local = now.astimezone(PACIFIC)
    return FIRST_HOUR <= local.hour < LAST_HOUR or (local.hour == LAST_HOUR and local.minute == 0)


def decide(runs: list[dict], now: datetime) -> tuple[bool, str]:
    """Whether to dispatch, and why, given the workflow's most recent runs."""
    for run in runs:
        if run.get("status") in ACTIVE:
            return False, f"run {run.get('id')} is {run.get('status')}"
    for run in runs:
        created = run.get("created_at")
        if not created:
            continue
        started = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if now - started < RECENT:
            return False, f"run {run.get('id')} ({run.get('event')}, {run.get('conclusion') or run.get('status')}) started {int((now - started).total_seconds() // 60)} min ago"
    latest = runs[0].get("created_at") if runs else None
    return True, f"no feeds run in the last {int(RECENT.total_seconds() // 60)} min (latest {latest or 'none'})"


def token() -> str:
    value = os.environ.get("GITHUB_TOKEN", "").strip()
    if value:
        return value
    url = subprocess.run(["git", "-C", str(CLONE), "remote", "get-url", "origin"], capture_output=True, text=True).stdout.strip()
    match = re.match(r"https://x-access-token:([^@\s]+)@github\.com/", url)
    return match.group(1) if match else ""


def api(method: str, url: str, secret: str, body: dict | None = None) -> tuple[int, dict | None]:
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {secret}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "patch-these-feed-backup",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urlopen(request, timeout=20) as response:
        payload = response.read()
        return response.status, (json.loads(payload) if payload else None)


def log(message: str) -> None:
    path = Path(os.environ.get("PT_STATE_DIR") or "/workspace/pt-state") / "feed-backup.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.stat().st_size > LOG_LIMIT:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stamp = datetime.now(PACIFIC).strftime("%Y-%m-%d %H:%M:%S %Z")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp} {message}\n")
    print(f"{stamp} {message}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc)
    if not args.force and not in_window(now):
        log("skip: outside 06:00-23:00 PT")
        return 0
    secret = token()
    if not secret:
        log("error: no GITHUB_TOKEN in the environment or the clone's origin URL")
        return 1
    try:
        _, payload = api("GET", f"{API}/runs?per_page=10", secret)
        runs = (payload or {}).get("workflow_runs") or []
        dispatch, reason = decide(runs, now)
        if args.force:
            dispatch, reason = True, "forced; " + reason
        if not dispatch:
            log(f"skip: {reason}")
            return 0
        if args.dry_run:
            log(f"dry run: would dispatch ({reason})")
            return 0
        status, _ = api("POST", f"{API}/dispatches", secret, {"ref": "main"})
        log(f"dispatched feeds.yml on main: HTTP {status} ({reason})")
        return 0 if status in (200, 204) else 1
    except HTTPError as error:
        log(f"error: GitHub API HTTP {error.code}")
        return 1
    except (URLError, OSError, ValueError) as error:
        log(f"error: {type(error).__name__}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
