#!/usr/bin/env python3
"""Track social leads as issues, separately from the 14-day seen-posts store.

seen_posts.py remembers which posts were read. This file remembers what they
were about, so a second report of the same flaw days later is recognized:

  $PT_STATE_DIR/tracked-issues.json   (PT_STATE_DIR defaults to /workspace/pt-state)

States:
  pending    noticed, not yet judged
  evaluated  judged and not published for now (out of scope, not credible yet)
  tracked    published as an edition item (early signal or verified); has item_id
  closed     no longer watched (resolved, dismissed, or expired)

Allowed moves: pending -> evaluated | tracked | closed; evaluated -> pending |
tracked | closed; tracked -> closed; closed -> pending (reopen).

Usage:
  python scripts/tracked_issues.py add ID --title "..." [--cve CVE-...] [--product name] [--post URL] [--note "..."]
  python scripts/tracked_issues.py set ID STATE [--item-id ID] [--edition YYYY-MM-DD] [--note "..."]
  python scripts/tracked_issues.py attach ID [--post URL] [--cve ...] [--product ...] [--note "..."]
  python scripts/tracked_issues.py match TEXT_OR_URL_OR_CVE [...]   # open issues that match
  python scripts/tracked_issues.py list [--state STATE] [--json]
  python scripts/tracked_issues.py show ID
  python scripts/tracked_issues.py prune     # close pending/evaluated issues idle 14 days; drop closed ones idle 30 days
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from seen_posts import normalize  # noqa: E402

DEFAULT_STATE_DIR = "/workspace/pt-state"
STATES = ("pending", "evaluated", "tracked", "closed")
ALLOWED = {
    "pending": {"evaluated", "tracked", "closed"},
    "evaluated": {"pending", "tracked", "closed"},
    "tracked": {"closed"},
    "closed": {"pending"},
}
IDLE_DAYS = 14
CLOSED_DAYS = 30
ID_PATTERN = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


class IssueError(ValueError):
    pass


def store_path() -> Path:
    return Path(os.environ.get("PT_STATE_DIR") or DEFAULT_STATE_DIR) / "tracked-issues.json"


def stamp(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: Path) -> dict:
    if not path.is_file():
        return {}
    return dict(json.loads(path.read_text(encoding="utf-8")).get("issues") or {})


def save(path: Path, issues: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"issues": {key: issues[key] for key in sorted(issues)}}, indent=1, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        handle.write(payload)
    os.replace(handle.name, path)


def _cves(values) -> list[str]:
    result = []
    for value in values or []:
        if not CVE_PATTERN.fullmatch(value.strip()):
            raise IssueError(f"not a CVE id: {value}")
        result.append(value.strip().upper())
    return result


def _post(url: str) -> dict:
    key = normalize(url)
    if key is None:
        raise IssueError(f"not a recognized post URL: {url}")
    return {"id": key, "url": url}


def _merge(issue: dict, posts=(), cves=(), products=(), note=None, now=None) -> None:
    known = {post["id"] for post in issue["posts"]}
    for url in posts or []:
        post = _post(url)
        if post["id"] not in known:
            issue["posts"].append(post)
            known.add(post["id"])
    issue["cves"] = sorted(set(issue["cves"]) | set(_cves(cves)))
    issue["products"] = sorted(set(issue["products"]) | {p.strip().lower() for p in products or [] if p.strip()})
    if note:
        issue["notes"].append({"at": stamp(now), "note": note})


def add(issues: dict, issue_id: str, title: str, now: datetime, posts=(), cves=(), products=(), note=None) -> dict:
    if not ID_PATTERN.fullmatch(issue_id or ""):
        raise IssueError("id must be a lowercase slug like example-product")
    if issue_id in issues:
        raise IssueError(f"{issue_id} already exists; use attach or set")
    if not (title or "").strip():
        raise IssueError("a title is required")
    issue = {"id": issue_id, "title": title.strip(), "state": "pending", "created_at": stamp(now), "updated_at": stamp(now),
             "posts": [], "cves": [], "products": [], "item_id": None, "edition": None, "notes": [],
             "history": [{"at": stamp(now), "from": None, "to": "pending"}]}
    _merge(issue, posts, cves, products, note, now)
    issues[issue_id] = issue
    return issue


def get(issues: dict, issue_id: str) -> dict:
    if issue_id not in issues:
        raise IssueError(f"no issue {issue_id}")
    return issues[issue_id]


def set_state(issues: dict, issue_id: str, state: str, now: datetime, note=None, item_id=None, edition=None) -> dict:
    issue = get(issues, issue_id)
    if state not in STATES:
        raise IssueError(f"state must be one of {', '.join(STATES)}")
    if state != issue["state"] and state not in ALLOWED[issue["state"]]:
        raise IssueError(f"cannot move {issue_id} from {issue['state']} to {state}")
    if item_id is not None:
        if not ID_PATTERN.fullmatch(item_id):
            raise IssueError("item_id must be an edition item id")
        issue["item_id"] = item_id
    if edition is not None:
        datetime.strptime(edition, "%Y-%m-%d")
        issue["edition"] = edition
    if state == "tracked" and not issue["item_id"]:
        raise IssueError("tracked needs --item-id, the edition item that covers it")
    if state != issue["state"]:
        issue["history"].append({"at": stamp(now), "from": issue["state"], "to": state, **({"note": note} if note else {})})
        issue["state"] = state
    if note:
        issue["notes"].append({"at": stamp(now), "note": note})
    issue["updated_at"] = stamp(now)
    return issue


def attach(issues: dict, issue_id: str, now: datetime, posts=(), cves=(), products=(), note=None) -> dict:
    issue = get(issues, issue_id)
    _merge(issue, posts, cves, products, note, now)
    issue["updated_at"] = stamp(now)
    return issue


def match(issues: dict, values: list[str], include_closed: bool = False) -> list[dict]:
    """Issues that share a post, a CVE id, or a product name with any value."""
    found = []
    keys = {normalize(value) for value in values} - {None}
    cves = {cve.upper() for value in values for cve in CVE_PATTERN.findall(value)}
    text = " ".join(values).lower()
    for issue in issues.values():
        if issue["state"] == "closed" and not include_closed:
            continue
        if ({post["id"] for post in issue["posts"]} & keys or set(issue["cves"]) & cves
                or any(re.search(r"(?<![a-z0-9])" + re.escape(product) + r"(?![a-z0-9])", text) for product in issue["products"])):
            found.append(issue)
    return sorted(found, key=lambda issue: issue["updated_at"], reverse=True)


def prune(issues: dict, now: datetime, idle_days: int = IDLE_DAYS, closed_days: int = CLOSED_DAYS) -> tuple[dict, list[str], list[str]]:
    kept, closed, dropped = {}, [], []
    for key, issue in issues.items():
        updated = datetime.fromisoformat(issue["updated_at"].replace("Z", "+00:00"))
        if issue["state"] == "closed" and updated < now - timedelta(days=closed_days):
            dropped.append(key)
            continue
        if issue["state"] in ("pending", "evaluated") and updated < now - timedelta(days=idle_days):
            set_state({key: issue}, key, "closed", now, note=f"no new reports in {idle_days} days")
            closed.append(key)
        kept[key] = issue
    return kept, closed, dropped


def line(issue: dict) -> str:
    extra = ", ".join(issue["cves"] + issue["products"])
    item = f" -> {issue['item_id']}" if issue.get("item_id") else ""
    return f"{issue['state']:<9} {issue['id']}{item}: {issue['title']}" + (f" [{extra}]" if extra else "") + f" ({len(issue['posts'])} posts, updated {issue['updated_at']})"


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def details(p):
        p.add_argument("--post", action="append", default=[])
        p.add_argument("--cve", action="append", default=[])
        p.add_argument("--product", action="append", default=[])
        p.add_argument("--note")

    a = sub.add_parser("add"); a.add_argument("id"); a.add_argument("--title", required=True); details(a)
    s = sub.add_parser("set"); s.add_argument("id"); s.add_argument("state", choices=STATES)
    s.add_argument("--item-id"); s.add_argument("--edition"); s.add_argument("--note")
    t = sub.add_parser("attach"); t.add_argument("id"); details(t)
    m = sub.add_parser("match"); m.add_argument("values", nargs="+"); m.add_argument("--include-closed", action="store_true")
    ls = sub.add_parser("list"); ls.add_argument("--state", choices=STATES); ls.add_argument("--json", action="store_true")
    sh = sub.add_parser("show"); sh.add_argument("id")
    sub.add_parser("prune")
    args = parser.parse_args(argv)
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    path = store_path()
    issues = load(path)
    try:
        if args.command == "add":
            issue = add(issues, args.id, args.title, now, args.post, args.cve, args.product, args.note)
        elif args.command == "set":
            issue = set_state(issues, args.id, args.state, now, args.note, args.item_id, args.edition)
        elif args.command == "attach":
            issue = attach(issues, args.id, now, args.post, args.cve, args.product, args.note)
        elif args.command == "match":
            print(json.dumps(match(issues, args.values, args.include_closed), indent=1, ensure_ascii=False))
            return 0
        elif args.command == "list":
            rows = [i for i in issues.values() if not args.state or i["state"] == args.state]
            rows.sort(key=lambda i: i["updated_at"], reverse=True)
            print(json.dumps(rows, indent=1, ensure_ascii=False) if args.json else "\n".join(map(line, rows)) or "no issues")
            return 0
        elif args.command == "show":
            print(json.dumps(get(issues, args.id), indent=1, ensure_ascii=False))
            return 0
        else:
            issues, closed, dropped = prune(issues, now)
            save(path, issues)
            print(f"closed {len(closed)} idle; dropped {len(dropped)} closed; kept {len(issues)}", file=sys.stderr)
            return 0
    except IssueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    save(path, issues)
    print(line(issue))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
