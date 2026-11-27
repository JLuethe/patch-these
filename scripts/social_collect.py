#!/usr/bin/env python3
"""Collect early-signal candidates from Bluesky and Mastodon, and keep a run report.

Reads social/queries.json and social/watchlist.json, runs every Bluesky and
Mastodon query newest first over the window since that query's checkpoint
(minus a 10-minute overlap), and writes, under $PT_STATE_DIR (default
/workspace/pt-state, never the repository):

  social-candidates.json   candidate posts, newest first, deduplicated; feed it
                           to `seen_posts.py filter --file`
  social-report.json       one row per query: state, pages, posts, window
  social-checkpoints.json  per-query checkpoints

Each query reads at most its page budget (never more than 8 pages). Its state is
  ok          the window was covered and posts were kept
  empty       the window was covered and nothing was kept
  incomplete  the page budget ran out before the window was covered
  failed      the first request failed (the checkpoint does not move); a
              later page failing makes the query incomplete, with its error

X is searched by the routine with its own tool. `plan` prints each X query
with its start_time, and `record` adds an X query's result (and its candidate
URLs) to the same report, candidates file and checkpoints.

Usage:
  python scripts/social_collect.py collect [--platform all|bluesky|mastodon] [--since ISO] [--dry-run]
  python scripts/social_collect.py plan [--platform x]
  python scripts/social_collect.py record --id x:zero_day --state ok --pages 1 --posts 18 [--candidates FILE]
  python scripts/social_collect.py summary

The Mastodon token (MASTODON_TOKEN) is read-only, sent only to mastodon.social,
and never printed.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import html
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from seen_posts import normalize  # noqa: E402

DEFAULT_STATE_DIR = "/workspace/pt-state"
STATES = ("ok", "empty", "incomplete", "failed")
BSKY_SEARCH = "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts"
BSKY_AUTHOR_FEED = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"
TOKEN_HOST = "mastodon.social"
USER_AGENT = "patch-these-social-collect/1 (+https://github.com/JLuethe/patch-these)"
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


class FetchError(Exception):
    pass


def http_get(url: str, token: str | None = None) -> object:
    """GET a JSON document. Tests replace this function."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with urlopen(Request(url, headers=headers), timeout=25) as response:
            return json.load(response)
    except HTTPError as error:
        raise FetchError(f"HTTP {error.code}") from None
    except (URLError, TimeoutError, OSError, ValueError) as error:
        raise FetchError(type(error).__name__) from None


# ---------- time and files ----------

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def state_dir() -> Path:
    return Path(os.environ.get("PT_STATE_DIR") or DEFAULT_STATE_DIR)


def read_json(path: Path, default):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    os.replace(handle.name, path)


def load_config(root: Path = ROOT) -> tuple[dict, dict]:
    queries = json.loads((root / "social" / "queries.json").read_text(encoding="utf-8"))
    watchlist = json.loads((root / "social" / "watchlist.json").read_text(encoding="utf-8"))
    return queries, watchlist


# ---------- posts and matching ----------

@dataclass
class Post:
    url: str
    platform: str
    author: str
    created_at: datetime
    text: str
    bot: bool = False


def plain_text(markup: str) -> str:
    text = re.sub(r"<br\s*/?>|</p>", " ", markup or "")
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", text))).strip()


def slug(term: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", term.lower()).strip("-")


def term_pattern(term: str) -> re.Pattern:
    """Case-insensitive whole-word match; a space or hyphen in the term matches either."""
    words = re.split(r"[\s\-]+", term.strip('"').strip())
    return re.compile(r"(?<![A-Za-z0-9])" + r"[\s\-]+".join(map(re.escape, words)) + r"(?![A-Za-z0-9])", re.I)


def matches_family(text: str, family: dict) -> bool:
    if not any(term_pattern(term).search(text) for term in family["terms"]):
        return False
    if family.get("contextual"):
        return any(term_pattern(term).search(text) for term in family.get("context_terms") or [])
    return True


def matching_families(text: str, families: dict) -> list[str]:
    found = [name for name, family in families.items() if matches_family(text, family)]
    if CVE_ID.search(text) and "catchup" in families and "catchup" not in found:
        found.append("catchup")
    return found


# ---------- queries ----------

@dataclass
class Query:
    id: str
    platform: str
    kind: str
    description: str
    max_pages: int
    fetch: Callable[[object], tuple[list[Post], object]]
    family: str | None = None
    keep: Callable[[Post], list[str]] | None = None  # families matched, or [] to drop
    watchlist: bool = False


def bluesky_post(item: dict) -> Post | None:
    post = item.get("post", item)
    if item.get("reason"):  # a repost or pin in an author feed
        return None
    author = post.get("author") or {}
    handle = author.get("handle") or author.get("did") or ""
    rkey = str(post.get("uri", "")).rsplit("/", 1)[-1]
    when = parse_time(post.get("indexedAt")) or parse_time((post.get("record") or {}).get("createdAt"))
    if not handle or not rkey or when is None:
        return None
    text = (post.get("record") or {}).get("text") or ""
    return Post(f"https://bsky.app/profile/{handle}/post/{rkey}", "bluesky", handle, when, re.sub(r"\s+", " ", text).strip())


def mastodon_post(status: dict) -> Post | None:
    if status.get("reblog"):
        return None
    account = status.get("account") or {}
    when = parse_time(status.get("created_at"))
    url = status.get("url") or status.get("uri")
    if not url or when is None:
        return None
    return Post(url, "mastodon", account.get("acct") or "", when, plain_text(status.get("content") or ""), bool(account.get("bot")))


def bluesky_search(term: str, since: datetime, limit: int):
    """Unauthenticated search refuses its own cursor (HTTP 403, tested 2026-11-27),
    so page by time instead: the next page ends where this one's oldest post is."""
    def fetch(cursor):
        params = {"q": term, "sort": "latest", "limit": limit, "since": iso(since)}
        if cursor:
            params["until"] = cursor
        data = http_get(f"{BSKY_SEARCH}?{urlencode(params)}")
        raw = data.get("posts") or []
        posts = [p for p in (bluesky_post(item) for item in raw) if p]
        oldest = min((str(item.get("indexedAt")) for item in raw if item.get("indexedAt")), default=None)
        more = len(raw) >= limit and oldest is not None and oldest != cursor
        return posts, oldest if more else None
    return fetch


def bluesky_author(handle: str, limit: int, feed_filter: str):
    def fetch(cursor):
        params = {"actor": handle, "limit": limit, "filter": feed_filter}
        if cursor:
            params["cursor"] = cursor
        data = http_get(f"{BSKY_AUTHOR_FEED}?{urlencode(params)}")
        posts = [p for p in (bluesky_post(item) for item in data.get("feed") or []) if p]
        return posts, data.get("cursor") if len(data.get("feed") or []) >= limit else None
    return fetch


def mastodon_timeline(url: str, limit: int, token: str | None = None):
    def fetch(cursor):
        params = {"limit": limit}
        if cursor:
            params["max_id"] = cursor
        joiner = "&" if "?" in url else "?"
        data = http_get(f"{url}{joiner}{urlencode(params)}", token)
        statuses = data if isinstance(data, list) else []
        posts = [p for p in (mastodon_post(s) for s in statuses) if p]
        next_cursor = statuses[-1].get("id") if len(statuses) >= limit and statuses else None
        return posts, next_cursor
    return fetch


def mastodon_search(host: str, term: str, limit: int, token: str | None):
    def fetch(cursor):
        offset = int(cursor or 0)
        params = {"q": term, "type": "statuses", "limit": limit, "resolve": "false", "offset": offset}
        data = http_get(f"https://{host}/api/v2/search?{urlencode(params)}", token)
        statuses = (data or {}).get("statuses") or []
        posts = [p for p in (mastodon_post(s) for s in statuses) if p]
        return posts, offset + limit if len(statuses) >= limit else None
    return fetch


def mastodon_account_statuses(acct: str, limit: int, cache: dict):
    user, host = acct.split("@", 1)

    def fetch(cursor):
        account_id = cache.get(acct.lower())
        if not account_id:
            found = http_get(f"https://{host}/api/v1/accounts/lookup?{urlencode({'acct': user})}")
            account_id = str((found or {}).get("id") or "")
            if not account_id:
                raise FetchError("account not found")
            cache[acct.lower()] = account_id
        url = f"https://{host}/api/v1/accounts/{account_id}/statuses?exclude_replies=true&exclude_reblogs=true"
        return mastodon_timeline(url, limit)(cursor)
    return fetch


def build_queries(queries: dict, watchlist: dict, since_for: Callable[[str], datetime], token: str | None,
                  account_cache: dict, platforms: set[str]) -> list[Query]:
    families = queries["families"]
    ceiling = int(queries["rules"]["page_ceiling"])
    result: list[Query] = []

    def pages(budgets: dict, name: str) -> int:
        return min(ceiling, int(budgets.get(name, budgets.get("default", 1))))

    def family_keep(name: str):
        family = families[name]
        return (lambda post: [name] if matches_family(post.text, family) else []) if family.get("contextual") else (lambda post: [name])

    if "bluesky" in platforms:
        bsky = queries["bluesky"]
        for name in bsky["families"]:
            for term in families[name]["terms"]:
                qid = f"bluesky:{name}:{slug(term)}"
                result.append(Query(qid, "bluesky", "search", term, pages(bsky["max_pages"], name),
                                    bluesky_search(term, since_for(qid), int(bsky["limit"])), name, family_keep(name)))
        bw = watchlist["bluesky"]
        for account in bw["accounts"]:
            qid = f"bluesky:watch:{account['handle']}"
            result.append(Query(qid, "bluesky", "watchlist", account["handle"], min(ceiling, int(bw["max_pages"])),
                                bluesky_author(account["handle"], int(bw["limit"]), bw["filter"]), watchlist=True))
    if "mastodon" in platforms:
        for host, config in queries["mastodon"]["instances"].items():
            host_token = token if host == TOKEN_HOST else None  # never send the token elsewhere
            search = config.get("search")
            if search and host_token:
                for name in search["families"]:
                    for term in families[name]["terms"]:
                        qid = f"{host}:search:{name}:{slug(term)}"
                        result.append(Query(qid, "mastodon", "search", term, pages(search["max_pages"], name),
                                            mastodon_search(host, term, int(search["limit"]), host_token), name, family_keep(name)))
            for tag in config.get("tags") or []:
                qid = f"{host}:tag:{tag}"
                result.append(Query(qid, "mastodon", "tag", f"#{tag}", min(ceiling, int(config.get("tag_max_pages", 1))),
                                    mastodon_timeline(f"https://{host}/api/v1/timelines/tag/{tag}", 40)))
            local = config.get("local_timeline")
            if local:
                qid = f"{host}:local"
                keep = (lambda post: matching_families(post.text, families)) if local.get("match_families") else None
                result.append(Query(qid, "mastodon", "local", f"{host} local timeline", min(ceiling, int(local["max_pages"])),
                                    mastodon_timeline(f"https://{host}/api/v1/timelines/public?local=true", int(local["limit"])),
                                    keep=keep))
        mw = watchlist["mastodon"]
        for account in mw["accounts"]:
            qid = f"mastodon:watch:{account['acct'].lower()}"
            result.append(Query(qid, "mastodon", "watchlist", account["acct"], min(ceiling, int(mw["max_pages"])),
                                mastodon_account_statuses(account["acct"], int(mw["limit"]), account_cache), watchlist=True))
    return result


# ---------- running ----------

@dataclass
class Outcome:
    row: dict
    kept: list[tuple[Post, list[str]]] = field(default_factory=list)


def run_query(query: Query, since: datetime, skip_bots: bool = True, pause: float = 0.0) -> Outcome:
    row = {"id": query.id, "platform": query.platform, "kind": query.kind, "query": query.description,
           "family": query.family, "watchlist": query.watchlist, "window_start": iso(since),
           "max_pages": query.max_pages, "pages": 0, "posts": 0, "kept": 0, "oldest_reached": None,
           "state": "failed", "error": None}
    outcome = Outcome(row)
    cursor, covered = None, False
    oldest: datetime | None = None
    try:
        while row["pages"] < query.max_pages:
            if row["pages"] and pause:
                time.sleep(pause)
            posts, cursor = query.fetch(cursor)
            row["pages"] += 1
            row["posts"] += len(posts)
            for post in posts:
                oldest = post.created_at if oldest is None or post.created_at < oldest else oldest
                if post.created_at < since or (skip_bots and post.bot):
                    continue
                families = query.keep(post) if query.keep else ([query.family] if query.family else [])
                if query.keep and not families:
                    continue
                outcome.kept.append((post, families))
            if not posts or cursor is None or (oldest is not None and oldest < since):
                covered = True
                break
    except FetchError as error:
        row["error"] = str(error)
        # A failure after at least one page keeps what was read and reports the gap.
        row["state"] = "incomplete" if row["pages"] else "failed"
        row["oldest_reached"] = iso(oldest) if oldest else None
        row["kept"] = len(outcome.kept)
        return outcome
    row["oldest_reached"] = iso(oldest) if oldest else None
    row["kept"] = len(outcome.kept)
    row["state"] = ("ok" if outcome.kept else "empty") if covered else "incomplete"
    return outcome


def window_start(checkpoints: dict, qid: str, now: datetime, rules: dict, since: datetime | None = None) -> datetime:
    if since is not None:
        return since
    saved = parse_time((checkpoints.get(qid) or {}).get("checkpoint"))
    if saved is None:
        return now - timedelta(hours=float(rules["default_lookback_hours"]))
    return saved - timedelta(minutes=float(rules["overlap_minutes"]))


def merge_candidates(existing: list[dict], new_rows: list[dict]) -> list[dict]:
    by_key: dict[str, dict] = {}
    order: list[str] = []
    for row in existing + new_rows:
        key = normalize(row.get("url", "")) or row.get("url", "")
        if key in by_key:
            current = by_key[key]
            for listed in ("queries", "families"):
                current[listed] = sorted(set(current.get(listed) or []) | set(row.get(listed) or []))
            current["watchlist"] = bool(current.get("watchlist") or row.get("watchlist"))
            continue
        by_key[key] = dict(row)
        order.append(key)
    rows = [by_key[key] for key in order]
    rows.sort(key=lambda row: row.get("created_at") or "", reverse=True)
    return rows


def totals(rows: list[dict]) -> dict:
    counts = {state: 0 for state in STATES}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    return counts


def update_checkpoints(checkpoints: dict, rows: list[dict], started: str) -> dict:
    updated = dict(checkpoints)
    for row in rows:
        entry = dict(updated.get(row["id"]) or {})
        entry["last_state"] = row["state"]
        entry["last_run"] = started
        if row["state"] != "failed":
            entry["checkpoint"] = started
        updated[row["id"]] = entry
    return updated


def collect(platforms: set[str], since: datetime | None = None, dry_run: bool = False,
            root: Path = ROOT, pause: float = 0.2, now: datetime | None = None) -> dict:
    queries, watchlist = load_config(root)
    directory = state_dir()
    checkpoints = read_json(directory / "social-checkpoints.json", {})
    cache_path = directory / "mastodon-accounts.json"
    account_cache = read_json(cache_path, {})
    now = now or utcnow()
    started = iso(now)
    token = os.environ.get("MASTODON_TOKEN") or None
    rules = queries["rules"]
    query_list = build_queries(queries, watchlist, lambda qid: window_start(checkpoints, qid, now, rules, since),
                               token, account_cache, platforms)
    rows, candidates = [], []
    skip_bots = bool(queries["mastodon"].get("skip_bot_accounts", True))
    for query in query_list:
        outcome = run_query(query, window_start(checkpoints, query.id, now, rules, since), skip_bots, pause)
        rows.append(outcome.row)
        for post, families in outcome.kept:
            candidates.append({"url": post.url, "platform": post.platform, "author": post.author,
                               "created_at": iso(post.created_at), "text": post.text[:500],
                               "queries": [query.id], "families": sorted(set(families)), "watchlist": query.watchlist})
        if pause:
            time.sleep(pause)
    if "mastodon" in platforms and not token:
        rows.append({"id": f"{TOKEN_HOST}:search", "platform": "mastodon", "kind": "search", "query": "family terms",
                     "family": None, "watchlist": False, "window_start": None, "max_pages": 0, "pages": 0, "posts": 0,
                     "kept": 0, "oldest_reached": None, "state": "failed", "error": "MASTODON_TOKEN not set"})
    candidates = merge_candidates([], candidates)
    report = {"run_started_at": started, "finished_at": iso(utcnow()), "platforms": sorted(platforms),
              "queries": rows, "totals": totals(rows), "candidates": len(candidates)}
    if not dry_run:
        write_json(directory / "social-candidates.json", candidates)
        write_json(directory / "social-report.json", report)
        write_json(directory / "social-checkpoints.json", update_checkpoints(checkpoints, rows, started))
        write_json(cache_path, account_cache)
    return report


# ---------- X: plan and record ----------

def x_plan(now: datetime | None = None, root: Path = ROOT) -> list[dict]:
    queries, watchlist = load_config(root)
    checkpoints = read_json(state_dir() / "social-checkpoints.json", {})
    now = now or utcnow()
    rules = queries["rules"]
    plan = [{"id": f"x:{q['id']}", "family": q["family"], "query": q["query"], "max_pages": q["max_pages"],
             "start_time": iso(window_start(checkpoints, f"x:{q['id']}", now, rules))} for q in queries["x"]["queries"]]
    plan.append({"id": "x:watchlist", "family": None, "query": watchlist["x"]["query"],
                 "max_pages": watchlist["x"]["max_pages"], "start_time": iso(window_start(checkpoints, "x:watchlist", now, rules))})
    return plan


def read_candidate_file(path: str) -> list:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if stripped.startswith("["):
        return json.loads(stripped)
    return [line.strip() for line in text.splitlines() if line.strip()]


def record(args, now: datetime | None = None) -> dict:
    directory = state_dir()
    now = now or utcnow()
    report = read_json(directory / "social-report.json", {})
    started = parse_time(report.get("run_started_at"))
    if started is None or now - started > timedelta(hours=3):
        report = {"run_started_at": iso(now), "platforms": [], "queries": [], "candidates": 0}
        started = now
    row = {"id": args.id, "platform": args.id.split(":", 1)[0], "kind": "watchlist" if args.id.endswith(":watchlist") else "search",
           "query": args.query, "family": args.family, "watchlist": args.id.endswith(":watchlist"),
           "window_start": args.window_start, "max_pages": args.max_pages, "pages": args.pages, "posts": args.posts,
           "kept": args.kept if args.kept is not None else args.posts, "oldest_reached": args.oldest,
           "state": args.state, "error": args.error}
    report["queries"] = [r for r in report.get("queries", []) if r["id"] != args.id] + [row]
    if row["platform"] not in report.setdefault("platforms", []):
        report["platforms"].append(row["platform"])
    report["totals"] = totals(report["queries"])
    report["finished_at"] = iso(now)
    candidates = read_json(directory / "social-candidates.json", []) if report["queries"][:-1] else []
    if args.candidates:
        new_rows = []
        for entry in read_candidate_file(args.candidates):
            item = dict(entry) if isinstance(entry, dict) else {"url": str(entry)}
            item.setdefault("platform", row["platform"])
            item["queries"] = sorted(set(item.get("queries") or []) | {args.id})
            item["families"] = sorted(set(item.get("families") or []) | ({args.family} if args.family else set()))
            item["watchlist"] = bool(item.get("watchlist") or row["watchlist"])
            new_rows.append(item)
        candidates = merge_candidates(candidates, new_rows)
    report["candidates"] = len(candidates)
    write_json(directory / "social-candidates.json", candidates)
    write_json(directory / "social-report.json", report)
    checkpoints = read_json(directory / "social-checkpoints.json", {})
    write_json(directory / "social-checkpoints.json", update_checkpoints(checkpoints, [row], iso(started)))
    return row


def summary_lines(report: dict) -> list[str]:
    if not report:
        return ["no report yet"]
    lines = [f"run started {report.get('run_started_at')}; candidates {report.get('candidates', 0)}; "
             + ", ".join(f"{state} {count}" for state, count in (report.get("totals") or {}).items())]
    for row in report.get("queries", []):
        if row["state"] in ("incomplete", "failed"):
            detail = row.get("error") or f"oldest reached {row.get('oldest_reached')}, window start {row.get('window_start')}"
            lines.append(f"  {row['state']:<10} {row['id']} ({row['pages']}/{row['max_pages']} pages): {detail}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect", help="Run the Bluesky and Mastodon queries and the watchlist.")
    c.add_argument("--platform", choices=["all", "bluesky", "mastodon"], default="all")
    c.add_argument("--since", help="Override every window start (ISO time).")
    c.add_argument("--dry-run", action="store_true", help="Print the report; write no state.")
    p = sub.add_parser("plan", help="Print the X queries with their start_time and page budget.")
    p.add_argument("--platform", choices=["x"], default="x")
    r = sub.add_parser("record", help="Record one X query's result in the run report.")
    r.add_argument("--id", required=True, help="x:<family> or x:watchlist, as printed by plan.")
    r.add_argument("--state", required=True, choices=STATES)
    r.add_argument("--pages", type=int, required=True)
    r.add_argument("--posts", type=int, required=True)
    r.add_argument("--kept", type=int)
    r.add_argument("--max-pages", type=int)
    r.add_argument("--query")
    r.add_argument("--family")
    r.add_argument("--window-start")
    r.add_argument("--oldest", help="created_at of the oldest post reached.")
    r.add_argument("--error")
    r.add_argument("--candidates", help="File (or -) with the candidate post URLs, one per line or a JSON list.")
    sub.add_parser("summary", help="Print the last report's totals and its incomplete or failed queries.")
    args = parser.parse_args(argv)

    if args.command == "collect":
        platforms = {"bluesky", "mastodon"} if args.platform == "all" else {args.platform}
        since = parse_time(args.since) if args.since else None
        if args.since and since is None:
            parser.error("--since must be an ISO time")
        report = collect(platforms, since, args.dry_run)
        if args.dry_run:
            print(json.dumps(report, indent=1))
        for line in summary_lines(report):
            print(line, file=sys.stderr)
        return 0
    if args.command == "plan":
        print(json.dumps(x_plan(), indent=1))
        return 0
    if args.command == "record":
        if not args.id.startswith("x:"):
            parser.error("record is for X queries (x:<family> or x:watchlist)")
        row = record(args)
        print(f"recorded {row['id']}: {row['state']}", file=sys.stderr)
        return 0
    for line in summary_lines(read_json(state_dir() / "social-report.json", {})):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
