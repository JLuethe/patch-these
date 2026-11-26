#!/usr/bin/env python3
"""Remember which social posts the editorial routine has already handled.

The store is a small JSON file on the routine's machine, never in the
repository, so recording posts does not create commits or Pages deploys:

  $PT_STATE_DIR/seen-posts.json   (PT_STATE_DIR defaults to /workspace/pt-state)

Ids are normalized per platform:
  x:<status id>                    from https://x.com/<user>/status/<id> (twitter.com too)
  bsky:<at-uri>                    from at://did:.../app.bsky.feed.post/<rkey>
  bsky:<handle>/<rkey>             from https://bsky.app/profile/<handle>/post/<rkey>
  masto:<status url>               from https://<host>/@<user>/<id> and similar

Usage:
  python scripts/seen_posts.py filter < candidates.txt      # print the unseen candidates
  python scripts/seen_posts.py filter --file candidates.json
  python scripts/seen_posts.py add URL_OR_ID [...]          # or pipe them on stdin
  python scripts/seen_posts.py prune                        # drop entries older than 14 days
  python scripts/seen_posts.py normalize URL_OR_ID [...]

Input for filter and add is either a JSON list (of strings, or of objects with
an "id", "url" or "uri" field) or one URL or id per line. filter prints the
unseen entries in the same form it read them. add and filter both prune
entries older than PT_SEEN_DAYS days (default 14).
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
from urllib.parse import urlsplit

DEFAULT_STATE_DIR = "/workspace/pt-state"
DEFAULT_DAYS = 14
X_HOSTS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com", "mobile.x.com"}


def state_path() -> Path:
    return Path(os.environ.get("PT_STATE_DIR") or DEFAULT_STATE_DIR) / "seen-posts.json"


def normalize(value: str) -> str | None:
    """A stable per-platform id for a post URL, AT URI, or already-normalized id."""
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith("x:"):
        rest = value[2:]
        return f"x:{rest}" if rest.isdigit() else None
    if value.startswith("masto:"):
        key = normalize(value[len("masto:"):])
        return key if key and key.startswith("masto:") else None
    if value.startswith("bsky:"):
        rest = value[len("bsky:"):]
        if rest.startswith("at://"):
            return normalize(rest)
        match = re.fullmatch(r"([^/\s]+)/([A-Za-z0-9]+)", rest)
        return f"bsky:{match.group(1).lower()}/{match.group(2)}" if match else None
    if value.startswith("at://"):
        match = re.fullmatch(r"at://([^/\s]+)/app\.bsky\.feed\.post/([A-Za-z0-9]+)", value)
        return f"bsky:at://{match.group(1)}/app.bsky.feed.post/{match.group(2)}" if match else None
    if not value.startswith(("https://", "http://")):
        return None
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    if host in X_HOSTS:
        match = re.search(r"/status(?:es)?/(\d+)", path)
        return f"x:{match.group(1)}" if match else None
    if host in {"bsky.app", "www.bsky.app"}:
        match = re.fullmatch(r"/profile/([^/]+)/post/([A-Za-z0-9]+)", path)
        return f"bsky:{match.group(1).lower()}/{match.group(2)}" if match else None
    if re.search(r"/(?:@[^/]+|users/[^/]+/statuses|notice|objects)/[A-Za-z0-9]+$", path):
        return f"masto:https://{host}{path}"
    return None


def _entry_value(entry) -> str:
    if isinstance(entry, dict):
        return str(entry.get("id") or entry.get("url") or entry.get("uri") or "")
    return str(entry)


def read_entries(text: str) -> tuple[list, bool]:
    """Entries and whether they came as JSON."""
    stripped = text.strip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("expected a JSON list")
        return data, True
    return [line.strip() for line in text.splitlines() if line.strip()], False


def load(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    return dict(json.loads(path.read_text(encoding="utf-8")).get("posts") or {})


def save(path: Path, posts: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"posts": {key: posts[key] for key in sorted(posts)}}, indent=1) + "\n"
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        handle.write(payload)
    os.replace(handle.name, path)


def prune(posts: dict[str, str], now: datetime, days: int) -> dict[str, str]:
    cutoff = now - timedelta(days=days)
    kept = {}
    for key, when in posts.items():
        try:
            if datetime.fromisoformat(when.replace("Z", "+00:00")) >= cutoff:
                kept[key] = when
        except (AttributeError, ValueError):
            continue
    return kept


def unseen(entries: list, posts: dict[str, str]) -> list:
    """Entries whose normalized id is not stored. Unrecognized entries are kept, to be safe."""
    result, emitted = [], set()
    for entry in entries:
        key = normalize(_entry_value(entry))
        if key is not None and (key in posts or key in emitted):
            continue
        if key is not None:
            emitted.add(key)
        result.append(entry)
    return result


def add(posts: dict[str, str], values: list[str], stamp: str) -> tuple[dict[str, str], list[str]]:
    added, skipped = dict(posts), []
    for value in values:
        key = normalize(value)
        if key is None:
            skipped.append(value)
            continue
        added.setdefault(key, stamp)
    return added, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["filter", "add", "prune", "normalize"])
    parser.add_argument("values", nargs="*", help="Post URLs or ids (add, normalize). Read from stdin when omitted.")
    parser.add_argument("--file", type=Path, help="Read candidates from this file instead of stdin.")
    parser.add_argument("--days", type=int, default=int(os.environ.get("PT_SEEN_DAYS") or DEFAULT_DAYS))
    args = parser.parse_args(argv)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    path = state_path()

    def entries() -> tuple[list, bool]:
        if args.values:
            return list(args.values), False
        return read_entries(args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read())

    if args.command == "normalize":
        for value in entries()[0]:
            print(normalize(_entry_value(value)) or f"unrecognized: {_entry_value(value)}")
        return 0
    stored = load(path)
    posts = prune(stored, now, args.days)
    if args.command == "prune":
        save(path, posts)
        print(f"kept {len(posts)}; pruned {len(stored) - len(posts)}", file=sys.stderr)
        return 0
    if args.command == "filter":
        items, as_json = entries()
        fresh = unseen(items, posts)
        if posts != stored:
            save(path, posts)
        print(json.dumps(fresh, indent=1, ensure_ascii=False) if as_json else "\n".join(map(str, fresh)))
        print(f"{len(fresh)} unseen of {len(items)}", file=sys.stderr)
        return 0
    values = [_entry_value(entry) for entry in entries()[0]]
    posts, skipped = add(posts, values, stamp)
    save(path, posts)
    for value in skipped:
        print(f"not a recognized post URL or id, skipped: {value}", file=sys.stderr)
    print(f"recorded {len(values) - len(skipped)}; stored {len(posts)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
