#!/usr/bin/env python3
"""Fetch public discovery feeds into feeds/cache/. No edition facts are decided here.

Confirmed working, and included:
  cisa-kev              https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  msrc                  https://api.msrc.microsoft.com/update-guide/rss
  chrome-releases       https://chromereleases.googleblog.com/feeds/posts/default
  mozilla-security      https://blog.mozilla.org/security/feed/
  cisco-psirt           https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
  fortinet-psirt        https://filestore.fortinet.com/fortiguard/rss/ir.xml
  palo-alto             https://security.paloaltonetworks.com/rss.xml
  ubuntu-usn            https://ubuntu.com/security/notices/rss.xml
  arch-linux            https://security.archlinux.org/advisory/feed.atom
  jenkins-advisories    https://www.jenkins.io/security/advisories/rss.xml
  github-advisories     https://api.github.com/advisories (reviewed, critical and high)
  hacker-news           https://hn.algolia.com/api/v1/search_by_date

Skipped after a check this session: nginx.org has no advisory feed; Apple's
security-release RSS candidates returned HTML; Mozilla's MFSA feed URL 404s
(the security blog feed is used instead); the Arch tracker JSON has no
publication dates, so the dated Atom feed from the same tracker is used; the
OSV API needs a package name and has no confirmed recent-list endpoint.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from patchthese.feedcache import (  # noqa: E402
    apply_fetched_at,
    content_signature,
    new_kev_entries,
    parse_feed_xml,
    parse_github_advisories,
    parse_hn,
    parse_kev,
    dedupe,
    within_window,
)

USER_AGENT = "patch-these-feed-cache/1.0 (+https://github.com/JLuethe/patch-these)"
FEEDS = (
    ("msrc", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("chrome-releases", "https://chromereleases.googleblog.com/feeds/posts/default"),
    ("mozilla-security", "https://blog.mozilla.org/security/feed/"),
    ("cisco-psirt", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("fortinet-psirt", "https://filestore.fortinet.com/fortiguard/rss/ir.xml"),
    ("palo-alto", "https://security.paloaltonetworks.com/rss.xml"),
    ("ubuntu-usn", "https://ubuntu.com/security/notices/rss.xml"),
    ("arch-linux", "https://security.archlinux.org/advisory/feed.atom"),
    ("jenkins-advisories", "https://www.jenkins.io/security/advisories/rss.xml"),
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_URLS = (
    "https://api.github.com/advisories?type=reviewed&severity=critical&per_page=50",
    "https://api.github.com/advisories?type=reviewed&severity=high&per_page=50",
)
def hn_urls(now: datetime) -> tuple[str, ...]:
    cutoff = int((now - timedelta(hours=72)).timestamp())
    return (
        f"https://hn.algolia.com/api/v1/search_by_date?query=CVE-2026&tags=story&hitsPerPage=15&numericFilters=created_at_i>{cutoff}",
        f"https://hn.algolia.com/api/v1/search_by_date?query=zero-day&tags=story&hitsPerPage=10&numericFilters=created_at_i>{cutoff}",
        f"https://hn.algolia.com/api/v1/search_by_date?query=security%20patch&tags=story&hitsPerPage=10&numericFilters=created_at_i>{cutoff}",
    )
MAX_BYTES = 5_000_000


def fetch(url: str, token: str | None = None, timeout: float = 25) -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/atom+xml, application/rss+xml, */*"}
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError(f"response larger than {MAX_BYTES} bytes")
    return payload


def _read_json(path: Path, default):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_cache(output: Path, *, token: str | None, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    fetched_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    collected = []
    failures = []

    try:
        kev_items = parse_kev(json.loads(fetch(KEV_URL).decode("utf-8")))
    except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError) as error:
        print(f"cisa-kev failed: {type(error).__name__}", file=sys.stderr)
        return 1

    seen_path = output / "kev-seen.json"
    previous_seen = set(_read_json(seen_path, {"ids": []}).get("ids") or [])
    baseline = not seen_path.is_file()
    fresh_kev = [] if baseline else new_kev_entries(kev_items, previous_seen)
    collected.extend(within_window(kev_items, now))
    collected.extend(fresh_kev)

    for source, url in FEEDS:
        try:
            collected.extend(parse_feed_xml(fetch(url), source))
        except (OSError, HTTPError, URLError, ValueError, ET.ParseError) as error:
            failures.append(source)
            print(f"{source} failed: {type(error).__name__}", file=sys.stderr)

    for url in GITHUB_URLS:
        try:
            collected.extend(parse_github_advisories(json.loads(fetch(url, token=token).decode("utf-8"))))
        except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError) as error:
            failures.append("github-advisories")
            print(f"github-advisories failed: {type(error).__name__}", file=sys.stderr)
            break

    for url in hn_urls(now):
        try:
            collected.extend(parse_hn(json.loads(fetch(url).decode("utf-8"))))
        except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError) as error:
            failures.append("hacker-news")
            print(f"hacker-news failed: {type(error).__name__}", file=sys.stderr)
            break

    latest_path = output / "latest.json"
    previous_latest = _read_json(latest_path, {"items": []}).get("items") or []
    windowed = within_window(dedupe(collected), now)
    # Keep a brand-new KEV row even when its dateAdded is older than the window.
    for item in fresh_kev:
        if not any(existing["source"] == item["source"] and existing["id"] == item["id"] for existing in windowed):
            windowed.append(item)
    stamped = apply_fetched_at(windowed, previous_latest, fetched_at)
    latest = {"fetched_at": fetched_at, "window_hours": 72, "items": stamped}
    kev_new = {
        "fetched_at": fetched_at,
        "baseline": baseline,
        "entries": apply_fetched_at(fresh_kev, [], fetched_at),
    }
    seen = {"ids": sorted(item["id"] for item in kev_items)}

    changed = False
    if content_signature(stamped) != content_signature(previous_latest):
        _write_json(latest_path, latest)
        changed = True
    kev_path = output / "kev-new.json"
    if fresh_kev or not kev_path.is_file():
        _write_json(kev_path, kev_new)
        changed = True
    if seen["ids"] != sorted(previous_seen):
        _write_json(seen_path, seen)
        changed = True

    print(
        f"sources ok; failures={sorted(set(failures)) or 'none'}; "
        f"window_items={len(stamped)}; new_kev={len(fresh_kev)}; baseline={baseline}; changed={changed}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "feeds" / "cache")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and print counts without writing the cache.")
    args = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN") or None
    if args.dry_run:
        scratch = args.output / ".dry-run"
        code = build_cache(scratch, token=token)
        if scratch.exists():
            import shutil
            shutil.rmtree(scratch)
        return code
    return build_cache(args.output, token=token)


if __name__ == "__main__":
    raise SystemExit(main())
