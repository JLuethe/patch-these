"""Normalize discovery feeds. No network. Items are leads, not edition facts."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import re
import xml.etree.ElementTree as ET

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
WINDOW_HOURS = 72
MAX_ITEMS = 300
FIELDS = ("source", "id", "title", "url", "published", "cves", "fetched_at")


def extract_cves(*texts: str | None) -> list[str]:
    found = []
    for text in texts:
        if not text:
            continue
        for cve in CVE_RE.findall(text):
            if cve not in found:
                found.append(cve)
    return found


def to_z(value: str | None) -> str | None:
    """Return an RFC 3339 UTC timestamp, or None when the feed has no usable time."""
    if not value or not str(value).strip():
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node: ET.Element, name: str) -> str:
    for child in node:
        if _local(child.tag) == name and child.text:
            return " ".join(child.text.split())
    return ""


def _https(url: str) -> str | None:
    url = url.strip()
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    if url.startswith("https://") and " " not in url:
        return url
    return None


def _item(source: str, item_id: str, title: str, url: str | None, published: str | None, cves: list[str]) -> dict | None:
    safe_url = _https(url or "")
    if not item_id or not title or safe_url is None:
        return None
    return {
        "source": source,
        "id": item_id[:180],
        "title": title[:300],
        "url": safe_url,
        "published": published,
        "cves": cves,
    }


def parse_feed_xml(payload: bytes | str, source: str) -> list[dict]:
    """Parse an RSS 2.0 or Atom document into normalized leads."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    payload = payload.lstrip(b"\xef\xbb\xbf \n\r\t")
    root = ET.fromstring(payload)
    kind = _local(root.tag)
    if kind == "feed":
        return _parse_atom(root, source)
    return _parse_rss(root, source)


def _parse_atom(root: ET.Element, source: str) -> list[dict]:
    items = []
    for entry in root:
        if _local(entry.tag) != "entry":
            continue
        title = _child_text(entry, "title")
        item_id = _child_text(entry, "id") or title
        published = to_z(_child_text(entry, "published") or _child_text(entry, "updated"))
        url = None
        for child in entry:
            if _local(child.tag) != "link":
                continue
            href = child.attrib.get("href") or ""
            rel = child.attrib.get("rel") or "alternate"
            if rel == "alternate" and href:
                url = href
                break
            if url is None and href:
                url = href
        summary = _child_text(entry, "summary") or _child_text(entry, "content")
        item = _item(source, item_id, title, url, published, extract_cves(title, summary, item_id))
        if item:
            items.append(item)
    return items


def _parse_rss(root: ET.Element, source: str) -> list[dict]:
    items = []
    for node in root.iter():
        if _local(node.tag) != "item":
            continue
        title = _child_text(node, "title")
        url = _child_text(node, "link")
        item_id = _child_text(node, "guid") or url or title
        published = to_z(_child_text(node, "pubDate") or _child_text(node, "date"))
        description = _child_text(node, "description")
        item = _item(source, item_id, title, url, published, extract_cves(title, description, item_id))
        if item:
            items.append(item)
    return items


def parse_kev(payload: dict) -> list[dict]:
    items = []
    for vuln in payload.get("vulnerabilities") or []:
        cve = vuln.get("cveID") or ""
        if not cve:
            continue
        added = vuln.get("dateAdded") or ""
        published = to_z(f"{added}T00:00:00Z") if re.fullmatch(r"\d{4}-\d{2}-\d{2}", added) else None
        item = _item(
            "cisa-kev",
            cve,
            vuln.get("vulnerabilityName") or cve,
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            published,
            [cve],
        )
        if item:
            items.append(item)
    return items


def parse_github_advisories(payload: list) -> list[dict]:
    items = []
    if not isinstance(payload, list):
        return items
    for advisory in payload:
        if not isinstance(advisory, dict):
            continue
        ghsa = advisory.get("ghsa_id") or ""
        title = advisory.get("summary") or ghsa
        cves = []
        if advisory.get("cve_id"):
            cves.append(advisory["cve_id"])
        for cve in extract_cves(title, advisory.get("description")):
            if cve not in cves:
                cves.append(cve)
        item = _item(
            "github-advisories",
            ghsa,
            title,
            advisory.get("html_url"),
            to_z(advisory.get("published_at")),
            cves,
        )
        if item:
            items.append(item)
    return items


def parse_hn(payload: dict) -> list[dict]:
    """Keep the Hacker News discussion URL. Do not store the outbound link.

    The caller asks Algolia for CVE, zero-day, or patch stories. Titles are kept
    as returned; the outbound story URL is not.
    """
    items = []
    for hit in payload.get("hits") or []:
        title = " ".join(str(hit.get("title") or "").split())
        if not title:
            continue
        object_id = str(hit.get("objectID") or "")
        item = _item(
            "hacker-news",
            object_id,
            title,
            f"https://news.ycombinator.com/item?id={object_id}" if object_id else None,
            to_z(hit.get("created_at")),
            extract_cves(title),
        )
        if item:
            items.append(item)
    return items


def dedupe(items: list[dict]) -> list[dict]:
    kept: dict[tuple[str, str], dict] = {}
    for item in items:
        key = (item["source"], item["id"])
        current = kept.get(key)
        if current is None or (item.get("published") or "") > (current.get("published") or ""):
            kept[key] = item
    return list(kept.values())


def within_window(items: list[dict], now: datetime, *, hours: int = WINDOW_HOURS) -> list[dict]:
    start = now - timedelta(hours=hours)
    end = now + timedelta(hours=1)
    selected = []
    for item in items:
        published = item.get("published")
        if not published:
            continue
        stamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if start <= stamp <= end:
            selected.append(item)
    selected.sort(key=lambda item: (item.get("published") or "", item["source"], item["id"]), reverse=True)
    return selected[:MAX_ITEMS]


def new_kev_entries(current: list[dict], seen_ids: set[str]) -> list[dict]:
    return [item for item in current if item["id"] not in seen_ids]


def apply_fetched_at(items: list[dict], previous: list[dict], fetched_at: str) -> list[dict]:
    old = {(item["source"], item["id"]): item.get("fetched_at") for item in previous}
    stamped = []
    for item in items:
        copy = dict(item)
        copy["fetched_at"] = old.get((item["source"], item["id"]), fetched_at)
        stamped.append({key: copy.get(key) for key in FIELDS})
    return stamped


def content_signature(items: list[dict]) -> list[tuple]:
    """Identity of a cache ignoring fetched_at, so a quiet run does not rewrite the file."""
    return sorted(
        (item["source"], item["id"], item["title"], item["url"], item.get("published"), tuple(item.get("cves") or []))
        for item in items
    )


STALE_AFTER = timedelta(hours=24)


def hn_cve_years(now: datetime) -> list[int]:
    """CVE id years to search on Hacker News: this year and last year.

    CVE ids carry the year they were reserved, so last year's ids keep
    appearing well into the new year. Both are always searched.
    """
    return [now.year, now.year - 1]


def update_source_status(previous: dict, ok: list[str], failed: dict[str, str], fetched_at: str) -> dict:
    """Per-source health. last_ok carries forward when a source fails this run."""
    sources = {name: dict(record) for name, record in (previous.get("sources") or {}).items()}
    for name in ok:
        record = sources.setdefault(name, {"tracked_since": fetched_at})
        record.update(last_ok=fetched_at, last_attempt=fetched_at, last_error=None)
    for name, error in failed.items():
        record = sources.setdefault(name, {"tracked_since": fetched_at, "last_ok": None})
        record.setdefault("last_ok", None)
        record.update(last_attempt=fetched_at, last_error=error)
    return {"checked_at": fetched_at, "stale_after_hours": int(STALE_AFTER.total_seconds() // 3600), "sources": {key: sources[key] for key in sorted(sources)}}


def stale_sources(status: dict, now: datetime, *, after: timedelta = STALE_AFTER) -> list[tuple[str, str | None]]:
    """Sources whose last success (or tracking start, if never) is older than `after`."""
    stale = []
    for name, record in (status.get("sources") or {}).items():
        reference = record.get("last_ok") or record.get("tracked_since")
        if not reference:
            continue
        stamp = datetime.fromisoformat(reference.replace("Z", "+00:00"))
        if now - stamp > after:
            stale.append((name, record.get("last_ok")))
    return stale
