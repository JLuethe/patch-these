"""Shared publication labels and URL/date handling."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from datetime import date, datetime
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

PRIORITIES = {"act_now": "Act now", "act_soon": "Act soon", "monitor": "Monitor"}
PRIORITY_ORDER = {key: index for index, key in enumerate(PRIORITIES)}
AUDIENCES = {"applications_and_servers": "Apps & servers", "end_users": "My computer", "both": "Everyone & operators"}
ACTIONS = {"update": "Update", "mitigate": "Mitigate", "replace": "Replace", "rotate": "Rotate credentials", "investigate": "Check applicability"}
REPO = "https://github.com/JLuethe/patch-these"
DESCRIPTION = (
    "A daily, plain-English briefing of security issues raised on X, Bluesky and Mastodon, "
    "checked against vendor advisories, CISA KEV and EPSS, and turned into what to patch. "
    "No exploit details."
)
X_HOSTS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"}
BLUESKY_HOSTS = {"bsky.app", "www.bsky.app"}
_X_STATUS = re.compile(r"^/[^/]+/status/\d+$")
_BLUESKY_POST = re.compile(r"^/profile/[^/]+/post/[^/]+$")
_MASTODON_STATUS = re.compile(r"^/(?:@[^/]+/\d+|users/[^/]+/statuses/\d+)$")


def human_date(value: str) -> str:
    d = date.fromisoformat(value)
    return f"{d.day} {d.strftime('%B %Y')}"


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))


def human_time(value: str) -> str:
    d = timestamp(value).astimezone(ZoneInfo("America/Los_Angeles"))
    return f"{d.day} {d.strftime('%b %Y')} · {d.strftime('%I:%M %p').lstrip('0')} {d.tzname()}"


def coverage(edition: dict) -> str:
    start, end = edition["coverage_start"], edition["coverage_end"]
    if start == end:
        return human_date(start)
    a, b = date.fromisoformat(start), date.fromisoformat(end)
    if (a.year, a.month) == (b.year, b.month):
        return f"{a.day}–{b.day} {b.strftime('%B %Y')}"
    return f"{human_date(start)} – {human_date(end)}"


def social_platform(url: str) -> str | None:
    """Return X, Bluesky, or Mastodon when url is a public status permalink."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/") or "/"
    if host in X_HOSTS and _X_STATUS.match(path):
        return "X"
    if host in BLUESKY_HOSTS and _BLUESKY_POST.match(path):
        return "Bluesky"
    if host not in X_HOSTS | BLUESKY_HOSTS and _MASTODON_STATUS.match(path):
        return "Mastodon"
    return None


def normalize_site_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("SITE_URL must be an absolute https URL without credentials, a query, or a fragment")
    if any(part in {".", ".."} for part in parsed.path.split("/")):
        raise ValueError("SITE_URL cannot contain relative path segments")
    return value.rstrip("/")


def root_path(site_url: str, path: str = "") -> str:
    """Project-root paths also work when 404.html is served at a missing deep URL."""
    base = urlsplit(site_url).path.rstrip("/")
    return f"{base}/{path.lstrip('/')}"


def exploited_cves(item: dict) -> list[str] | None:
    """CVEs carrying the item's exploitation status, or None when it applies to the whole item.

    Returns a list only when per-CVE records show that the item-level status is
    narrower than the item: for example, one exploited CVE among several.
    """
    exploitation = item["exploitation"]
    by_cve = exploitation.get("by_cve")
    if not by_cve or exploitation["status"] == "unknown":
        return None
    matching = [record["cve"] for record in by_cve if record["status"] == exploitation["status"]]
    if set(matching) >= set(item["cves"]):
        return None
    return matching


def exploitation_label(item: dict) -> str | None:
    """Reader-facing exploitation label, scoped to specific CVEs when that is more accurate."""
    status = item["exploitation"]["status"]
    if status not in {"confirmed", "reported"}:
        return None
    label = f"Exploitation {status}"
    scoped = exploited_cves(item)
    if scoped is None:
        return label
    if len(scoped) <= 2:
        return f"{label} for {' and '.join(scoped)}"
    return f"{label} for {len(scoped)} of {len(item['cves'])} CVEs"


def is_early_signal(item: dict) -> bool:
    """An unverified lead. Omitted verification means the item is verified."""
    return item.get("verification") == "early_signal"


def for_audience(item: dict, audience: str | None) -> bool:
    return audience is None or item["audience"] in {audience, "both"}


def ordered_items(edition: dict, audience: str | None = None) -> list[dict]:
    return sorted((item for item in edition["items"] if for_audience(item, audience)), key=lambda item: PRIORITY_ORDER[item["priority"]])
