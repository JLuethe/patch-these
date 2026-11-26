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
    "A plain-English security briefing, updated every 4 hours from 6 AM to 10 PM Pacific. "
    "It finds new issues on X, Bluesky and Mastodon, publishes unconfirmed leads as early signals, "
    "and recommends patches only after a vendor advisory, CISA KEV, or NVD confirms them. "
    "No exploit details."
)
# Header line. DESCRIPTION, the full statement, stays in meta tags and feeds.
TAGLINE = "Plain-English security updates every 4 hours. Unconfirmed leads are labeled; patch advice waits for a primary source."
X_HOSTS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"}
BLUESKY_HOSTS = {"bsky.app", "www.bsky.app"}
_X_STATUS = re.compile(r"^/[^/]+/status/\d+$")
_BLUESKY_POST = re.compile(r"^/profile/[^/]+/post/[^/]+$")
_MASTODON_STATUS = re.compile(r"^/(?:@[^/]+/\d+|users/[^/]+/statuses/\d+)$")


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def brief(text: str, *, max_sentences: int = 2, max_chars: int = 220) -> str:
    """The first one or two whole sentences, for cards that link to the full item.

    Never cuts inside a sentence: the first sentence is always kept whole, and
    a second is added only when both fit within max_chars.
    """
    sentences = _SENTENCE_END.split(" ".join(text.split()))
    kept = [sentences[0]]
    for sentence in sentences[1:max_sentences]:
        if len(" ".join(kept + [sentence])) > max_chars:
            break
        kept.append(sentence)
    return " ".join(kept)


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


# An incident or supply-chain compromise is not "exploitation" of a vulnerability.
STATUS_NOUNS = {"incident": "Breach", "supply_chain": "Compromise"}


def status_noun(item: dict) -> str:
    """What the exploitation field means for this item's kind: Exploitation, Breach, or Compromise."""
    return STATUS_NOUNS.get(item.get("kind") or "", "Exploitation")


def exploitation_label(item: dict) -> str | None:
    """Reader-facing exploitation label, scoped to specific CVEs when that is more accurate.

    Incidents say "Breach confirmed" and supply-chain items say "Compromise confirmed",
    never "Exploitation confirmed".
    """
    status = item["exploitation"]["status"]
    if status not in {"confirmed", "reported"}:
        return None
    label = f"{status_noun(item)} {status}"
    scoped = exploited_cves(item)
    if scoped is None:
        return label
    if len(scoped) <= 2:
        return f"{label} for {' and '.join(scoped)}"
    return f"{label} for {len(scoped)} of {len(item['cves'])} CVEs"


def is_early_signal(item: dict) -> bool:
    """An unverified lead. Omitted verification means the item is verified."""
    return item.get("verification") == "early_signal"


def is_single_source(item: dict) -> bool:
    """An early signal resting on one source, usually one social post."""
    return is_early_signal(item) and len(item["sources"]) == 1


def verification_labels(item: dict) -> list[str]:
    """Reader-facing verification state, empty for a verified item."""
    if not is_early_signal(item):
        return []
    return ["Not yet verified"] + (["Single source"] if is_single_source(item) else [])


def for_audience(item: dict, audience: str | None) -> bool:
    return audience is None or item["audience"] in {audience, "both"}


def ordered_items(edition: dict, audience: str | None = None) -> list[dict]:
    return sorted((item for item in edition["items"] if for_audience(item, audience)), key=lambda item: PRIORITY_ORDER[item["priority"]])
