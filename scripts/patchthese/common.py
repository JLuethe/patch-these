"""Shared publication labels and URL/date handling."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from datetime import date, datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

PRIORITIES = {"act_now": "Act now", "act_soon": "Act soon", "monitor": "Monitor"}
PRIORITY_ORDER = {key: index for index, key in enumerate(PRIORITIES)}
AUDIENCES = {"applications_and_servers": "Apps & servers", "end_users": "My computer", "both": "Everyone & operators"}
ACTIONS = {"update": "Update", "mitigate": "Mitigate", "replace": "Replace", "rotate": "Rotate credentials", "investigate": "Check applicability"}
REPO = "https://github.com/JLuethe/patch-these"
DESCRIPTION = "A calm briefing of security updates: what applies to you, why it matters, and what to do next."


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


def for_audience(item: dict, audience: str | None) -> bool:
    return audience is None or item["audience"] in {audience, "both"}


def ordered_items(edition: dict, audience: str | None = None) -> list[dict]:
    return sorted((item for item in edition["items"] if for_audience(item, audience)), key=lambda item: PRIORITY_ORDER[item["priority"]])
