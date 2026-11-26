"""Pick feed-cache rows worth waking the editorial routine for. No network.

Two kinds of row wake the routine:

1. kev_new: a CVE that was not in CISA's KEV catalog on the previous fetch.
2. covered_advisory: an advisory row that was not in the previous cache
   snapshot and matches a product covered in an edition from the last
   COVERED_DAYS days (data/products.json appearances).

Matching is deliberately simple, case-insensitive whole-word matching:

- Product match: the first segment of the stable product id (for example
  "nginx" from "nginx-http2") or the full product name appears in the row's
  title or id. Segments shorter than three characters are ignored.
- Vendor match: the row comes from a vendor's own feed (VENDOR_TERMS), and one
  of that vendor's terms appears in the covered product's name or id. A new
  Palo Alto advisory therefore wakes the routine whenever any Palo Alto product
  was covered this week.

Hacker News rows never wake the routine. A row wakes it at most once: its key
goes into woken.json and is kept for WOKEN_DAYS days.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from datetime import date, datetime, timedelta
import re

COVERED_DAYS = 7
WOKEN_DAYS = 30
WAKE_FILE_LIMIT = 25
POST_LIMIT = 10
NO_WAKE_SOURCES = frozenset({"hacker-news", "cisa-kev"})
VENDOR_TERMS = {
    "msrc": ("microsoft", "windows", "azure", "exchange", "sharepoint", "office", "outlook"),
    "chrome-releases": ("chrome", "chromium"),
    "mozilla-security": ("mozilla", "firefox", "thunderbird"),
    "cisco-psirt": ("cisco",),
    "fortinet-psirt": ("fortinet", "fortios", "fortigate", "fortiweb", "fortimanager", "fortianalyzer", "forticlient"),
    "palo-alto": ("palo alto", "pan-os", "globalprotect", "prisma"),
    "ubuntu-usn": ("ubuntu", "canonical"),
    "arch-linux": ("arch linux",),
    "jenkins-advisories": ("jenkins",),
}


def row_key(row: dict) -> str:
    return f"{row['source']}:{row['id']}"


def _has_word(haystack: str, term: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", haystack) is not None


def covered_products(index: dict, today: date, *, days: int = COVERED_DAYS) -> list[dict]:
    """Products with an appearance in an edition dated within `days` days of today."""
    cutoff = today - timedelta(days=days)
    covered = []
    for product in index.get("products") or []:
        dates = []
        for appearance in product.get("appearances") or []:
            try:
                dates.append(date.fromisoformat(appearance.get("digest_date") or ""))
            except ValueError:
                continue
        if any(cutoff <= day <= today + timedelta(days=1) for day in dates):
            covered.append({"id": product["id"], "product": product.get("product") or product["id"]})
    return covered


def product_terms(product: dict) -> list[str]:
    terms = [product["product"].lower()]
    head = product["id"].split("-", 1)[0].lower()
    if len(head) >= 3:
        terms.append(head)
    return list(dict.fromkeys(terms))


def match_products(row: dict, covered: list[dict]) -> list[str]:
    """Covered product ids this advisory row matches."""
    text = f"{row.get('title') or ''} {row.get('id') or ''}".lower()
    vendor_terms = VENDOR_TERMS.get(row.get("source") or "", ())
    matched = []
    for product in covered:
        name = f"{product['product']} {product['id'].replace('-', ' ')} {product['id']}".lower()
        if any(_has_word(text, term) for term in product_terms(product)) or any(_has_word(name, term) for term in vendor_terms):
            matched.append(product["id"])
    return matched


def new_rows(current: list[dict], previous: list[dict]) -> list[dict]:
    """Rows not in the previous snapshot. An empty previous snapshot is a baseline: nothing is new."""
    if not previous:
        return []
    seen = {row_key(row) for row in previous}
    return [row for row in current if row_key(row) not in seen]


def _wake_row(row: dict, reason: str, matched: list[str]) -> dict:
    record = {
        "reason": reason,
        "source": row["source"],
        "id": row["id"],
        "title": row["title"],
        "url": row["url"],
        "cves": list(row.get("cves") or []),
        "matched_products": matched,
    }
    if row.get("advisory_lines"):
        record["advisory_lines"] = row["advisory_lines"]
    return record


def select_wake_rows(kev_new: list[dict], fresh_advisories: list[dict], covered: list[dict], woken: dict) -> list[dict]:
    """Wake-worthy rows that have not woken the routine before. KEV rows come first."""
    rows, keys = [], set()
    for row in kev_new:
        key = row_key(row)
        if key not in woken and key not in keys:
            keys.add(key)
            rows.append(_wake_row(row, "kev_new", match_products({**row, "source": ""}, covered)))
    for row in fresh_advisories:
        key = row_key(row)
        if row.get("source") in NO_WAKE_SOURCES or key in woken or key in keys:
            continue
        matched = match_products(row, covered)
        if matched:
            keys.add(key)
            rows.append(_wake_row(row, "covered_advisory", matched))
    return rows


def record_woken(woken: dict, rows: list[dict], stamp: str, now: datetime, *, days: int = WOKEN_DAYS) -> dict:
    """Add these rows to woken.json's ids and drop entries older than `days`."""
    cutoff = now - timedelta(days=days)
    kept = {}
    for key, when in (woken or {}).items():
        try:
            if datetime.fromisoformat(when.replace("Z", "+00:00")) >= cutoff:
                kept[key] = when
        except (AttributeError, ValueError):
            continue
    for row in rows:
        kept.setdefault(row_key(row), stamp)
    return {key: kept[key] for key in sorted(kept)}


def post_body(rows: list[dict], *, limit: int = POST_LIMIT) -> dict:
    """The JSON body the workflow POSTs: short fields, at most `limit` rows."""
    short = lambda value, size: value if value is None or len(value) <= size else value[: size - 1] + "…"
    return {
        "reason": "feed",
        "total": len(rows),
        "rows": [
            {
                "reason": row["reason"],
                "source": row["source"],
                "id": short(row["id"], 120),
                "title": short(row["title"], 160),
                "url": row["url"],
                "cves": row["cves"][:5],
                "matched_products": row["matched_products"][:5],
            }
            for row in rows[:limit]
        ],
    }
