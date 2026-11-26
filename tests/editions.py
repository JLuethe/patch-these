"""Small synthetic editions for publishing tests.

They do not depend on today's date or on any committed edition, so a new
day's data can never break a rendering test. Dates are far in the future and
follow the strictest current validation rules.
"""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DAY_ONE = "2030-03-01"
DAY_TWO = "2030-03-02"
README = """# patch-these test copy

Maintained by [John Luethe](https://github.com/JLuethe).

<!-- BEGIN GENERATED EDITION -->
<!-- END GENERATED EDITION -->
"""


def source(source_id: str = "advisory", *, kind: str = "vendor_advisory", url: str | None = None,
           supports: list[str] | None = None, checked_at: str | None = "2030-03-01T12:00:00Z", label: str | None = None) -> dict:
    if kind == "social_report":
        checked_at = None
    return {
        "id": source_id,
        "kind": kind,
        "url": url or f"https://vendor.example/{source_id}",
        "label": label or f"Fixture {source_id}",
        "checked_at": checked_at,
        "supports": supports if supports is not None else ["summary", "affected", "action", "fixes", "exploitation", "kev", "cvss", "epss"],
    }


def item(item_id: str = "example-server", product: str = "Example Server", *, cve: str = "CVE-2030-10001", **changes) -> dict:
    """A verified Act soon update with one fix, one KEV lookup and one EPSS score."""
    record = {
        "id": item_id,
        "product": product,
        "kind": "vulnerability",
        "verification": "verified",
        "audience": "applications_and_servers",
        "priority": "act_soon",
        "action_type": "update",
        "priority_reason": "A fixed release is available for affected installations.",
        "cves": [cve],
        "affected": "Versions before 2.4.1.",
        "fix_status": "available",
        "fixes": [{"component": product, "version": "2.4.1", "platform": None, "branch": "2.4", "cves": [cve], "source_ids": ["advisory"]}],
        "summary": f"{product} has a fixture vulnerability. The vendor fixed it in 2.4.1. Nothing here describes a real product.",
        "action": f"Upgrade {product} to 2.4.1 or later.",
        "exploitation": {"status": "unknown", "source_ids": []},
        "kev": [{"cve": cve, "listed": False, "date_added": None, "source_ids": ["advisory"]}],
        "cvss": [],
        "epss": [{"cve": cve, "probability": 0.0123, "score_date": DAY_ONE, "source_ids": ["advisory"]}],
        "sources": [source()],
    }
    record.update(deepcopy(changes))
    return record


def early_signal(item_id: str = "example-lead", product: str = "Example Lead", **changes) -> dict:
    """An unverified lead resting on one social post."""
    record = {
        "id": item_id,
        "product": product,
        "kind": "incident",
        "verification": "early_signal",
        "audience": "applications_and_servers",
        "priority": "monitor",
        "action_type": "investigate",
        "priority_reason": "One public post reports this and no vendor notice has been read.",
        "cves": [],
        "affected": None,
        "fix_status": "unknown",
        "fixes": [],
        "summary": f"A public post says {product} had a security incident. No vendor notice confirms it yet.",
        "action": f"Check whether you use {product}; watch for the vendor's notice.",
        "gaps": "No vendor notice was found, so scope and steps are unconfirmed.",
        "exploitation": {"status": "unknown", "source_ids": []},
        "kev": [],
        "cvss": [],
        "epss": [],
        "sources": [source("post", kind="social_report", url="https://x.com/example/status/1234567890", supports=["summary"], label="Discussed on X")],
    }
    record.update(deepcopy(changes))
    return record


def edition(digest_date: str = DAY_ONE, items: list[dict] | None = None, *, featured: list[str] | None = None, **changes) -> dict:
    items = [item()] if items is None else items
    record = {
        "schema_version": 2,
        "digest_date": digest_date,
        "coverage_start": digest_date,
        "coverage_end": digest_date,
        "published_at": f"{digest_date}T14:00:00Z",
        "updated_at": f"{digest_date}T14:00:00Z",
        "corrections": [],
        "featured_item_ids": featured if featured is not None else [entry["id"] for entry in items if entry.get("verification") != "early_signal"][:3],
        "items": items,
    }
    record.update(deepcopy(changes))
    for entry in record["items"]:
        for row in entry["sources"]:
            if row["checked_at"] is not None:
                row["checked_at"] = f"{digest_date}T12:00:00Z"
        for row in entry["epss"]:
            row["score_date"] = digest_date
    return record


def write_edition(root: Path, payload: dict) -> Path:
    path = Path(root) / "data" / f"{payload['digest_date']}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def publication(root: Path, editions: list[dict]) -> Path:
    """A buildable repository copy with only the given editions."""
    root = Path(root)
    shutil.copytree(ROOT / "assets", root / "assets")
    (root / "data").mkdir()
    shutil.copyfile(ROOT / "data" / "schema.json", root / "data" / "schema.json")
    shutil.copyfile(ROOT / "METHODOLOGY.md", root / "METHODOLOGY.md")
    (root / "README.md").write_text(README, encoding="utf-8")
    for payload in editions:
        write_edition(root, payload)
    return root
