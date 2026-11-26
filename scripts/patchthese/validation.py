"""Validate canonical editions without trusting a second Markdown copy.

Schema checks establish shape and scalar bounds. The checks here establish
relationships within an edition; they do not verify a vendor's factual claims.
"""

from __future__ import annotations

import json
import math
import re
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from .common import social_platform

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "data" / "schema.json"
EDITION_FILE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\.json$")
EXPLOITATION_RANK = {"confirmed": 0, "reported": 1, "unknown": 2}
# Editions up to this date were migrated from schema 1 and may lack check times.
# Every later edition must record when each evidentiary source was checked.
CHECK_TIMES_REQUIRED_AFTER = date(2026, 11, 25)


class ValidationError(ValueError):
    """An edition cannot safely be published in its current form."""


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker()
    missing = {"date", "date-time", "uri"} - checker.checkers.keys()
    _require(not missing, "Install jsonschema[format] so date-time and URI formats are checked")
    return Draft202012Validator(schema, format_checker=checker)


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid RFC3339 timestamp {value!r}") from exc
    _require(parsed.tzinfo is not None, f"timestamp needs a UTC offset: {value!r}")
    return parsed.astimezone(timezone.utc)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _source_refs(record: dict, sources: dict, field: str, where: str) -> None:
    for source_id in record["source_ids"]:
        _require(source_id in sources, f"{where}: unknown source id {source_id!r}")
        _require(
            field in sources[source_id]["supports"],
            f"{where}: source {source_id!r} does not declare support for {field}",
        )


def _validate_item(item: dict, updated: datetime, *, require_check_times: bool = False) -> None:
    where = f"item {item['id']}"
    cves = set(item["cves"])
    source_ids = [source["id"] for source in item["sources"]]
    _require(len(source_ids) == len(set(source_ids)), f"{where}: duplicate source id")
    sources = {source["id"]: source for source in item["sources"]}

    for source in sources.values():
        url = source["url"]
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ValidationError(f"{where}: invalid source URL") from exc
        _require(
            parsed.scheme == "https" and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not any(char.isspace() for char in url),
            f"{where}: source URLs must use HTTPS without credentials or whitespace",
        )
        if source["kind"] == "social_report":
            _require(
                social_platform(url) is not None,
                f"{where}: social_report URL must be an X, Bluesky, or Mastodon status permalink",
            )
        if require_check_times and source["kind"] != "social_report":
            _require(
                source["checked_at"] is not None,
                f"{where}: source {source['id']!r} needs checked_at; editions after "
                f"{CHECK_TIMES_REQUIRED_AFTER.isoformat()} must record when each non-social source was checked",
            )
        if source["checked_at"] is not None:
            _require(
                _time(source["checked_at"]) <= updated,
                f"{where}: source checked_at cannot follow edition updated_at",
            )

    fixes = item["fixes"]
    available = item["fix_status"] == "available"
    _require(bool(fixes) == available, f"{where}: available fixes require fix_status available, and vice versa")
    if item["action_type"] == "update":
        _require(available, f"{where}: update action requires an available fix")
    for fix in fixes:
        _require(set(fix["cves"]) <= cves, f"{where}: fix references a CVE outside this item")
        _source_refs(fix, sources, "fixes", where)

    exploitation = item["exploitation"]
    _source_refs(exploitation, sources, "exploitation", where)
    if exploitation["status"] in {"confirmed", "reported"}:
        _require(bool(exploitation["source_ids"]), f"{where}: exploitation status needs a source")
    by_cve = exploitation.get("by_cve")
    if by_cve is not None:
        _require(bool(by_cve), f"{where}: exploitation.by_cve must list at least one CVE when present")
        listed = [record["cve"] for record in by_cve]
        _require(len(listed) == len(set(listed)), f"{where}: duplicate exploitation.by_cve record")
        for record in by_cve:
            _require(record["cve"] in cves, f"{where}: exploitation.by_cve references a CVE outside this item")
            _source_refs(record, sources, "exploitation", where)
            if record["status"] in {"confirmed", "reported"}:
                _require(bool(record["source_ids"]), f"{where}: exploitation status for {record['cve']} needs a source")
        strongest = min((record["status"] for record in by_cve), key=EXPLOITATION_RANK.__getitem__)
        _require(
            exploitation["status"] == strongest,
            f"{where}: item exploitation status {exploitation['status']!r} must equal the strongest per-CVE status {strongest!r}",
        )

    kev_cves = [record["cve"] for record in item["kev"]]
    _require(len(kev_cves) == len(set(kev_cves)), f"{where}: duplicate KEV record")
    for record in item["kev"]:
        _require(record["cve"] in cves, f"{where}: KEV references a CVE outside this item")
        _source_refs(record, sources, "kev", where)
        if record["listed"] is not None:
            _require(bool(record["source_ids"]), f"{where}: known KEV membership needs a source")
        if record["listed"] is True:
            _require(item["priority"] != "monitor", f"{where}: a KEV-listed vulnerability cannot be monitor")
        else:
            _require(record["date_added"] is None, f"{where}: a KEV date requires listed true")
        if record["date_added"] is not None:
            _require(date.fromisoformat(record["date_added"]) <= updated.date(), f"{where}: KEV date follows updated_at")

    for record in item["cvss"]:
        _require(record["cve"] is None or record["cve"] in cves, f"{where}: CVSS references a CVE outside this item")
        _require(math.isfinite(record["score"]), f"{where}: CVSS score must be finite")
        _source_refs(record, sources, "cvss", where)

    epss_cves = [record["cve"] for record in item["epss"]]
    _require(len(epss_cves) == len(set(epss_cves)), f"{where}: duplicate EPSS record")
    for record in item["epss"]:
        _require(record["cve"] in cves, f"{where}: EPSS references a CVE outside this item")
        _require(math.isfinite(record["probability"]), f"{where}: EPSS probability must be finite")
        _source_refs(record, sources, "epss", where)
        if record["score_date"] is not None:
            _require(date.fromisoformat(record["score_date"]) <= updated.date(), f"{where}: EPSS score date follows updated_at")

    if item.get("verification") == "early_signal":
        _require(
            item["action_type"] == "investigate",
            f"{where}: an early_signal cannot recommend a patch; action_type must be investigate",
        )
        _require(
            item["fix_status"] != "available" and not item["fixes"],
            f"{where}: an early_signal cannot carry a patch",
        )
        _require(
            exploitation["status"] != "confirmed",
            f"{where}: an early_signal cannot use confirmed exploitation",
        )
        for record in by_cve or []:
            _require(
                record["status"] != "confirmed",
                f"{where}: an early_signal cannot use confirmed exploitation",
            )
        _require(bool(item["sources"]), f"{where}: an early_signal needs at least one source")
        _require(bool((item.get("gaps") or "").strip()), f"{where}: an early_signal needs gaps saying what is unconfirmed")
        _require(
            all(row.get("listed") is not True for row in item["kev"]),
            f"{where}: an early_signal cannot treat a KEV listing as confirmed",
        )


def validate_payload(payload: dict, expected_date: str | None = None) -> None:
    """Raise ValidationError for schema or cross-field errors; never modify data."""
    errors = sorted(_validator().iter_errors(payload), key=lambda error: str(list(error.absolute_path)))
    if errors:
        details = []
        for error in errors[:8]:
            location = ".".join(str(part) for part in error.absolute_path) or "edition"
            details.append(f"{location}: {error.message}")
        raise ValidationError("; ".join(details))

    edition_date = date.fromisoformat(payload["digest_date"])
    if expected_date is not None:
        _require(payload["digest_date"] == expected_date, "digest_date does not match the filename")
    start = date.fromisoformat(payload["coverage_start"])
    end = date.fromisoformat(payload["coverage_end"])
    _require(start <= end <= edition_date, "expected coverage_start <= coverage_end <= digest_date")

    published = _time(payload["published_at"])
    updated = _time(payload["updated_at"])
    _require(published <= updated, "updated_at must not precede published_at")
    # The editorial date and UTC publication date need not match across timezones.

    ids = [item["id"] for item in payload["items"]]
    _require(len(ids) == len(set(ids)), "duplicate item id")
    item_ids = set(ids)
    _require(set(payload["featured_item_ids"]) <= item_ids, "featured_item_ids contains an unknown item")
    early_ids = {item["id"] for item in payload["items"] if item.get("verification") == "early_signal"}
    _require(not (early_ids & set(payload["featured_item_ids"])), "an early_signal item cannot be featured")

    previous_correction = published
    for correction in payload["corrections"]:
        at = _time(correction["at"])
        _require(previous_correction <= at <= updated, "corrections must be chronological between published_at and updated_at")
        _require(set(correction["item_ids"]) <= item_ids, "correction references an unknown item")
        previous_correction = at

    require_check_times = edition_date > CHECK_TIMES_REQUIRED_AFTER
    for item in payload["items"]:
        _validate_item(item, updated, require_check_times=require_check_times)


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValidationError(f"invalid JSON number {value}")


def load_editions(data_dir: Path) -> list[dict]:
    """Load dated edition JSON files; ignore schema and other support files."""
    editions = []
    for path in sorted(Path(data_dir).glob("*.json")):
        if not EDITION_FILE.fullmatch(path.name):
            continue
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            validate_payload(payload, expected_date=path.stem)
        except (ValueError, OSError) as exc:
            raise ValidationError(f"{path.name}: {exc}") from exc
        editions.append(payload)
    return sorted(editions, key=lambda payload: payload["digest_date"])
