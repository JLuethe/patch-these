"""Regression tests for publication boundaries, independent of any first issue."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from patchthese.validation import ValidationError, load_editions, validate_payload


@pytest.fixture
def edition():
    return {
        "schema_version": 2,
        "digest_date": "2026-11-25",
        "coverage_start": "2026-11-24",
        "coverage_end": "2026-11-25",
        "published_at": "2026-11-26T04:00:00Z",
        "updated_at": "2026-11-26T05:00:00Z",
        "corrections": [],
        "featured_item_ids": ["example-service"],
        "items": [{
            "id": "example-service",
            "product": "Example service",
            "audience": "applications_and_servers",
            "priority": "act_soon",
            "action_type": "update",
            "priority_reason": "An update is available for exposed installations.",
            "cves": ["CVE-2026-99999"],
            "affected": "Before 2.0",
            "fix_status": "available",
            "fixes": [{"component": "Example service", "version": "2.0", "platform": None,
                       "branch": "2.x", "cves": ["CVE-2026-99999"], "source_ids": ["advisory"]}],
            "summary": "A test fixture, not a real advisory.",
            "action": "Update the example service.",
            "exploitation": {"status": "unknown", "source_ids": []},
            "kev": [{"cve": "CVE-2026-99999", "listed": None, "date_added": None, "source_ids": []}],
            "cvss": [],
            "epss": [{"cve": "CVE-2026-99999", "probability": 0.01, "score_date": None, "source_ids": ["advisory"]}],
            "sources": [{"id": "advisory", "kind": "vendor_advisory",
                         "url": "https://example.invalid/advisory", "label": "Fixture advisory",
                         "checked_at": None, "supports": ["fixes", "exploitation", "kev", "epss"]}],
        }],
    }


def test_real_editions_and_quiet_days_are_valid(edition):
    root = Path(__file__).resolve().parents[1]
    assert load_editions(root / "data")
    validate_payload(edition)
    edition["items"] = []
    edition["featured_item_ids"] = []
    validate_payload(edition)


def test_source_references_are_local_to_the_product(edition):
    other = deepcopy(edition["items"][0])
    other["id"] = "another-service"
    other["sources"][0]["id"] = "another-advisory"
    other["fixes"][0]["source_ids"] = ["another-advisory"]
    other["epss"][0]["source_ids"] = ["another-advisory"]
    edition["items"].append(other)
    edition["items"][0]["fixes"][0]["source_ids"] = ["another-advisory"]
    with pytest.raises(ValidationError, match="unknown source id"):
        validate_payload(edition)


def test_fix_cannot_claim_an_unrelated_cve(edition):
    edition["items"][0]["fixes"][0]["cves"] = ["CVE-2026-88888"]
    with pytest.raises(ValidationError, match="CVE outside this item"):
        validate_payload(edition)


def test_declared_source_must_support_the_field(edition):
    edition["items"][0]["sources"][0]["supports"].remove("fixes")
    with pytest.raises(ValidationError, match="does not declare support for fixes"):
        validate_payload(edition)


def test_known_exploitation_requires_evidence_and_cannot_be_monitor(edition):
    item = edition["items"][0]
    item["exploitation"]["status"] = "confirmed"
    with pytest.raises(ValidationError, match="exploitation status needs a source"):
        validate_payload(edition)
    item["exploitation"]["source_ids"] = ["advisory"]
    item["kev"][0].update(listed=True, source_ids=["advisory"])
    item["priority"] = "monitor"
    with pytest.raises(ValidationError, match="cannot be monitor"):
        validate_payload(edition)
    item["priority"] = "act_now"
    validate_payload(edition)


def test_unavailable_and_unknown_fixes_are_distinct_valid_states(edition):
    item = edition["items"][0]
    item["fixes"] = []
    item["fix_status"] = "unknown"
    item["action_type"] = "investigate"
    validate_payload(edition)
    item["fix_status"] = "unavailable"
    item["action_type"] = "mitigate"
    validate_payload(edition)
    item["action_type"] = "update"
    with pytest.raises(ValidationError, match="requires an available fix"):
        validate_payload(edition)


@pytest.mark.parametrize("change", [
    lambda p: p.update(coverage_end="2026-02-30"),
    lambda p: p.update(coverage_start="2026-11-26"),
    lambda p: p.update(updated_at="2026-11-26T03:00:00Z"),
    lambda p: p["items"][0]["sources"][0].update(checked_at="2026-11-27T00:00:00Z"),
    lambda p: p.update(corrections=[{"at": "2026-11-26T06:00:00Z", "summary": "A correction", "item_ids": []}]),
    lambda p: p["items"][0]["epss"][0].update(probability=1.2),
    lambda p: p["items"][0]["sources"][0].update(url="javascript:alert(1)"),
])
def test_invalid_dates_probabilities_and_source_urls_fail(edition, change):
    change(edition)
    with pytest.raises(ValidationError):
        validate_payload(edition)


def test_duplicate_ids_and_unknown_featured_items_fail(edition):
    edition["items"].append(deepcopy(edition["items"][0]))
    with pytest.raises(ValidationError, match="duplicate item id"):
        validate_payload(edition)
    edition["items"].pop()
    edition["featured_item_ids"] = ["missing-item"]
    with pytest.raises(ValidationError, match="unknown item"):
        validate_payload(edition)


def test_loader_ignores_schema_checks_filename_and_rejects_duplicate_keys(tmp_path, edition):
    (tmp_path / "schema.json").write_text('{"not": "an edition"}')
    day = tmp_path / "2026-11-25.json"
    day.write_text(json.dumps(edition))
    assert load_editions(tmp_path) == [edition]
    day.rename(tmp_path / "2026-11-24.json")
    with pytest.raises(ValidationError, match="does not match the filename"):
        load_editions(tmp_path)
    (tmp_path / "2026-11-24.json").unlink()
    day.write_text('{"schema_version": 2, "schema_version": 1}')
    with pytest.raises(ValidationError, match="duplicate JSON key"):
        load_editions(tmp_path)


def _two_cve_item(edition):
    item = edition["items"][0]
    item["cves"].append("CVE-2026-99998")
    item["kev"].append({"cve": "CVE-2026-99998", "listed": None, "date_added": None, "source_ids": []})
    item["priority"] = "act_now"
    return item


def test_per_cve_exploitation_must_match_the_item_status(edition):
    item = _two_cve_item(edition)
    item["exploitation"] = {"status": "confirmed", "source_ids": ["advisory"], "by_cve": [
        {"cve": "CVE-2026-99999", "status": "confirmed", "source_ids": ["advisory"]},
        {"cve": "CVE-2026-99998", "status": "unknown", "source_ids": []},
    ]}
    validate_payload(edition)
    item["exploitation"]["status"] = "reported"
    with pytest.raises(ValidationError, match="must equal the strongest per-CVE status 'confirmed'"):
        validate_payload(edition)


@pytest.mark.parametrize("record, message", [
    ({"cve": "CVE-2026-88888", "status": "unknown", "source_ids": []}, "CVE outside this item"),
    ({"cve": "CVE-2026-99998", "status": "reported", "source_ids": []}, "needs a source"),
    ({"cve": "CVE-2026-99999", "status": "unknown", "source_ids": []}, "duplicate exploitation.by_cve"),
])
def test_per_cve_exploitation_records_are_checked(edition, record, message):
    item = _two_cve_item(edition)
    item["exploitation"] = {"status": "confirmed", "source_ids": ["advisory"], "by_cve": [
        {"cve": "CVE-2026-99999", "status": "confirmed", "source_ids": ["advisory"]}, record,
    ]}
    with pytest.raises(ValidationError, match=message):
        validate_payload(edition)


def test_per_cve_exploitation_sources_must_support_exploitation(edition):
    item = _two_cve_item(edition)
    item["sources"][0]["supports"].remove("exploitation")
    item["exploitation"] = {"status": "unknown", "source_ids": [], "by_cve": [
        {"cve": "CVE-2026-99999", "status": "unknown", "source_ids": ["advisory"]},
    ]}
    with pytest.raises(ValidationError, match="does not declare support for exploitation"):
        validate_payload(edition)


def _next_day(edition):
    edition.update(digest_date="2026-11-26", coverage_start="2026-11-26", coverage_end="2026-11-26",
                   published_at="2026-11-27T04:00:00Z", updated_at="2026-11-27T05:00:00Z")


def test_new_editions_must_record_when_evidence_was_checked(edition):
    validate_payload(edition)  # The migrated first edition may lack check times.
    _next_day(edition)
    with pytest.raises(ValidationError, match="source 'advisory' needs checked_at"):
        validate_payload(edition)
    edition["items"][0]["sources"][0]["checked_at"] = "2026-11-27T03:00:00Z"
    validate_payload(edition)


@pytest.mark.parametrize("url", [
    "https://x.com/example/status/1",
    "https://twitter.com/example/status/1",
    "https://bsky.app/profile/example.bsky.social/post/3abc",
    "https://mastodon.social/@example/123456",
    "https://mastodon.social/@example@infosec.exchange/123456",
    "https://infosec.exchange/@example/123456",
    "https://infosec.exchange/users/example/statuses/123456",
])
def test_social_discovery_posts_do_not_need_check_times(edition, url):
    _next_day(edition)
    item = edition["items"][0]
    item["sources"][0]["checked_at"] = "2026-11-27T03:00:00Z"
    item["sources"].append({"id": "post", "kind": "social_report", "url": url,
                            "label": "Discussed in public", "checked_at": None, "supports": ["summary"]})
    validate_payload(edition)


@pytest.mark.parametrize("url", [
    "https://vendor.example/advisory",
    "https://bsky.app/profile/example.bsky.social",
    "https://mastodon.social/explore",
    "https://x.com/example",
])
def test_social_report_rejects_a_url_that_is_not_a_status(edition, url):
    _next_day(edition)
    item = edition["items"][0]
    item["sources"][0]["checked_at"] = "2026-11-27T03:00:00Z"
    item["sources"].append({"id": "post", "kind": "social_report", "url": url,
                            "label": "Not a status", "checked_at": None, "supports": ["summary"]})
    with pytest.raises(ValidationError, match="X, Bluesky, or Mastodon status"):
        validate_payload(edition)
