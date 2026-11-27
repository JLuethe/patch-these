"""social/queries.json: the early-signal scan's families, budgets and per-platform queries."""
import json
from pathlib import Path
import re

import pytest

QUERIES = json.loads((Path(__file__).resolve().parents[1] / "social" / "queries.json").read_text(encoding="utf-8"))
FAMILIES = QUERIES["families"]
REQUIRED_FAMILIES = {
    "zero_day": {"0day", '"zero-day"', "zeroday"},
    "auth": {'"auth bypass"', '"authentication bypass"', '"authorization bypass"', '"account takeover"'},
    "execution": {'"remote code execution"', '"unauthenticated RCE"', '"command injection"', '"SQL injection"'},
    "file_request": {'"arbitrary file read"', '"arbitrary file write"', '"path traversal"', "SSRF"},
    "privilege": {'"privilege escalation"', '"sandbox escape"', '"container escape"'},
    "exploitation": {'"suspected exploitation"', '"exploitation attempts"', '"actively exploited"', '"in the wild"'},
    "new_exploitability": {'"exploit released"', '"public exploit"', '"patch bypass"'},
    "early_disclosure": {'"CVE pending"', '"no CVE"', "unpatched", '"vendor notified"'},
    "advisory_allowance": {'"security advisory"'},
    "catchup": {"CVE"},
}


def all_terms():
    return {term for family in FAMILIES.values() for term in family["terms"]}


def test_every_planned_family_and_term_is_present():
    assert set(FAMILIES) == set(REQUIRED_FAMILIES)
    for name, terms in REQUIRED_FAMILIES.items():
        assert set(FAMILIES[name]["terms"]) == terms, name
        assert FAMILIES[name]["label"]


def test_noisy_terms_are_out_of_the_core_scan():
    assert not {"breach", "KEV", '"patch now"'} & all_terms()
    for query in QUERIES["x"]["queries"]:
        assert not re.search(r"\bbreach\b|\bKEV\b|patch now", query["query"], re.I), query["id"]
    assert set(QUERIES["rules"]["removed_from_core_scan"]) == {"breach", "KEV", '"patch now"'}


def test_no_engagement_minimum_no_cve_year_filter_and_latest_ordering():
    rules = QUERIES["rules"]
    assert rules["engagement_minimum"] is None and rules["cve_year_filter"] is None
    assert rules["ordering"] == "latest" and QUERIES["bluesky"]["sort"] == "latest"
    assert QUERIES["x"]["mode"] == "Latest" and QUERIES["x"]["sort_order"] == "recency"
    text = json.dumps(QUERIES)
    assert not re.search(r"CVE-20\d\d", text)
    assert "min_faves" not in text and "min_retweets" not in text and "min_replies" not in text


def test_early_disclosure_is_contextual():
    family = FAMILIES["early_disclosure"]
    assert family["contextual"] is True and family["context_terms"] and family["note"]
    query = next(q for q in QUERIES["x"]["queries"] if q["family"] == "early_disclosure")["query"]
    assert all(term in query for term in family["context_terms"])


def test_x_has_one_or_query_per_family_and_stays_in_budget():
    x = QUERIES["x"]
    queries = x["queries"]
    assert [q["family"] for q in queries] == list(FAMILIES)
    assert len({q["id"] for q in queries}) == len(queries)
    for query in queries:
        for term in FAMILIES[query["family"]]["terms"]:
            assert term in query["query"], (query["id"], term)
        assert 1 <= query["max_pages"] <= QUERIES["rules"]["page_ceiling"]
    assert sum(q["max_pages"] for q in queries) <= x["max_calls_per_run"] <= 60
    catchup = next(q for q in queries if q["family"] == "catchup")
    assert catchup["query"].split()[0] == "CVE"


def test_catchup_has_its_own_budget_on_every_platform():
    assert "catchup" in QUERIES["bluesky"]["max_pages"]
    masto = QUERIES["mastodon"]["instances"]["mastodon.social"]["search"]["max_pages"]
    assert "catchup" in masto


def test_bluesky_and_mastodon_use_known_families_and_tight_tags():
    assert set(QUERIES["bluesky"]["families"]) <= set(FAMILIES)
    for key in QUERIES["bluesky"]["max_pages"]:
        assert key == "default" or key in FAMILIES
    instances = QUERIES["mastodon"]["instances"]
    assert {"mastodon.social", "infosec.exchange"} <= set(instances)
    social = instances["mastodon.social"]
    assert set(social["search"]["families"]) <= set(FAMILIES)
    assert "infosec" not in social["tags"] and "cybersecurity" not in social["tags"]
    assert {"cve", "zeroday", "0day"} <= set(social["tags"])
    for tag in social["tags"]:
        assert re.fullmatch(r"[a-z0-9]+", tag)
    assert instances["infosec.exchange"]["local_timeline"]["max_pages"] <= QUERIES["rules"]["page_ceiling"]
