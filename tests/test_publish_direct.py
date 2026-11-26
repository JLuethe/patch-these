"""Direct-publish decisions that do not touch the network or git."""

from datetime import datetime, timezone

from publish_direct import blocking_dead, commit_message, reported_new_dead


def test_commit_message_uses_pacific_time():
    when = datetime(2026, 11, 26, 23, 15, tzinfo=timezone.utc)
    assert commit_message([__import__("pathlib").Path("data/2026-11-26.json")], when) == "Update 2026-11-26 edition (15:15 PT run)"


def test_new_nonsocial_dead_links_are_reported_and_do_not_block():
    results = [
        {"target": "https://vendor.example/new", "status": "dead", "kind": "external", "detail": "HTTP 404"},
        {"target": "https://vendor.example/old", "status": "dead", "kind": "external", "detail": "HTTP 404"},
        {"target": "https://x.com/example/status/1", "status": "inconclusive", "kind": "external", "detail": "login"},
        {"target": "README.md", "status": "dead", "kind": "local", "detail": "missing"},
    ]
    new_urls = {"https://vendor.example/new"}
    assert [item["target"] for item in reported_new_dead(results, new_urls)] == ["https://vendor.example/new"]
    assert [item["target"] for item in blocking_dead(results, new_urls)] == ["https://vendor.example/old", "README.md"]
