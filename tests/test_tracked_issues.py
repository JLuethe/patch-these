"""tracked_issues.py: issue states, transitions, matching and pruning, in a temporary state dir."""
from datetime import datetime, timedelta, timezone
import json

import pytest

import tracked_issues as ti

NOW = datetime(2026, 11, 27, 18, 0, tzinfo=timezone.utc)


@pytest.fixture()
def state(monkeypatch, tmp_path):
    monkeypatch.setenv("PT_STATE_DIR", str(tmp_path))
    return tmp_path


def stored(state):
    return json.loads((state / "tracked-issues.json").read_text())["issues"]


def test_lifecycle_pending_evaluated_tracked_closed(state, capsys):
    assert ti.main(["add", "example-vpn", "--title", "Example VPN auth bypass", "--cve", "cve-2026-1111",
                    "--product", "Example VPN", "--post", "https://x.com/a/status/1"], NOW) == 0
    issue = stored(state)["example-vpn"]
    assert issue["state"] == "pending" and issue["cves"] == ["CVE-2026-1111"] and issue["posts"] == [{"id": "x:1", "url": "https://x.com/a/status/1"}]
    assert ti.main(["set", "example-vpn", "evaluated", "--note", "one unverified post"], NOW + timedelta(hours=1)) == 0
    assert ti.main(["set", "example-vpn", "tracked"], NOW) == 2, "tracked needs the edition item id"
    assert "item-id" in capsys.readouterr().err
    assert ti.main(["set", "example-vpn", "tracked", "--item-id", "example-vpn", "--edition", "2026-11-27"], NOW + timedelta(hours=2)) == 0
    assert ti.main(["set", "example-vpn", "pending"], NOW) == 2, "tracked can only be closed"
    assert ti.main(["set", "example-vpn", "closed", "--note", "verified and patched"], NOW + timedelta(hours=3)) == 0
    issue = stored(state)["example-vpn"]
    assert [h["to"] for h in issue["history"]] == ["pending", "evaluated", "tracked", "closed"]
    assert issue["item_id"] == "example-vpn" and issue["edition"] == "2026-11-27"
    assert ti.main(["set", "example-vpn", "pending", "--note", "new bypass reported"], NOW + timedelta(days=1)) == 0, "closed can reopen"


def test_add_validates_ids_cves_posts_and_duplicates(state):
    assert ti.main(["add", "Bad Id", "--title", "x"], NOW) == 2
    assert ti.main(["add", "ok-id", "--title", "x", "--cve", "CVE-26-1"], NOW) == 2
    assert ti.main(["add", "ok-id", "--title", "x", "--post", "https://vendor.example/advisory"], NOW) == 2
    assert ti.main(["add", "ok-id", "--title", "x"], NOW) == 0
    assert ti.main(["add", "ok-id", "--title", "again"], NOW) == 2
    assert ti.main(["set", "missing", "closed"], NOW) == 2


def test_attach_dedupes_posts_across_url_forms(state):
    ti.main(["add", "foo", "--title", "Foo", "--post", "https://x.com/a/status/9"], NOW)
    ti.main(["attach", "foo", "--post", "https://twitter.com/a/status/9", "--post", "https://bsky.app/profile/a.b/post/3x",
             "--cve", "CVE-2026-0002", "--note", "second report"], NOW + timedelta(hours=1))
    issue = stored(state)["foo"]
    assert [p["id"] for p in issue["posts"]] == ["x:9", "bsky:a.b/3x"]
    assert issue["cves"] == ["CVE-2026-0002"] and issue["notes"][0]["note"] == "second report"
    assert issue["updated_at"] == ti.stamp(NOW + timedelta(hours=1))


def test_match_finds_open_issues_by_post_cve_or_product(state, capsys):
    ti.main(["add", "foo", "--title", "Foo", "--product", "FooServer", "--cve", "CVE-2026-0003", "--post", "https://x.com/a/status/5"], NOW)
    ti.main(["add", "bar", "--title", "Bar", "--product", "bar"], NOW)
    ti.main(["set", "bar", "closed"], NOW)
    issues = ti.load(ti.store_path())
    assert [i["id"] for i in ti.match(issues, ["new fooserver exploit seen"])] == ["foo"]
    assert [i["id"] for i in ti.match(issues, ["patch for cve-2026-0003 out"])] == ["foo"]
    assert [i["id"] for i in ti.match(issues, ["https://twitter.com/z/status/5"])] == ["foo"]
    assert ti.match(issues, ["a crowbar"]) == [], "products match whole words only"
    assert ti.match(issues, ["bar is down"]) == [] and [i["id"] for i in ti.match(issues, ["bar is down"], include_closed=True)] == ["bar"]
    capsys.readouterr()
    assert ti.main(["match", "CVE-2026-0003"], NOW) == 0
    assert [i["id"] for i in json.loads(capsys.readouterr().out)] == ["foo"]


def test_prune_closes_idle_leads_and_drops_old_closed_issues(state):
    ti.main(["add", "idle", "--title", "Idle lead"], NOW - timedelta(days=15))
    ti.main(["add", "fresh", "--title", "Fresh lead"], NOW - timedelta(days=2))
    ti.main(["add", "published", "--title", "Published"], NOW - timedelta(days=40))
    ti.main(["set", "published", "tracked", "--item-id", "published"], NOW - timedelta(days=40))
    ti.main(["add", "old", "--title", "Old"], NOW - timedelta(days=40))
    ti.main(["set", "old", "closed"], NOW - timedelta(days=31))
    assert ti.main(["prune"], NOW) == 0
    issues = stored(state)
    assert set(issues) == {"idle", "fresh", "published"}
    assert issues["idle"]["state"] == "closed" and "14 days" in issues["idle"]["notes"][-1]["note"]
    assert issues["fresh"]["state"] == "pending" and issues["published"]["state"] == "tracked"


def test_list_filters_by_state(state, capsys):
    ti.main(["add", "a", "--title", "A"], NOW)
    ti.main(["add", "b", "--title", "B"], NOW + timedelta(minutes=1))
    ti.main(["set", "b", "evaluated"], NOW + timedelta(minutes=2))
    capsys.readouterr()
    ti.main(["list", "--state", "evaluated", "--json"], NOW)
    assert [i["id"] for i in json.loads(capsys.readouterr().out)] == ["b"]
    ti.main(["list"], NOW)
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("evaluated b") and out[1].startswith("pending   a")
