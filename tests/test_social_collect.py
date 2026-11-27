"""social_collect.py: paging, states, checkpoints, candidates and the X record path, with mocked HTTP."""
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

import social_collect as sc

NOW = datetime(2026, 11, 27, 18, 0, tzinfo=timezone.utc)


def t(minutes_ago: float) -> str:
    return sc.iso(NOW - timedelta(minutes=minutes_ago))


def bsky(handle, rkey, minutes_ago, text="text"):
    return {"uri": f"at://did:plc:x/app.bsky.feed.post/{rkey}", "author": {"handle": handle},
            "indexedAt": t(minutes_ago), "record": {"text": text, "createdAt": t(minutes_ago)}}


def masto(host, user, sid, minutes_ago, text="text", bot=False):
    return {"id": str(sid), "url": f"https://{host}/@{user}/{sid}", "created_at": t(minutes_ago),
            "content": f"<p>{text}</p>", "account": {"acct": user, "bot": bot}}


def query(pages, max_pages=8, family="auth", keep=None):
    """A Query whose pages come from a list; an Exception in the list is raised."""
    def fetch(cursor):
        index = cursor or 0
        page = pages[index]
        if isinstance(page, Exception):
            raise page
        posts = [p for p in (sc.bluesky_post(item) for item in page) if p]
        return posts, index + 1 if index + 1 < len(pages) else None
    return sc.Query("bluesky:test", "bluesky", "search", "term", max_pages, fetch, family, keep)


SINCE = NOW - timedelta(hours=4)


def test_states_ok_empty_incomplete_and_failed():
    ok = sc.run_query(query([[bsky("a.b", "1", 10)]]), SINCE)
    assert ok.row["state"] == "ok" and ok.row["kept"] == 1
    empty = sc.run_query(query([[]]), SINCE)
    assert empty.row["state"] == "empty" and empty.row["pages"] == 1
    old_only = sc.run_query(query([[bsky("a.b", "1", 300)]]), SINCE)
    assert old_only.row["state"] == "empty", "a page reaching past the window covers it"
    budget = sc.run_query(query([[bsky("a.b", str(i), 10 + i)] for i in range(5)], max_pages=2), SINCE)
    assert budget.row["state"] == "incomplete" and budget.row["pages"] == 2 and budget.row["kept"] == 2
    assert budget.row["oldest_reached"] == t(11)
    failed = sc.run_query(query([sc.FetchError("HTTP 500")]), SINCE)
    assert failed.row["state"] == "failed" and failed.row["error"] == "HTTP 500"
    partial = sc.run_query(query([[bsky("a.b", "1", 10)], sc.FetchError("HTTP 403")]), SINCE)
    assert partial.row["state"] == "incomplete" and partial.row["error"] == "HTTP 403" and partial.row["kept"] == 1


def test_posts_older_than_the_window_and_bots_are_dropped():
    statuses = [masto("m.s", "human", 2, 5), masto("m.s", "robot", 1, 6, bot=True)]
    fetch = lambda cursor: ([sc.mastodon_post(s) for s in statuses], None)
    outcome = sc.run_query(sc.Query("m", "mastodon", "tag", "#cve", 2, fetch), SINCE)
    assert [post.author for post, _ in outcome.kept] == ["human"]


def test_contextual_family_needs_a_security_word():
    family = {"terms": ["unpatched", '"no CVE"'], "contextual": True, "context_terms": ["vulnerability", "exploit", "CVE"]}
    assert sc.matches_family("Unpatched router vulnerability under attack", family)
    assert not sc.matches_family("my unpatched jeans", family)
    assert sc.matches_family("RCE, no CVE yet, exploit is public", family)
    assert sc.term_pattern('"zero-day"').search("a zero day in the wild") and sc.term_pattern("SSRF").search("an SSRF bug")
    assert sc.term_pattern('"zero-day"').search("Zero-Day") and not sc.term_pattern("0day").search("10days")
    families = {"catchup": {"terms": ["CVE"]}, "auth": {"terms": ['"auth bypass"']}}
    assert sorted(sc.matching_families("Fix for CVE-2026-1234 auth bypass", families)) == ["auth", "catchup"]
    assert sc.matching_families("lunch", families) == []


def test_bluesky_search_pages_by_time_because_the_cursor_is_refused():
    calls = []

    def fake(url, token=None):
        params = parse_qs(urlsplit(url).query)
        calls.append(params)
        if "until" not in params:
            return {"posts": [bsky("a.b", "2", 10), bsky("a.b", "1", 20)], "cursor": "refused"}
        return {"posts": [bsky("a.b", "1", 20)]}

    sc.http_get, original = fake, sc.http_get
    try:
        outcome = sc.run_query(sc.Query("q", "bluesky", "search", "x", 8, sc.bluesky_search("x", SINCE, 2), "auth"), SINCE)
    finally:
        sc.http_get = original
    assert "cursor" not in calls[1] and calls[1]["until"] == [t(20)]
    assert calls[0]["sort"] == ["latest"] and calls[0]["since"] == [sc.iso(SINCE)]
    assert outcome.row["state"] == "ok" and outcome.row["pages"] == 2


class FakeNetwork:
    def __init__(self):
        self.calls = []

    def __call__(self, url, token=None):
        parts = urlsplit(url)
        self.calls.append((parts.hostname, token))
        params = parse_qs(parts.query)
        if parts.hostname == "api.bsky.app":
            term = params["q"][0]
            if term == "SSRF":
                raise sc.FetchError("HTTP 500")
            if term == "unpatched":
                return {"posts": [bsky("c.d", "u1", 30, "unpatched phone"), bsky("c.d", "u2", 31, "unpatched VPN vulnerability")]}
            if term == '"auth bypass"':
                return {"posts": [bsky("a.b", "same", 15, "auth bypass in Foo CVE-2026-1")]}
            if term == "CVE":
                return {"posts": [bsky("a.b", "same", 15, "auth bypass in Foo CVE-2026-1")]}
            return {"posts": []}
        if parts.hostname == "public.api.bsky.app":
            return {"feed": [{"post": bsky(params["actor"][0], "w1", 50, "anything at all")},
                             {"post": bsky("other", "rp", 40), "reason": {"$type": "app.bsky.feed.defs#reasonRepost"}}]}
        if parts.path.endswith("/accounts/lookup"):
            return {"id": "77"}
        if "/accounts/77/statuses" in parts.path:
            return [masto(parts.hostname, "watcher", 900, 25, "no keyword here")]
        if parts.path.startswith("/api/v1/timelines/public"):
            return [masto(parts.hostname, "a", 3, 5, "lunch"), masto(parts.hostname, "b", 2, 6, "path traversal in Bar"),
                    masto(parts.hostname, "c", 1, 7, "see CVE-2026-55")]
        if parts.path.startswith("/api/v1/timelines/tag/"):
            return [masto(parts.hostname, "t", 10, 8, "tagged"), masto(parts.hostname, "bot", 9, 9, "bot post", bot=True)]
        if parts.path == "/api/v2/search":
            return {"statuses": []}
        raise AssertionError(url)


@pytest.fixture()
def network(monkeypatch, tmp_path):
    fake = FakeNetwork()
    monkeypatch.setattr(sc, "http_get", fake)
    monkeypatch.setenv("PT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("MASTODON_TOKEN", "secret-token-value")
    return fake


def test_collect_writes_candidates_report_and_checkpoints(network, tmp_path, capsys):
    report = sc.collect({"bluesky", "mastodon"}, pause=0, now=NOW)
    candidates = json.loads((tmp_path / "social-candidates.json").read_text())
    urls = [row["url"] for row in candidates]
    assert len(urls) == len(set(urls))
    shared = next(row for row in candidates if row["url"].endswith("/post/same"))
    assert set(shared["families"]) == {"auth", "catchup"} and len(shared["queries"]) == 2
    assert not any(row["url"].endswith("/post/u1") for row in candidates), "contextual term without a security word"
    assert any(row["url"].endswith("/post/u2") for row in candidates)
    assert not any("/post/rp" in url for url in urls), "reposts in author feeds are skipped"
    watch = [row for row in candidates if row["watchlist"]]
    assert watch and all(row["families"] == [] for row in watch), "watchlist posts are kept without keywords"
    local = [row["url"] for row in candidates if "/@" in row["url"] and "infosec.exchange" in row["url"] and not row["watchlist"]]
    assert sorted(local) == ["https://infosec.exchange/@b/2", "https://infosec.exchange/@c/1"]
    assert not any("/@bot/" in url for url in urls)
    assert [row["created_at"] for row in candidates] == sorted((row["created_at"] for row in candidates), reverse=True)

    states = {row["id"]: row["state"] for row in report["queries"]}
    assert states["bluesky:file_request:ssrf"] == "failed"
    assert states["bluesky:auth:auth-bypass"] == "ok" and states["bluesky:privilege:container-escape"] == "empty"
    assert report["totals"]["failed"] == 1 and report["candidates"] == len(candidates)
    saved = json.loads((tmp_path / "social-report.json").read_text())
    assert saved["totals"] == report["totals"]

    checkpoints = json.loads((tmp_path / "social-checkpoints.json").read_text())
    assert checkpoints["bluesky:auth:auth-bypass"]["checkpoint"] == sc.iso(NOW)
    assert "checkpoint" not in checkpoints["bluesky:file_request:ssrf"]
    assert checkpoints["bluesky:file_request:ssrf"]["last_state"] == "failed"

    later = NOW + timedelta(hours=4)
    rules = json.loads((sc.ROOT / "social" / "queries.json").read_text())["rules"]
    assert sc.window_start(checkpoints, "bluesky:auth:auth-bypass", later, rules) == NOW - timedelta(minutes=10)
    assert sc.window_start(checkpoints, "bluesky:file_request:ssrf", later, rules) == later - timedelta(hours=4)


def test_the_mastodon_token_only_goes_to_mastodon_social_and_is_never_printed(network, tmp_path, capsys):
    sc.collect({"mastodon"}, pause=0, now=NOW)
    sent = {host for host, token in network.calls if token}
    assert sent == {"mastodon.social"}
    for path in tmp_path.iterdir():
        assert "secret-token-value" not in path.read_text()
    out = capsys.readouterr()
    assert "secret-token-value" not in out.out + out.err


def test_without_a_token_search_is_reported_failed_and_tags_still_run(network, monkeypatch):
    monkeypatch.delenv("MASTODON_TOKEN")
    report = sc.collect({"mastodon"}, pause=0, now=NOW)
    states = {row["id"]: row["state"] for row in report["queries"]}
    assert states["mastodon.social:search"] == "failed"
    assert states["mastodon.social:tag:cve"] == "ok"
    assert not any(host == "mastodon.social" and token for host, token in network.calls)


def test_dry_run_writes_no_state(network, tmp_path):
    sc.collect({"bluesky"}, pause=0, now=NOW, dry_run=True)
    assert list(tmp_path.iterdir()) == []


def record_args(**overrides):
    base = dict(id="x:auth", state="ok", pages=1, posts=3, kept=None, max_pages=2, query="(...)", family="auth",
                window_start=t(240), oldest=t(200), error=None, candidates=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_x_plan_and_record_share_the_report_and_checkpoints(network, tmp_path):
    plan = sc.x_plan(now=NOW)
    assert [row["id"] for row in plan][-1] == "x:watchlist"
    assert all(row["start_time"] == t(240) for row in plan)
    assert sum(row["max_pages"] for row in plan) <= 40
    sc.collect({"bluesky"}, pause=0, now=NOW)
    before = len(json.loads((tmp_path / "social-candidates.json").read_text()))
    urls = tmp_path / "x.txt"
    urls.write_text("https://x.com/a/status/1\nhttps://twitter.com/a/status/1\nhttps://x.com/b/status/2\n")
    sc.record(record_args(candidates=str(urls)), now=NOW + timedelta(minutes=5))
    sc.record(record_args(id="x:catchup", state="incomplete", pages=4, posts=100, family="catchup"), now=NOW + timedelta(minutes=6))
    sc.record(record_args(id="x:zero_day", state="failed", pages=0, posts=0, error="rate limited"), now=NOW + timedelta(minutes=7))
    report = json.loads((tmp_path / "social-report.json").read_text())
    states = {row["id"]: row["state"] for row in report["queries"]}
    assert states["x:auth"] == "ok" and states["x:catchup"] == "incomplete" and states["x:zero_day"] == "failed"
    assert "bluesky:auth:auth-bypass" in states, "X rows join the collector's report"
    candidates = json.loads((tmp_path / "social-candidates.json").read_text())
    assert len(candidates) == before + 2
    x_row = next(row for row in candidates if row["url"] == "https://x.com/a/status/1")
    assert x_row["queries"] == ["x:auth"] and x_row["families"] == ["auth"] and x_row["platform"] == "x"
    checkpoints = json.loads((tmp_path / "social-checkpoints.json").read_text())
    assert checkpoints["x:auth"]["checkpoint"] == sc.iso(NOW), "the checkpoint is the run start"
    assert "checkpoint" not in checkpoints["x:zero_day"]
    replan = {row["id"]: row["start_time"] for row in sc.x_plan(now=NOW + timedelta(hours=4))}
    assert replan["x:auth"] == t(10) and replan["x:zero_day"] == sc.iso(NOW)


def test_candidates_feed_straight_into_seen_posts_filter(network, tmp_path):
    import seen_posts
    sc.collect({"bluesky"}, pause=0, now=NOW)
    entries, as_json = seen_posts.read_entries((tmp_path / "social-candidates.json").read_text())
    assert as_json and entries
    assert all(seen_posts.normalize(entry["url"]) for entry in entries)


def test_summary_lists_incomplete_and_failed_queries():
    report = {"run_started_at": t(0), "candidates": 2, "totals": {"ok": 1, "failed": 1},
              "queries": [{"id": "a", "state": "ok", "pages": 1, "max_pages": 1},
                          {"id": "b", "state": "failed", "pages": 0, "max_pages": 1, "error": "HTTP 500"}]}
    lines = sc.summary_lines(report)
    assert "candidates 2" in lines[0] and len(lines) == 2 and "HTTP 500" in lines[1]
