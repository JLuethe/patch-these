"""Feed normalization uses fixtures only. These tests do not open the network."""

from datetime import datetime, timezone

from patchthese.feedcache import (
    apply_fetched_at,
    content_signature,
    dedupe,
    extract_cves,
    new_kev_entries,
    parse_feed_xml,
    parse_github_advisories,
    parse_hn,
    parse_kev,
    within_window,
)

ATOM = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>https://example.invalid/adv/1</id>
    <title>Example advisory CVE-2026-1000</title>
    <updated>2026-11-26T12:00:00Z</updated>
    <link rel="alternate" href="https://example.invalid/adv/1"/>
    <summary>Fixed in 1.2.3 or later.</summary>
  </entry>
  <entry>
    <id>skip-me</id>
    <title>No link</title>
    <updated>2026-11-26T12:00:00Z</updated>
  </entry>
</feed>
"""

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item>
    <title>USN for CVE-2026-2000</title>
    <link>https://example.invalid/usn/2000</link>
    <guid>https://example.invalid/usn/2000</guid>
    <pubDate>Thu, 26 Nov 2026 18:00:00 GMT</pubDate>
    <description>Update the package.</description>
  </item>
</channel></rss>
"""


def test_http_feed_links_are_stored_as_https():
    payload = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry>
      <id>tag:example</id><title>Desktop update</title>
      <updated>2026-11-24T18:36:59Z</updated>
      <link rel="alternate" href="http://chromereleases.googleblog.com/2026/11/example.html"/>
    </entry></feed>"""
    items = parse_feed_xml(payload, "chrome-releases")
    assert items[0]["url"] == "https://chromereleases.googleblog.com/2026/11/example.html"


def test_atom_and_rss_keep_https_links_and_cves():
    atom = parse_feed_xml(ATOM, "example-atom")
    assert atom == [{
        "source": "example-atom",
        "id": "https://example.invalid/adv/1",
        "title": "Example advisory CVE-2026-1000",
        "url": "https://example.invalid/adv/1",
        "published": "2026-11-26T12:00:00Z",
        "cves": ["CVE-2026-1000"],
    }]
    rss = parse_feed_xml(RSS, "example-rss")
    assert rss[0]["cves"] == ["CVE-2026-2000"]
    assert rss[0]["published"] == "2026-11-26T18:00:00Z"
    assert extract_cves("CVE-2026-1000 and CVE-2026-1000") == ["CVE-2026-1000"]


def test_window_dedupes_and_drops_old_or_undated_items():
    now = datetime(2026, 11, 26, 20, 0, tzinfo=timezone.utc)
    items = [
        {"source": "a", "id": "1", "title": "New", "url": "https://example.invalid/new", "published": "2026-11-26T18:00:00Z", "cves": []},
        {"source": "a", "id": "1", "title": "Newer title", "url": "https://example.invalid/new", "published": "2026-11-26T19:00:00Z", "cves": ["CVE-2026-9"]},
        {"source": "a", "id": "old", "title": "Old", "url": "https://example.invalid/old", "published": "2026-11-01T00:00:00Z", "cves": []},
        {"source": "a", "id": "undated", "title": "Undated", "url": "https://example.invalid/none", "published": None, "cves": []},
    ]
    selected = within_window(dedupe(items), now)
    assert [item["id"] for item in selected] == ["1"]
    assert selected[0]["title"] == "Newer title"


def test_kev_diff_and_github_and_hn_shapes():
    kev = parse_kev({"vulnerabilities": [
        {"cveID": "CVE-2026-16232", "dateAdded": "2026-07-22", "vulnerabilityName": "Check Point auth bypass"},
        {"cveID": "CVE-2026-99999", "dateAdded": "2026-11-26", "vulnerabilityName": "New catalog entry"},
    ]})
    fresh = new_kev_entries(kev, {"CVE-2026-16232"})
    assert [item["id"] for item in fresh] == ["CVE-2026-99999"]
    advisories = parse_github_advisories([{
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2026-3000",
        "summary": "Example package issue",
        "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "published_at": "2026-11-26T01:00:00Z",
    }])
    assert advisories[0]["source"] == "github-advisories"
    assert advisories[0]["cves"] == ["CVE-2026-3000"]
    stories = parse_hn({"hits": [
        {"objectID": "42", "title": "CVE-2026-3000 is being discussed", "url": "https://exploit.example/poc", "created_at": "2026-11-26T02:00:00Z"},
        {"objectID": "43", "title": "Chrome vulnerability allows code execution", "created_at": "2026-11-26T02:00:00Z"},
    ]})
    assert stories[0]["url"] == "https://news.ycombinator.com/item?id=42"
    assert "exploit.example" not in stories[0]["url"]
    assert len(stories) == 2


def test_fetched_at_is_kept_for_an_unchanged_lead():
    previous = [{"source": "a", "id": "1", "title": "New", "url": "https://example.invalid/new", "published": "2026-11-26T19:00:00Z", "cves": [], "fetched_at": "2026-11-26T18:00:00Z"}]
    current = [{key: value for key, value in previous[0].items() if key != "fetched_at"}]
    stamped = apply_fetched_at(current, previous, "2026-11-26T20:00:00Z")
    assert stamped[0]["fetched_at"] == "2026-11-26T18:00:00Z"
    assert content_signature(stamped) == content_signature(previous)


def test_hacker_news_searches_this_years_and_last_years_cve_ids():
    from fetch_feeds import hn_urls
    from patchthese.feedcache import hn_cve_years
    assert hn_cve_years(datetime(2027, 1, 3, tzinfo=timezone.utc)) == [2027, 2026]
    assert hn_cve_years(datetime(2031, 6, 1, tzinfo=timezone.utc)) == [2031, 2030]
    urls = hn_urls(datetime(2027, 1, 3, tzinfo=timezone.utc))
    assert any("query=CVE-2027&" in url for url in urls)
    assert any("query=CVE-2026&" in url for url in urls)
    assert not any("query=CVE-2025&" in url for url in urls)


def test_last_ok_carries_forward_and_staleness_is_reported_after_24_hours():
    from datetime import timedelta
    from patchthese.feedcache import stale_sources, update_source_status
    first = update_source_status({}, ["a", "b"], {}, "2026-11-26T00:00:00Z")
    second = update_source_status(first, ["a"], {"b": "HTTPError"}, "2026-11-26T12:00:00Z")
    assert second["sources"]["b"]["last_ok"] == "2026-11-26T00:00:00Z"
    assert second["sources"]["b"]["last_error"] == "HTTPError"
    assert second["sources"]["a"]["last_ok"] == "2026-11-26T12:00:00Z"
    noon = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
    assert stale_sources(second, noon) == []  # Down for 12 hours: not stale yet.
    assert stale_sources(second, noon + timedelta(hours=13)) == [("b", "2026-11-26T00:00:00Z")]
    never = update_source_status({}, [], {"c": "URLError"}, "2026-11-26T00:00:00Z")
    assert stale_sources(never, noon + timedelta(hours=13)) == [("c", None)]


def _fake_fetcher(failing=()):
    import json as _json
    from fetch_feeds import FEEDS, KEV_URL

    feed_urls = dict((url, name) for name, url in FEEDS)

    def fetcher(url, token=None, timeout=25):
        name = feed_urls.get(url) or ("cisa-kev" if url == KEV_URL else "github-advisories" if "api.github.com" in url else "hacker-news")
        if name in failing:
            raise OSError("down")
        if name == "cisa-kev":
            return _json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-16232", "dateAdded": "2026-07-22", "vulnerabilityName": "x"}]}).encode()
        if name == "github-advisories":
            return b"[]"
        if name == "hacker-news":
            return b'{"hits": []}'
        return ATOM.replace(b"https://example.invalid/adv/1", f"https://example.invalid/{name}/1".encode())
    return fetcher


def test_build_cache_keeps_a_failed_sources_rows_and_warns_only_when_stale(tmp_path, capsys, monkeypatch):
    import json as _json
    from datetime import timedelta
    from fetch_feeds import build_cache
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    start = datetime(2026, 11, 26, 13, 0, tzinfo=timezone.utc)
    assert build_cache(tmp_path, token=None, now=start, fetcher=_fake_fetcher()) == 0
    status = _json.loads((tmp_path / "status.json").read_text())
    assert status["sources"]["palo-alto"]["last_ok"] == "2026-11-26T13:00:00Z"
    capsys.readouterr()

    later = start + timedelta(hours=6)
    assert build_cache(tmp_path, token=None, now=later, fetcher=_fake_fetcher({"palo-alto"})) == 0
    latest = _json.loads((tmp_path / "latest.json").read_text())
    assert any(item["source"] == "palo-alto" for item in latest["items"])
    status = _json.loads((tmp_path / "status.json").read_text())
    assert status["sources"]["palo-alto"]["last_ok"] == "2026-11-26T13:00:00Z"
    assert "::warning" not in capsys.readouterr().out

    much_later = start + timedelta(hours=25)
    assert build_cache(tmp_path, token=None, now=much_later, fetcher=_fake_fetcher({"palo-alto"})) == 0
    out = capsys.readouterr().out
    assert "::warning title=Stale discovery feed::palo-alto has not succeeded for more than 24 hours" in out


def test_build_cache_fails_only_when_every_source_fails(tmp_path):
    from fetch_feeds import FEEDS, build_cache
    everything = {"cisa-kev", "github-advisories", "hacker-news", *(name for name, _ in FEEDS)}
    now = datetime(2026, 11, 26, 13, 0, tzinfo=timezone.utc)
    assert build_cache(tmp_path, token=None, now=now, fetcher=_fake_fetcher(everything)) == 1
    assert build_cache(tmp_path, token=None, now=now, fetcher=_fake_fetcher({"cisa-kev"})) == 0
