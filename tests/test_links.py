"""Offline checks for link-result semantics; no public sites are contacted."""

from pathlib import Path
import sys
from urllib.error import HTTPError, URLError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_links


def test_markdown_links_ignore_examples_and_preserve_parentheses():
    source = """
[Advisory](https://vendor.example/advisory_(v2))
<https://vendor.example/next>
[reference]: https://vendor.example/reference "Title"
`[example](https://not-a-link.example)`
```markdown
[example](https://also-not-a-link.example)
```
"""
    assert set(check_links.markdown_targets(source)) == {
        "https://vendor.example/advisory_(v2)",
        "https://vendor.example/next",
        "https://vendor.example/reference",
    }


@pytest.mark.parametrize("code", [404, 410])
def test_public_not_found_is_dead(code):
    def unavailable(request, timeout):
        raise HTTPError(request.full_url, code, "Unavailable", {}, None)

    result = check_links.check_external("https://vendor.example/advisory", opener=unavailable)
    assert result["status"] == "dead"
    assert result["status_code"] == code


@pytest.mark.parametrize("code", [401, 403, 404, 410, 429])
def test_social_login_and_error_pages_are_inconclusive(code):
    def unavailable(request, timeout):
        raise HTTPError(request.full_url, code, "Unavailable", {}, None)

    result = check_links.check_external("https://x.com/researcher/status/123", opener=unavailable, sleeper=lambda _: None)
    assert result["status"] == "inconclusive"


@pytest.mark.parametrize("code", [401, 403, 429, 500, 503])
def test_public_access_failures_do_not_mean_dead(code):
    def unavailable(request, timeout):
        raise HTTPError(request.full_url, code, "Unavailable", {}, None)

    result = check_links.check_external("https://vendor.example/advisory", opener=unavailable, sleeper=lambda _: None)
    assert result["status"] == "inconclusive"
    assert result["attempts"] == (3 if code == 429 or code >= 500 else 1)


def test_transient_network_failure_is_retried():
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def geturl(self):
            return "https://vendor.example/advisory"

    def eventually_available(request, timeout):
        calls.append(request.full_url)
        if len(calls) < 2:
            raise URLError("Temporary network error")
        return Response()

    result = check_links.check_external("https://vendor.example/advisory", opener=eventually_available, sleeper=lambda _: None)
    assert result["status"] == "available"
    assert result["attempts"] == 2


def test_collect_deduplicates_json_and_markdown_sources(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data/2026-11-25.json").write_text(
        '{"items":[{"sources":[{"url":"https://vendor.example/advisory"}]}]}', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text(
        "[Source](https://vendor.example/advisory#details) [Method](METHODOLOGY.md)", encoding="utf-8"
    )
    external, local = check_links.collect_links(tmp_path)
    assert external == {"https://vendor.example/advisory": {"data/2026-11-25.json", "README.md"}}
    assert local == {"METHODOLOGY.md": {"README.md"}}


def test_summary_does_not_claim_inconclusive_links_are_verified():
    summary = check_links.report_summary([{
        "status": "inconclusive", "target": "https://vendor.example", "detail": "HTTP 403"
    }])
    assert "1 inconclusive" in summary
    assert "need manual review" in summary


def test_social_login_page_is_not_verified_even_when_http_200():
    assert check_links.classify_http(200, "x.com") == "inconclusive"


class _SocialResponse:
    def __init__(self, url):
        self.status = 200
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self._url


@pytest.mark.parametrize("url", [
    "https://bsky.app/profile/example.bsky.social/post/3abc",
    "https://mastodon.social/@example/123456",
    "https://mastodon.social/@example@infosec.exchange/123456",
    "https://infosec.exchange/@example/123456",
    "https://infosec.exchange/users/example/statuses/123456",
])
def test_bluesky_and_mastodon_posts_are_inconclusive_when_unauthenticated(url):
    def opened(request, timeout):
        return _SocialResponse(request.full_url)

    result = check_links.check_external(url, opener=opened, sleeper=lambda _: None)
    assert result["status"] == "inconclusive"
    assert "not verified" in result["detail"]


def test_a_normal_page_on_a_mastodon_server_is_still_checked():
    def missing(request, timeout):
        raise HTTPError(request.full_url, 404, "Unavailable", {}, None)

    result = check_links.check_external("https://infosec.exchange/about", opener=missing, sleeper=lambda _: None)
    assert result["status"] == "dead"


def test_missing_local_link_fails_and_leaves_report(tmp_path):
    (tmp_path / "README.md").write_text("[Missing](missing.md)", encoding="utf-8")
    report = tmp_path / "report.json"
    assert check_links.main(["--root", str(tmp_path), "--report", str(report)]) == 1
    assert '"dead": 1' in report.read_text(encoding="utf-8")
