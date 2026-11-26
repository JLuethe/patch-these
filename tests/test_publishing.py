"""Publication regressions: future editions, corrections, safe output and URLs."""
# SPDX-License-Identifier: MIT
from copy import deepcopy
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

import pytest

from patchthese.editorial import markdown_digest
from patchthese.feeds import ATOM, build_feed
from patchthese.publishing import StaleGeneratedFiles, build_site, stale_generated_files
from patchthese.rendering import render_markdown
from patchthese.validation import load_editions

ROOT = Path(__file__).resolve().parents[1]
SITE_URL = "https://example.org/patch-these"


@pytest.fixture
def publication(tmp_path):
    for folder in ("assets", "data"):
        shutil.copytree(ROOT / folder, tmp_path / folder)
    for name in ("METHODOLOGY.md", "README.md"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    return tmp_path


def edition_at(root):
    path = sorted((root / "data").glob("????-??-??.json"))[-1]
    return json.loads(path.read_text())


def test_tomorrow_can_publish_without_any_of_todays_products(publication):
    tomorrow = deepcopy(edition_at(publication))
    tomorrow.update(digest_date="2026-11-26", coverage_start="2026-11-26", coverage_end="2026-11-26", published_at="2026-11-27T04:00:00Z", updated_at="2026-11-27T04:00:00Z", corrections=[], featured_item_ids=[])
    item = deepcopy(tomorrow["items"][0])
    item.update(id="independent-example", product="Independent example", summary="A fixture for a different day's subject.", action="Review this example's configuration.", affected=None, cves=[], fixes=[], cvss=[], epss=[], kev=[], sources=[], exploitation={"status": "unknown", "source_ids": []}, fix_status="unknown", action_type="investigate", priority="monitor", priority_reason="More information is needed.")
    item["sources"] = [{"id": "fixture", "kind": "vendor_advisory", "url": "https://example.org/advisory", "label": "Fixture advisory", "checked_at": "2026-11-27T03:00:00Z", "supports": ["summary"]}]
    tomorrow["items"] = [item]
    (publication / "data" / "2026-11-26.json").write_text(json.dumps(tomorrow))
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    assert "Independent example" in home
    assert "158.0.8127.89" not in home
    assert "4403.4405.va_b_cdb_b_d0b_89f" not in home
    assert json.loads((output / "latest.json").read_text())["digest_date"] == "2026-11-26"
    assert (output / "digests" / "2026-11-25" / "index.html").exists()


def test_empty_edition_is_an_explicit_quiet_day(publication):
    edition = edition_at(publication)
    edition.update(items=[], featured_item_ids=[])
    for correction in edition["corrections"]:
        correction["item_ids"] = []
    (publication / "data" / f"{edition['digest_date']}.json").write_text(json.dumps(edition))
    output = build_site(publication, site_url=SITE_URL)
    assert "No new verified items" in (output / "index.html").read_text()
    assert "No new verified items" in (output / "feeds" / "everyone.xml").read_text()
    assert "No new verified items" in (output / "digests" / f"{edition['digest_date']}.md").read_text()


def test_json_changes_reach_all_generated_views_and_normal_build_is_read_only(publication):
    edition = edition_at(publication)
    edition["items"][0]["action"] = "A unique corrected action for this regression."
    data_file = publication / "data" / f"{edition['digest_date']}.json"
    data_file.write_text(json.dumps(edition))
    (publication / "digests").mkdir()
    stale_digest = publication / "digests" / f"{edition['digest_date']}.md"
    stale_digest.write_text("A stale unrelated Markdown copy is not an input.")
    before = {path: path.read_bytes() for path in publication.rglob("*") if path.is_file()}
    output = build_site(publication, site_url=SITE_URL)
    for path, original in before.items():
        assert path.read_bytes() == original
    for path in ("index.html", "feed.xml", f"digests/{edition['digest_date']}.md", f"data/{edition['digest_date']}.json", "latest.json"):
        assert edition["items"][0]["action"] in (output / path).read_text()
    build_site(publication, site_url=SITE_URL, write_generated=True)
    assert edition["items"][0]["action"] in (publication / "README.md").read_text()
    assert stale_digest.read_text() == markdown_digest(edition, SITE_URL)


def test_code_ranges_are_escaped_once_and_unsafe_html_is_removed():
    html = render_markdown('`version < 10.6.22` and `a > b`')
    assert "<code>version &lt; 10.6.22</code>" in html
    assert "&amp;lt;" not in html
    unsafe = render_markdown('<script>alert(1)</script>\n\n<img src="x" onerror="alert(1)">\n\n[bad](javascript:alert(1))\n\n![broken](missing.png){onerror="alert(1)"}')
    assert "<script" not in unsafe
    assert "<img" not in unsafe
    assert 'href="javascript:' not in unsafe


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        self.urls.extend(value for key, value in attrs if key in {"href", "src"})


def test_nested_404_uses_project_root_links_and_all_local_assets_exist(publication):
    output = build_site(publication, site_url=SITE_URL)
    for file in output.rglob("*.html"):
        parsed = Links()
        parsed.feed(file.read_text())
        for url in parsed.urls:
            if url.startswith(("https://", "http://", "#")):
                continue
            assert url.startswith("/patch-these/"), (file, url)
            path = url.removeprefix("/patch-these/").split("#")[0].split("?")[0]
            target = output / path
            assert target.is_file() or (target / "index.html").is_file(), (file, target)
    missing = (output / "404.html").read_text()
    assert 'href="/patch-these/assets/style.css"' in missing
    assert 'href="./' not in missing
    assert 'property="og:image"' in missing
    assert 'name="twitter:card"' in missing


def test_corrections_advance_feed_timestamps_even_for_an_older_edition(publication):
    first = edition_at(publication)
    second = deepcopy(first)
    second.update(digest_date="2026-11-26", published_at="2026-11-27T04:00:00Z", updated_at="2026-11-27T04:00:00Z", corrections=[])
    before = ET.fromstring(build_feed([first, second], SITE_URL))
    first["updated_at"] = "2026-11-28T04:00:00Z"
    first["corrections"].append({"at": first["updated_at"], "summary": "Corrected the earlier advice.", "item_ids": []})
    after = ET.fromstring(build_feed([first, second], SITE_URL))
    tag = lambda value: f"{{{ATOM}}}{value}"
    assert before.findtext(tag("updated")) != after.findtext(tag("updated"))
    assert after.findtext(tag("updated")) == first["updated_at"]
    entries = after.findall(tag("entry"))
    assert entries[-1].findtext(tag("updated")) == first["updated_at"]
    assert entries[-1].findtext(tag("id")) == f"{SITE_URL}/digests/{first['digest_date']}/"
    assert "Corrected the earlier advice" in entries[-1].findtext(tag("content"))


def test_audience_feeds_include_shared_items_and_exclude_the_other_audience(publication):
    edition = edition_at(publication)
    for audience, excluded in [("end_users", "applications_and_servers"), ("applications_and_servers", "end_users")]:
        feed = ET.fromstring(build_feed([edition], SITE_URL, audience=audience))
        content = "".join(entry.findtext(f"{{{ATOM}}}content") for entry in feed.findall(f"{{{ATOM}}}entry"))
        for item in edition["items"]:
            needle = "#item-" + item["id"] + '"'
            assert (needle in content) == (item["audience"] != excluded)


def test_source_text_cannot_become_html(publication):
    edition = edition_at(publication)
    edition["items"][0]["summary"] = '<img src=x onerror="alert(1)"> A literal source claim.'
    (publication / "data" / f"{edition['digest_date']}.json").write_text(json.dumps(edition))
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    assert "<img src=x" not in home
    assert "&lt;img src=x" in home


def test_failed_validation_keeps_the_last_successful_site(publication):
    output = build_site(publication, site_url=SITE_URL)
    before = (output / "index.html").read_bytes()
    (publication / "data" / "2026-11-26.json").write_text('{"schema_version": 99}')
    with pytest.raises(ValueError):
        build_site(publication, site_url=SITE_URL)
    assert (output / "index.html").read_bytes() == before


def test_generated_markdown_cannot_inject_instructions_from_version_text(publication):
    edition = edition_at(publication)
    edition["items"][0]["fixes"][0]["version"] = '1.0`\n\n## Forged instruction\n[bad](javascript:alert(1))'
    generated = markdown_digest(edition, SITE_URL)
    assert "\n## Forged instruction" not in generated
    rendered = render_markdown(generated)
    assert 'href="javascript:' not in rendered
    assert "Forged instruction" in rendered  # A literal code string, never a heading.


def test_lowercase_rfc3339_and_structured_fix_values_reach_the_feed(publication):
    edition = edition_at(publication)
    edition["published_at"] = edition["published_at"].lower()
    edition["updated_at"] = edition["updated_at"].lower()
    edition["items"][0]["action"] = "Use the fixed release listed below."
    (publication / "data" / f"{edition['digest_date']}.json").write_text(json.dumps(edition))
    output = build_site(publication, site_url=SITE_URL)
    feed = ET.fromstring((output / "feed.xml").read_text())
    content = feed.find(f"{{{ATOM}}}entry").findtext(f"{{{ATOM}}}content")
    for fix in edition["items"][0]["fixes"]:
        assert fix["version"] in content
    for cve in edition["items"][0]["cves"]:
        assert cve in content


def test_check_mode_fails_when_generated_views_are_stale(publication):
    shutil.copytree(ROOT / "digests", publication / "digests")
    build_site(publication, site_url=SITE_URL, write_generated=True)
    build_site(publication, site_url=SITE_URL, check_generated=True)

    edition = edition_at(publication)
    edition["items"][0]["action"] = edition["items"][0]["action"] + " Then confirm the version."
    (publication / "data" / f"{edition['digest_date']}.json").write_text(json.dumps(edition))
    with pytest.raises(StaleGeneratedFiles, match=r"digests/2026-11-25\.md, README\.md"):
        build_site(publication, site_url=SITE_URL, check_generated=True)

    build_site(publication, site_url=SITE_URL, write_generated=True)
    (publication / "digests" / "2026-11-24.md").write_text("# An orphan\n")
    with pytest.raises(StaleGeneratedFiles, match="no matching data"):
        build_site(publication, site_url=SITE_URL, check_generated=True)


def test_committed_generated_views_match_the_json():
    assert stale_generated_files(ROOT, load_editions(ROOT / "data"), "https://jluethe.github.io/patch-these") == []


def test_exploitation_label_names_only_the_exploited_cves(publication):
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    chrome = home[home.index('id="item-chrome-desktop"'):]
    chrome = chrome[:chrome.index("</article>")]
    assert "Exploitation confirmed for CVE-2026-125350" in chrome
    assert "CVE-2026-134401: Unknown." in chrome
    drupal = home[home.index('id="item-drupal-core"'):]
    assert '<p class="evidence">Exploitation confirmed ·' in drupal[:drupal.index("</article>")]
