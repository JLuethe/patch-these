"""Publication regressions: future editions, corrections, safe output and URLs.

Every test builds from small synthetic editions (tests/editions.py), so a new
day's data or a quiet day never breaks them. Only
test_committed_generated_views_match_the_json reads the real data, on purpose.
"""
# SPDX-License-Identifier: MIT
from html.parser import HTMLParser
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

import editions as fx
from patchthese.common import exploitation_label, verification_labels
from patchthese.editorial import markdown_digest
from patchthese.feeds import ATOM, build_feed
from patchthese.publishing import StaleGeneratedFiles, build_site, stale_generated_files
from patchthese.rendering import render_markdown, source_link
from patchthese.validation import load_editions

ROOT = Path(__file__).resolve().parents[1]
SITE_URL = "https://example.org/patch-these"


def two_days():
    first = fx.edition(fx.DAY_ONE, [fx.item("old-server", "Old Server", cve="CVE-2030-10001")])
    second = fx.edition(fx.DAY_TWO, [
        fx.item("new-server", "New Server", cve="CVE-2030-20001"),
        fx.item("desktop-app", "Desktop App", cve="CVE-2030-20002", audience="end_users"),
        fx.item("shared-tool", "Shared Tool", cve="CVE-2030-20003", audience="both"),
        fx.early_signal(),
    ])
    return first, second


@pytest.fixture
def publication(tmp_path):
    return fx.publication(tmp_path, list(two_days()))


def latest(root):
    path = sorted((root / "data").glob("????-??-??.json"))[-1]
    return json.loads(path.read_text())


def save(root, payload):
    fx.write_edition(root, payload)


def between(html, start, end="</article>"):
    chunk = html[html.index(start):]
    return chunk[:chunk.index(end)]


def test_the_homepage_shows_the_newest_edition_only(publication):
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    assert "New Server" in home
    assert "Old Server" not in home
    assert json.loads((output / "latest.json").read_text())["digest_date"] == fx.DAY_TWO
    assert "Old Server" in (output / "digests" / fx.DAY_ONE / "index.html").read_text()


def test_a_new_day_can_publish_without_any_of_the_previous_days_products(publication):
    tomorrow = fx.edition("2030-03-03", [fx.item("independent-example", "Independent example", cve="CVE-2030-30001")])
    save(publication, tomorrow)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    assert "Independent example" in home
    assert "New Server" not in home


def test_site_credits_the_maintainer(publication):
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    assert home.count('By <a href="https://github.com/JLuethe">John Luethe</a>') == 2
    assert "updated every 4 hours from 6 AM to 10 PM Pacific" in home
    assert "finds new issues on X, Bluesky and Mastodon" in home
    assert "No exploit details." in home
    feed = (output / "feed.xml").read_text()
    assert "updated every 4 hours from 6 AM to 10 PM Pacific" in feed
    assert "Maintained by [John Luethe](https://github.com/JLuethe)." in (ROOT / "README.md").read_text()


def test_social_source_labels_name_the_platform():
    assert "X · Discussed" in source_link({"kind": "social_report", "url": "https://x.com/example/status/1", "label": "Discussed"})
    assert "Bluesky · Discussed" in source_link({"kind": "social_report", "url": "https://bsky.app/profile/example.bsky.social/post/3abc", "label": "Discussed"})
    assert "Mastodon · Discussed" in source_link({"kind": "social_report", "url": "https://infosec.exchange/@example/123", "label": "Discussed"})


def test_empty_edition_is_an_explicit_quiet_day(publication):
    save(publication, fx.edition(fx.DAY_TWO, []))
    output = build_site(publication, site_url=SITE_URL)
    assert "No new verified items" in (output / "index.html").read_text()
    assert "No new verified items" in (output / "feeds" / "everyone.xml").read_text()
    assert "No new verified items" in (output / "digests" / f"{fx.DAY_TWO}.md").read_text()


def test_json_changes_reach_all_generated_views_and_normal_build_is_read_only(publication):
    edition = latest(publication)
    edition["items"][0]["action"] = "A unique corrected action for this regression."
    save(publication, edition)
    (publication / "digests").mkdir()
    stale_digest = publication / "digests" / f"{fx.DAY_TWO}.md"
    stale_digest.write_text("A stale unrelated Markdown copy is not an input.")
    before = {path: path.read_bytes() for path in publication.rglob("*") if path.is_file()}
    output = build_site(publication, site_url=SITE_URL)
    for path, original in before.items():
        assert path.read_bytes() == original
    for path in ("index.html", "feed.xml", f"digests/{fx.DAY_TWO}.md", f"data/{fx.DAY_TWO}.json", "latest.json"):
        assert "A unique corrected action for this regression." in (output / path).read_text()
    build_site(publication, site_url=SITE_URL, write_generated=True)
    assert "A unique corrected action for this regression." in (publication / "README.md").read_text()
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


def test_corrections_advance_feed_timestamps_even_for_an_older_edition():
    first, second = two_days()
    before = ET.fromstring(build_feed([first, second], SITE_URL))
    first["updated_at"] = "2030-03-04T04:00:00Z"
    first["corrections"].append({"at": first["updated_at"], "summary": "Corrected the earlier advice.", "item_ids": []})
    after = ET.fromstring(build_feed([first, second], SITE_URL))
    tag = lambda value: f"{{{ATOM}}}{value}"
    assert before.findtext(tag("updated")) != after.findtext(tag("updated"))
    assert after.findtext(tag("updated")) == first["updated_at"]
    entries = after.findall(tag("entry"))
    assert entries[-1].findtext(tag("updated")) == first["updated_at"]
    assert entries[-1].findtext(tag("id")) == f"{SITE_URL}/digests/{fx.DAY_ONE}/"
    assert "Corrected the earlier advice" in entries[-1].findtext(tag("content"))


def test_audience_feeds_include_shared_items_and_exclude_the_other_audience():
    _first, edition = two_days()
    for audience, excluded in [("end_users", "applications_and_servers"), ("applications_and_servers", "end_users")]:
        feed = ET.fromstring(build_feed([edition], SITE_URL, audience=audience))
        content = "".join(entry.findtext(f"{{{ATOM}}}content") for entry in feed.findall(f"{{{ATOM}}}entry"))
        for item in edition["items"]:
            needle = "#item-" + item["id"] + '"'
            assert (needle in content) == (item["audience"] != excluded), item["id"]


def test_source_text_cannot_become_html(publication):
    edition = latest(publication)
    edition["items"][0]["summary"] = '<img src=x onerror="alert(1)"> A literal source claim.'
    save(publication, edition)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    assert "<img src=x" not in home
    assert "&lt;img src=x" in home


def test_failed_validation_keeps_the_last_successful_site(publication):
    output = build_site(publication, site_url=SITE_URL)
    before = (output / "index.html").read_bytes()
    (publication / "data" / f"{fx.DAY_TWO}.json").write_text('{"schema_version": 99}')
    with pytest.raises(ValueError):
        build_site(publication, site_url=SITE_URL)
    assert (output / "index.html").read_bytes() == before


def test_generated_markdown_cannot_inject_instructions_from_version_text():
    _first, edition = two_days()
    edition["items"][0]["fixes"][0]["version"] = '1.0`\n\n## Forged instruction\n[bad](javascript:alert(1))'
    generated = markdown_digest(edition, SITE_URL)
    assert "\n## Forged instruction" not in generated
    rendered = render_markdown(generated)
    assert 'href="javascript:' not in rendered
    assert "Forged instruction" in rendered  # A literal code string, never a heading.


def test_lowercase_rfc3339_and_structured_fix_values_reach_the_feed(publication):
    edition = latest(publication)
    edition["published_at"] = edition["published_at"].lower()
    edition["updated_at"] = edition["updated_at"].lower()
    edition["items"][0]["action"] = "Use the fixed release listed below."
    save(publication, edition)
    output = build_site(publication, site_url=SITE_URL)
    content = ET.fromstring((output / "feed.xml").read_text()).find(f"{{{ATOM}}}entry").findtext(f"{{{ATOM}}}content")
    for fix in edition["items"][0]["fixes"]:
        assert fix["version"] in content
    for cve in edition["items"][0]["cves"]:
        assert cve in content


def test_check_mode_fails_when_generated_views_are_stale(publication):
    build_site(publication, site_url=SITE_URL, write_generated=True)
    build_site(publication, site_url=SITE_URL, check_generated=True)
    edition = latest(publication)
    edition["items"][0]["action"] += " Then confirm the version."
    save(publication, edition)
    with pytest.raises(StaleGeneratedFiles, match=rf"digests/{fx.DAY_TWO}\.md, README\.md"):
        build_site(publication, site_url=SITE_URL, check_generated=True)
    build_site(publication, site_url=SITE_URL, write_generated=True)
    (publication / "digests" / "2030-02-28.md").write_text("# An orphan\n")
    with pytest.raises(StaleGeneratedFiles, match="no matching data"):
        build_site(publication, site_url=SITE_URL, check_generated=True)


def test_committed_generated_views_match_the_json():
    assert stale_generated_files(ROOT, load_editions(ROOT / "data"), "https://jluethe.github.io/patch-these") == []


def test_dated_permalinks_featured_actions_and_product_index(publication):
    second = latest(publication)
    second["items"].append(fx.item("old-server", "Old Server", cve="CVE-2030-20009"))
    save(publication, second)
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    featured = home.split('class="featured-grid"', 1)[1].split("</section>", 1)[0]
    assert "Upgrade New Server to 2.4.1 or later." in featured
    assert f'class="permalink" href="/patch-these/digests/{fx.DAY_TWO}/#item-new-server"' in home
    digest = (output / "digests" / fx.DAY_ONE / "index.html").read_text()
    assert f'class="permalink" href="/patch-these/digests/{fx.DAY_ONE}/#item-old-server"' in digest
    assert 'rel="icon" href="/patch-these/assets/favicon.svg"' in home
    assert (output / "assets" / "favicon.svg").is_file()
    index = json.loads((output / "data" / "products.json").read_text())
    by_id = {row["id"]: row for row in index["products"]}
    assert {row["digest_date"] for row in by_id["old-server"]["appearances"]} == {fx.DAY_ONE, fx.DAY_TWO}
    assert "old-server" in (output / "products" / "index.html").read_text()
    assert "Vulnerability" in home and "Incident" in home


def test_early_signals_are_labeled_in_html_json_and_feeds(publication):
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    section = home.split('id="early-signals"', 1)[1].split("</section>", 1)[0]
    assert "Early signals: not yet verified" in home
    assert "Not yet verified" in section and "Single source" in section
    assert "Check whether you use Example Lead" in section
    assert "New Server" not in section
    featured = home.split('class="featured-grid"', 1)[1].split("</section>", 1)[0]
    assert "Example Lead" not in featured
    data = json.loads((output / "latest.json").read_text())
    assert any(item["id"] == "example-lead" and item["verification"] == "early_signal" for item in data["items"])
    feed = (output / "feed.xml").read_text()
    assert "Not yet verified · Single source" in feed
    assert "Early signals: not yet verified" in feed


def test_early_signals_stay_above_the_featured_and_verified_items(publication):
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    assert home.index('id="early-signals"') < home.index('id="priority-findings"') < home.index('id="item-new-server"')


def test_exploitation_label_names_only_the_exploited_cves(publication):
    edition = latest(publication)
    two = fx.item("two-cves", "Two CVEs", cve="CVE-2030-20011")
    two["cves"].append("CVE-2030-20012")
    two["fixes"][0]["cves"].append("CVE-2030-20012")
    two["priority"] = "act_now"
    two["exploitation"] = {"status": "confirmed", "source_ids": ["advisory"], "by_cve": [
        {"cve": "CVE-2030-20011", "status": "confirmed", "source_ids": ["advisory"]},
        {"cve": "CVE-2030-20012", "status": "unknown", "source_ids": []},
    ]}
    whole = fx.item("whole-item", "Whole Item", cve="CVE-2030-20013", priority="act_now",
                    exploitation={"status": "confirmed", "source_ids": ["advisory"]})
    edition["items"] += [two, whole]
    save(publication, edition)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    card = between(home, 'id="item-two-cves"')
    assert "Exploitation confirmed for CVE-2030-20011" in card
    assert "CVE-2030-20012: Unknown." in card
    assert '<p class="evidence">Exploitation confirmed <span' in between(home, 'id="item-whole-item"')


def test_incidents_and_supply_chain_never_say_exploitation_confirmed(publication):
    base = {"cves": [], "exploitation": {"status": "confirmed", "source_ids": ["a"]}, "sources": [{}]}
    assert exploitation_label({**base, "kind": "vulnerability"}) == "Exploitation confirmed"
    assert exploitation_label(base) == "Exploitation confirmed"
    assert exploitation_label({**base, "kind": "incident"}) == "Breach confirmed"
    assert exploitation_label({**base, "kind": "supply_chain"}) == "Compromise confirmed"
    reported = {**base, "kind": "incident", "exploitation": {"status": "reported", "source_ids": ["a"]}}
    assert exploitation_label(reported) == "Breach reported"
    assert verification_labels({**base, "verification": "early_signal"}) == ["Not yet verified", "Single source"]
    assert verification_labels({**base, "verification": "early_signal", "sources": [{}, {}]}) == ["Not yet verified"]
    assert verification_labels({**base, "verification": "verified"}) == []

    edition = latest(publication)
    edition["items"] += [
        fx.item("breached-service", "Breached Service", cves=[], kind="incident", priority="act_now", action_type="rotate",
                fix_status="not_applicable", fixes=[], kev=[], epss=[], summary="The vendor confirmed a breach.",
                action="Rotate your credentials.", exploitation={"status": "confirmed", "source_ids": ["advisory"]}),
        fx.item("tampered-image", "Tampered Image", cves=[], kind="supply_chain", priority="act_now", action_type="replace",
                fix_status="not_applicable", fixes=[], kev=[], epss=[], summary="The vendor confirmed tampered images.",
                action="Replace the image.", exploitation={"status": "confirmed", "source_ids": ["advisory"]}),
    ]
    save(publication, edition)
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    breach, compromise = between(home, 'id="item-breached-service"'), between(home, 'id="item-tampered-image"')
    assert "Breach confirmed" in breach and "Exploitation confirmed" not in breach
    assert "Compromise confirmed" in compromise and "Exploitation confirmed" not in compromise
    digest = (output / "digests" / f"{fx.DAY_TWO}.md").read_text()
    assert "**Breach:** confirmed." in digest and "**Compromise:** confirmed." in digest
    feed = (output / "feed.xml").read_text()
    assert "Breach confirmed" in feed and "Compromise confirmed" in feed
    assert "Exploitation confirmed" not in feed


def test_every_output_keeps_an_early_signals_verification_state_and_only_source(publication):
    post = "https://x.com/example/status/1234567890"
    output = build_site(publication, site_url=SITE_URL, write_generated=True)
    home = (output / "index.html").read_text()
    card = between(home, 'id="item-example-lead"')
    assert "Not yet verified" in card and "Single source" in card
    sources_line = card.split('<p class="sources">', 1)[1].split("</p>", 1)[0]
    assert post in sources_line  # The only source is on the card, not just in the details.
    digest = (output / "digests" / f"{fx.DAY_TWO}.md").read_text()
    section = digest.split("## Early signals: not yet verified", 1)[1].split("\n## ", 1)[0]
    assert "**Not yet verified · Single source · Incident" in section
    assert f"]({post})" in section and "X post" in section
    readme = (publication / "README.md").read_text()
    assert "Not yet verified. Single source." in readme and f"]({post})" in readme
    for path in ("feed.xml", "feeds/operators.xml"):
        feed = (output / path).read_text()
        entry = feed.split("Example Lead", 1)[1]
        assert "Not yet verified · Single source" in feed
        assert post in entry
    data = json.loads((output / "latest.json").read_text())
    lead = next(item for item in data["items"] if item["id"] == "example-lead")
    assert lead["verification"] == "early_signal" and lead["sources"][0]["url"] == post
    index = json.loads((output / "data" / "products.json").read_text())
    appearance = next(row for row in index["products"] if row["id"] == "example-lead")["appearances"][0]
    assert appearance["verification"] == "early_signal"
    assert "(not yet verified)" in (output / "products" / "index.html").read_text()


def test_verified_items_keep_primary_sources_first_on_the_card(publication):
    edition = latest(publication)
    edition["items"][0]["sources"].append(fx.source("post", kind="social_report", url="https://x.com/example/status/99", supports=["summary"]))
    save(publication, edition)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    sources_line = between(home, 'id="item-new-server"').split('<p class="sources">', 1)[1].split("</p>", 1)[0]
    assert "vendor.example/advisory" in sources_line and "x.com/example/status/99" not in sources_line


def test_a_quiet_check_is_shown_separately_from_the_last_content_change(publication):
    edition = latest(publication)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    assert "Last checked" not in home
    edition["last_checked_at"] = f"{fx.DAY_TWO}T22:00:00Z"
    save(publication, edition)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    meta = home.split('class="hero-meta"', 1)[1].split("</div>", 1)[0]
    assert "Updated 2 Mar 2030 · 6:00 AM PST" in meta
    assert "Last checked 2 Mar 2030 · 2:00 PM PST" in meta


def test_brief_keeps_whole_sentences():
    from patchthese.common import brief
    assert brief("Upgrade to 1.30.8 or later. Also update images. Then check logs.") == "Upgrade to 1.30.8 or later. Also update images."
    long_first = "Install " + "x" * 300 + " now. Second."
    assert brief(long_first) == "Install " + "x" * 300 + " now."
    assert brief("One sentence only") == "One sentence only"
    assert brief("Short. " + "Y" * 250 + ".") == "Short."


def test_featured_cards_are_short_and_jump_to_the_full_item(publication):
    edition = latest(publication)
    edition["items"][0]["action"] = "Upgrade New Server to 2.4.1 or later. Restart the service. Rotate the admin password. Review the audit log."
    edition["items"][0]["steps"] = ["Back up the configuration.", "Install 2.4.1 or later."]
    save(publication, edition)
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    featured = home.split('class="featured-grid"', 1)[1].split("</section>", 1)[0]
    card = featured.split('<a class="featured-card" href="#item-new-server">', 1)[1].split("</a>", 1)[0]
    assert "Upgrade New Server to 2.4.1 or later. Restart the service." in card
    assert "Rotate the admin password" not in card
    assert "Full details" in card and "More steps in the full item." in card
    assert 'id="item-new-server"' in home


def test_steps_render_as_ordered_lists_everywhere(publication):
    edition = latest(publication)
    edition["items"][0]["action"] = "Follow the vendor's guidance for your setup."
    edition["items"][0]["steps"] = ["If exposed, upgrade to 2.4.1 or later now.", "Otherwise, upgrade at the next window."]
    save(publication, edition)
    output = build_site(publication, site_url=SITE_URL)
    card = between((output / "index.html").read_text(), 'id="item-new-server"')
    assert '<ol class="action-steps"><li>If exposed, upgrade to 2.4.1 or later now.</li><li>Otherwise, upgrade at the next window.</li></ol>' in card
    digest = (output / "digests" / f"{fx.DAY_TWO}.md").read_text()
    assert "**What to do:** Follow the vendor's guidance for your setup.\n\n1. If exposed, upgrade to 2.4.1 or later now.\n2. Otherwise, upgrade at the next window." in digest
    feed = (output / "feed.xml").read_text()
    assert "&lt;ol&gt;&lt;li&gt;If exposed, upgrade to 2.4.1 or later now.&lt;/li&gt;" in feed


def test_briefing_date_is_uppercase_day_month_year():
    from patchthese.common import briefing_date
    assert briefing_date("2026-11-27") == "27 NOVEMBER 2026"
    assert briefing_date("2030-03-02") == "02 MARCH 2030"
    assert briefing_date("2026-01-05") == "05 JANUARY 2026"


def test_homepage_uses_the_requested_intro_date_and_counts(publication):
    output = build_site(publication, site_url=SITE_URL)
    home = (output / "index.html").read_text()
    assert "Tracking emerging threats, updated throughout the day." in home
    assert 'LATEST BRIEFING <span aria-hidden="true">·</span> <time datetime="2030-03-02">02 MARCH 2030</time>' in home
    assert "Updated every four hours, 6 AM–10 PM Pacific." in home
    assert "Monitoring X, Bluesky, Mastodon, security research blogs, and other sources for newly disclosed vulnerabilities and reports of active exploitation." in home
    assert "Early signals are clearly labeled, findings are verified against primary sources, and recommended actions are prioritized by urgency." in home
    assert "Independent security intelligence, updated throughout the day." not in home
    assert "Emerging Threats" not in home
    intro = home[home.index("Tracking emerging threats"):home.index("Security findings")]
    assert intro.index("Tracking emerging threats, updated throughout the day.") < intro.index("LATEST BRIEFING") < intro.index("Updated every four hours, 6 AM–10 PM Pacific.") < intro.index("Monitoring X, Bluesky, Mastodon") < intro.index("Early signals are clearly labeled")
    stats = home.split('class="edition-stats"', 1)[1].split("</div></div>", 1)[0]
    assert "<strong>04</strong><span>Security findings</span>" in stats
    assert "<strong>00</strong><span>Act now if affected</span>" in stats
    assert "<strong>03</strong><span>Act soon</span>" in stats
    assert "<strong>01</strong><span>Early signals</span>" in stats
    assert "Priority Findings" in home
    assert "Key security developments, affected products, and recommended actions from the latest briefing." in home
    nav = home.split('aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    assert ">Archive</a>" in nav and ">Methodology</a>" in nav and ">Subscribe</a>" in nav
    assert "Latest briefing" not in nav and "Our method" not in nav
    digest = (output / "digests" / fx.DAY_TWO / "index.html").read_text()
    assert 'FROM THE ARCHIVE <span aria-hidden="true">·</span> <time datetime="2030-03-02">02 MARCH 2030</time>' in digest
    assert "Emerging Threats" not in digest
    assert "Tracking emerging threats, updated throughout the day." not in digest
    assert "Monitoring X, Bluesky, Mastodon" not in digest
    quiet = fx.edition("2030-03-03", [fx.item("solo-server", "Solo Server", cve="CVE-2030-30009")])
    save(publication, quiet)
    later = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    later_stats = later.split('class="edition-stats"', 1)[1].split("</div></div>", 1)[0]
    assert "<strong>01</strong><span>Security findings</span>" in later_stats
    assert "<strong>00</strong><span>Act now if affected</span>" in later_stats
    assert "<strong>01</strong><span>Act soon</span>" in later_stats
    assert "Early signals" not in later_stats


def test_first_screen_is_compact_and_early_signals_keep_their_place(publication):
    home = (build_site(publication, site_url=SITE_URL) / "index.html").read_text()
    assert "Tracking emerging threats, updated throughout the day." in home
    assert "Updated every four hours, 6 AM–10 PM Pacific." in home
    assert "Find your software. Understand the risk." not in home
    before_signals = home[home.index('class="hero"'):home.index('id="early-signals"')]
    assert "Early signals are clearly labeled" in before_signals and "featured-grid" not in before_signals
    assert home.index('id="early-signals"') < home.index('id="priority-findings"')


def test_markdown_readme_and_atom_list_early_signals_before_verified_items(publication):
    output = build_site(publication, site_url=SITE_URL, write_generated=True)
    digest = (output / "digests" / f"{fx.DAY_TWO}.md").read_text()
    assert digest.index("## Early signals: not yet verified") < digest.index("## Start here") < digest.index("### New Server")
    assert "Not yet verified · Single source" in digest.split("## Start here", 1)[0]
    readme = (publication / "README.md").read_text()
    assert readme.index("### Early signals: not yet verified") < readme.index("### For everyone")
    for path in ("feed.xml", "feeds/operators.xml"):
        root = ET.fromstring((output / path).read_text())
        entry = root.find(f"{{{ATOM}}}entry")
        content = entry.find(f"{{{ATOM}}}content").text
        summary = entry.find(f"{{{ATOM}}}summary").text
        assert content.index("Early signals: not yet verified") < content.index("Example Lead") < content.index("Verified items")
        assert summary.startswith("Example Lead: Not yet verified")
        assert "Not yet verified · Single source" in content and "https://x.com/example/status/1234567890" in content
