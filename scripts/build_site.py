#!/usr/bin/env python3
"""Check digests against their JSON and build the static site into _site/."""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from html import escape
from pathlib import Path

try:
    import markdown
except ImportError:
    sys.exit("Install Markdown first: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent.parent
DIGESTS = ROOT / "digests"
DATA = ROOT / "data"
SITE = ROOT / "_site"
STYLE = ROOT / "assets" / "style.css"

SITE_URL = os.environ.get("SITE_URL", "https://jluethe.github.io/patch-these").rstrip("/")
REPO = "https://github.com/JLuethe/patch-these"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_RE = re.compile(r"^\d+(?:\.\d+)?%$")
X_RE = re.compile(r"^https://x\.com/[A-Za-z0-9_]+/status/\d+$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FENCE_RE = re.compile(r"^```", re.MULTILINE)

PRIORITIES = {"patch_now", "patch_soon", "watch"}
AUDIENCES = {"applications_and_servers", "end_users", "both"}
MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

REQUIRED_KEYS = [
    "id",
    "cve",
    "product",
    "affected",
    "fixed_versions",
    "cvss",
    "epss",
    "kev",
    "priority",
    "audience",
    "lower_relevance",
    "summary",
    "action",
    "advisory_url",
    "x_post_urls",
]

METHOD_PHRASES = [
    "X posts are linked, not copied.",
    "Bluesky, Mastodon, Reddit, and Hacker News",
    "Actively exploited, or critical and widely deployed.",
    "High severity with a patch.",
    "No patch, or limited impact.",
    "Applications & servers.",
    "End users.",
    "Both.",
    "curated, not complete",
    "It is unofficial.",
    "not professional advice",
    "not affiliated with CISA, FIRST, or any vendor",
    "vendor advisory",
    "EPSS is a probability, not a certainty.",
    "NVD",
    "FIRST EPSS",
]


class BuildError(SystemExit):
    pass


def fail(message: str) -> None:
    raise BuildError(message)


def human_date(iso: str) -> str:
    year, month, day = (int(part) for part in iso.split("-"))
    return f"{day} {MONTHS[month - 1]} {year}"


def human_span(start: str, end: str) -> str:
    if start == end:
        return human_date(start)
    sy, sm, sd = (int(part) for part in start.split("-"))
    ey, em, ed = (int(part) for part in end.split("-"))
    if sy == ey and sm == em:
        return f"{sd}–{ed} {MONTHS[sm - 1]} {sy}"
    if sy == ey:
        return f"{sd} {MONTHS[sm - 1]} – {ed} {MONTHS[em - 1]} {sy}"
    return f"{human_date(start)} – {human_date(end)}"


def slice_from_heading(text: str, heading: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == heading), None)
    if start is None:
        fail(f"missing heading {heading!r}")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break
    return "\n".join(lines[start:end]).strip()


def load_pairs() -> list[dict]:
    digest_paths = sorted(DIGESTS.glob("*.md"))
    data_paths = sorted(DATA.glob("*.json"))
    if not digest_paths:
        fail("digests/ has no markdown files")

    dates = []
    for path in digest_paths:
        if not DATE_RE.match(path.stem):
            fail(f"unexpected file in digests/: {path.name}")
        dates.append(path.stem)
    data_dates = []
    for path in data_paths:
        if not DATE_RE.match(path.stem):
            fail(f"unexpected file in data/: {path.name}")
        data_dates.append(path.stem)
    if dates != data_dates:
        fail(f"digest dates {dates} do not match data dates {data_dates}")

    pairs = []
    for date in dates:
        digest_text = (DIGESTS / f"{date}.md").read_text(encoding="utf-8")
        try:
            payload = json.loads((DATA / f"{date}.json").read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"data/{date}.json is not valid JSON: {exc}")
        validate_pair(date, digest_text, payload)
        pairs.append({"date": date, "markdown": digest_text, "data": payload})
    validate_readme(pairs[-1])
    return pairs


def validate_pair(date: str, digest: str, payload: dict) -> None:
    if payload.get("schema_version") != 1:
        fail(f"{date}: schema_version must be 1")
    if payload.get("digest_date") != date:
        fail(f"{date}: digest_date does not match the filename")
    start = payload.get("coverage_start")
    end = payload.get("coverage_end")
    if not (isinstance(start, str) and isinstance(end, str) and DATE_RE.match(start) and DATE_RE.match(end)):
        fail(f"{date}: coverage_start and coverage_end must be YYYY-MM-DD")
    if not (start <= end <= date):
        fail(f"{date}: expected coverage_start <= coverage_end <= digest_date")

    if FENCE_RE.search(digest):
        fail(f"{date}: digests do not use fenced code blocks")

    items = payload.get("items")
    if not isinstance(items, list) or not items:
        fail(f"{date}: items must be a non-empty list")

    headings = {
        "applications_and_servers": "## Applications & servers",
        "end_users": "## End users",
        "both": "## Both",
    }
    present = {item.get("audience") for item in items if isinstance(item, dict)}
    digest_lines = digest.splitlines()
    for audience, heading in headings.items():
        if audience in present and heading not in digest_lines:
            fail(f"{date}: digest is missing {heading}")
    for heading in ("## Patch these", "### For app and server owners", "### For everyone"):
        if heading not in digest_lines:
            fail(f"{date}: digest is missing {heading}")

    seen_ids = set()
    for index, item in enumerate(items, start=1):
        validate_item(date, digest, index, item, seen_ids)


def validate_readme(latest: dict) -> None:
    date = latest["date"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    method = (ROOT / "METHODOLOGY.md").read_text(encoding="utf-8")
    for phrase in METHOD_PHRASES:
        if phrase not in method:
            fail(f"METHODOLOGY.md is missing {phrase!r}")
    for phrase in (
        "Issues raised on X, verified, and turned into",
        "Bluesky, Mastodon, Reddit, and Hacker News",
        f"{SITE_URL}/",
        f"{SITE_URL}/feed.xml",
        f"digests/{date}.md",
        "curated, not complete",
        "not professional advice",
        "EPSS is a probability, not a certainty.",
    ):
        if phrase not in readme:
            fail(f"README.md is missing {phrase!r}")

    digest_summary = slice_from_heading(latest["markdown"], "### For app and server owners")
    readme_summary = slice_from_heading(readme, "### For app and server owners")
    if digest_summary != readme_summary:
        diff = "\n".join(
            difflib.unified_diff(
                digest_summary.splitlines(),
                readme_summary.splitlines(),
                fromfile="digest",
                tofile="README.md",
                lineterm="",
            )
        )
        fail("README Patch these block does not match the digest:\n" + diff)


def validate_item(date: str, digest: str, index: int, item: dict, seen_ids: set[str]) -> None:
    where = f"{date} item {index}"
    if not isinstance(item, dict):
        fail(f"{where} is not an object")
    missing = [key for key in REQUIRED_KEYS if key not in item]
    if missing:
        fail(f"{where} is missing {', '.join(missing)}")

    item_id = item["id"]
    if not isinstance(item_id, str) or not SLUG_RE.match(item_id):
        fail(f"{where} has an invalid id")
    if item_id in seen_ids:
        fail(f"{where} repeats id {item_id}")
    seen_ids.add(item_id)

    cves = item["cve"]
    if cves is not None:
        if not isinstance(cves, list) or not cves or not all(isinstance(cve, str) and CVE_RE.match(cve) for cve in cves):
            fail(f"{where} cve must be a list of CVE ids or null")
        for cve in cves:
            if cve not in digest:
                fail(f"{where} CVE {cve} is not in the digest")

    product = item["product"]
    if not isinstance(product, str) or not product.strip():
        fail(f"{where} needs a product")
    if product not in digest:
        fail(f"{where} product {product!r} is not in the digest")

    if item["affected"] is not None and not isinstance(item["affected"], str):
        fail(f"{where} affected must be a string or null")

    versions = item["fixed_versions"]
    if not isinstance(versions, list) or not all(isinstance(version, str) and version.strip() for version in versions):
        fail(f"{where} fixed_versions must be a list of strings")
    for version in versions:
        if version not in digest:
            fail(f"{where} fixed version {version!r} is not in the digest")

    check_cvss(item["cvss"], where, set(cves or []))
    check_epss(item["epss"], where, set(cves or []))
    check_kev(item["kev"], where, set(cves or []))
    for score in listed_scores(item["cvss"], item["epss"]):
        if score not in digest:
            fail(f"{where} score {score!r} is not in the digest")

    if item["priority"] not in PRIORITIES:
        fail(f"{where} has an unknown priority")
    if item["audience"] not in AUDIENCES:
        fail(f"{where} has an unknown audience")
    if not isinstance(item["lower_relevance"], bool):
        fail(f"{where} lower_relevance must be true or false")
    if item["lower_relevance"] and item["priority"] != "watch":
        fail(f"{where} lower-relevance items are tagged watch")

    for field in ("summary", "action"):
        value = item[field]
        if not isinstance(value, str) or not value.strip() or "<" in value:
            fail(f"{where} {field} must be plain text")

    check_urls(item["advisory_url"], where, "advisory_url", r"^https://")
    check_urls(item["x_post_urls"], where, "x_post_urls", X_RE)
    for url in item["advisory_url"] + item["x_post_urls"]:
        if url not in digest:
            fail(f"{where} URL is not in the digest: {url}")


def listed_scores(cvss, epss) -> list[str]:
    found = []

    def walk(value, kind: str) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for inner in value.values():
                walk(inner, kind)
            return
        if kind == "epss":
            found.append(value)
            return
        if isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            found.append(str(value))
            return
        found.append(value)

    walk(cvss, "cvss")
    walk(epss, "epss")
    return found


def check_cvss(value, where: str, cves: set[str]) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        fail(f"{where} cvss is not a boolean")
    if isinstance(value, (int, float)):
        if not 0 <= float(value) <= 10:
            fail(f"{where} cvss {value} is outside 0–10")
        return
    if isinstance(value, str):
        if not value.strip():
            fail(f"{where} cvss string is empty")
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            if key not in cves:
                fail(f"{where} cvss key {key} is not one of the item's CVEs")
            check_cvss(inner, where, cves)
        return
    fail(f"{where} cvss has an unsupported type")


def check_epss(value, where: str, cves: set[str]) -> None:
    if value is None:
        return
    if isinstance(value, str):
        if not EPSS_RE.match(value):
            fail(f"{where} epss must look like 1.13%")
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            if key not in cves:
                fail(f"{where} epss key {key} is not one of the item's CVEs")
            if not isinstance(inner, str) or not EPSS_RE.match(inner):
                fail(f"{where} epss for {key} must look like 1.13%")
        return
    fail(f"{where} epss has an unsupported type")


def check_kev(value, where: str, cves: set[str] | None) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if not DATE_RE.match(value):
            fail(f"{where} kev date must be YYYY-MM-DD")
        return
    if isinstance(value, dict):
        if cves is None:
            fail(f"{where} kev objects do not nest")
        if not value:
            fail(f"{where} kev object is empty")
        for key, inner in value.items():
            if key not in cves:
                fail(f"{where} kev key {key} is not one of the item's CVEs")
            check_kev(inner, where, None)
        return
    fail(f"{where} kev has an unsupported type")


def check_urls(value, where: str, field: str, pattern) -> None:
    if not isinstance(value, list):
        fail(f"{where} {field} must be a list")
    seen = set()
    matcher = re.compile(pattern) if isinstance(pattern, str) else pattern
    for url in value:
        if not isinstance(url, str) or not matcher.match(url):
            fail(f"{where} {field} has an invalid URL: {url!r}")
        if url in seen:
            fail(f"{where} {field} repeats {url}")
        seen.add(url)


def render_markdown(text: str) -> str:
    safe = text.replace("<", "&lt;")
    html = markdown.markdown(
        safe,
        extensions=["extra", "sane_lists", "toc"],
        extension_configs={"toc": {"permalink": False}},
        output_format="html5",
    )
    html = re.sub(
        r"<h4(?: id=\"[^\"]+\")?>Patch now</h4>",
        '<h4><span class="tag now">Patch now</span></h4>',
        html,
    )
    html = re.sub(
        r"<h4(?: id=\"[^\"]+\")?>Patch soon</h4>",
        '<h4><span class="tag soon">Patch soon</span></h4>',
        html,
    )
    html = re.sub(
        r"<h4(?: id=\"[^\"]+\")?>Watch</h4>",
        '<h4><span class="tag watch">Watch</span></h4>',
        html,
    )
    return (
        html.replace("<strong>Patch now</strong>", '<strong class="tag now">Patch now</strong>')
        .replace("<strong>Patch soon</strong>", '<strong class="tag soon">Patch soon</strong>')
        .replace("<strong>Watch</strong>", '<strong class="tag watch">Watch</strong>')
    )


def root_href(depth: int) -> str:
    return "./" if depth == 0 else "../" * depth


def rel(depth: int, path: str) -> str:
    return root_href(depth) + path


def page(title: str, description: str, depth: int, canonical_path: str, body: str, body_class: str) -> str:
    home = root_href(depth)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<meta name="description" content="{escape(description)}">
<link rel="canonical" href="{escape(SITE_URL + canonical_path)}">
<link rel="stylesheet" href="{escape(rel(depth, 'assets/style.css'))}">
<link rel="alternate" type="application/atom+xml" title="patch-these" href="{escape(rel(depth, 'feed.xml'))}">
</head>
<body class="{escape(body_class)}">
<a class="skip" href="#main">Skip to content</a>
<div class="wrap">
<header class="site-header">
<p class="wordmark"><a href="{escape(home)}">patch-these</a></p>
<p class="tagline">Issues raised on X, verified, and turned into a short list of what to patch.</p>
<nav>
<a href="{escape(home)}">Latest</a>
<a href="{escape(rel(depth, 'methodology/'))}">How this is made</a>
<a href="{escape(rel(depth, 'feed.xml'))}">RSS</a>
</nav>
</header>
<main id="main">
{body}
</main>
<footer>
<p>Curated, not complete. Unofficial. Not professional advice. Not affiliated with CISA, FIRST, or any vendor. Verify the vendor advisory. EPSS is a probability, not a certainty.</p>
<p><a href="{escape(rel(depth, 'methodology/'))}">How this is made</a> · <a href="{escape(REPO + '/blob/main/LICENSE')}">CC BY 4.0</a> · <a href="{escape(REPO + '/blob/main/CONTRIBUTING.md')}">Add a digest</a></p>
</footer>
</div>
</body>
</html>
"""


def xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def build_feed(pairs: list[dict]) -> str:
    latest = pairs[-1]["date"]
    entries = []
    for pair in reversed(pairs):
        date = pair["date"]
        link = f"{SITE_URL}/digests/{date}/"
        title = f"patch-these — {human_date(date)}"
        summary = render_markdown(slice_from_heading(pair["markdown"], "### For app and server owners"))
        content = render_markdown(pair["markdown"])
        entries.append(
            f"""  <entry>
    <id>{xml_escape(link)}</id>
    <title>{xml_escape(title)}</title>
    <updated>{date}T00:00:00Z</updated>
    <link rel="alternate" type="text/html" href="{xml_escape(link)}"/>
    <summary type="html">{xml_escape(summary)}</summary>
    <content type="html">{xml_escape(content)}</content>
  </entry>"""
        )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <id>{xml_escape(SITE_URL + "/")}</id>
  <title>patch-these</title>
  <subtitle>Issues raised on X, verified, and turned into a short list of what to patch.</subtitle>
  <updated>{latest}T00:00:00Z</updated>
  <link rel="alternate" type="text/html" href="{xml_escape(SITE_URL + "/")}"/>
  <link rel="self" type="application/atom+xml" href="{xml_escape(SITE_URL + "/feed.xml")}"/>
  <author><name>patch-these</name></author>
  <rights>Creative Commons Attribution 4.0 International</rights>
{chr(10).join(entries)}
</feed>
"""


def write_site(pairs: list[dict]) -> None:
    if SITE.exists():
        shutil.rmtree(SITE)
    (SITE / "assets").mkdir(parents=True)
    (SITE / "data").mkdir()
    shutil.copyfile(STYLE, SITE / "assets" / "style.css")

    latest = pairs[-1]
    latest_date = latest["date"]
    summary_html = render_markdown(slice_from_heading(latest["markdown"], "### For app and server owners"))
    rows = []
    for pair in reversed(pairs):
        date = pair["date"]
        span = human_span(pair["data"]["coverage_start"], pair["data"]["coverage_end"])
        rows.append(
            "<li>"
            f'<a href="{escape(rel(0, f"digests/{date}/"))}">{escape(human_date(date))}</a>'
            f'<span class="when">{escape(span)}</span>'
            "</li>"
        )
    home = f"""<article class="summary">
<p class="kicker">Latest · <time datetime="{latest_date}">{escape(human_date(latest_date))}</time></p>
<h1>Patch these</h1>
<p class="coverage">Covers {escape(human_span(latest["data"]["coverage_start"], latest["data"]["coverage_end"]))}</p>
<p class="lede"><a href="{escape(rel(0, f"digests/{latest_date}/"))}">Full digest</a></p>
{summary_html}
</article>
<section>
<h2>All digests</h2>
<ul class="digest-list">
{chr(10).join(rows)}
</ul>
</section>
"""
    description = "Issues raised on X, verified, and turned into a short list of what to patch."
    (SITE / "index.html").write_text(
        page("patch-these", description, 0, "/", home, "home"),
        encoding="utf-8",
    )

    for pair in pairs:
        date = pair["date"]
        folder = SITE / "digests" / date
        folder.mkdir(parents=True)
        span = human_span(pair["data"]["coverage_start"], pair["data"]["coverage_end"])
        body = f"""<article class="digest">
{render_markdown(pair["markdown"])}
</article>
<p class="sidecar"><a href="{escape(rel(2, f"data/{date}.json"))}">Structured data</a> · <a href="{escape(REPO + f"/blob/main/digests/{date}.md")}">Markdown</a></p>
"""
        (folder / "index.html").write_text(
            page(
                f"{human_date(date)} — patch-these",
                f"patch-these for {human_date(date)}, covering {span}.",
                2,
                f"/digests/{date}/",
                body,
                "digest",
            ),
            encoding="utf-8",
        )
        shutil.copyfile(DATA / f"{date}.json", SITE / "data" / f"{date}.json")

    method = (ROOT / "METHODOLOGY.md").read_text(encoding="utf-8")
    method_dir = SITE / "methodology"
    method_dir.mkdir()
    (method_dir / "index.html").write_text(
        page(
            "How this is made — patch-these",
            "Sources, priorities, and the disclaimer for patch-these.",
            1,
            "/methodology/",
            f'<article class="digest">{render_markdown(method)}</article>',
            "method",
        ),
        encoding="utf-8",
    )

    missing = page(
        "Not found — patch-these",
        "That page is not in the patch-these briefing.",
        0,
        "/404.html",
        "<h1>Not in this briefing</h1><p>The page is not here. The latest digest is on the front page.</p>",
        "missing",
    )
    (SITE / "404.html").write_text(missing, encoding="utf-8")

    feed = build_feed(pairs)
    (SITE / "feed.xml").write_text(feed, encoding="utf-8")
    ET.fromstring(feed)

    for html_path in SITE.rglob("*.html"):
        text = html_path.read_text(encoding="utf-8")
        if "<script" in text.lower():
            fail(f"unexpected script in {html_path}")
    index = (SITE / "index.html").read_text(encoding="utf-8")
    for needle in ("Patch these", "For everyone", "158.0.8127.89", "feed.xml"):
        if needle not in index:
            fail(f"homepage is missing {needle}")
    digest_html = (SITE / "digests" / latest_date / "index.html").read_text(encoding="utf-8")
    if "4403.4405.va_b_cdb_b_d0b_89f" not in digest_html:
        fail("digest page dropped the Jenkins plugin version")


def main() -> None:
    pairs = load_pairs()
    write_site(pairs)
    print(f"Built {SITE} with {len(pairs)} digest{'s' if len(pairs) != 1 else ''}.")


if __name__ == "__main__":
    try:
        main()
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
