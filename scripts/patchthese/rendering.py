"""Escaped HTML components and sanitized editorial Markdown."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from html import escape
from urllib.parse import urljoin, urlsplit

import markdown
import nh3

from .common import ACTIONS, AUDIENCES, DESCRIPTION, brief, PRIORITIES, REPO, briefing_date, coverage, exploitation_label, human_date, human_time, is_early_signal, ordered_items, root_path, social_platform, status_noun, timestamp, verification_labels

_CLEANER_OPTIONS = dict(
    tags={"p", "a", "strong", "em", "code", "pre", "ul", "ol", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "br", "table", "thead", "tbody", "tr", "th", "td"},
    clean_content_tags={"script", "style", "iframe", "object", "svg", "math"},
    attributes={"a": {"href", "title"}, "h1": {"id"}, "h2": {"id"}, "h3": {"id"}, "h4": {"id"}, "th": {"scope"}},
    url_schemes={"https", "http", "mailto"},
)
_CLEANER = nh3.Cleaner(**_CLEANER_OPTIONS)


def render_markdown(text: str, *, relative_base: str | None = None) -> str:
    # Render code spans before sanitizing so '<' is escaped exactly once.
    rendered = markdown.markdown(text, extensions=["tables", "sane_lists", "toc"], output_format="html5")
    if relative_base:
        def resolve_href(tag: str, attribute: str, value: str) -> str:
            if tag == "a" and attribute == "href" and not value.startswith("#") and not urlsplit(value).scheme:
                return urljoin(relative_base, value)
            return value
        return nh3.Cleaner(**_CLEANER_OPTIONS, attribute_filter=resolve_href).clean(rendered)
    return _CLEANER.clean(rendered)


def source_link(source: dict, label: str | None = None) -> str:
    text = label or source["label"]
    if source.get("kind") == "social_report":
        platform = social_platform(source.get("url", ""))
        if platform:
            text = f"{platform} · {text}"
    return f'<a class="source-link" href="{escape(source["url"], quote=True)}" rel="noopener noreferrer">{escape(text)}</a>'


def source_refs(item: dict, ids: list[str]) -> str:
    sources = {source["id"]: source for source in item["sources"]}
    return " · ".join(source_link(sources[sid]) for sid in ids)


def urgency(item: dict) -> str:
    return f'<span class="urgency urgency--{item["priority"]}">{PRIORITIES[item["priority"]]}</span>'


def item_detail(item: dict) -> str:
    blocks = []
    if item["cves"]:
        blocks.append('<p><strong>Vulnerabilities:</strong> ' + ", ".join(escape(cve) for cve in item["cves"]) + '</p>')
    if item["fixes"]:
        rows = []
        for fix in item["fixes"]:
            scope = " · ".join(value for value in [fix["component"], fix["platform"], fix["branch"]] if value)
            refs = source_refs(item, fix["source_ids"])
            rows.append(f'<tr><td>{escape(scope)}</td><td><code>{escape(fix["version"])}</code></td><td>{escape(", ".join(fix["cves"]) or "See advisory")}<br>{refs}</td></tr>')
        blocks.append('<div class="table-scroll"><table><caption>Fixed releases and their scope</caption><thead><tr><th scope="col">Component / platform / branch</th><th scope="col">Version</th><th scope="col">Applies to / evidence</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')
    exploitation = item["exploitation"]
    if exploitation.get("by_cve"):
        cve_rows = "".join(
            f'<li>{escape(record["cve"])}: {escape(record["status"].capitalize())}. {source_refs(item, record["source_ids"])}</li>'
            for record in exploitation["by_cve"]
        )
        blocks.append(f'<p><strong>{status_noun(item)}:</strong></p><ul>{cve_rows}</ul>')
    else:
        blocks.append(f'<p><strong>{status_noun(item)}:</strong> {escape(exploitation["status"].capitalize())}. {source_refs(item, exploitation["source_ids"])}</p>')
    for entry in item["kev"]:
        state = "Listed" if entry["listed"] is True else "Not listed at the recorded check" if entry["listed"] is False else "Membership not established"
        when = f'; added {escape(entry["date_added"])}' if entry["date_added"] else ""
        blocks.append(f'<p><strong>KEV · {escape(entry["cve"])}:</strong> {state}{when}. {source_refs(item, entry["source_ids"])}</p>')
    scores = []
    for entry in item["cvss"]:
        version = f' {escape(entry["version"])}' if entry["version"] else ""
        identity = f' · {escape(entry["cve"])}' if entry["cve"] else ""
        authority = f' · {escape(entry["authority"])}' if entry["authority"] else ""
        scores.append(f'<li>Reported CVSS{version}: <strong>{entry["score"]:g}</strong>{identity}{authority}. {source_refs(item, entry["source_ids"])}</li>')
    for entry in item["epss"]:
        when = escape(entry["score_date"] or "original score date not recorded")
        scores.append(f'<li>Reported EPSS: <strong>{entry["probability"]:.2%}</strong> · {escape(entry["cve"])} · {when}. {source_refs(item, entry["source_ids"])}</li>')
    if scores:
        blocks.append('<h4>Scores, with context</h4><ul>' + "".join(scores) + '</ul><p class="muted">EPSS estimates probability; it does not prove exploitation. An undated reported score is not a current measurement.</p>')
    rows = []
    for source in item["sources"]:
        status = f'Checked {human_time(source["checked_at"])}' if source["checked_at"] else "Check time not recorded"
        support = ", ".join(source["supports"]).replace("_", " ")
        if source["kind"] == "social_report":
            kind_label = f"{social_platform(source['url']) or 'Social'} post"
        else:
            kind_label = source["kind"].replace("_", " ")
        rows.append(f'<li>{source_link(source)} <span class="muted">— {escape(kind_label)}. {escape(status)}. Supports: {escape(support or "discovery")}.</span></li>')
    blocks.append('<h4>Evidence and source checks</h4><ul class="sources">' + "".join(rows) + '</ul>')
    return "".join(blocks)


def steps_list(item: dict) -> str:
    steps = item.get("steps") or []
    if not steps:
        return ""
    return '<ol class="action-steps">' + "".join(f"<li>{escape(step)}</li>" for step in steps) + "</ol>"


ITEM_KINDS = {"vulnerability": "Vulnerability", "incident": "Incident", "supply_chain": "Supply chain"}


def item_card(item: dict, digest_date: str, site_url: str, *, interactive: bool = True) -> str:
    product = escape(item["product"])
    item_id = escape(item["id"])
    search = " ".join([item["product"], item["summary"], item["action"], *item.get("steps", []), item["affected"] or "", *item["cves"]])
    primary = [source for source in item["sources"] if source["kind"] != "social_report"]
    # An early signal may rest on a single post; never hide its only source.
    shown = primary[:2] or item["sources"][:2]
    links = " · ".join(source_link(source) for source in shown) or "Source details below"
    checked = [source["checked_at"] for source in primary if source["checked_at"]]
    check_label = f'Latest source check: {human_time(max(checked, key=timestamp))}' if checked else "Source check time not recorded"
    labels = []
    exploitation = exploitation_label(item)
    if exploitation:
        labels.append(exploitation)
    if any(row["listed"] is True for row in item["kev"]):
        labels.append("KEV listed")
    if item["fix_status"] == "unavailable":
        labels.append("No official patch")
    elif item["fix_status"] == "unknown":
        labels.append("Patch details unconfirmed")
    evidence = " · ".join(labels) or "Check the affected scope"
    kind = ITEM_KINDS.get(item.get("kind") or "", "")
    kind_label = f'<span class="item-kind">{escape(kind)}</span>' if kind else ""
    unverified = "".join(
        f'<span class="unverified-label">{escape(label)}</span>' if index == 0 else f'<span class="single-source-label">{escape(label)}</span>'
        for index, label in enumerate(verification_labels(item))
    )
    gaps = item.get("gaps")
    notes = f'<p class="verification-notes"><strong>Verification notes:</strong> {escape(gaps)}</p>' if gaps else ""
    permalink = escape(root_path(site_url, f"digests/{digest_date}/#item-{item['id']}"))
    watch = f'<button class="watch-button js-only" type="button" data-watch-id="{item_id}" aria-pressed="false" aria-label="Save {product} to my products"><span class="watch-label">Save product</span></button>' if interactive else ""
    return f'''<article class="briefing-item" id="item-{item_id}" data-product="{escape(item['product'].lower())}" data-product-id="{item_id}" data-audience="{item['audience']}" data-priority="{item['priority']}" data-search="{escape(search)}">
<header class="item-header"><div class="item-heading"><div class="item-meta">{unverified}{urgency(item)}{kind_label}<span class="action-type">{ACTIONS[item['action_type']]}</span></div><h3>{product}</h3></div>{watch}</header>
<p class="evidence">{escape(evidence)} <span aria-hidden="true">·</span> {AUDIENCES[item['audience']]}</p>
<p class="item-summary">{escape(item['summary'])}</p>
<div class="action-box"><strong>What to do</strong><p>{escape(item['action'])}</p>{steps_list(item)}</div>
<p class="applies-to"><strong>Applies to:</strong> {escape(item['affected'] or 'Affected versions not confirmed. Check the advisory for your installation.')}</p>
<p class="priority-reason"><strong>Why this priority:</strong> {escape(item['priority_reason'])}</p>
<p class="sources">{links}</p><p class="item-meta muted">{escape(check_label)}</p>
<details class="item-details"><summary>Versions, evidence &amp; scores</summary>{item_detail(item)}</details>
{notes}<a class="permalink" href="{permalink}" aria-label="Link to {product}">Link to this item <span aria-hidden="true">↗</span></a>
</article>'''


def page(title: str, body: str, site_url: str, path: str, *, description: str = DESCRIPTION, edition: dict | None = None, body_class: str = "") -> str:
    url = site_url + path
    href = lambda value: escape(root_path(site_url, value))
    dates = f' data-digest-date="{edition["digest_date"]}" data-updated-at="{edition["updated_at"]}"' if edition else ""
    article_meta = f'<meta property="article:published_time" content="{edition["published_at"]}"><meta property="article:modified_time" content="{edition["updated_at"]}">' if edition else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><meta name="description" content="{escape(description)}">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'">
<link rel="canonical" href="{escape(url)}"><link rel="icon" href="{href('assets/favicon.svg')}" type="image/svg+xml"><link rel="stylesheet" href="{href('assets/style.css')}">
<link rel="alternate" type="application/atom+xml" title="patch-these — all updates" href="{href('feed.xml')}">
<link rel="alternate" type="application/atom+xml" title="patch-these — for everyone" href="{href('feeds/everyone.xml')}">
<link rel="alternate" type="application/atom+xml" title="patch-these — apps and servers" href="{href('feeds/operators.xml')}">
<meta property="og:type" content="{'article' if edition else 'website'}"><meta property="og:site_name" content="patch-these">
<meta property="og:title" content="{escape(title)}"><meta property="og:description" content="{escape(description)}"><meta property="og:url" content="{escape(url)}">
<meta property="og:image" content="{escape(site_url + '/assets/social-card.png')}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta property="og:image:alt" content="patch-these — know what needs attention, and what to do next">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{escape(title)}"><meta name="twitter:description" content="{escape(description)}"><meta name="twitter:image" content="{escape(site_url + '/assets/social-card.png')}">{article_meta}
<script src="{href('assets/app.js')}" defer></script></head>
<body class="{escape(body_class)}"{dates}><a class="skip" href="#main">Skip to content</a>
<div class="wrap"><header class="site-header"><div class="header-top"><div class="brand"><a class="wordmark" href="{href('')}">patch-these</a><p class="byline">By <a href="https://github.com/JLuethe">John Luethe</a></p></div><nav class="main-nav" aria-label="Main"><a href="{href('archive/')}">Archive</a><span aria-hidden="true">·</span><a href="{href('methodology/')}">Methodology</a><span aria-hidden="true">·</span><a href="{href('subscribe/')}">Subscribe</a></nav></div></header>
<main id="main">{body}</main>
<footer class="site-footer"><div><a class="wordmark" href="{href('')}">patch-these.</a><p>By <a href="https://github.com/JLuethe">John Luethe</a></p><p>Curated, not complete. Unofficial. Updated every 4 hours, 6 AM–10 PM Pacific. Early signals are not confirmed. Verify the vendor advisory before acting.</p><p class="muted">Not professional advice. Not affiliated with CISA, FIRST, or any vendor. EPSS is a probability, not a certainty.</p></div><div class="feed-links"><a href="{href('products/')}">Products</a><a href="{href('subscribe/')}">Atom feeds</a><a href="{href('latest.json')}">Latest JSON</a><a href="{href('data/schema.json')}">Data schema</a><a href="{escape(REPO)}">GitHub</a><a href="{escape(REPO + '/blob/main/LICENSE')}">Content: CC BY 4.0</a><a href="{escape(REPO + '/blob/main/LICENSE-CODE')}">Code: MIT</a></div></footer></div></body></html>'''


def filters(total: int) -> str:
    return f'''<section aria-labelledby="all-items"><div class="section-heading"><div><p class="eyebrow">Your software, your next step</p><h2 id="all-items">The full briefing</h2></div><p id="result-count" role="status" aria-live="polite">{total} items</p></div>
<form class="filters js-only" id="filters" role="search"><div class="filter-field"><label for="search">Find your software</label><input id="search" type="search" placeholder="Product, CVE, or keyword" autocomplete="off"></div><div class="filter-field"><label for="audience">Show updates for</label><select id="audience"><option value="all">Everyone</option><option value="end_users">My computer</option><option value="applications_and_servers">Apps &amp; servers</option></select></div><div class="filter-field"><label for="urgency">Urgency</label><select id="urgency"><option value="all">All priorities</option><option value="act_now">Act now</option><option value="act_soon">Act soon</option><option value="monitor">Monitor</option></select></div><div class="filter-actions"><button id="watchlist-toggle" type="button" aria-pressed="false">My saved products <span id="saved-count">0</span></button><button id="clear-filters" type="button">Clear filters</button></div></form><p id="watchlist-status" class="sr-only" role="status"></p><p id="no-results" class="notice" hidden>No matching updates. Try another product or clear your filters. This is a curated briefing; a missing product does not mean it is unaffected.</p></section>'''


def early_signals(edition: dict, site_url: str) -> str:
    items = [item for item in ordered_items(edition) if is_early_signal(item)]
    if not items:
        return ""
    cards = "".join(item_card(item, edition["digest_date"], site_url) for item in items)
    return (
        '<section class="early-signals" aria-labelledby="early-signals">'
        '<div class="section-heading"><div><p class="eyebrow">Hot off the press</p>'
        '<h2 id="early-signals">Early signals: not yet verified</h2></div></div>'
        '<p class="muted">These leads are not confirmed. Do not patch from this section. A later correction promotes a lead in place once a primary source confirms it.</p>'
        f'<div class="early-grid">{cards}</div></section>'
    )


def featured(edition: dict) -> str:
    by_id = {item["id"]: item for item in edition["items"]}
    cards = []
    for index, item_id in enumerate(edition["featured_item_ids"], 1):
        item = by_id[item_id]
        if is_early_signal(item):
            continue
        more = " More steps in the full item." if item.get("steps") else ""
        cards.append(f'<a class="featured-card" href="#item-{escape(item_id)}"><span class="featured-number">0{index}</span>{urgency(item)}<h3>{escape(item["product"])}</h3><p>{escape(brief(item["action"]))}{more}</p><span class="featured-action">{ACTIONS[item["action_type"]]} <span class="featured-jump">Full details <span aria-hidden="true">↓</span></span></span></a>')
    if not cards:
        return ""
    return (
        '<section class="featured" aria-labelledby="priority-findings">'
        '<div class="section-intro"><h2 id="priority-findings">Priority Findings</h2>'
        '<p>Key security developments, affected products, and recommended actions from the latest briefing.</p></div>'
        '<div class="featured-grid">' + "".join(cards) + "</div></section>"
    )


def corrections(edition: dict) -> str:
    if not edition["corrections"]:
        return ""
    rows = "".join(f'<li><time datetime="{row["at"]}">{escape(human_time(row["at"]))}</time><p>{escape(row["summary"])}</p></li>' for row in reversed(edition["corrections"]))
    return f'<details class="corrections"><summary>Edition notes &amp; corrections ({len(edition["corrections"])})</summary><ol>{rows}</ol></details>'


def checked_meta(edition: dict) -> str:
    """The last editorial check, shown only when it is later than the last content change."""
    checked = edition.get("last_checked_at")
    if not checked or timestamp(checked) <= timestamp(edition["updated_at"]):
        return ""
    return f'<span>Last checked {human_time(checked)}</span>'


def edition_stats(edition: dict) -> str:
    items = ordered_items(edition)
    verified = [item for item in items if not is_early_signal(item)]
    signals = len(items) - len(verified)
    now = sum(item["priority"] == "act_now" for item in verified)
    soon = sum(item["priority"] == "act_soon" for item in verified)
    boxes = [
        f'<div class="stat"><strong>{len(items):02d}</strong><span>Security findings</span></div>',
        f'<div class="stat stat--now"><strong>{now:02d}</strong><span>Act now if affected</span></div>',
        f'<div class="stat stat--soon"><strong>{soon:02d}</strong><span>Act soon</span></div>',
    ]
    if signals:
        boxes.append(f'<div class="stat stat--signals"><strong>{signals:02d}</strong><span>Early signals</span></div>')
    return '<div class="edition-stats" aria-label="Edition summary">' + "".join(boxes) + "</div>"


def briefing_intro(edition: dict, *, latest: bool) -> str:
    kicker = "LATEST BRIEFING" if latest else "FROM THE ARCHIVE"
    date_label = briefing_date(edition["digest_date"])
    heading = "Independent security intelligence, updated throughout the day." if latest else "From the archive."
    meta = (
        f'<div class="hero-meta"><span>Covers {coverage(edition)}</span>'
        f'<span>Updated {human_time(edition["updated_at"])}</span>'
        f"{checked_meta(edition)}</div>"
    )
    hero = (
        f'<section class="hero"><h1 class="lede">{heading}</h1>'
        f'<p class="eyebrow briefing-kicker">{kicker} <span aria-hidden="true">·</span> '
        f'<time datetime="{edition["digest_date"]}">{date_label}</time></p>{meta}</section>'
    )
    if not latest:
        return hero + edition_stats(edition)
    emerging = (
        '<section class="emerging-threats" aria-labelledby="emerging-threats">'
        '<h2 id="emerging-threats">Emerging Threats</h2>'
        "<p>Tracking emerging security threats and vulnerabilities across X, Bluesky, Mastodon, security research blogs, and other sources.</p>"
        "<p>Early reports are clearly identified, findings are verified against authoritative sources, and recommendations are prioritized by urgency — all in plain English.</p>"
        "<p>Updated every four hours, 6 AM–10 PM Pacific.</p>"
        "</section>"
    )
    return hero + emerging + edition_stats(edition)


def briefing_body(edition: dict, site_url: str, *, latest: bool) -> str:
    items = ordered_items(edition)
    verified = [item for item in items if not is_early_signal(item)]
    href = lambda value: escape(root_path(site_url, value))
    cards = "".join(item_card(item, edition["digest_date"], site_url) for item in verified)
    edition_notes = f'<p class="verification-notes"><strong>Verification notes:</strong> {escape(edition["gaps"])}</p>' if edition.get("gaps") else ""
    signals = early_signals(edition, site_url)
    if not cards:
        cards = '<p class="notice">No new verified items in this edition. This does not establish that your software has no outstanding updates.</p>'
    return f'''{briefing_intro(edition, latest=latest)}
<p class="notice" id="freshness-note" hidden></p>{corrections(edition)}{edition_notes}{signals}{featured(edition)}{filters(len(verified))}
<div class="content-grid"><div class="briefing-list">{cards}</div><aside class="briefing-sidebar" aria-label="Reading the briefing"><section class="sidebar-card"><p class="eyebrow">Keep it relevant</p><h2>A smaller reading list.</h2><p>Use the filters to find your software. Save products to keep your own list on this browser.</p><p class="muted">Product selection is a reading preference, not a scan of your installed software.</p></section><section class="sidebar-card"><p class="eyebrow">How to read this</p><h2>Urgency ≠ a patch.</h2><p><strong>Act now</strong><br>Prioritize action if your installation is affected.</p><p><strong>Act soon</strong><br>Plan the recommended update or mitigation.</p><p><strong>Monitor</strong><br>Follow developments; the next step may change.</p><p>No patch can mean mitigate or replace. Check the affected scope and the source.</p><a href="{href('methodology/')}">Read our method ↗</a></section><section class="sidebar-card"><p class="eyebrow">Stay in the loop</p><h2>Choose your feed.</h2><p>All updates, personal software, or apps and servers. Read in your preferred feed reader.</p><a href="{href('subscribe/')}">Subscribe to an Atom feed ↗</a></section></aside></div>
<p class="sidecar"><a href="{href('data/' + edition['digest_date'] + '.json')}">This edition as JSON</a> · <a href="{href('digests/' + edition['digest_date'] + '.md')}">Generated Markdown</a></p>'''


def archive_body(editions: list[dict], site_url: str) -> str:
    rows = "".join(f'<li><a href="{escape(root_path(site_url, "digests/" + edition["digest_date"] + "/"))}">{human_date(edition["digest_date"])}</a><span class="when">{len(edition["items"])} items · Covers {coverage(edition)}</span></li>' for edition in reversed(editions))
    return '<section class="archive"><p class="eyebrow">The record</p><h1>Every briefing.</h1><p>Read past editions and their corrections. Advice is dated; check current vendor guidance before acting.</p><ul class="digest-list">' + rows + '</ul></section>'


def subscribe_body(site_url: str) -> str:
    rows = []
    for path, title, detail in [("feed.xml", "The full briefing", "Every item in each edition."), ("feeds/everyone.xml", "For your computer", "End-user software, plus items relevant to everyone."), ("feeds/operators.xml", "For apps & servers", "Infrastructure, libraries and services, plus items relevant to everyone.")]:
        url = site_url + "/" + path
        rows.append(f'<section class="sidebar-card"><h2>{title}</h2><p>{detail}</p><a href="{escape(root_path(site_url, path))}">Open Atom feed ↗</a><p><code>{escape(url)}</code></p></section>')
    return '<section class="prose"><p class="eyebrow">Less checking, more knowing</p><h1>Follow what matters.</h1><p>Paste a feed URL into your preferred RSS/Atom reader. The briefing is updated every 4 hours from 6 AM to 10 PM Pacific. Each edition includes confirmed actions, early signals labeled as not yet verified, and source links. Corrections update the entry.</p><div class="feed-options">' + "".join(rows) + '</div><h2>Prefer structured data?</h2><p><a href="' + escape(root_path(site_url, "latest.json")) + '">latest.json</a> always contains the newest edition, using our <a href="' + escape(root_path(site_url, "data/schema.json")) + '">published JSON Schema</a>. Schema version 2 separates urgency, exploitation, KEV membership and fixes.</p></section>'
