"""Generate Markdown views from the same facts used by HTML and feeds."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import re
from urllib.parse import quote

from .common import ACTIONS, AUDIENCES, PRIORITIES, coverage, human_date, human_time, ordered_items

GENERATED_START = "<!-- BEGIN GENERATED EDITION -->"
GENERATED_END = "<!-- END GENERATED EDITION -->"


def md_text(value: str) -> str:
    # Structured editorial fields are plain text, not a second Markdown input.
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_\[\]{}])", r"\\\1", value).replace("\n", " ")


def md_code(value: str) -> str:
    value = " ".join(value.split())
    width = max((len(run) for run in re.findall(r"`+", value)), default=0) + 1
    fence = "`" * width
    return f"{fence} {value} {fence}"


def md_url(value: str) -> str:
    return quote(value, safe=":/?&=%#@+;,~.-_")


def markdown_digest(edition: dict, site_url: str) -> str:
    rows = [f"# {human_date(edition['digest_date'])}", "", "<!-- Generated from data/" + edition["digest_date"] + ".json. Edit the JSON, then run python scripts/build_site.py --write-generated. -->", "", f"Coverage: {coverage(edition)}.", "", f"Updated: {human_time(edition['updated_at'])}.", "", "Urgency describes when to act if affected. The action may be an update, mitigation, replacement, or credential rotation. Missing information is marked as unknown."]
    if edition.get("gaps"):
        rows += ["", f"**Verification notes:** {md_text(edition['gaps'])}"]
    if not edition["items"]:
        rows += ["", "No new verified items in this edition. This does not establish that your software has no outstanding updates."]
    if edition["corrections"]:
        rows += ["", "## Corrections"]
        for correction in edition["corrections"]:
            rows += ["", f"- **{human_time(correction['at'])}:** {md_text(correction['summary'])}"]
    by_id = {item["id"]: item for item in edition["items"]}
    featured = [by_id[item_id] for item_id in edition["featured_item_ids"]]
    if featured:
        rows += ["", "## Start here, if you use these", "", "These are starting points, not the only urgent items. Check the full list for your software.", ""]
        for item in featured:
            rows += [f"- **{md_text(item['product'])}:** {md_text(item['action'])}"]
    for priority, label in PRIORITIES.items():
        items = [item for item in ordered_items(edition) if item["priority"] == priority]
        if not items:
            continue
        rows += ["", f"## {label}"]
        for item in items:
            kind = {"vulnerability": "Vulnerability", "incident": "Incident", "supply_chain": "Supply chain"}.get(item.get("kind") or "")
            lead = " · ".join(part for part in (kind, ACTIONS[item["action_type"]], AUDIENCES[item["audience"]]) if part)
            rows += ["", f"### {md_text(item['product'])}", "", f"**{lead}**", "", md_text(item["summary"]), "", f"**What to do:** {md_text(item['action'])}", "", f"**Why:** {md_text(item['priority_reason'])}", "", f"**Applies to:** {md_text(item['affected'] or 'Affected versions not confirmed. Check the advisory before deciding whether this applies to your installation.')}"]
            if item.get("gaps"):
                rows += ["", f"**Verification notes:** {md_text(item['gaps'])}"]
            if item["cves"]:
                rows += ["", "**CVEs:** " + ", ".join(item["cves"])]
            if item["fixes"]:
                rows += ["", "**Fixes by component / platform / branch:**", ""]
                for fix in item["fixes"]:
                    scope = " / ".join(str(v) for v in (fix["component"], fix["platform"], fix["branch"]) if v)
                    cves = "; " + ", ".join(fix["cves"]) if fix["cves"] else ""
                    rows += [f"- {md_text(scope)}: {md_code(fix['version'])}{cves}."]
            by_cve = item["exploitation"].get("by_cve")
            if by_cve:
                rows += ["", "**Exploitation:** " + "; ".join(f"{record['cve']} {record['status']}" for record in by_cve) + "."]
            else:
                rows += ["", "**Exploitation:** " + item["exploitation"]["status"] + "."]
            for kev in item["kev"]:
                status = "listed" if kev["listed"] is True else "not listed" if kev["listed"] is False else "not established"
                added = f"; added {kev['date_added']}" if kev["date_added"] else ""
                rows += [f"- KEV {kev['cve']}: {status}{added}."]
            rows += ["", "**Sources:**", ""]
            for source in item["sources"]:
                checked = f"; checked {human_time(source['checked_at'])}" if source["checked_at"] else "; check not recorded"
                rows += [f"- [{md_text(source['label'])}]({md_url(source['url'])}) ({source['kind'].replace('_', ' ')}{checked})."]
            for score in item["cvss"]:
                rows += [f"- Reported CVSS{(' ' + md_text(score['version'])) if score['version'] else ''}: {score['score']:g}" + (f" ({score['cve']})" if score["cve"] else "") + "."]
            for score in item["epss"]:
                when = score["score_date"] or "original score date not recorded"
                rows += [f"- Reported EPSS: {score['probability']:.2%} ({score['cve']}; {when})."]
            rows += ["", f"[Link to this item]({md_url(site_url)}/digests/{edition['digest_date']}/#item-{item['id']})"]
    rows += ["", "## About this briefing", "", "Curated, not complete. Unofficial. Not professional advice. Verify actions against the vendor advisory. EPSS is a probability, not a certainty.", ""]
    return "\n".join(rows)


def readme_block(edition: dict, site_url: str) -> str:
    rows = [GENERATED_START, f"## Latest edition — {human_date(edition['digest_date'])}", "", f"[Read the briefing]({site_url}/) · [Full Markdown digest](digests/{edition['digest_date']}.md) · [Structured data](data/{edition['digest_date']}.json)", "", f"Coverage: {coverage(edition)}. Updated: {human_time(edition['updated_at'])}."]
    for audience, label in [("end_users", "For everyone"), ("applications_and_servers", "For app and server owners")]:
        rows += ["", f"### {label}", ""]
        relevant = ordered_items(edition, audience)
        if not relevant:
            rows += ["No items for this audience in this edition."]
        for item in relevant:
            url = f"{site_url}/digests/{edition['digest_date']}/#item-{item['id']}"
            rows += [f"- **[{md_text(item['product'])}]({md_url(url)}) — {PRIORITIES[item['priority']]} / {ACTIONS[item['action_type']]}:** {md_text(item['action'])}"]
    rows += ["", GENERATED_END]
    return "\n".join(rows)


def replace_readme_block(readme: str, edition: dict, site_url: str) -> str:
    if readme.count(GENERATED_START) != 1 or readme.count(GENERATED_END) != 1:
        raise ValueError("README needs one BEGIN/END GENERATED EDITION marker pair")
    start = readme.index(GENERATED_START)
    end = readme.index(GENERATED_END) + len(GENERATED_END)
    if end < start:
        raise ValueError("README generated markers are reversed")
    return readme[:start] + readme_block(edition, site_url) + readme[end:]
