"""Atom feeds with stable entry IDs and real correction timestamps."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

from html import escape
import xml.etree.ElementTree as ET

from .common import ACTIONS, DESCRIPTION, PRIORITIES, exploitation_label, human_date, is_early_signal, ordered_items, social_platform, timestamp, verification_labels

ATOM = "http://www.w3.org/2005/Atom"
ET.register_namespace("", ATOM)


def source_label(source: dict) -> str:
    platform = social_platform(source["url"]) if source["kind"] == "social_report" else None
    return f"{platform} · {source['label']}" if platform else source["label"]


def build_feed(editions: list[dict], site_url: str, *, audience: str | None = None, feed_path: str = "feed.xml") -> str:
    feed = ET.Element(f"{{{ATOM}}}feed", {"{http://www.w3.org/XML/1998/namespace}lang": "en"})
    def add(parent, name: str, text: str | None = None, **attrs):
        node = ET.SubElement(parent, f"{{{ATOM}}}{name}", attrs)
        node.text = text
        return node
    title = "patch-these" + ({"end_users": " — for everyone", "applications_and_servers": " — apps & servers"}.get(audience, ""))
    add(feed, "id", site_url + "/" + feed_path)
    add(feed, "title", title)
    add(feed, "subtitle", DESCRIPTION)
    add(feed, "updated", max(editions, key=lambda edition: timestamp(edition["updated_at"]))["updated_at"])
    add(feed, "link", rel="self", type="application/atom+xml", href=site_url + "/" + feed_path)
    add(feed, "link", rel="alternate", type="text/html", href=site_url + "/")
    author = add(feed, "author")
    add(author, "name", "patch-these")
    add(feed, "rights", "Creative Commons Attribution 4.0 International")
    for edition in reversed(editions):
        items = ordered_items(edition, audience)
        if edition["items"] and not items:
            continue
        link = f"{site_url}/digests/{edition['digest_date']}/"
        if audience:
            link += f"?audience={audience}"
        entry = add(feed, "entry")
        add(entry, "id", link)
        add(entry, "title", f"{title} — {human_date(edition['digest_date'])}")
        add(entry, "published", edition["published_at"])
        add(entry, "updated", edition["updated_at"])
        add(entry, "link", rel="alternate", type="text/html", href=link)
        summary = "; ".join(
            f"{item['product']}: {'Not yet verified' if is_early_signal(item) else PRIORITIES[item['priority']] + ' / ' + ACTIONS[item['action_type']]}"
            for item in items
        ) or "No new verified items in this edition."
        add(entry, "summary", summary, type="text")
        blocks = []
        if edition["corrections"]:
            blocks.append("<h2>Corrections</h2><ul>" + "".join(f'<li>{escape(row["summary"])}</li>' for row in edition["corrections"]) + "</ul>")
        early = [item for item in items if is_early_signal(item)]
        if early:
            blocks.append("<h2>Early signals: not yet verified</h2><p>These leads are not confirmed. Do not patch from them.</p>")
        for item in items:
            primary = [source for source in item["sources"] if source["kind"] != "social_report"]
            # Early signals keep their discovery posts; they may be the only source.
            cited = item["sources"] if is_early_signal(item) or not primary else primary
            sources = " · ".join(f'<a href="{escape(source["url"])}">{escape(source_label(source))}</a>' for source in cited)
            status = " · ".join(verification_labels(item)) if is_early_signal(item) else f"{PRIORITIES[item['priority']]} · {ACTIONS[item['action_type']]}"
            evidence = exploitation_label(item)
            if evidence:
                status += f" · {evidence}"
            steps = item.get("steps") or []
            steps_html = ("<ol>" + "".join(f"<li>{escape(step)}</li>" for step in steps) + "</ol>") if steps else ""
            blocks.append(f'<h2><a href="{escape(link + "#item-" + item["id"])}">{escape(item["product"])}</a></h2><p><strong>{escape(status)}</strong></p><p>{escape(item["summary"])}</p><p><strong>What to do:</strong> {escape(item["action"])}</p>{steps_html}<p><strong>Applies to:</strong> {escape(item["affected"] or "Affected versions not confirmed; check the advisory.")}</p><p><strong>Why:</strong> {escape(item["priority_reason"])}</p><p>{sources}</p>')
            if item["cves"]:
                blocks.append('<p><strong>CVEs:</strong> ' + escape(", ".join(item["cves"])) + '</p>')
            if item["fixes"]:
                fixes = []
                for fix in item["fixes"]:
                    scope = " / ".join(value for value in [fix["component"], fix["platform"], fix["branch"]] if value)
                    identity = f' ({escape(", ".join(fix["cves"]))})' if fix["cves"] else ""
                    fixes.append(f'<li>{escape(scope)}: <code>{escape(fix["version"])}</code>{identity}</li>')
                blocks.append('<p><strong>Fixed releases:</strong></p><ul>' + "".join(fixes) + '</ul>')
        if not items:
            blocks.append("<p>No new verified items in this edition. This does not establish that your software has no outstanding updates.</p>")
        add(entry, "content", "".join(blocks), type="html")
    return ET.tostring(feed, encoding="unicode", xml_declaration=True)
