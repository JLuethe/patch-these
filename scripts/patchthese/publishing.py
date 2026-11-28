"""Build a complete static publication from validated editions."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import shutil
import tempfile
from html import escape
from pathlib import Path
import xml.etree.ElementTree as ET

from .common import REPO, human_date, normalize_site_url, root_path
from .editorial import markdown_digest, replace_readme_block
from .feeds import build_feed
from .rendering import archive_body, briefing_body, page, render_markdown, subscribe_body
from .validation import load_editions


class StaleGeneratedFiles(ValueError):
    """Committed generated views no longer match the JSON they come from."""


def product_index(editions: list[dict]) -> dict:
    """Stable product ids, with every edition and item that uses each id."""
    products: dict[str, dict] = {}
    for edition in editions:
        for item in edition["items"]:
            record = products.setdefault(item["id"], {"id": item["id"], "product": item["product"], "appearances": []})
            record["product"] = item["product"]
            record["appearances"].append({"digest_date": edition["digest_date"], "item_id": item["id"], "verification": item.get("verification") or "verified"})
    return {"products": [products[key] for key in sorted(products)]}


def products_body(index: dict, site_url: str) -> str:
    rows = []
    for product in index["products"]:
        links = []
        for appearance in product["appearances"]:
            href = escape(root_path(site_url, f"digests/{appearance['digest_date']}/#item-{appearance['item_id']}"))
            note = " (not yet verified)" if appearance.get("verification") == "early_signal" else ""
            links.append(f'<a href="{href}">{escape(appearance["digest_date"])}</a>{note}')
        rows.append(f'<li><strong>{escape(product["product"])}</strong> <span class="muted">{escape(product["id"])}</span><br>{" · ".join(links)}</li>')
    listing = "".join(rows) or "<li>No products have been published yet.</li>"
    return f'<section class="prose"><p class="eyebrow">Across editions</p><h1>Products</h1><p>Each id is the stable item id used by Save product. One id can appear in more than one edition.</p><ul>{listing}</ul></section>'


def stale_generated_files(root: Path, editions: list[dict], site_url: str) -> list[str]:
    """List committed generated files that differ from what the editions produce."""
    root = Path(root)
    stale = []
    expected = {}
    for edition in editions:
        expected[f"digests/{edition['digest_date']}.md"] = markdown_digest(edition, site_url)
    readme_path = root / "README.md"
    expected["README.md"] = replace_readme_block(readme_path.read_text(encoding="utf-8"), editions[-1], site_url)
    expected["data/products.json"] = json.dumps(product_index(editions), ensure_ascii=False, indent=2) + "\n"
    for relative, content in expected.items():
        path = root / relative
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            stale.append(relative)
    known = {f"{edition['digest_date']}.md" for edition in editions}
    for path in sorted((root / "digests").glob("*.md")):
        if path.name not in known:
            stale.append(f"digests/{path.name} (no matching data/*.json edition)")
    return stale


def build_site(root: Path, *, site_url: str = "https://jluethe.github.io/patch-these", write_generated: bool = False, check_generated: bool = False) -> Path:
    root = Path(root)
    site_url = normalize_site_url(site_url)
    editions = load_editions(root / "data")
    if not editions:
        raise ValueError("Add at least one data/YYYY-MM-DD.json edition before building")
    latest = editions[-1]
    if write_generated and check_generated:
        raise ValueError("Use either --write-generated or --check, not both")
    if check_generated:
        stale = stale_generated_files(root, editions, site_url)
        if stale:
            raise StaleGeneratedFiles(
                "Generated files are out of date with data/*.json: " + ", ".join(stale)
                + ". Run python scripts/build_site.py --write-generated and commit the result."
            )
    destination = root / "_site"
    generated = {edition["digest_date"]: markdown_digest(edition, site_url) for edition in editions}
    readme = None
    if write_generated:
        readme = replace_readme_block((root / "README.md").read_text(encoding="utf-8"), latest, site_url)
    # Don't destroy the last successful build if validation or rendering fails.
    with tempfile.TemporaryDirectory(prefix=".site-build-", dir=root) as temporary:
        output = Path(temporary) / "site"
        output.mkdir()
        shutil.copytree(root / "assets", output / "assets")
        for asset in ("style.css", "app.js", "social-card-v2.png", "favicon.svg"):
            if not (output / "assets" / asset).is_file():
                raise ValueError(f"Missing publication asset: assets/{asset}")
        def write(path: str, content: str) -> None:
            target = output / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        write("index.html", page("patch-these — know what needs attention", briefing_body(latest, site_url, latest=True), site_url, "/", edition=latest, body_class="home"))
        for edition in editions:
            date = edition["digest_date"]
            write(f"digests/{date}/index.html", page(f"{human_date(date)} — patch-these", briefing_body(edition, site_url, latest=False), site_url, f"/digests/{date}/", edition=edition, body_class="digest"))
            write(f"digests/{date}.md", generated[date])
            write(f"data/{date}.json", json.dumps(edition, ensure_ascii=False, indent=2) + "\n")
        latest_json = json.dumps(latest, ensure_ascii=False, indent=2) + "\n"
        write("latest.json", latest_json)
        write("data/latest.json", latest_json)
        shutil.copyfile(root / "data" / "schema.json", output / "data" / "schema.json")
        index = product_index(editions)
        index_json = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
        write("data/products.json", index_json)
        write("products/index.html", page("Products — patch-these", products_body(index, site_url), site_url, "/products/"))
        write("archive/index.html", page("All briefings — patch-these", archive_body(editions, site_url), site_url, "/archive/"))
        write("subscribe/index.html", page("Subscribe — patch-these", subscribe_body(site_url), site_url, "/subscribe/"))
        method = render_markdown((root / "METHODOLOGY.md").read_text(encoding="utf-8"), relative_base=REPO + "/blob/main/")
        write("methodology/index.html", page("How this is made — patch-these", f'<article class="prose">{method}</article>', site_url, "/methodology/"))
        missing = f'<section class="prose"><p class="eyebrow">404 / page not found</p><h1>This page isn’t in the briefing.</h1><p>Try the <a href="{escape(root_path(site_url))}">latest edition</a> or browse <a href="{escape(root_path(site_url, "archive/"))}">the archive</a>.</p></section>'
        write("404.html", page("Page not found — patch-these", missing, site_url, "/404.html"))
        for audience, path in [(None, "feed.xml"), ("end_users", "feeds/everyone.xml"), ("applications_and_servers", "feeds/operators.xml")]:
            feed = build_feed(editions, site_url, audience=audience, feed_path=path)
            ET.fromstring(feed)
            write(path, feed)
        write(".nojekyll", "")
        # Static aliases and social metadata can be crawled without JavaScript.
        sitemap = ET.Element("urlset", {"xmlns": "http://www.sitemaps.org/schemas/sitemap/0.9"})
        for path in ["/", "/archive/", "/products/", "/subscribe/", "/methodology/"] + [f"/digests/{edition['digest_date']}/" for edition in editions]:
            entry = ET.SubElement(sitemap, "url")
            ET.SubElement(entry, "loc").text = site_url + path
        write("sitemap.xml", ET.tostring(sitemap, encoding="unicode", xml_declaration=True))
        write("robots.txt", f"User-agent: *\nAllow: /\nSitemap: {site_url}/sitemap.xml\n")
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(output), destination)
    if write_generated:
        (root / "digests").mkdir(exist_ok=True)
        for date, content in generated.items():
            (root / "digests" / f"{date}.md").write_text(content, encoding="utf-8")
        (root / "README.md").write_text(readme, encoding="utf-8")
        (root / "data" / "products.json").write_text(json.dumps(product_index(editions), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return destination
