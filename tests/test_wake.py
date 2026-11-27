"""Wake-row selection and dedupe. Fixtures only, no network."""
import json
from datetime import date, datetime, timedelta, timezone

from patchthese.wake import covered_products, match_products, new_rows, post_body, record_woken, select_wake_rows

INDEX = {"products": [
    {"id": "nginx-http2", "product": "F5 NGINX Open Source and NGINX Plus", "appearances": [{"digest_date": "2026-11-25"}]},
    {"id": "palo-alto-pan-os", "product": "Palo Alto Networks PAN-OS", "appearances": [{"digest_date": "2026-11-26"}]},
    {"id": "old-thing", "product": "Old Thing", "appearances": [{"digest_date": "2026-10-01"}]},
]}
COVERED = covered_products(INDEX, date(2026, 11, 26))


def row(source, item_id, title, cves=()):
    return {"source": source, "id": item_id, "title": title, "url": f"https://vendor.example/{item_id}", "published": "2026-11-26T10:00:00Z", "cves": list(cves), "fetched_at": "2026-11-26T10:05:00Z"}


def test_only_products_from_the_last_week_are_covered():
    assert [product["id"] for product in COVERED] == ["nginx-http2", "palo-alto-pan-os"]


def test_product_and_vendor_matching_is_whole_word():
    assert match_products(row("github-advisories", "GHSA-1", "nginx-ui allows path traversal"), COVERED) == ["nginx-http2"]
    assert match_products(row("github-advisories", "GHSA-2", "engine nginxish parser bug"), COVERED) == []
    # Any new advisory on a covered vendor's own feed matches that vendor's products.
    assert match_products(row("palo-alto", "PAN-1", "GlobalProtect: denial of service"), COVERED) == ["palo-alto-pan-os"]
    assert match_products(row("cisco-psirt", "cisco-1", "Cisco IOS XE advisory"), COVERED) == []


def test_new_rows_skip_the_baseline_and_known_rows():
    old = [row("palo-alto", "PAN-1", "old")]
    current = old + [row("palo-alto", "PAN-2", "new")]
    assert new_rows(current, []) == []
    assert [item["id"] for item in new_rows(current, old)] == ["PAN-2"]


def test_kev_rows_come_first_and_nothing_wakes_twice():
    kev = [row("cisa-kev", "CVE-2026-1", "Palo Alto Networks PAN-OS bug", ["CVE-2026-1"])]
    fresh = [
        row("palo-alto", "PAN-2", "PAN-OS advisory"),
        row("hacker-news", "99", "nginx zero-day discussion"),
        row("cisco-psirt", "cisco-1", "Cisco advisory"),
    ]
    rows = select_wake_rows(kev, fresh, COVERED, {})
    assert [(item["reason"], item["id"]) for item in rows] == [("kev_new", "CVE-2026-1"), ("covered_advisory", "PAN-2")]
    assert rows[0]["matched_products"] == ["palo-alto-pan-os"]
    now = datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc)
    woken = record_woken({"cisa-kev:CVE-2025-9": "2026-09-01T00:00:00Z"}, rows, "2026-11-26T18:00:00Z", now)
    assert set(woken) == {"cisa-kev:CVE-2026-1", "palo-alto:PAN-2"}  # the 30-day-old entry is pruned
    assert select_wake_rows(kev, fresh, COVERED, woken) == []


def test_post_body_is_capped_and_short():
    rows = select_wake_rows([], [row("palo-alto", f"PAN-{n}", "PAN-OS " + "x" * 400) for n in range(15)], COVERED, {})
    body = post_body(rows)
    assert body["reason"] == "feed" and body["total"] == 15 and len(body["rows"]) == 10
    assert all(len(item["title"]) <= 160 for item in body["rows"])
    assert "advisory_lines" not in body["rows"][0]


def test_build_cache_writes_wake_rows_once(tmp_path):
    from fetch_feeds import FEEDS, KEV_URL, build_cache
    products = tmp_path / "products.json"
    products.write_text(json.dumps(INDEX))
    cache = tmp_path / "cache"
    kev = [{"cveID": "CVE-2026-16232", "dateAdded": "2026-07-22", "vulnerabilityName": "old"}]
    palo = ["PAN-1"]

    def fetcher(url, token=None, timeout=25):
        names = dict((feed_url, name) for name, feed_url in FEEDS)
        if url == KEV_URL:
            return json.dumps({"vulnerabilities": kev}).encode()
        if "api.github.com" in url:
            return b"[]"
        if "algolia" in url:
            return b'{"hits": []}'
        if names.get(url) == "palo-alto":
            items = "".join(f"<item><title>PAN-OS {pan}</title><link>https://security.paloaltonetworks.com/{pan}</link><guid>{pan}</guid><pubDate>Thu, 26 Nov 2026 12:00:00 GMT</pubDate></item>" for pan in palo)
            return f'<?xml version="1.0"?><rss version="2.0"><channel>{items}</channel></rss>'.encode()
        return b'<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>'

    start = datetime(2026, 11, 26, 13, 0, tzinfo=timezone.utc)
    body = tmp_path / "body.json"
    assert build_cache(cache, token=None, now=start, fetcher=fetcher, products_path=products, wake_body=body) == 0
    assert json.loads((cache / "wake.json").read_text())["rows"] == []  # first run is the baseline
    assert not body.exists()

    kev.append({"cveID": "CVE-2026-99999", "dateAdded": "2026-11-26", "vulnerabilityName": "new"})
    palo.append("PAN-2")
    later = start + timedelta(minutes=30)
    assert build_cache(cache, token=None, now=later, fetcher=fetcher, products_path=products, wake_body=body) == 0
    wake = json.loads((cache / "wake.json").read_text())
    assert [(item["reason"], item["id"]) for item in wake["rows"]] == [("kev_new", "CVE-2026-99999"), ("covered_advisory", "PAN-2")]
    assert json.loads(body.read_text())["total"] == 2
    assert set(json.loads((cache / "woken.json").read_text())["ids"]) == {"cisa-kev:CVE-2026-99999", "palo-alto:PAN-2"}

    assert build_cache(cache, token=None, now=later + timedelta(minutes=30), fetcher=fetcher, products_path=products, wake_body=body) == 0
    assert json.loads((cache / "wake.json").read_text())["rows"] == []
    assert not body.exists()


def test_feeds_workflow_keeps_the_test_wake_separate_from_scheduled_runs():
    from pathlib import Path
    import re
    text = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "feeds.yml").read_text()
    steps = {match.group(1): match.group(2) for match in re.finditer(r"- name: ([^\n]+)\n((?:        [^\n]*\n|\n)*)", text)}
    for name in ("Restore the cache from the feed-cache branch", "Fetch public discovery feeds",
                 "Publish the cache to the feed-cache branch", "Wake the editorial routine for new KEV entries or covered-vendor advisories"):
        assert steps[name].startswith("        if: ${{ !inputs.test_wake }}\n")
    test_step = steps["Send a test wake (manual test_wake runs only)"]
    assert test_step.startswith("        if: ${{ inputs.test_wake }}\n")
    assert '{"reason":"test","total":0,"rows":[]}' in test_step and "woken" not in test_step
    assert "-K \"$RUNNER_TEMP/wake-curl.conf\"" in test_step and "echo \"$WAKE_SECRET" not in test_step


MS_UBUNTU = [
    {"id": "microsoft-visio", "product": "Microsoft Office Visio"},
    {"id": "linux-nfsd", "product": "Linux kernel NFS server (nfsd)"},
    {"id": "azure-api-management-classic", "product": "Azure API Management Classic"},
    {"id": "canonical-lxd", "product": "Canonical LXD"},
]


def test_msrc_rows_wake_only_when_they_name_a_covered_product():
    kernel = row("msrc", "CVE-2026-62840", "CVE-2026-62840 Linux Kernel Elevation of Privilege Vulnerability")
    visio = row("msrc", "CVE-2026-70001", "CVE-2026-70001 Microsoft Visio Remote Code Execution Vulnerability")
    edge = row("msrc", "CVE-2026-70002", "CVE-2026-70002 Microsoft Edge (Chromium-based) Spoofing Vulnerability")
    apim = row("msrc", "CVE-2026-70003", "CVE-2026-70003 Azure API Management Classic Information Disclosure")
    assert match_products(kernel, MS_UBUNTU) == []
    assert match_products(visio, MS_UBUNTU) == ["microsoft-visio"]
    assert match_products(edge, MS_UBUNTU) == []
    assert match_products(apim, MS_UBUNTU) == ["azure-api-management-classic"]
    assert [item["id"] for item in select_wake_rows([], [kernel, visio, edge], MS_UBUNTU, {})] == ["CVE-2026-70001"]


def test_ubuntu_rows_wake_only_when_they_name_a_covered_product():
    apache = row("ubuntu-usn", "USN-9016-2", "USN-9016-2: Apache HTTP Server regression")
    lxd = row("ubuntu-usn", "USN-9020-1", "USN-9020-1: LXD vulnerabilities")
    nfs = row("ubuntu-usn", "USN-9021-1", "USN-9021-1: Linux kernel vulnerabilities")
    assert match_products(apache, MS_UBUNTU) == []
    assert match_products(lxd, MS_UBUNTU) == ["canonical-lxd"]
    assert match_products(nfs, MS_UBUNTU) == []


def test_other_vendor_feeds_keep_vendor_wide_matching():
    assert match_products(row("palo-alto", "PAN-9", "GlobalProtect: denial of service"), COVERED) == ["palo-alto-pan-os"]
