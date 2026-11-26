# patch-these

A calm security briefing: what applies to you, why it matters, and what to do next.

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 25 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-25.md) · [Structured data](data/2026-11-25.json)

Coverage: 23–25 November 2026. Updated: 25 Nov 2026 · 9:55 PM PST.

### For everyone

- **[Google Chrome](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-chrome-desktop) — Act now / Update:** Update Chrome to 158.0.8127.88 on Linux, or 158.0.8127.88 or 158.0.8127.89 on Windows and macOS. Check the separate vendor advisories and update channels for applications that embed Chromium.
- **[Firefox and Thunderbird](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-firefox-thunderbird) — Act soon / Update:** Update to Firefox 161, Firefox ESR 153.8, or Firefox ESR 115.46. Update to Thunderbird 161 or Thunderbird 153.8.
- **[Omarchy dell-xps-touchpad-haptics](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-omarchy-dell-xps-touchpad-haptics) — Act soon / Update:** Update to 1.0.0-4.

### For app and server owners

- **[Google Chrome](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-chrome-desktop) — Act now / Update:** Update Chrome to 158.0.8127.88 on Linux, or 158.0.8127.88 or 158.0.8127.89 on Windows and macOS. Check the separate vendor advisories and update channels for applications that embed Chromium.
- **[Drupal core](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-drupal-core) — Act now / Update:** Update to 10.6.22, 11.3.22, or 11.4.13. Lock down /core/install.php and keep settings.php unwritable. End-of-life lines have no fix.
- **[VMware vCenter](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-vmware-vcenter) — Act now / Update:** Apply the cumulative update for your supported branch: vCenter 9.1.2, 9.0.2.0300, or 8.0 U3m; use VCF 5.2.5 for the affected Cloud Foundation branch. Follow the applicable Broadcom response matrix and keep management access restricted.
- **[GeoServer](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-geoserver) — Act now / Update:** Update to 3.0.2, 2.28.6, or 2.27.7.
- **[Juniper Session Smart](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-juniper-session-smart) — Act now / Update:** Update to 7.0.5, 7.1.7, or 7.2.3.
- **[MONAI Label](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-monai-label) — Act now / Update:** Update to 0.8.6. Enable authentication until you do.
- **[N-able Mail Assure / SpamExperts](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-nable-mail-assure) — Act now / Update:** Update to 20261121.1943.
- **[Azure API Management Classic](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-azure-api-management-classic) — Act now / Rotate credentials:** For affected Classic instances, rotate tokens and secrets, review access logs and the data behind the gateway, and verify the service update using NSM guidance. Contact the provider if the instance is not updated.
- **[Bytebase DBHub MCP](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-bytebase-dbhub-mcp) — Act now / Mitigate:** Restrict network access to trusted clients and keep the affected service off untrusted networks while tracking the vendor remediation.
- **[Idunno.AntiCsrf](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-idunno-anticsrf) — Act now / Replace:** Replace Idunno.AntiCsrf with a supported anti-CSRF mechanism and investigate exposed applications for compromise. Follow Mandiant guidance when removing the component so request-forgery protection is retained.
- **[Optimizely Web Experimentation](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-optimizely-web-experimentation) — Act now / Check applicability:** If you run this product, investigate exposure now and obtain the vendor remediation instructions through its CISA KEV catalog entry. Missing patch details are an information gap, not a reason to defer action.
- **[Mitel MiCollab](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-mitel-micollab) — Act now / Check applicability:** If you run this product, investigate exposure now and obtain the vendor remediation instructions through its CISA KEV catalog entry. Missing patch details are an information gap, not a reason to defer action.
- **[Danfoss AK-SM 800A](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-danfoss-ak-sm-800a) — Act now / Check applicability:** If you run this product, investigate exposure now and obtain the vendor remediation instructions through its CISA KEV catalog entry. Missing patch details are an information gap, not a reason to defer action.
- **[Xen Orchestra](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-xen-orchestra) — Act now / Check applicability:** If you run this product, investigate exposure now and obtain the vendor remediation instructions through its CISA KEV catalog entry. Missing patch details are an information gap, not a reason to defer action.
- **[simple-git](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-simple-git) — Act soon / Update:** Update to simple-git 4.1.0 and @simple-git/argv-parser 3.0.0. Do not pass untrusted input to listRemote() or raw().
- **[Jenkins plugins](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-jenkins-plugins) — Act soon / Update:** Update Pipeline: Groovy to 4403.4405.va\_b\_cdb\_b\_d0b\_89f and Script Security to 1436.1438.v3dc5ef7d16f2, and update the other affected plugins named in the advisory.

<!-- END GENERATED EDITION -->

## How publication works

Each edition has one editable source: `data/YYYY-MM-DD.json`. JSON Schema and semantic validation check dates, evidence references, CVEs, priorities, and the relationship between fixes and vulnerabilities. The builder generates HTML, Markdown, the README edition block, structured downloads, and three Atom feeds from those same records.

The site is plain static HTML, CSS, and a small local script for optional filters. All briefing content and source links work without JavaScript. Saved products stay in the reader's browser; there are no accounts, analytics, or installation scans.

The repository provides validation and publishing, plus a weekly link check. It does not currently include an automated news collector. A person or external producer prepares the JSON; [CONTRIBUTING.md](CONTRIBUTING.md) defines that contract. A link responding successfully does not by itself verify a claim.

## Develop and publish an edition

Use Python 3.12 or later.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python scripts/build_site.py --write-generated
```

The normal build, `python scripts/build_site.py`, only writes `_site/`. Use `--write-generated` when you want to refresh the committed digest Markdown and the marked README block. Do not hand-edit those generated views.

GitHub Actions tests pull requests and builds the site. Merges to `main` deploy to GitHub Pages after **Settings → Pages → Build and deployment → Source: GitHub Actions** is enabled. The workflow pins its actions and keeps deployment permissions out of the build job.

## Data and feeds

Schema version 2 is defined in [data/schema.json](data/schema.json). It separates exploitation reports, KEV membership, urgency, action type, and fixed releases by component, platform, branch, and CVE. A missing value means unknown, not safe. Source checks and score dates remain visible, including missing historical check times.

Published endpoints:

| Endpoint | Contents |
| --- | --- |
| `/latest.json` and `/data/latest.json` | Newest edition |
| `/data/YYYY-MM-DD.json` | A specific edition |
| `/data/schema.json` | JSON Schema for consumers |
| `/feed.xml` | All items, as Atom |
| `/feeds/everyone.xml` | End-user and shared items, as Atom |
| `/feeds/operators.xml` | Application/server and shared items, as Atom |

Corrections retain stable edition IDs and advance `updated_at`, including in feeds. Schema version 2 changes the original version 1 field shapes; consumers should check `schema_version` before reading an edition.

## Scope and licenses

Curated, not complete. Unofficial. Not professional advice. Not affiliated with CISA, FIRST, or any vendor. Verify actions against the vendor advisory. EPSS is a probability, not a certainty.

Writing and editorial data are [CC BY 4.0](LICENSE). Software in `scripts/`, `assets/`, `tests/`, and workflow/configuration code is [MIT licensed](LICENSE-CODE). Attribute patch-these and link the edition when reusing its writing or data.
