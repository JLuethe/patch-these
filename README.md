# patch-these

A plain-English security briefing, updated every 4 hours from 6 AM to 10 PM Pacific. It looks for new issues on X, Bluesky and Mastodon, publishes unconfirmed leads as early signals, and recommends patches only after a vendor advisory, CISA KEV, NVD, or another primary source confirms them. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 27 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-27.md) · [Structured data](data/2026-11-27.json)

Coverage: 27 November 2026. Updated: 27 Nov 2026 · 9:57 AM PST.

### Early signals: not yet verified

- **Not yet verified. [U.S. Air Force Cloud One](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-us-air-force-cloud-one):** Check whether your organization runs workloads on or connects to Air Force Cloud One; watch for an official Air Force statement or customer notice. Source: [Discussed on X](https://x.com/IndiaToday/status/2126373146920091741) · [Discussed on X](https://x.com/LeadingReport/status/2126373767211532675).

### For everyone

- **[RealVNC Viewer, Server, Connect, Classic Viewer and On-Demand Assist](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-realvnc) — Act soon / Update:** Update RealVNC Viewer and the Connect app to 8.6.2 or later, Server to 7.19.1 or later, Classic Viewer to 7.18.3 or later, and On-Demand Assist to 3.5.0 or later; check that mobile Viewer and Server apps have updated (Viewer 4.9.6, Server iOS 2.8.2, Server Android 2.8.4 or later).

### For app and server owners

- **[Apache Roller](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-apache-roller) — Act now / Update:** Upgrade Apache Roller to 6.1.6 or later (6.1.7 is the current release). If you can't upgrade right away, apply Apache's interim mitigation below and restart Roller.
- **[RealVNC Viewer, Server, Connect, Classic Viewer and On-Demand Assist](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-realvnc) — Act soon / Update:** Update RealVNC Viewer and the Connect app to 8.6.2 or later, Server to 7.19.1 or later, Classic Viewer to 7.18.3 or later, and On-Demand Assist to 3.5.0 or later; check that mobile Viewer and Server apps have updated (Viewer 4.9.6, Server iOS 2.8.2, Server Android 2.8.4 or later).
- **[F5 BIG-IP and BIG-IQ (iControl SOAP)](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-f5-big-ip-icontrol-soap) — Act soon / Update:** Update BIG-IP to 21.1.0.3, 17.5.1.10 or 17.1.3.6 or later on your branch, and BIG-IQ to 8.4.2.3 or later. Until then, remove iControl SOAP access for users who are not fully trusted and restrict iControl SOAP to trusted networks.

<!-- END GENERATED EDITION -->

## How publication works

Each edition has one editable source: `data/YYYY-MM-DD.json`. JSON Schema and semantic validation check dates, evidence references, CVEs, priorities, and the relationship between fixes and vulnerabilities. The builder generates HTML, Markdown, the README edition block, structured downloads, and three Atom feeds from those same records.

The site is plain static HTML, CSS, and a small local script for optional filters. All briefing content and source links work without JavaScript. Saved products stay in the reader's browser; there are no accounts, analytics, or installation scans.

Editions are updated in place through the day, at 6 AM, 10 AM, 2 PM, 6 PM and 10 PM Pacific, with a corrections log. Official sources arrive through a feed cache refreshed about every 30 minutes. A person still prepares the edition JSON; [CONTRIBUTING.md](CONTRIBUTING.md) defines that contract. The repository provides validation and publishing, plus a weekly link check. A link responding successfully does not by itself verify a claim.

## Develop and publish an edition

Use Python 3.12 or later.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/build_site.py --write-generated
python -m pytest
python scripts/build_site.py --check
python scripts/check_links.py --report _reports/link-check.json
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
