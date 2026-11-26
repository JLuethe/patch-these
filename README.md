# patch-these

A daily, plain-English briefing of security issues raised on X, Bluesky and Mastodon, checked against vendor advisories, CISA KEV and EPSS, and turned into what to patch. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 26 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-26.md) · [Structured data](data/2026-11-26.json)

Coverage: 25–26 November 2026. Updated: 26 Nov 2026 · 7:12 AM PST.

### For everyone

- **[Microsoft Office Visio](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-microsoft-visio) — Act soon / Update:** Install Office LTSC 2024 build 16.0.17932.21140 or Office LTSC 2021 build 16.0.14334.21048. For Microsoft 365 Apps for Enterprise, install the build listed at https://aka.ms/OfficeSecurityReleases. That build was not listed in the MSRC API.
- **[1Password](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-1password) — Monitor / Mitigate:** No account change is needed, per 1Password. Be wary of unexpected 1Password email, including invitations or recovery requests you did not start.

### For app and server owners

- **[F5 NGINX Open Source and NGINX Plus](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-nginx-http2) — Act now / Update:** Upgrade NGINX Open Source to 1.30.7 (stable) or 1.31.9 (mainline), and NGINX Plus to 37.0.8.1 or 37.3.0.1. Also update ingress controllers and container images that bundle NGINX. For NGINX Plus R34, R35, and R36, see F5 article K000163926. That page did not render, so no fixed version was verified for those releases.
- **[Airbyte Core](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-airbyte-core-images) — Act now / Update:** Upgrade Airbyte Core platform images (server, worker, bootloader, cron, connector-sidecar, container-orchestrator, workload-api-server, workload-init-container, and workload-launcher) to 2.6.0. Replace connector images with source-postgres 3.8.13, destination-postgres 3.0.26, destination-redshift 4.0.14, destination-bigquery 3.2.4, source-facebook-marketing 6.1.13, source-mssql 5.1.6, source-mysql 3.53.11, destination-snowflake 5.2.3, and source-google-sheets 0.13.3, including copies in private registries. If a tampered image ran, rotate the credentials in the source and destination systems themselves and review their activity logs for the exposure window.
- **[Check Point Security Management](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-checkpoint-security-management) — Act now / Mitigate:** Apply the fix and hardening in Check Point sk185169 (per sk185169; the hotfix build was not verified) and restrict Trusted Clients and management access to trusted IP addresses. Investigate exposed management servers for compromise.
- **[VirtueMart](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-virtuemart) — Act now / Update:** Upgrade VirtueMart to 4.8.10. Release 4.8.8 fixed CVE-2026-133335; 4.8.10 also fixes an issue that lets someone fake a paid order. VirtueMart offers a hotfix for 4.0 and later; this edition does not name that hotfix build.
- **[WP Rocket](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-wp-rocket) — Act now / Update:** Update WP Rocket to 3.24.2.
- **[HPE AirWave](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-hpe-airwave) — Act soon / Update:** Update HPE AirWave to 8.3.0.8 or later.
- **[Jenkins plugins](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-jenkins-plugins) — Act soon / Update:** Update Script Security to 1436.1438.v3dc5ef7d16f2 and Pipeline: Groovy to 4403.4405.va\_b\_cdb\_b\_d0b\_89f, and update the other affected plugins named in the 2026-11-25 advisory.
- **[vm2](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-vm2) — Monitor / Mitigate:** Do not allowlist the crypto builtin for untrusted code. A fixed vm2 release was not established in the sources read for this edition.
- **[PyJWT](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-pyjwt) — Monitor / Update:** Update PyJWT to 2.14.0 where the application accepts both HMAC and asymmetric algorithms. This edition does not establish a fixed release for Red Hat Ansible Automation Platform.

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
