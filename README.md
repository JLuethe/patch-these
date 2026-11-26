# patch-these

A daily, plain-English briefing of security issues raised on X, Bluesky and Mastodon, checked against vendor advisories, CISA KEV and EPSS, and turned into what to patch. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 26 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-26.md) · [Structured data](data/2026-11-26.json)

Coverage: 25–26 November 2026. Updated: 26 Nov 2026 · 8:00 AM PST.

### For everyone

- **[Microsoft Office Visio](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-microsoft-visio) — Act soon / Update:** Install Office LTSC 2024 build 16.0.17932.21140 or a later build on that branch, or Office LTSC 2021 build 16.0.14334.21048 or a later build on that branch. For Microsoft 365 Apps for Enterprise, install the build listed at https://aka.ms/OfficeSecurityReleases.
- **[1Password](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-1password) — Act soon / Mitigate:** You do not need to update anything in your 1Password account. Be cautious about phishing attempts in the form of unexpected emails, texts, or calls that mention 1Password, invitations, or account recovery. 1Password will never ask for your account password or Secret Key. Only enter them in the official 1Password app or on the official website, and only when you opened the app or typed the address yourself. The Secret Key is only needed the first time you sign in on a new device or browser. Keep your Secret Key and account password safe. If you see something suspicious, tell 1Password at support@1password.com.

### For app and server owners

- **[F5 NGINX Open Source and NGINX Plus](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-nginx-http2) — Act now / Update:** Upgrade NGINX Open Source to 1.30.8 or later on the stable branch, or to 1.31.10 or later on the mainline branch. Also update ingress controllers and container images that bundle NGINX. For NGINX Plus, install the fixed release F5 names for your branch in article K000163926.
- **[Airbyte Core](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-airbyte-core-images) — Act now / Update:** Upgrade to 2.6.0 or later and rotate environment variables that were made available to the platform. Upgrade each affected connector to its replacement tag or any later one: source-postgres 3.8.13 or later, destination-postgres 3.0.26 or later, destination-redshift 4.0.14 or later, destination-bigquery 3.2.4 or later, source-facebook-marketing 6.1.13 or later, source-mssql 5.1.6 or later, source-mysql 3.53.11 or later, destination-snowflake 5.2.3 or later, and source-google-sheets 0.13.3 or later. In the Airbyte UI, click Workspace settings, click Sources or Destinations, click the pencil icon on the affected connector, enter the safe image version or its digest, and click Submit. If you mirror images in your own registry and the tampered version is there, replace it immediately: authenticate to your registry, pull the safe tag, retag it into your registry while keeping the airbyte/&lt;name&gt;:&lt;tag&gt; path, and push it. Rotate the credentials the connector used in the source or destination itself, then enter the new credentials in Airbyte. Review activity in those tools from the first sync on the tampered image until you rotated: sign-ins, queries, and data changes. If you find a match, email security@airbyte.io.
- **[Check Point Security Management](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-checkpoint-security-management) — Act now / Update:** Install the Jumbo Hotfix Accumulator for R82.10 starting from Take 36 or later, for R82 starting from Take 118 or later, and for R81.20 starting from Take 158 or later. Follow the security hardening steps in sk185169: use the security hardening guide, limit Trusted Clients so the type is not Any, and restrict management access and implied rules to trusted addresses. Investigate exposed management servers for compromise.
- **[VirtueMart](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-virtuemart) — Act now / Update:** Upgrade VirtueMart to 4.8.10 or later. Release 4.8.8 fixed CVE-2026-133335; 4.8.10 also fixes an issue that lets someone fake a paid order.
- **[WP Rocket](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-wp-rocket) — Act now / Update:** Update WP Rocket to 3.24.2 or later.
- **[HPE AirWave](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-hpe-airwave) — Act soon / Update:** Update HPE AirWave to 8.3.0.8 or later.
- **[Jenkins plugins](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-jenkins-plugins) — Act soon / Update:** Update Script Security to 1436.1438.v3dc5ef7d16f2 or a later release, and Pipeline: Groovy to 4403.4405.va\_b\_cdb\_b\_d0b\_89f or a later release, and update the other affected plugins named in the 2026-11-25 advisory.
- **[vm2](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-vm2) — Monitor / Update:** Update vm2 to 3.12.1 or later. Do not allowlist the crypto builtin for untrusted code.
- **[PyJWT](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-pyjwt) — Monitor / Update:** Update PyJWT to 2.14.0 or later where the application accepts both HMAC and asymmetric algorithms.

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
