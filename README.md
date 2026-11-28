# patch-these

A plain-English security briefing, updated every 4 hours from 6 AM to 10 PM Pacific. It looks for new issues on X, Bluesky and Mastodon, publishes unconfirmed leads as early signals, and recommends patches only after a vendor advisory, CISA KEV, NVD, or another primary source confirms them. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 28 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-28.md) · [Structured data](data/2026-11-28.json)

Coverage: 27–28 November 2026. Updated: 28 Nov 2026 · 9:58 AM PST.

### Early signals: not yet verified

- **Not yet verified. [Laravel framework (TokenGuard API token auth)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-laravel-tokenguard):** Check whether your Laravel apps use the TokenGuard api\_token driver on MySQL or MariaDB, and watch for Laravel's advisory and fixed release. Source: [Discussed on X](https://x.com/mehmetalpersen/status/2126692224817643554) · [Discussed on X](https://x.com/zoomeyebot/status/2126688930208834042).
- **Not yet verified. [Git (clone --recurse-submodules)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-git-recurse-submodules):** Check which Git versions are installed on your machines (there may be more than one), avoid recursive clones of untrusted repositories, and watch for the Git project's security release notes. Source: [Discussed on X](https://x.com/devtoollab/status/2126729010784977162) · [CISA KEV catalog feed, dateReleased 2026-11-27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **Not yet verified. [Apple macOS (authd)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-macos-authd):** Check that your Macs are on the latest macOS update and look for CVE-2026-112430 in Apple's security release notes. Source: [Discussed on X](https://x.com/right2bear/status/2126722035921428710) · [CISA KEV catalog feed, dateReleased 2026-11-27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **Not yet verified. [Fortinet FortiOS](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-fortinet-fortios-126259):** Check whether you run FortiOS devices with management interfaces reachable from the internet, and watch Fortinet's PSIRT page for an advisory on CVE-2026-126259. Source: [Discussed on X](https://x.com/ToolsWatch/status/2126735959261958446) · [CISA KEV catalog feed, dateReleased 2026-11-27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **Not yet verified. [Traefik proxy](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-traefik-137481):** Check whether your Traefik deployments put auth middleware in front of Java or Spring backends, and watch Traefik's GitHub security advisories. Source: [Discussed on X](https://x.com/BeaconLabMX/status/2126719495959978465) · [CISA KEV catalog feed, dateReleased 2026-11-27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **Not yet verified. [Budibase (@budibase/server)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-budibase-server):** Check whether your Budibase apps expose MongoDB queries with PUBLIC execution permission, and watch Budibase's GitHub security advisories. Source: [Discussed on X](https://x.com/SamAiPr/status/2126730212909920459) · [Discussed on X](https://x.com/SamAiPr/status/2126729706284491082).
- **Not yet verified. [Android (zero-click flaw)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-android-58882):** Check that your Android phones show a recent security patch level, and look for CVE-2026-58882 in Google's Android Security Bulletin. Source: [Discussed on Bluesky](https://bsky.app/profile/iheuktech.bsky.social/post/3n3f5adihaa24) · [CISA KEV catalog feed, dateReleased 2026-11-27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).

### For everyone

No items for this audience in this edition.

### For app and server owners

- **[React Server Components and Next.js](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-react-server-components) — Act soon / Update:** Upgrade the react-server-dom packages to 19.0.9, 19.1.10, 19.2.9 or 19.3.1 or later in your line, and Next.js 16 apps to 16.4.1 or later (16.4.6 is the current release).
- **[PHP (PHP-FPM)](https://jluethe.github.io/patch-these/digests/2026-11-28/#item-php-fpm) — Act soon / Update:** Upgrade PHP to 8.2.36, 8.3.37, 8.4.28 or 8.5.13 or later and restart PHP-FPM.

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

The shared social preview is authored in `assets/social-card.svg`. After editing it, regenerate the PNG with `rsvg-convert assets/social-card.svg -o assets/social-card.png` (librsvg), and bump the image URL version in `scripts/patchthese/rendering.py` so future shares request the new image.

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
