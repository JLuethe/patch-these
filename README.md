# patch-these

A daily, plain-English briefing of security issues raised on X, Bluesky and Mastodon, checked against vendor advisories, CISA KEV and EPSS, and turned into what to patch. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 25 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-25.md) · [Structured data](data/2026-11-25.json)

Coverage: 23–25 November 2026. Updated: 25 Nov 2026 · 11:21 PM PST.

### For everyone

- **[Google Chrome](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-chrome-desktop) — Act now / Update:** Update Chrome to 158.0.8127.88 on Linux, or 158.0.8127.88 or 158.0.8127.89 on Windows and macOS. Check the separate vendor advisories and update channels for applications that embed Chromium.
- **[Java SE / OpenJDK](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-java-se) — Act now / Update:** Inventory JDKs and runtimes, including those bundled in apps and containers. Update to the fixed OpenJDK builds (8u514, 11.0.33.1, 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1) or apply the Oracle November 2026 Critical Security Patch Update, prioritizing internet-facing systems. Exact Oracle patch build strings beyond the affected versions were not extracted. If you cannot patch immediately, CISA recommends restricting and validating Base64 input, enforcing input-size limits, and limiting unauthenticated access. Red Hat points to bulletin RHSB-2026-018 for a detailed mitigation procedure. The Red Hat CVE page does not list the JVM flag.
- **[Firefox and Thunderbird](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-firefox-thunderbird) — Act soon / Update:** Update to Firefox 161, Firefox ESR 153.8, or Firefox ESR 115.46. Update to Thunderbird 161 or Thunderbird 153.8.
- **[Omarchy dell-xps-touchpad-haptics](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-omarchy-dell-xps-touchpad-haptics) — Act soon / Update:** Update to 1.0.0-4.

### For app and server owners

- **[Google Chrome](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-chrome-desktop) — Act now / Update:** Update Chrome to 158.0.8127.88 on Linux, or 158.0.8127.88 or 158.0.8127.89 on Windows and macOS. Check the separate vendor advisories and update channels for applications that embed Chromium.
- **[Drupal core](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-drupal-core) — Act now / Update:** Update to 10.6.23, 11.3.23, or 11.4.14, then run update.php (an update hook must run). Lock down /core/install.php and keep settings.php unwritable. Check logs for unauthorized access, especially unexpected use of user 1, and confirm user 1's email. End-of-life lines have no fix.
- **[VMware vCenter](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-vmware-vcenter) — Act now / Update:** Apply the cumulative update for your supported branch: vCenter 9.1.2, 9.0.2.0300, or 8.0 U3m; use VCF 5.2.5 for the affected Cloud Foundation branch. Follow the applicable Broadcom response matrix and keep management access restricted.
- **[GeoServer](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-geoserver) — Act now / Update:** Update to 3.0.2, 2.28.6, or 2.27.7.
- **[Juniper Session Smart](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-juniper-session-smart) — Act now / Update:** Update to 7.0.5, 7.1.7, or 7.2.3.
- **[MONAI Label](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-monai-label) — Act now / Update:** Update to 0.8.6. Enable authentication until you do.
- **[N-able Mail Assure / SpamExperts](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-nable-mail-assure) — Act now / Update:** Update to 20261121.1943.
- **[Azure API Management Classic](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-azure-api-management-classic) — Act now / Rotate credentials:** For affected Classic instances, rotate tokens and secrets, review access logs and the data behind the gateway, and verify the service update using NSM guidance. Contact the provider if the instance is not updated.
- **[Bytebase DBHub MCP](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-bytebase-dbhub-mcp) — Act now / Mitigate:** Restrict network access to trusted clients and keep the affected service off untrusted networks while tracking the vendor remediation.
- **[Idunno.AntiCsrf](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-idunno-anticsrf) — Act now / Replace:** Replace Idunno.AntiCsrf with a supported anti-CSRF mechanism and investigate exposed applications for compromise. Follow Mandiant guidance when removing the component so request-forgery protection is retained.
- **[Optimizely Web Experimentation](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-optimizely-web-experimentation) — Act now / Check applicability:** If you do not use Web Experimentation, Optimizely says no action is required. If you do, treat 07:51–22:24 UTC on 16 November 2026 as the exposure window and follow the customer report: confirm whether Optimizely told you the account was affected, review site activity where the snippet ran on payment or cryptocurrency pages, and keep a strong Content Security Policy. Optimizely has withdrawn the earlier guidance to leave the snippet disabled. This correction read the shortened 20 November report, not the full customer-portal version, and it has no customer-installable fix version.
- **[Mitel MiCollab](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-mitel-micollab) — Act now / Update:** Upgrade to MiCollab 10.3 (10.3.0.18) and apply the patch Mitel provides for that release, or upgrade to a later release. Until then, restrict external access to the Audio, Web and Video Conferencing component. Mitel points to Knowledge Base article KB000129195 for patch steps; this correction did not open that article, so the patch build number is unknown here.
- **[Danfoss AK-SM 800A](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-danfoss-ak-sm-800a) — Act now / Update:** Install software 3.3 for the 2023 advisory and 4.2 for CVE-2025-41450. Danfoss lists no workaround in either advisory. Do not assume that moving only to 4.2 also covers the 3.3 fixes; the advisories do not say that.
- **[Xen Orchestra](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-xen-orchestra) — Act now / Update:** Update to Xen Orchestra 6.9.2 on the stable channel or 6.10.1 on the latest channel (xo-server 5.211.2 or 5.213.1). Do not expose Xen Orchestra to the internet. If compromise is suspected, follow the vendor advisory for recovery, including secret rotation. This briefing does not repeat attacker infrastructure or detection patterns from that advisory.
- **[Linux kernel NFS server (nfsd)](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-linux-nfsd) — Act now / Update:** Install a kernel that includes the fix (the upstream versions above, or a distribution kernel that names this CVE) and reboot. If a vendor kernel is not yet available, Red Hat's mitigation is to stop or disable nfs-server if it is not needed, or restrict port 2049 to trusted networks.
- **[Hex.pm](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-hex-pm) — Act now / Rotate credentials:** Change the hex.pm password and reset 2FA at hex.pm/dashboard/security: set up a new authenticator app and store new recovery codes. Until a new Hex client with a rotated registry signing system ships, fetch packages only from repo.hex.pm, not third-party mirrors. Treat unexpected email claiming to be from Hex with care. Operators of self-hosted hexpm must update to the 23 November build.
- **[Java SE / OpenJDK](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-java-se) — Act now / Update:** Inventory JDKs and runtimes, including those bundled in apps and containers. Update to the fixed OpenJDK builds (8u514, 11.0.33.1, 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1) or apply the Oracle November 2026 Critical Security Patch Update, prioritizing internet-facing systems. Exact Oracle patch build strings beyond the affected versions were not extracted. If you cannot patch immediately, CISA recommends restricting and validating Base64 input, enforcing input-size limits, and limiting unauthenticated access. Red Hat points to bulletin RHSB-2026-018 for a detailed mitigation procedure. The Red Hat CVE page does not list the JVM flag.
- **[WP connect WordPress plugins](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-wp-connect-plugins) — Act now / Replace:** Uninstall the affected plugin versions and run a full site scan. If indicators from the CVE record are present (the module includes/airwp-online.php, traffic to tascredit-pay.com, unexpected WP-Cron hooks, or new PHP files under uploads), treat the site as compromised and rotate credentials and API keys. Do not wait for a vendor update.
- **[Cisco Expressway Series](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-cisco-expressway) — Act now / Update:** Upgrade clustered Expressway-C and Expressway-E to X15.5.20 or later. X14 and earlier must migrate to a fixed release; Cisco does not name a specific X14 patch here.
- **[simple-git](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-simple-git) — Act soon / Update:** Update to simple-git 4.1.0 and @simple-git/argv-parser 3.0.0. Do not pass untrusted input to listRemote() or raw().
- **[Jenkins plugins](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-jenkins-plugins) — Act soon / Update:** Update Pipeline: Groovy to 4403.4405.va\_b\_cdb\_b\_d0b\_89f and Script Security to 1436.1438.v3dc5ef7d16f2, and update the other affected plugins named in the advisory.
- **[Artifex Ghostscript](https://jluethe.github.io/patch-these/digests/2026-11-25/#item-ghostscript) — Act soon / Update:** Update Ghostscript to 10.08.0 or a distribution package that fixes CVE-2026-125396, including copies bundled in document-conversion, preview, and print services. Until then, avoid passing untrusted PostScript, EPS, or PDF to Ghostscript. Sophos notes that -dSAFER alone does not protect against this issue.

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
