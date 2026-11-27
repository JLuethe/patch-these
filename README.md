# patch-these

A plain-English security briefing, updated every 4 hours from 6 AM to 10 PM Pacific. It looks for new issues on X, Bluesky and Mastodon, publishes unconfirmed leads as early signals, and recommends patches only after a vendor advisory, CISA KEV, NVD, or another primary source confirms them. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 26 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-26.md) · [Structured data](data/2026-11-26.json)

Coverage: 25–26 November 2026. Updated: 26 Nov 2026 · 10:08 PM PST.

### Early signals: not yet verified

- **Not yet verified. [Cacti](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-cacti-core):** Check whether you run Cacti and whether guest access is enabled and reachable; watch for an advisory from the Cacti project. Source: [SecurityOnline report on the researcher's disclosure](https://securityonline.info/cacti-zero-day-rce-4http2root-poc/) · [Discussed on Bluesky](https://bsky.app/profile/securityonline.bsky.social/post/3n3amexvv6v2x).
- **Not yet verified. [Linux kernel NFS server (nfsd)](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-linux-kernel-nfsd):** Check whether any of your Linux systems run the kernel NFS server and whether port 2049 is reachable from untrusted networks; watch for kernel and distribution advisories. Source: [Discussed on Bluesky](https://bsky.app/profile/greptipsfeed.bsky.social/post/3n3awpawcqc2t) · [Discussed on Bluesky](https://bsky.app/profile/did:plc:wjohl6xdbk2az53ufpxzuujd/post/3n3awjc4dp22s).
- **Not yet verified. Single source. [Rackspace Spot](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-rackspace-spot):** Check whether you run workloads on Rackspace Spot; watch for Rackspace's customer notice on the breach and the shutdown date. Source: [Discussed on X](https://x.com/rtehrani/status/2125993016066253088).
- **Not yet verified. Single source. [USA TODAY Co. subscriber accounts](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-usa-today-subscribers):** If you have a USA TODAY or affiliated newspaper subscription, be wary of phishing that mentions your subscription; watch for a notice from the publisher. Source: [Discussed on X](https://x.com/zubiqo/status/2126068935523250494).
- **Not yet verified. [Zodia Custody](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-zodia-custody):** If your organization is a Zodia Custody client, check for a notice from Zodia and watch for targeted phishing using your contacts' names. Source: [Discussed on X](https://x.com/infinitimarkets/status/2126069765341069781) · [Discussed on X (service restored)](https://x.com/infinitimarkets/status/2126069780621008953).
- **Not yet verified. [SAP (GitHub development platform)](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-sap-github):** If you run SAP software or use SAP's open-source projects, watch for SAP guidance on affected repositories, builds or code-signing keys before trusting new SAP-signed packages. Source: [Handelsblatt report quoting SAP's statement (German)](https://www.handelsblatt.com/technik/ki/sap-it-sicherheitsvorfall-bei-sap-haben-verdaechtige-aktivitaeten-identifiziert/100273138.html) · [Cybersecurity News report](https://cybersecuritynews.com/sap-security-incident/).

### For everyone

- **[Microsoft Office Visio](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-microsoft-visio) — Act soon / Update:** Install Office LTSC 2024 build 16.0.17932.21140 or a later build on that branch, or Office LTSC 2021 build 16.0.14334.21048 or a later build on that branch. For Microsoft 365 Apps for Enterprise, install the build listed at https://aka.ms/OfficeSecurityReleases.
- **[1Password](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-1password) — Act soon / Mitigate:** You do not need to update anything in your 1Password account. Be cautious about phishing attempts in the form of unexpected emails, texts, or calls that mention 1Password, invitations, or account recovery. 1Password will never ask for your account password or Secret Key. Only enter them in the official 1Password app or on the official website, and only when you opened the app or typed the address yourself. The Secret Key is only needed the first time you sign in on a new device or browser. Keep your Secret Key and account password safe. If you see something suspicious, tell 1Password at support@1password.com.
- **[Todoist](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-todoist) — Act soon / Rotate credentials:** Follow the instructions in the email Todoist sent you; if you did not receive one, Todoist says there is nothing to do. Todoist's notification comes from no-reply@notify.todoist.com; watch for fake emails.
- **[Flight Centre Travel Group (Travel Associates, Cruiseabout)](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-flight-centre-booking-system) — Act soon / Mitigate:** If you booked accommodation through Flight Centre, Travel Associates or Cruiseabout, be alert to unexpected emails, calls or messages about your bookings, and don't click links, open attachments or share personal information, passwords or payment details in response.
- **[EasyEquities](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-easyequities) — Act soon / Mitigate:** If you have an EasyEquities account, treat any unexpected call, email, SMS or WhatsApp asking for personal or banking details with caution even if it seems to come from EasyEquities, and never share your password or one-time PIN.

### For app and server owners

- **[F5 NGINX Open Source and NGINX Plus](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-nginx-http2) — Act now / Update:** Upgrade NGINX Open Source to 1.30.8 or later on the stable branch, or to 1.31.10 or later on the mainline branch. Also update ingress controllers and container images that bundle NGINX. For NGINX Plus, install the fixed release F5 names for your branch in article K000163926.
- **[Airbyte Core](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-airbyte-core-images) — Act now / Update:** Upgrade to 2.6.0 or later and rotate environment variables that were made available to the platform.
- **[Check Point Security Management](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-checkpoint-security-management) — Act now / Update:** Install the Jumbo Hotfix Accumulator for R82.10 starting from Take 36 or later, for R82 starting from Take 118 or later, and for R81.20 starting from Take 158 or later.
- **[VirtueMart](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-virtuemart) — Act now / Update:** Upgrade VirtueMart to 4.8.10 or later. Release 4.8.8 fixed CVE-2026-133335; 4.8.10 also fixes an issue that lets someone fake a paid order.
- **[WP Rocket](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-wp-rocket) — Act now / Update:** Update WP Rocket to 3.24.2 or later.
- **[Palo Alto Networks PAN-OS](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-paloalto-panos) — Act now / Update:** Follow Palo Alto Networks' guidance for your setup.
- **[HPE AirWave](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-hpe-airwave) — Act soon / Update:** Update HPE AirWave to 8.3.0.8 or later.
- **[Jenkins plugins](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-jenkins-plugins) — Act soon / Update:** Update Script Security to 1436.1438.v3dc5ef7d16f2 or a later release, and Pipeline: Groovy to 4403.4405.va\_b\_cdb\_b\_d0b\_89f or a later release, and update the other affected plugins named in the 2026-11-25 advisory.
- **[Canonical LXD](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-canonical-lxd) — Act soon / Update:** Update LXD to 5.0.12, 5.21.10 or 6.10.2 or later on your release line, prioritizing servers with OIDC login enabled.
- **[Mitel OpenScape 4000 and OpenScape 4000 Manager](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-mitel-openscape-4000) — Act soon / Update:** Upgrade OpenScape 4000 and OpenScape 4000 Manager to V11 R2.14 or later; on V11 R1.26 apply PLT HF5, and on V10 R0.28 to V11 R0.22 (Manager: V10 R1.34 to V11 R0.22) apply Mitel's patch.
- **[vm2](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-vm2) — Monitor / Update:** Update vm2 to 3.12.1 or later. Do not allowlist the crypto builtin for untrusted code.
- **[PyJWT](https://jluethe.github.io/patch-these/digests/2026-11-26/#item-pyjwt) — Monitor / Update:** Update PyJWT to 2.14.0 or later where the application accepts both HMAC and asymmetric algorithms.

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
