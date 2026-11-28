# patch-these

A plain-English security briefing, updated every 4 hours from 6 AM to 10 PM Pacific. It looks for new issues on X, Bluesky and Mastodon, publishes unconfirmed leads as early signals, and recommends patches only after a vendor advisory, CISA KEV, NVD, or another primary source confirms them. No exploit details.

Maintained by [John Luethe](https://github.com/JLuethe).

Read by audience, search for a product or CVE, or save the products you follow in your browser. Urgency and action are separate: an exploited product without a patch can still require immediate mitigation or replacement.

**[Website](https://jluethe.github.io/patch-these/)** · **[Choose an Atom feed](https://jluethe.github.io/patch-these/subscribe/)** · **[Latest JSON](https://jluethe.github.io/patch-these/latest.json)** · **[Methodology](METHODOLOGY.md)**

<!-- BEGIN GENERATED EDITION -->
## Latest edition — 27 November 2026

[Read the briefing](https://jluethe.github.io/patch-these/) · [Full Markdown digest](digests/2026-11-27.md) · [Structured data](data/2026-11-27.json)

Coverage: 27 November 2026. Updated: 27 Nov 2026 · 10:02 PM PST.

### Early signals: not yet verified

- **Not yet verified. [Oracle E-Business Suite](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-oracle-ebs):** Check whether your Oracle E-Business Suite systems have the October 2026 Critical Patch Update applied, and review them for signs of compromise while the exploitation report is confirmed. Source: [Discussed on Bluesky](https://bsky.app/profile/getpokemon7.bsky.social/post/3n3drvn2yac2s) · [Discussed on Bluesky](https://bsky.app/profile/getpokemon7.bsky.social/post/3n3dvxep6qk2s).
- **Not yet verified. [llama.cpp (ggml RPC server)](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-llama-cpp-rpc):** Check whether you run the llama.cpp RPC server (rpc-server) and on which build, and keep it off untrusted networks while you confirm the fixed build with the llama.cpp project. Source: [Discussed on X](https://x.com/tokendudu/status/2126541596724457728) · [Discussed on X](https://x.com/ll685998568638/status/2126552424618094726).
- **Not yet verified. [Synology DiskStation Manager (DSM)](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-synology-dsm):** Check the DSM version on your Synology NAS devices and look for a DSM update in Control Panel; confirm the fixed versions in Synology advisory Synology\_SA\_26\_21. Source: [Discussed on X](https://x.com/Teeeda_worker/status/2126541729423843534) · [NVD record CVE-2026-120382](https://nvd.nist.gov/vuln/detail/CVE-2026-120382).
- **Not yet verified. [AnsibleForms](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-ansibleforms):** Check whether you run AnsibleForms, especially where it is reachable from the internet; read the project's release notes and security advisory before choosing a version. Source: [Discussed on Bluesky](https://bsky.app/profile/eventmonitor.bsky.social/post/3n3fp3p5q5uym) · [Discussed on X](https://x.com/cvedotnow/status/2126411338851221709).
- **Not yet verified. [vm2](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-vm2-nodevm):** Check whether your applications use vm2's NodeVM to run untrusted code; watch the vm2 GitHub advisories for a fix and limit the built-in modules the sandbox can load. Source: [Discussed on X](https://x.com/HugoValters/status/2126386070720053389) · [Discussed on Bluesky](https://bsky.app/profile/hugovalters.bsky.social/post/3n3cu5qdas32s).
- **Not yet verified. [Exim](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-exim):** Check whether you run Exim mail servers; watch the Exim project and your Linux distribution for a security advisory. Source: [Discussed on Bluesky](https://bsky.app/profile/pingoru.bsky.social/post/3n3d3v5b3fz2w) · [CISA KEV catalog feed, catalogVersion 2026.11.27](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
- **Not yet verified. [POSTAL 2 (Steam Workshop mods)](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-postal-2):** If you play POSTAL 2, let Steam update the game and avoid installing Workshop mods from unknown authors until the fix is confirmed. Source: [Discussed on Bluesky](https://bsky.app/profile/offseq.bsky.social/post/3n3dpksgukr2p) · [Discussed on X](https://x.com/cvedotnew/status/2126515491082830040).
- **Not yet verified. [Linux kernel](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-linux-kernel-tcpanic):** Check your Linux distribution's security tracker for CVE-2026-99288 and plan the kernel update it names for internet-facing servers. Source: [Discussed on X](https://x.com/hakunoba/status/2126483755011555466) · [Discussed on X](https://x.com/v4bel/status/2126483558567166118).
- **Not yet verified. [U.S. Air Force Cloud One](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-us-air-force-cloud-one):** Check whether your organization runs workloads on or connects to Air Force Cloud One; watch for an official Air Force statement or customer notice. Source: [Discussed on X](https://x.com/IndiaToday/status/2126373146920091741) · [Discussed on X](https://x.com/LeadingReport/status/2126373767211532675).

### For everyone

- **[NoMachine Personal Edition for Windows](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-nomachine-personal-windows) — Act now / Mitigate:** If you downloaded and ran the NoMachine Personal Edition for Windows installer between 19 November 13:43 UTC and 20 November 10:00 UTC, treat that computer as fully exposed and follow NoMachine's steps, with reinstalling Windows as the safest fix.
- **[RealVNC Viewer, Server, Connect, Classic Viewer and On-Demand Assist](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-realvnc) — Act soon / Update:** Update RealVNC Viewer and the Connect app to 8.6.2 or later, Server to 7.19.1 or later, Classic Viewer to 7.18.3 or later, and On-Demand Assist to 3.5.0 or later; check that mobile Viewer and Server apps have updated (Viewer 4.9.6, Server iOS 2.8.2, Server Android 2.8.4 or later).

### For app and server owners

- **[Apache Roller](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-apache-roller) — Act now / Update:** Upgrade Apache Roller to 6.1.6 or later (6.1.7 is the current release). If you can't upgrade right away, apply Apache's interim mitigation below and restart Roller.
- **[NoMachine Personal Edition for Windows](https://jluethe.github.io/patch-these/digests/2026-11-27/#item-nomachine-personal-windows) — Act now / Mitigate:** If you downloaded and ran the NoMachine Personal Edition for Windows installer between 19 November 13:43 UTC and 20 November 10:00 UTC, treat that computer as fully exposed and follow NoMachine's steps, with reinstalling Windows as the safest fix.
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
