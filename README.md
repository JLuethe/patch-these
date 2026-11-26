# patch-these

Issues raised on X, verified, and turned into patch these: a calm, plain-English daily briefing of what to update.

## Patch these — 25 November 2026

[Full digest for 25 November 2026](digests/2026-11-25.md)

### For app and server owners

#### Patch now

- **Chrome, including Electron apps that ship their own copy.** Install Chrome 158.0.8127.88 on Linux, or 158.0.8127.88 or 158.0.8127.89 on Windows and Mac. CVE-2026-134401, a sandbox escape via a crafted page, is not known to be exploited. The update also covers exploited CVE-2026-125350, which was fixed in 157.0.8103.50. Update VS Code, Slack, and Cursor separately. A Chrome update does not update them.
- **Drupal core** (CVE-2026-132165, actively exploited, KEV 24 November). Update to 10.6.22, 11.3.22, or 11.4.13. End-of-life lines have no fix. Lock down `/core/install.php` and keep `settings.php` unwritable.
- **VMware vCenter** (CVE-2026-123890, exploited, KEV 20 November; CVE-2026-123903, not known to be exploited). Update to 9.1.2, 9.0.2.0300, or 8.0 U3m, and VCF 5.2.5. There is no workaround. Keep vCenter off the internet.
- **GeoServer** (CVE-2026-120705, CVE-2026-129243, and related CVE-2026-129245). Update to 3.0.2, 2.28.6, or 2.27.7. Active exploitation has been reported.
- **Juniper Session Smart** (CVE-2026-103406, KEV 25 November). Update to 7.0.5, 7.1.7, or 7.2.3. There is no workaround.
- **MONAI Label** (CVE-2026-133968, KEV 23 November), versions 0.8.5 and earlier. Update to 0.8.6. Enable authentication until you do.
- **N-able Mail Assure / SpamExperts** (CVE-2026-134624, KEV 23 November). Update to 20261121.1943.
- **Azure API Management Classic.** Microsoft found unauthorized access to secrets around 18 November and mitigated it on 19 November. No CVE was found. Rotate all secrets and review logs.

#### Patch soon

- **simple-git** (CVE-2026-134815). Update to simple-git 4.1.0 and `@simple-git/argv-parser 3.0.0`. The issue is argument injection when untrusted input reaches `listRemote()` or `raw()`.
- **Jenkins plugins** (advisory 2026-11-25, 14 CVEs in 11 plugins). Update Pipeline: Groovy to `4403.4405.va_b_cdb_b_d0b_89f` and Script Security to `1436.1438.v3dc5ef7d16f2`, and update the other affected plugins named in the advisory.

#### Watch

- **Bytebase DBHub MCP** (CVE-2026-136441). No patch. Restrict network access.
- **Idunno.AntiCsrf** (CVE-2026-131914, KEV 24 November). Abandoned, and there is no fix. Replace it.
- Also on the KEV list, with no patch details in this briefing: Optimizely Web Experimentation (CVE-2026-132224), Mitel MiCollab (CVE-2026-133275, CVE-2026-133303, CVE-2026-133311, CVE-2026-133323, CVE-2026-133324), Danfoss AK-SM 800A (CVE-2023-25914, CVE-2023-25915, CVE-2025-41450), and Xen Orchestra (CVE-2026-133469).

### For everyone

- Update Chrome to 158.0.8127.88 on Linux, or to 158.0.8127.88 or 158.0.8127.89 on Windows and Mac. If you use VS Code, Slack, or Cursor, install that app's update too.
- Update to Firefox 161, Firefox ESR 153.8, or Firefox ESR 115.46. Update to Thunderbird 161 or Thunderbird 153.8.
- If you use the Omarchy package `dell-xps-touchpad-haptics`, update it to 1.0.0-4.

This list is curated, not complete. Verify it against the vendor advisory.

## Subscribe

The briefings are on the web at <https://jluethe.github.io/patch-these/>, newest first, and as an RSS feed at <https://jluethe.github.io/patch-these/feed.xml>. The site goes live after GitHub Pages is set to deploy from GitHub Actions. Until then, the digest above is the latest issue.

## What this is

Each digest takes security issues raised and discussed on X, checks them against official sources, and sorts them for three audiences: applications and servers, end users, and both. Priorities are Patch now, Patch soon, and Watch. The method, the source list, and the disclaimer are in [METHODOLOGY.md](METHODOLOGY.md).

Later digests may also use issues raised on Bluesky, Mastodon, Reddit, and Hacker News. The 25 November 2026 digest does not.

This briefing is curated, not complete. It is unofficial. It is not professional advice. It is not affiliated with CISA, FIRST, or any vendor. Verify anything you plan to act on against the vendor advisory. EPSS is a probability, not a certainty.

## License

Writing in this repository is released under [Creative Commons Attribution 4.0 International](LICENSE). Attribute patch-these and link the digest you used.

## Adding a digest

A daily job adds `digests/YYYY-MM-DD.md`, `data/YYYY-MM-DD.json`, and an update to the Patch these block above. [CONTRIBUTING.md](CONTRIBUTING.md) is the checklist. The HTML site is generated; it is not edited by hand.
