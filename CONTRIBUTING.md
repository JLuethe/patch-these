# Adding a daily digest

A daily job publishes one day by committing three paths. It does not edit HTML. On push to `main`, GitHub Actions runs `python scripts/build_site.py`, which checks the files and rebuilds the site.

## 1. `digests/YYYY-MM-DD.md`

Use the date the digest is published. Copy the shape of `digests/2026-11-25.md`.

- Title is the date. The intro names the coverage window.
- Three sections, in this order, omitting a section only when it has no items:
  - `## Applications & servers`
  - `## End users`
  - `## Both`
- Each item is a `###` heading with the product name, then its own line `**Patch now**`, `**Patch soon**`, or `**Watch**`, then a short note and the fix.
- Link each X post. Do not paste the post.
- Link the vendor advisory and any CISA or CVE record the item actually uses.
- No fenced code blocks. Inline code for version numbers is fine.
- No exploit code, no proof-of-concept code, no attack steps. Name the issue and describe the impact in one sentence.
- End with `## Patch these`, then `### For app and server owners` and `### For everyone`. The homepage and the README both show this block. Items marked Both go in each half.

Keep a fact only when a source for that day stated it. Leave a CVSS, an EPSS, a KEV date, an affected range, or a fixed version out when the source did not give one.

## 2. `data/YYYY-MM-DD.json`

Same items, same date. `digest_date` matches the filename. `coverage_start` and `coverage_end` are the window the intro names.

`schema_version` is `1`. `items` is in source order. Group by `audience` and `priority` when displaying; the markdown is already grouped.

| Field | What to put |
| --- | --- |
| `id` | Stable slug, unique in the file. Lowercase letters, digits, hyphens. |
| `cve` | List of `CVE-YYYY-NNNN…` ids, or `null` when the day did not name ids. |
| `product` | Product name. The same string appears in the markdown. |
| `affected` | Affected range as stated, or `null`. |
| `fixed_versions` | List of version strings that appear verbatim in the markdown. Empty list when there is no fix. |
| `cvss` | A number, a short string such as `9.2 (4.0) / 8.1 (3.1)` or `ZDI CVSS 9.8`, an object keyed by CVE id, or `null`. |
| `epss` | A percentage string exactly as stated (`1.13%`), an object of those keyed by CVE id, or `null`. |
| `kev` | `null` if KEV was not discussed. `false` if the source said it is not known to be exploited. `true` if it was added to KEV and no date was given. `"YYYY-MM-DD"` when a KEV date was given. An object keyed by CVE id when the CVEs in one item differ. |
| `priority` | `patch_now`, `patch_soon`, or `watch`. |
| `audience` | `applications_and_servers` (Applications & servers), `end_users` (End users), or `both`. |
| `lower_relevance` | `true` only for KEV entries the digest files as lower relevance. Otherwise `false`. |
| `summary` | Plain sentences. What it is. No Markdown. |
| `action` | Plain sentences. What to update, rotate, or restrict. No Markdown. |
| `advisory_url` | List of `https` URLs for the official notes the item cites. Empty list if there are none. |
| `x_post_urls` | List of `https://x.com/<handle>/status/<id>` URLs. Empty list if the item has no X post. |

Every CVE id, advisory URL, X URL, EPSS string, CVSS value, and fixed version in the JSON has to appear in that day's markdown. The build fails when one is missing.

## 3. `README.md`

Replace the block that starts at `### For app and server owners` with that day's "Patch these" text, ending just before the next `##` heading. The build compares it to the digest and fails if they differ.

Point the "Full digest" link at `digests/YYYY-MM-DD.md`.

## Check before you commit

```bash
pip install -r requirements.txt
python scripts/build_site.py
```

The script writes `_site/` and does not need to be committed. `_site/` is gitignored.

## Publishing

The site is static HTML built by `.github/workflows/pages.yml`. It lists digests newest first and writes an Atom feed at `feed.xml`.

GitHub Pages has to be switched to GitHub Actions once, by a person with admin on the repo: Settings → Pages → Build and deployment → Source: GitHub Actions. The workflow cannot turn that on. After it is on, a push to `main` publishes the site. If the first deploy ran before Pages was enabled, re-run the workflow.
