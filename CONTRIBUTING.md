# Publishing and improving patch-these

The source of each issue is `data/YYYY-MM-DD.json`. Edit that file, check the evidence, run validation, and regenerate the public copies. Publishing is currently editor-driven; the repository does not contain a daily collector or an unattended research agent.

## Set up and check a change

Use Python 3.12 and install the build and test dependencies:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python scripts/build_site.py
```

The normal build validates JSON sources and writes `_site/`. It does not edit tracked files. Inspect the generated homepage, an issue page, feeds, and JSON output before publishing. Generated HTML is not committed.

After editing an issue's JSON, refresh the generated Markdown digests and README briefing explicitly:

```bash
python scripts/build_site.py --write-generated
```

Review those changes along with the source JSON in your pull request. Keep the README's generated briefing markers in place. Do not manually maintain separate versions of the same briefing in Markdown, README, and JSON. CI evaluates the source model and generated output; a matching copy of a claim is not independent verification.

## Author an issue

Copy the structure of `data/2026-11-25.json` and use schema version 2. Set `digest_date` to the publication date and keep it equal to the filename. `coverage_start` and `coverage_end` describe the reporting window. `published_at` and `updated_at` are RFC 3339 timestamps, including a timezone. Preserve the initial publication timestamp when making a correction.

`featured_item_ids` selects at most three items for the lead actions. The IDs must refer to that issue's items. Choose them for relevance and urgency.

Keep an item's `id` stable across editions and corrections for the same product or component: saved-product preferences use it as a durable key. Do not include publication dates or CVE numbers in that identifier; for example, use `jenkins-plugins`. Combine multiple advisories for the same product into one item in an edition, or use separate stable IDs when the advisories cover distinct components.

| Field | Meaning |
| --- | --- |
| `id`, `product` | Stable item identifier and reader-facing product name. |
| `audience` | `applications_and_servers`, `end_users`, or `both`. |
| `priority`, `priority_reason` | `act_now`, `act_soon`, or `monitor`, with an explanation of the urgency. |
| `action_type` | `update`, `mitigate`, `replace`, `rotate`, or `investigate`. |
| `summary`, `action` | Plain text explaining impact and the next action. |
| `cves` | Covered CVE identifiers; an empty list when none are established. |
| `affected` | Supported affected range or scope, or `null` when unknown. |
| `fix_status` | `available`, `unavailable`, `unknown`, or `not_applicable`. |
| `fixes` | Objects containing `component`, `version`, `platform`, `branch`, `cves`, and `source_ids`. Unknown platform or branch can be null. |
| `exploitation` | `status` (`confirmed`, `reported`, or `unknown`) and supporting `source_ids`. |
| `kev` | Per-CVE objects: `cve`, `listed` (true, false, or null), `date_added`, and `source_ids`. |
| `cvss` | Objects: `cve`, `score`, `version`, `authority`, and `source_ids`. Unknown metadata stays null. |
| `epss` | Objects: `cve`, numeric `probability` (0–1), `score_date`, and `source_ids`. An unrecorded historical score date stays null. |
| `sources` | Objects: `id`, `kind`, `url`, `label`, `checked_at`, and `supports`. |

Use source IDs local to each item and reference the sources supporting each fact. `supports` names the supported fields, such as `fixes`, `kev`, or `cvss`. `checked_at` records a check of the source content; do not populate it merely because a URL returned HTTP 200 or because the issue is being rebuilt.

Keep urgency separate from patch availability. An exploited issue without a patch may require immediate mitigation, replacement, or investigation. Known KEV entries and confirmed exploitation must not be classified Monitor. Missing remediation research does not imply low risk.

Do not infer non-exploitation from silence, infer KEV non-membership from a post, use one CVE's fix for another, or assume every platform and release branch uses the same version. Explain uncertainty in reader-facing text when it changes the recommended action.

## Check evidence and correct an issue

Use the original vendor advisory, government notice, or researcher disclosure when it supports the claim. Identify social reporting clearly. An incident timeline, fix, score, and exploitation assertion may each need different evidence.

Before publishing:

1. Confirm the product, affected scope, CVEs, and applicable release branches against the sources.
2. Confirm that versions, exploitation claims, and scores have the appropriate sources and dates, or are explicitly unknown.
3. Check urgency and action together. Review the lead actions and both audience views.
4. Run tests and build the site. Refresh generated Markdown and the README briefing with `--write-generated` when the source changes.

For a correction, update `updated_at` and append a record to `corrections` with `at`, `summary`, and `item_ids`. Explain what readers need to reconsider. Preserve the historical publication date and avoid silently rewriting consequential facts.

## Link checks

The weekly **Check source links** workflow can also run manually in GitHub Actions. It checks JSON source URLs and literal Markdown links and preserves `_reports/link-check.json` as an artifact. Run it locally with:

```bash
python scripts/check_links.py --report _reports/link-check.json
```

A confirmed public 404/410 or missing local target fails the check. HTTP 401/403/429, server errors, and network failures are inconclusive; transient failures are retried. Unauthenticated X/Twitter responses cannot establish whether a post is available or deleted and remain inconclusive. Review these results manually. A passing job means no confirmed dead links were found, not that every source was accessible or its claims verified.

The check runs weekly rather than on every pull request so network availability does not replace deterministic publication checks. It neither signs in to social services nor posts issues or messages.

## Publish

The **Pages** workflow tests and builds pull requests with read-only repository permissions. A successful push to `main` builds the site and deploys it through a separate job with Pages and identity-token permissions. Pull-request runs have separate concurrency groups and cannot cancel production deployment. Official actions are pinned to verified commit SHAs; review upstream releases before updating the pins.

GitHub Pages must use GitHub Actions as its source: **Settings → Pages → Build and deployment → Source: GitHub Actions**. After enabling it, merge the reviewed change and check deployment. If an earlier deployment failed because Pages was not enabled, rerun Pages after fixing that setting.

The website publishes an Atom feed for all issues and audience-specific Atom feeds. Both-audience items appear in each audience feed. Use the homepage's feed links to subscribe. Latest and dated JSON downloads come from the same source; use the JSON links instead of treating Markdown as a machine-readable API.

## Licensing

Writing, digests, and JSON editorial data are licensed under [Creative Commons Attribution 4.0 International](LICENSE). Attribute patch-these and link the issue used. Code in `scripts/`, `assets/`, `tests/`, schemas, and `.github/` is licensed under [MIT](LICENSE-CODE). Contributions to each part use its corresponding license. Third-party material retains its own terms.
