# How patch-these is put together

patch-these helps people decide what security work needs their attention: update a product, mitigate exposure, replace an unsupported component, rotate credentials, or investigate an incident. Each item explains who is affected, why it matters, what to do, and which sources support the advice.

The briefings are curated, not a complete inventory of vulnerabilities. A missing item does not mean a product is safe.

## Discovery and evidence

Social posts can draw attention to an issue. Vendor advisories, government alerts, original researcher reports, CVE records, and score services provide evidence for specific claims. A popular post is not evidence of exploitation or proof that a particular version is fixed.

Each JSON source record has an ID, a source kind, a URL, a label, the fields it supports, and a `checked_at` timestamp when a content check was actually performed. Fixes, exploitation reports, KEV membership, CVSS, and EPSS refer to those IDs. A remediation guide can support an action without substantiating the incident timeline; those claims may need different sources.

Source kinds are `vendor_advisory`, `government_alert`, `researcher_report`, `social_report`, `score_service`, and `cve_record`. Social sources remain visible as discovery or reported evidence. The November 25, 2026 issue was discovered through X; future issues may use other platforms. Posts are linked, not copied.

`checked_at` means the source content was checked. It is not the source publication date, the digest publication date, or the date an automated HTTP request succeeded. Historical records with no preserved verification timestamp retain `null`. Unknown information is never replaced by a guessed timestamp, score, affected range, or fixed version.

The current repository validates structure and builds the publication. It does not automatically collect social posts or prove the truth of source claims. An editor must check the evidence before publishing.

## Urgency and action

Urgency answers **when to act**. Action type answers **what to do**. A missing patch does not reduce the urgency of an exploited vulnerability.

| Urgency | Meaning |
| --- | --- |
| **Act now** (`act_now`) | Confirmed exploitation, KEV membership, or another documented reason for urgent action in an affected environment. |
| **Act soon** (`act_soon`) | A supported security improvement that should be scheduled, with no documented reason in this briefing to treat it as immediate. |
| **Monitor** (`monitor`) | Follow developments or investigate applicability when the available evidence does not justify a stronger urgency. It does not mean safe. |

Action types are `update`, `mitigate`, `replace`, `rotate`, and `investigate`. An Act now item may require replacement or mitigation when a patch is unavailable. Each item includes a `priority_reason` explaining the editorial judgment.

Confirmed exploitation and confirmed KEV membership cannot be classified Monitor. Missing patch details remain unknown and do not establish low risk. Relevance depends on the reader's installed products, versions, exposure, and configuration; it is separate from urgency for affected readers.

Fix availability is `available`, `unavailable`, `unknown`, or `not_applicable`. An empty list of fixes alone does not prove that no patch exists.

## Products, versions, and audiences

A fixed version is tied to its component, relevant CVEs, release branch, platform, and supporting sources when known. Different fixes grouped into one editorial item are not interchangeable. Follow the vendor's supported upgrade path and use a later supported release where appropriate.

Affected ranges remain `null` if they have not been established. Unknown does not mean unaffected. General advice to update a bundled application is not a claim that a particular release of that application fixes the vulnerability; that requires its own evidence.

Each item has one audience:

- **Applications & servers:** people operating sites, services, appliances, CI, or software dependencies.
- **End users:** people updating software on their computers.
- **Both:** an item relevant to each audience.

Audience views and feeds include Both items. Filtering does not alter an item's urgency.

## Exploitation, KEV, and scores

Exploitation status is `confirmed`, `reported`, or `unknown`, with source references. Unknown means the briefing has not established the status. It does not mean exploitation has not occurred. When an item covers several CVEs whose exploitation differs, each CVE gets its own status, and reader-facing labels name only the CVEs with confirmed or reported exploitation.

KEV membership is a separate per-CVE fact: `listed` is true, false, or unknown, with a date added when known. A vulnerability can be exploited without appearing in KEV. Do not infer `listed: false` from an absence of reporting or from an exploitation status of unknown.

CVSS describes severity. Records identify the CVE, score, scoring version and authority when known, and sources. Scores from different versions or authorities are not silently combined.

EPSS estimates exploitation probability over the next 30 days. It is not proof that exploitation has happened. Each record stores a probability between 0 and 1, its score date when known, and its sources. Historical percentages without a preserved score date retain `null`; they must not be represented as today's score. Low EPSS does not justify ignoring observed exploitation.

## Publication and corrections

`data/YYYY-MM-DD.json` is the authoritative editorial input. The generator builds the website, feeds, and downloadable JSON from it. Markdown digests and the README briefing are generated copies, refreshed explicitly by the editor. See [CONTRIBUTING.md](CONTRIBUTING.md).

`published_at` records initial publication. `updated_at` records a meaningful editorial revision. Corrections include a timestamp, a plain-language explanation, and affected item IDs. Record changes to versions, affected scope, sources, exploitation status, or urgency so readers can see what changed. Rebuilding unchanged content must not invent a new editorial update time.

The weekly link checker detects missing local links and public HTTP 404/410 responses. Authentication barriers, throttling, server errors, network failures, and unauthenticated social pages are explicitly inconclusive. A reachable URL does not validate a claim. Inconclusive results need manual review and remain in the workflow report.

## Scope and reuse

This is a defensive briefing. It describes impact and remediation without publishing exploit code, payloads, or attack instructions. Keep explanations focused on decisions a reader can make.

The project is unofficial and is not affiliated with CISA, FIRST, or any vendor. Check the applicable vendor advisory before acting. If it conflicts with this briefing, use the vendor's current guidance and report the discrepancy.

Editorial writing and JSON data are licensed under [CC BY 4.0](LICENSE); attribute patch-these and link the issue used. The generator, scripts, styles, tests, schema, and workflow code are licensed under [MIT](LICENSE-CODE). Third-party source material remains subject to its own terms.
