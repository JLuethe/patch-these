# How patch-these is put together

patch-these helps people decide what security work needs their attention: update a product, mitigate exposure, replace an unsupported component, rotate credentials, or investigate an incident. Each item explains who is affected, why it matters, what to do, and which sources support the advice.

The briefings are curated, not a complete inventory of vulnerabilities. A missing item does not mean a product is safe.

## Discovery and evidence

The briefing is updated every 4 hours, at 6 AM, 10 AM, 2 PM, 6 PM and 10 PM Pacific time, every day. Each calendar day has one dated edition, updated in place, with a corrections log. The 10 AM, 2 PM and 6 PM runs look only for new reports on X, Bluesky and Mastodon. The 6 AM and 10 PM runs also read the official-feed cache and recheck earlier urgent items. Between runs, a new CISA KEV entry or a new advisory for a product covered in the past week starts a short check of just that item. A run that finds nothing new changes nothing.

Each run looks first for new security issues on X, Bluesky and Mastodon, especially fresh posts that may not be fully validated yet. Unconfirmed leads are published as Early signals: not yet verified, with no hard patch recommendation. A patch recommendation, a confirmed exploitation status, or a CISA KEV listing is added only after a primary source confirms it: a vendor advisory, CISA KEV, NVD, FIRST EPSS, or the original researcher.

Official sources also arrive through a feed cache refreshed about every 30 minutes, including CISA KEV, vendor advisories, GitHub advisories, and Hacker News. Earlier urgent items are rechecked when those official feeds show a change for that product, so older items can lag between checks.

Social posts are discovery leads. They are not evidence of exploitation, of a fixed version, or of who is affected. Those claims are verified against primary sources: vendor advisories, government alerts, original researcher reports, CVE records, and score services. A popular post is not that evidence.

Social discovery searches for technical flaw descriptions, not only CVE ids: zero-day language, authentication and authorization bypass, code execution and injection, file access and request forgery, privilege escalation and sandbox escape, observed exploitation, newly public exploits and patch bypasses, and early disclosures such as "no CVE yet" or "unpatched". A separately budgeted catch-up query reads posts that mention CVE ids. There is no engagement minimum: a fresh post from a small account counts as much as a popular one. The exact terms are in [`social/queries.json`](social/queries.json). Sources:

- X search, newest first.
- Bluesky public post search, newest first.
- Mastodon: post search and the `#cve`, `#zeroday`, `#0day`, `#vulnerability` and `#securityadvisory` hashtag timelines on mastodon.social (which include federated posts from other servers), and the public local timeline of infosec.exchange.

A report does not need a CVE, a patch, or a confirmation to be published as an early signal, and having one does not disqualify it. Early signals cover security flaws and exploitation developments, including supply-chain compromises. General breach and incident news without a specific exploited flaw is not an early signal; a confirmed breach that readers need to act on is published as a verified incident item.

The 25 November 2026 edition was discovered through X only. Later editions may link posts from any of the three. Posts are linked, not copied. The briefing does not paste the text, attach screenshots, or embed media.

Each JSON source record has an ID, a source kind, a URL, a label, the fields it supports, and a `checked_at` timestamp when a content check was actually performed. Fixes, exploitation reports, KEV membership, CVSS, and EPSS refer to those IDs. A remediation guide can support an action without substantiating the incident timeline; those claims may need different sources.

Source kinds are `vendor_advisory`, `government_alert`, `researcher_report`, `social_report`, `score_service`, and `cve_record`. A `social_report` URL is an X status, a bsky.app post, or a Mastodon status permalink. `checked_at` may stay null for those posts.

`checked_at` means the source content was checked. It is not the source publication date, the digest publication date, or the date an automated HTTP request succeeded. Historical records with no preserved verification timestamp retain `null`. Unknown information is never replaced by a guessed timestamp, score, affected range, or fixed version.

The current repository validates structure, caches official feeds, and builds the publication. A collector script gathers candidate Bluesky and Mastodon posts and reports, per query, whether the whole window was read; it does not judge them, publish them, or prove the truth of source claims. An editor must check the evidence before publishing.

## Urgency and action

Urgency answers **when to act**. Action type answers **what to do**. A missing patch does not reduce the urgency of an exploited vulnerability.

| Urgency | Meaning |
| --- | --- |
| **Act now** (`act_now`) | Confirmed exploitation, KEV membership, or another documented reason for urgent action in an affected environment. |
| **Act soon** (`act_soon`) | A supported security improvement that should be scheduled, with no documented reason in this briefing to treat it as immediate. |
| **Monitor** (`monitor`) | Follow developments or investigate applicability when the available evidence does not justify a stronger urgency. It does not mean safe. |

Action types are `update`, `mitigate`, `replace`, `rotate`, and `investigate`. An Act now item may require replacement or mitigation when a patch is unavailable. Each item includes a `priority_reason` explaining the editorial judgment. An item may set `kind` to `vulnerability`, `incident`, or `supply_chain`. Editions published before that field omit it. `gaps`, on an edition or an item, holds verification notes. Those notes are not the customer action. Every item from the 2026-11-27 edition on states `verification` explicitly; on older editions it is `verified` when omitted. `early_signal` is an unverified lead: it is labeled "Not yet verified" on the site (plus "Single source" when one post is the only source), it is not a patch recommendation, and it is not a featured item. One credible post is enough to publish an early signal. A social post never supports exploitation, KEV membership, a fix, CVSS, or EPSS, and every CVE named in an item's text is listed in its CVE ids. For an incident the site says "Breach confirmed", and for a supply-chain compromise "Compromise confirmed", rather than "Exploitation confirmed". Feed-cache files on the `feed-cache` branch are discovery leads. A fact in an edition still comes from the primary source the lead links to.

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

One America/Los_Angeles calendar day is one edition file. Runs at 6 AM, 10 AM, 2 PM, 6 PM and 10 PM Pacific update that day's file and append a correction when something changes. Corrections on one edition are ordered: each `at` is at or after the previous correction and no later than `updated_at`. The first run of a new calendar day creates that day's file. A day with nothing new to verify is still published as an empty edition.

The weekly link checker detects missing local links and public HTTP 404/410 responses. Authentication barriers, throttling, server errors, network failures, and unauthenticated social pages are explicitly inconclusive. A reachable URL does not validate a claim. Inconclusive results need manual review and remain in the workflow report.

## Scope and reuse

This is a defensive briefing. It describes impact and remediation without publishing exploit code, payloads, or attack instructions. Keep explanations focused on decisions a reader can make.

The project is unofficial and is not affiliated with CISA, FIRST, or any vendor. Check the applicable vendor advisory before acting. If it conflicts with this briefing, use the vendor's current guidance and report the discrepancy.

Editorial writing and JSON data are licensed under [CC BY 4.0](LICENSE); attribute patch-these and link the issue used. The generator, scripts, styles, tests, schema, and workflow code are licensed under [MIT](LICENSE-CODE). Third-party source material remains subject to its own terms.
