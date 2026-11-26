# How patch-these is put together

patch-these is a daily briefing of security issues raised and discussed on X (Twitter). Each item is cross-checked against official sources, then written as a short list of what to patch.

The writing is calm and plain. The useful part is the fix: which version, which secret to rotate, or what to keep off the network.

## Sources

These are the sources a digest draws on, when they have something to say about an item:

- X (Twitter), where the issue was raised or discussed
- [NVD](https://nvd.nist.gov/)
- The vendor's own advisory
- The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)

A figure, a fixed version, or a KEV date is included only when one of that day's sources stated it. Missing scores are left blank. They are not filled in later from somewhere else.

Future digests may also take issues raised on Bluesky, Mastodon, Reddit, and Hacker News. Those are not sources for the 25 November 2026 digest.

## What we leave out

This project is strictly defensive. Digests do not include exploit code, proof-of-concept code, payloads, or step-by-step attack detail.

An item names the issue, states the impact in a sentence, and spends the rest of its space on the fix. When a post is mostly a proof of concept, the digest links the post and does not repeat the technique.

## How items are prioritized

Three labels, and only these:

- **Patch now.** Actively exploited, or critical and widely deployed.
- **Patch soon.** High severity with a patch.
- **Watch.** No patch, or limited impact.

A CISA KEV listing is the actively exploited catalog, so it normally meets Patch now. When a KEV entry is lower relevance for the usual audience and the digest has no patch details, it is tagged Watch until a vendor advisory is in hand. The 25 November 2026 digest does this for four KEV additions and says so in the item.

## Who each section is for

Every item is written once, under one of three audience sections:

- **Applications & servers.** People who run sites, services, appliances, CI, and the libraries those systems depend on.
- **End users.** People updating the software on their own computers.
- **Both.** The same issue matters to operators and to everyone else.

The publish-ready close of each digest, "Patch these", splits the same items into "For app and server owners" and "For everyone". An item marked Both appears in each half.

## X posts

X posts are linked, not copied. The digest does not paste the text of a post. The link is there so you can read the post at the source.

## Scores

CVSS is a severity score. EPSS is a probability that a vulnerability will be exploited in the wild, not a certainty, and not a statement that exploitation has already happened. A low EPSS is not a reason to ignore a vulnerability that is already being used. A high EPSS is not, by itself, proof that it has been.

## Disclaimer

This briefing is curated, not complete. It is unofficial. It is not professional advice. It is not affiliated with CISA, FIRST, or any vendor.

Verify anything you plan to act on against the vendor advisory. Where this page and a vendor disagree, the vendor wins. EPSS is a probability, not a certainty.
