# Discovery feed cache

The cache is no longer committed to `main`. `.github/workflows/feeds.yml`
refreshes it about every 30 minutes and force-pushes a single commit to the
`feed-cache` branch, with these files at the branch root:

- `latest.json`: leads from the last 72 hours.
- `kev-new.json`: CISA KEV entries that were not in the previous snapshot.
- `kev-seen.json`: the KEV ids seen last time (state for the next run).
- `status.json`: per-source `last_ok`, `last_attempt` and `last_error`.

Read it from any checkout:

```bash
git fetch origin feed-cache
git show origin/feed-cache:latest.json
git show origin/feed-cache:kev-new.json
git show origin/feed-cache:status.json
```

Rows are discovery leads, not edition facts.
