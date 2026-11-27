"""social/watchlist.json: a small, verified list of accounts read in full each run."""
import json
from datetime import date
from pathlib import Path
import re

WATCHLIST = json.loads((Path(__file__).resolve().parents[1] / "social" / "watchlist.json").read_text(encoding="utf-8"))


def accounts():
    for platform in ("x", "bluesky", "mastodon"):
        for account in WATCHLIST[platform]["accounts"]:
            yield platform, account


def test_watchlist_is_small_and_every_account_was_verified():
    rows = list(accounts())
    assert 10 <= len(rows) <= 20
    for platform, account in rows:
        assert account["name"] and account["why"] and account["verified_by"], account
        date.fromisoformat(account["verified_at"])


def test_watchlist_reads_posts_without_keywords():
    assert WATCHLIST["rules"]["keywords"] is False
    assert WATCHLIST["rules"]["replies"] is False and WATCHLIST["rules"]["reposts"] is False


def test_account_ids_are_well_formed_and_unique():
    x = WATCHLIST["x"]["accounts"]
    assert all(re.fullmatch(r"[A-Za-z0-9_]{1,15}", a["username"]) and a["user_id"].isdigit() for a in x)
    bsky = WATCHLIST["bluesky"]["accounts"]
    assert all(a["did"].startswith("did:plc:") and "." in a["handle"] for a in bsky)
    masto = WATCHLIST["mastodon"]["accounts"]
    assert all(re.fullmatch(r"[A-Za-z0-9_]+@[a-z0-9.-]+\.[a-z]+", a["acct"]) for a in masto)
    for key, rows in (("username", x), ("handle", bsky), ("acct", masto)):
        values = [row[key].lower() for row in rows]
        assert len(values) == len(set(values))


def test_x_query_names_every_account_once():
    query = WATCHLIST["x"]["query"]
    for account in WATCHLIST["x"]["accounts"]:
        assert query.count(f"from:{account['username']} ") + query.count(f"from:{account['username']})") == 1
    assert "-is:retweet" in query and "-is:reply" in query
    for platform in ("x", "bluesky", "mastodon"):
        assert 1 <= WATCHLIST[platform]["max_pages"] <= 8
