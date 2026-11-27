"""Seen-post store: normalization, filter, add and pruning, in a temporary state dir."""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from seen_posts import add, normalize, prune, unseen

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seen_posts.py"


def test_ids_are_normalized_per_platform():
    assert normalize("https://x.com/someone/status/2125247521727373445?s=20") == "x:2125247521727373445"
    assert normalize("https://twitter.com/someone/status/42") == "x:42"
    assert normalize("x:42") == "x:42"
    assert normalize("https://bsky.app/profile/Someone.bsky.social/post/3lk2abc") == "bsky:someone.bsky.social/3lk2abc"
    assert normalize("at://did:plc:abc/app.bsky.feed.post/3lk2abc") == "bsky:at://did:plc:abc/app.bsky.feed.post/3lk2abc"
    assert normalize("https://Infosec.Exchange/@someone/113456789012345678/") == "masto:https://infosec.exchange/@someone/113456789012345678"
    assert normalize("masto:https://infosec.exchange/@someone/1") == "masto:https://infosec.exchange/@someone/1"
    assert normalize("https://vendor.example/advisory") is None
    assert normalize("") is None


def test_filter_drops_seen_and_duplicate_posts_and_keeps_unknown_entries():
    posts = {"x:1": "2026-11-26T00:00:00Z"}
    entries = [
        {"url": "https://x.com/a/status/1"},
        {"url": "https://x.com/b/status/2"},
        {"url": "https://twitter.com/b/status/2"},
        {"url": "https://vendor.example/not-a-post"},
    ]
    assert unseen(entries, posts) == [entries[1], entries[3]]


def test_add_and_prune_after_fourteen_days():
    now = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
    posts, skipped = add({"x:old": "2026-11-01T00:00:00Z", "x:9": "2026-11-20T00:00:00Z"}, ["https://x.com/a/status/10", "nope"], "2026-11-26T12:00:00Z")
    assert skipped == ["nope"] and posts["x:10"] == "2026-11-26T12:00:00Z"
    assert set(prune(posts, now, 14)) == {"x:9", "x:10"}


def test_command_line_round_trip_uses_pt_state_dir(tmp_path):
    env = {"PT_STATE_DIR": str(tmp_path / "state"), "PATH": "/usr/bin:/bin"}
    run = lambda *args, stdin="": subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True, text=True, env=env, check=True)
    candidates = "https://x.com/a/status/1\nhttps://bsky.app/profile/a.bsky.social/post/3abc\n"
    assert run("filter", stdin=candidates).stdout.split() == candidates.split()
    run("add", "https://x.com/a/status/1")
    assert run("filter", stdin=candidates).stdout.split() == ["https://bsky.app/profile/a.bsky.social/post/3abc"]
    as_json = json.dumps([{"url": "https://x.com/a/status/1"}, {"url": "https://x.com/a/status/2"}])
    assert json.loads(run("filter", stdin=as_json).stdout) == [{"url": "https://x.com/a/status/2"}]
    stored = json.loads((tmp_path / "state" / "seen-posts.json").read_text())["posts"]
    assert list(stored) == ["x:1"]
