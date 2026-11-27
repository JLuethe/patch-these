import json
from pathlib import Path


def test_in_the_wild_suspended_on_bluesky_only():
    q = json.loads(Path("social/queries.json").read_text())
    suspended = {e["term"] for e in q["bluesky"]["suspended_terms"]}
    assert '"in the wild"' in suspended
    assert '"in the wild"' in q["families"]["exploitation"]["terms"]
