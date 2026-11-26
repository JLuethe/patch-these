"""Direct-publish decisions that do not touch the network or git."""

from datetime import datetime, timezone

from publish_direct import blocking_dead, commit_message, reported_new_dead


def test_commit_message_uses_pacific_time():
    when = datetime(2026, 11, 26, 23, 15, tzinfo=timezone.utc)
    assert commit_message([__import__("pathlib").Path("data/2026-11-26.json")], when) == "Update 2026-11-26 edition (15:15 PT run)"


def test_new_nonsocial_dead_links_are_reported_and_do_not_block():
    results = [
        {"target": "https://vendor.example/new", "status": "dead", "kind": "external", "detail": "HTTP 404"},
        {"target": "https://vendor.example/old", "status": "dead", "kind": "external", "detail": "HTTP 404"},
        {"target": "https://x.com/example/status/1", "status": "inconclusive", "kind": "external", "detail": "login"},
        {"target": "README.md", "status": "dead", "kind": "local", "detail": "missing"},
    ]
    new_urls = {"https://vendor.example/new"}
    assert [item["target"] for item in reported_new_dead(results, new_urls)] == ["https://vendor.example/new"]
    assert [item["target"] for item in blocking_dead(results, new_urls)] == ["https://vendor.example/old", "README.md"]


def _git(cwd, *args):
    import subprocess
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _repo_with_remote(tmp_path):
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    _git(tmp_path, "clone", str(remote), str(work))
    _git(work, "config", "user.name", "Test")
    _git(work, "config", "user.email", "test@example.invalid")
    _git(work, "checkout", "-b", "main")
    (work / "data").mkdir()
    (work / "data" / "edition.json").write_text("{}\n")
    _git(work, "add", ".")
    _git(work, "commit", "-m", "seed")
    _git(work, "push", "origin", "HEAD:main")
    return remote, work


def test_a_failed_push_is_retried_even_when_the_tree_is_clean(tmp_path, capsys):
    from publish_direct import commit_and_push
    remote, work = _repo_with_remote(tmp_path)
    (work / "data" / "edition.json").write_text('{"changed": true}\n')
    # First attempt: the push fails (unreachable remote), but the commit is made.
    missing = str(tmp_path / "missing.git")
    assert commit_and_push(work, ["data/edition.json"], "Update edition", missing) != 0
    assert _git(work, "status", "--porcelain") == ""
    assert _git(remote, "log", "-1", "--format=%s", "main") == "seed"
    # Second attempt: the tree is clean, but the waiting commit must still be pushed.
    assert commit_and_push(work, ["data/edition.json"], "Update edition", str(remote)) == 0
    assert _git(remote, "log", "-1", "--format=%s", "main") == "Update edition"
    assert "have not reached main yet" in capsys.readouterr().out


def test_nothing_to_publish_only_when_main_has_every_commit(tmp_path, capsys):
    from publish_direct import commit_and_push
    remote, work = _repo_with_remote(tmp_path)
    assert commit_and_push(work, ["data/edition.json"], "Update edition", str(remote)) == 0
    assert "Nothing to publish" in capsys.readouterr().out
    assert _git(remote, "log", "-1", "--format=%s", "main") == "seed"


def test_an_unreachable_remote_with_a_clean_tree_is_not_success(tmp_path):
    from publish_direct import commit_and_push
    _remote, work = _repo_with_remote(tmp_path)
    assert commit_and_push(work, ["data/edition.json"], "Update edition", str(tmp_path / "missing.git")) != 0


# Fast path detection and the no-change exit.

import copy
import json
import subprocess
import sys
from pathlib import Path

import editions as fx
from publish_direct import editions_changed, fast_path_check, fast_path_reason

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "publish_direct.py"


def _base():
    return fx.edition(fx.DAY_TWO, [fx.item("new-server", "New Server", cve="CVE-2030-20001"), fx.early_signal()])


def _lead(item_id="second-lead"):
    lead = fx.early_signal()
    lead["id"] = item_id
    return lead


def test_adding_or_editing_early_signals_is_fast_path_eligible():
    old = _base()
    new = copy.deepcopy(old)
    new["items"].append(_lead())
    new["items"][1]["summary"] += " A second post repeats the claim."
    new["updated_at"] = "2030-03-02T20:00:00Z"
    new["corrections"] = [{"at": "2030-03-02T20:00:00Z", "summary": "Reworded the lead."}]
    assert fast_path_reason(old, new) is None


def test_verified_changes_promotions_and_removals_need_the_full_path():
    old = _base()
    changed = copy.deepcopy(old)
    changed["items"][0]["action"] = "Upgrade now."
    assert "not an early signal" in fast_path_reason(old, changed)
    promoted = copy.deepcopy(old)
    promoted["items"][1]["verification"] = "verified"
    assert "not an early signal" in fast_path_reason(old, promoted)
    demoted = copy.deepcopy(old)
    demoted["items"][0] = {**demoted["items"][0], "verification": "early_signal"}
    assert "was verified before" in fast_path_reason(old, demoted)
    removed = copy.deepcopy(old)
    removed["items"].pop()
    assert "removed" in fast_path_reason(old, removed)
    featured = copy.deepcopy(old)
    featured["featured_item_ids"] = []
    assert "featured_item_ids" in fast_path_reason(old, featured)
    added_verified = copy.deepcopy(old)
    added_verified["items"].append(fx.item("other", "Other", cve="CVE-2030-20009"))
    assert "not an early signal" in fast_path_reason(old, added_verified)
    assert "new on main" in fast_path_reason(None, old)


def _seed_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    (repo / "data").mkdir()
    path = repo / "data" / f"{fx.DAY_TWO}.json"
    path.write_text(json.dumps(_base(), indent=2) + "\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "seed")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo, path


def test_fast_path_check_compares_with_origin_main(tmp_path):
    repo, path = _seed_repo(tmp_path)
    edition = json.loads(path.read_text())
    edition["items"].append(_lead())
    path.write_text(json.dumps(edition, indent=2) + "\n")
    (repo / "README.md").write_text("generated\n")
    assert fast_path_check(repo) is None
    (repo / "scripts.py").write_text("print()\n")
    assert "outside data" in fast_path_check(repo)
    (repo / "scripts.py").unlink()
    edition["items"][0]["action"] = "Upgrade now."
    path.write_text(json.dumps(edition, indent=2) + "\n")
    assert "not an early signal" in fast_path_check(repo)


def test_unchanged_editions_are_detected(tmp_path):
    repo, path = _seed_repo(tmp_path)
    assert not editions_changed(repo, [path])
    path.write_text(path.read_text().replace("New Server", "Newer Server"))
    assert editions_changed(repo, [path])


def test_a_run_with_no_edition_change_exits_cleanly_without_a_commit(tmp_path):
    """Runs against this checkout: the committed editions match HEAD only when untouched."""
    root = SCRIPT.parents[1]
    latest = sorted((root / "data").glob("????-??-??.json"))[-1]
    if editions_changed(root, [latest]):
        import pytest
        pytest.skip("the working copy has an edited edition")
    head = _git(root, "rev-parse", "HEAD")
    completed = subprocess.run([sys.executable, str(SCRIPT), "--dry-run", str(latest)], cwd=root, capture_output=True, text=True)
    assert completed.returncode == 0
    assert "Nothing to publish" in completed.stdout and "pytest" not in completed.stdout
    assert _git(root, "rev-parse", "HEAD") == head
