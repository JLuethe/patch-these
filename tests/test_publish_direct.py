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
