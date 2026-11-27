"""Backup feeds trigger: window and dispatch decision. No network."""
from datetime import datetime, timezone

from dispatch_feeds_backup import decide, in_window

NOW = datetime(2026, 11, 27, 17, 0, tzinfo=timezone.utc)  # 9:00 AM PT


def run(minutes_ago, status="completed", conclusion="success", event="schedule", run_id=1):
    start = NOW.timestamp() - minutes_ago * 60
    return {"id": run_id, "status": status, "conclusion": conclusion, "event": event,
            "created_at": datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def test_window_is_six_am_to_eleven_pm_pacific():
    assert in_window(datetime(2026, 11, 27, 14, 0, tzinfo=timezone.utc))      # 6:00 AM PT
    assert not in_window(datetime(2026, 11, 27, 13, 58, tzinfo=timezone.utc))  # 5:58 AM PT
    assert in_window(datetime(2026, 11, 28, 7, 0, tzinfo=timezone.utc))       # 11:00 PM PT
    assert not in_window(datetime(2026, 11, 28, 7, 28, tzinfo=timezone.utc))  # 11:28 PM PT


def test_skip_when_a_run_is_active_or_recent_and_dispatch_otherwise():
    assert decide([run(2, status="in_progress", conclusion=None)], NOW)[0] is False
    assert decide([run(90, status="queued", conclusion=None)], NOW)[0] is False
    assert decide([run(15)], NOW)[0] is False
    assert decide([run(25), run(60)], NOW)[0] is True
    assert decide([run(25, conclusion="failure")], NOW)[0] is True
    assert decide([], NOW)[0] is True
