import pandas as pd

from loganalyser.config import (
    AppConfig,
    FailedLoginConfig,
    SuccessAfterFailuresConfig,
    VolumeSpikeConfig,
)
from loganalyser.detection.engine import run_detection
from loganalyser.detection.rules import event_volume_spike, failed_login_burst, success_after_failures
from loganalyser.models import Severity

BASE = pd.Timestamp("2026-03-02T09:00:00Z")
COLUMNS = ["timestamp", "source_ip", "event_type", "outcome", "user", "event_id"]
A, B = "203.0.113.10", "203.0.113.11"


def make_events(rows):
    """rows: (minutes_after_start, ip, event_type, outcome, user). event_id = row number."""
    data = [
        dict(timestamp=BASE + pd.Timedelta(minutes=m), source_ip=ip, event_type=et,
             outcome=oc, user=user, event_id=i)
        for i, (m, ip, et, oc, user) in enumerate(rows)
    ]
    return pd.DataFrame(data, columns=COLUMNS)


def fails(minutes, ip=A, user="alice"):
    return [(m, ip, "login", "failure", user) for m in minutes]


# ------------------------------------------------- Rule 1: failed logins
FL = FailedLoginConfig(window_minutes=5, min_failures=5)


def test_below_threshold_gives_no_alert():
    assert failed_login_burst(make_events(fails([0, 1, 2, 3])), FL) == []


def test_at_threshold_gives_alert_with_evidence_and_time_range():
    alerts = failed_login_burst(make_events(fails([0, 1, 2, 3, 4])), FL)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence_event_ids == (0, 1, 2, 3, 4) and alert.event_count == 5
    assert alert.source_ip == A
    assert alert.start_time == BASE and alert.end_time == BASE + pd.Timedelta(minutes=4)
    assert alert.severity is Severity.MEDIUM
    assert alert.thresholds == {"window_minutes": 5, "min_failures": 5}


def test_failures_spread_beyond_the_window_do_not_fire():
    assert failed_login_burst(make_events(fails([0, 2, 4, 6, 8])), FL) == []


# ------------------------------------------------- Rule 2: volume spike
VS = VolumeSpikeConfig(window_minutes=1, max_events=5)


def burst(n, ip=A):
    return [(i * 0.1, ip, "access", "success", "alice") for i in range(n)]


def test_volume_at_the_maximum_does_not_fire_but_one_more_does():
    assert event_volume_spike(make_events(burst(5)), VS) == []
    alerts = event_volume_spike(make_events(burst(6)), VS)
    assert len(alerts) == 1 and alerts[0].event_count == 6
    assert alerts[0].severity is Severity.LOW


# ----------------------------------- Rule 3: success after failures
SF = SuccessAfterFailuresConfig(window_minutes=10, min_failures=5)


def test_success_after_enough_failures_fires_with_all_evidence():
    rows = fails([0, 1, 2, 3, 4]) + [(5, A, "login", "success", "alice")]
    alerts = success_after_failures(make_events(rows), SF)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence_event_ids == (0, 1, 2, 3, 4, 5)
    assert alert.severity is Severity.HIGH and alert.user == "alice" and alert.source_ip == A
    assert alert.start_time == BASE and alert.end_time == BASE + pd.Timedelta(minutes=5)
    assert "compromise" not in alert.description.lower()


def test_too_few_failures_before_the_success():
    rows = fails([0, 1, 2, 3]) + [(4, A, "login", "success", "alice")]
    assert success_after_failures(make_events(rows), SF) == []


def test_failures_older_than_the_window_do_not_count():
    rows = fails([0, 1, 2, 3, 4]) + [(20, A, "login", "success", "alice")]
    assert success_after_failures(make_events(rows), SF) == []


# ------------------------------------------------------------- Engine
def mixed_events():
    rows = fails([0, 1, 2, 3, 4], ip=A) + [(5, A, "login", "success", "alice")]  # rules 1 and 3
    rows += fails([30, 31, 32, 33, 34], ip=B, user="carol")                       # rule 1 only
    return make_events(rows)


def test_engine_orders_by_severity_then_time_and_numbers_alerts():
    alerts = run_detection(mixed_events(), AppConfig())
    assert [a.alert_id for a in alerts] == ["A-001", "A-002", "A-003"]
    assert [a.severity for a in alerts] == [Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM]
    assert [a.rule_id for a in alerts] == ["success_after_failures", "failed_login_burst", "failed_login_burst"]


def test_engine_gives_identical_results_regardless_of_row_order():
    events = mixed_events()
    shuffled = events.sample(frac=1, random_state=3).reset_index(drop=True)
    assert [a.to_dict() for a in run_detection(events, AppConfig())] == \
           [a.to_dict() for a in run_detection(shuffled, AppConfig())]
