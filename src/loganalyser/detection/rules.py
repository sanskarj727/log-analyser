"""The three detection rules.

Each rule is a function ``(events, config) -> list[Alert]``. ``events`` is the
normalised table with columns ``timestamp`` (UTC), ``source_ip``, ``event_type``,
``outcome``, ``user`` (may be empty) and ``event_id``. Rules do not change the
table, use no randomness and read no clock, so the same input always gives the
same alerts. Alert text describes a matched pattern, not a confirmed compromise.
"""
from datetime import timedelta

import pandas as pd

from .. import schema
from ..config import FailedLoginConfig, SuccessAfterFailuresConfig, VolumeSpikeConfig
from ..models import Alert, Severity

FAILED_LOGIN_BURST = "failed_login_burst"
EVENT_VOLUME_SPIKE = "event_volume_spike"
SUCCESS_AFTER_FAILURES = "success_after_failures"


def _in_order(events: pd.DataFrame) -> pd.DataFrame:
    """Sort by time, then event_id, so equal timestamps are ordered the same way every run."""
    return events.sort_values([schema.TIMESTAMP, schema.EVENT_ID], kind="stable")


def _find_spans(times: list, window: timedelta, min_count: int) -> list[list[int]]:
    """Sliding window over the sorted ``times`` of ONE source.

    A window ending at time t holds the events in (t - window, t], so two events
    exactly ``window`` apart are not in the same window. A window with at least
    ``min_count`` events is "hot". Hot windows that share events are merged, so
    one burst gives one ``[first_index, last_index]`` span (and one alert).
    """
    spans: list[list[int]] = []
    left = 0
    for right, t in enumerate(times):
        while t - times[left] >= window:
            left += 1
        if right - left + 1 >= min_count:
            if spans and left <= spans[-1][1]:
                spans[-1][1] = right
            else:
                spans.append([left, right])
    return spans


def failed_login_burst(events: pd.DataFrame, cfg: FailedLoginConfig) -> list[Alert]:
    """At least ``min_failures`` failed logins from one source_ip within ``window_minutes``."""
    is_failed_login = (events[schema.EVENT_TYPE] == "login") & (events[schema.OUTCOME] == "failure")
    window = timedelta(minutes=cfg.window_minutes)

    alerts = []
    for ip, group in _in_order(events[is_failed_login]).groupby(schema.SOURCE_IP, sort=True):
        for first, last in _find_spans(group[schema.TIMESTAMP].tolist(), window, cfg.min_failures):
            rows = group.iloc[first : last + 1]
            alerts.append(Alert(
                rule_id=FAILED_LOGIN_BURST,
                rule_name="Repeated failed logins",
                severity=Severity.MEDIUM,
                start_time=rows[schema.TIMESTAMP].iloc[0],
                end_time=rows[schema.TIMESTAMP].iloc[-1],
                evidence_event_ids=tuple(int(i) for i in rows[schema.EVENT_ID]),
                description=(
                    f"{len(rows)} failed login attempts from {ip} "
                    f"(threshold: {cfg.min_failures} within {cfg.window_minutes} minutes). "
                    "This matches a pattern consistent with password guessing."
                ),
                thresholds={"window_minutes": cfg.window_minutes, "min_failures": cfg.min_failures},
                source_ip=ip,
            ))
    return alerts


def event_volume_spike(events: pd.DataFrame, cfg: VolumeSpikeConfig) -> list[Alert]:
    """More than ``max_events`` events (any type) from one source_ip within ``window_minutes``."""
    window = timedelta(minutes=cfg.window_minutes)

    alerts = []
    for ip, group in _in_order(events).groupby(schema.SOURCE_IP, sort=True):
        for first, last in _find_spans(group[schema.TIMESTAMP].tolist(), window, cfg.max_events + 1):
            rows = group.iloc[first : last + 1]
            alerts.append(Alert(
                rule_id=EVENT_VOLUME_SPIKE,
                rule_name="Unusual event volume",
                severity=Severity.LOW,
                start_time=rows[schema.TIMESTAMP].iloc[0],
                end_time=rows[schema.TIMESTAMP].iloc[-1],
                evidence_event_ids=tuple(int(i) for i in rows[schema.EVENT_ID]),
                description=(
                    f"{len(rows)} events from {ip} "
                    f"(threshold: more than {cfg.max_events} within {cfg.window_minutes} minutes). "
                    "This volume is unusual compared with that threshold and may be worth reviewing."
                ),
                thresholds={"window_minutes": cfg.window_minutes, "max_events": cfg.max_events},
                source_ip=ip,
            ))
    return alerts


def success_after_failures(events: pd.DataFrame, cfg: SuccessAfterFailuresConfig) -> list[Alert]:
    """A successful login after at least ``min_failures`` failures for the same source_ip
    and user, within ``window_minutes`` before the success.

    Only failures since the previous success count, and a success uses them up,
    so one run of failures gives one alert.
    """
    is_login_result = (events[schema.EVENT_TYPE] == "login") & events[schema.OUTCOME].isin(
        ["failure", "success"]
    )
    logins = _in_order(events[is_login_result]).assign(_user=lambda d: d[schema.USER].fillna(""))
    window = timedelta(minutes=cfg.window_minutes)

    alerts = []
    for (ip, user), group in logins.groupby([schema.SOURCE_IP, "_user"], sort=True):
        failures = []  # (time, event_id) of failures since the last success
        for when, event_id, outcome in zip(
            group[schema.TIMESTAMP], group[schema.EVENT_ID], group[schema.OUTCOME]
        ):
            if outcome == "failure":
                failures.append((when, int(event_id)))
                continue
            recent = [(t, i) for t, i in failures if when - t < window]
            if len(recent) >= cfg.min_failures:
                alerts.append(Alert(
                    rule_id=SUCCESS_AFTER_FAILURES,
                    rule_name="Success after repeated failures",
                    severity=Severity.HIGH,
                    start_time=recent[0][0],
                    end_time=when,
                    evidence_event_ids=tuple(i for _, i in recent) + (int(event_id),),
                    description=(
                        f"{len(recent)} failed logins from {ip} were followed by a successful login "
                        f"(threshold: {cfg.min_failures} failures within {cfg.window_minutes} minutes). "
                        "This is consistent with possible credential guessing and should be reviewed."
                    ),
                    thresholds={"window_minutes": cfg.window_minutes, "min_failures": cfg.min_failures},
                    source_ip=ip,
                    user=user or None,
                ))
            failures = []
    return alerts
