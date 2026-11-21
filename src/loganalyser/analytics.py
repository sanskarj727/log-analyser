"""Pure helpers for the dashboard: summary counts, chart data, filters and evidence.

Nothing here imports Streamlit, so all of it is unit-tested directly.
"""
import pandas as pd

from . import schema
from .models import Alert, Severity

TIME_BUCKET = "15min"  # width of each bar in the events-over-time chart


# --------------------------------------------------------------------------
# Summaries and chart data
# --------------------------------------------------------------------------
def events_over_time(events: pd.DataFrame) -> pd.DataFrame:
    """Event counts per time bucket and outcome: columns time, outcome, count."""
    if events.empty:
        return pd.DataFrame(columns=["time", "outcome", "count"])
    bucket = events[schema.TIMESTAMP].dt.floor(TIME_BUCKET).rename("time")
    counts = events.groupby([bucket, events[schema.OUTCOME].rename("outcome")]).size().rename("count")
    return counts.reset_index().sort_values(["time", "outcome"], ignore_index=True)


def event_type_counts(events: pd.DataFrame) -> pd.DataFrame:
    """Events per event type, most common first: columns event_type, count."""
    counts = events[schema.EVENT_TYPE].value_counts().rename_axis("event_type").reset_index(name="count")
    return counts.sort_values(["count", "event_type"], ascending=[False, True], ignore_index=True)


def alerts_by_severity(alerts: list[Alert]) -> pd.DataFrame:
    """Alert counts per severity, low to high, including zeros: columns severity, count."""
    counts = {severity.label: 0 for severity in Severity}
    for alert in alerts:
        counts[alert.severity.label] += 1
    return pd.DataFrame({"severity": list(counts), "count": list(counts.values())})


def alerts_table(alerts: list[Alert]) -> pd.DataFrame:
    """One row per alert, for display."""
    return pd.DataFrame(
        [
            {
                "alert_id": a.alert_id,
                "severity": a.severity.label,
                "rule": a.rule_name,
                "source_ip": a.source_ip,
                "user": a.user,
                "start_time": a.start_time,
                "end_time": a.end_time,
                "events": a.event_count,
            }
            for a in alerts
        ],
        columns=["alert_id", "severity", "rule", "source_ip", "user", "start_time", "end_time", "events"],
    )


def evidence(events: pd.DataFrame, alert: Alert) -> pd.DataFrame:
    """The event rows an alert is based on."""
    return events[events[schema.EVENT_ID].isin(alert.evidence_event_ids)]


# --------------------------------------------------------------------------
# Filters (these change what is shown; detection always uses every event)
# --------------------------------------------------------------------------
def filter_events(events: pd.DataFrame, event_types, source_text: str) -> pd.DataFrame:
    """Events of the chosen types from sources containing ``source_text``."""
    keep = events[schema.EVENT_TYPE].isin(event_types)
    if source_text.strip():
        keep &= events[schema.SOURCE_IP].str.contains(source_text.strip(), case=False, regex=False)
    return events[keep]


def filter_alerts(alerts: list[Alert], severities, source_text: str) -> list[Alert]:
    """Alerts with a chosen severity and a source containing ``source_text``."""
    needle = source_text.strip().lower()
    return [
        a
        for a in alerts
        if a.severity.label in severities and (not needle or needle in (a.source_ip or "").lower())
    ]
