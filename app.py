"""Streamlit dashboard: pick or upload a dataset, set thresholds, explore events and alerts."""
from pathlib import Path

import pandas as pd
import streamlit as st

from loganalyser import analytics, charts, schema
from loganalyser.config import (
    AppConfig,
    FailedLoginConfig,
    SuccessAfterFailuresConfig,
    VolumeSpikeConfig,
)
from loganalyser.detection.engine import run_detection
from loganalyser.ingestion.loader import load_events
from loganalyser.models import Severity

SAMPLE_DIR = Path(__file__).parent / "data" / "sample"
SAMPLES = {"Sample: suspicious activity": "suspicious.csv", "Sample: normal activity": "normal.csv"}
UPLOAD = "Upload a CSV"
DEFAULTS = AppConfig()

st.set_page_config(page_title="Security Log Analyser", layout="wide")


def utc_text(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------
# Sidebar: data, thresholds, filters
# --------------------------------------------------------------------------
def choose_data():
    st.sidebar.header("Data")
    choice = st.sidebar.radio("Dataset", [*SAMPLES, UPLOAD], key="dataset")
    if choice == UPLOAD:
        upload = st.sidebar.file_uploader("CSV file", type="csv", key="upload")
        if upload is None:
            st.info(
                "Upload a CSV with the columns timestamp, source_ip, event_type and outcome "
                "(optional: user, severity), or choose a sample dataset in the sidebar."
            )
            st.stop()
        return load_events(upload)
    return load_events(SAMPLE_DIR / SAMPLES[choice])


def choose_thresholds() -> AppConfig:
    st.sidebar.header("Detection thresholds")
    fl, vs, sf = DEFAULTS.failed_logins, DEFAULTS.volume_spike, DEFAULTS.success_after_failures
    with st.sidebar.expander("Repeated failed logins", expanded=True):
        fl_min = st.number_input("Failures that trigger", 1, 10_000, fl.min_failures, key="fl_min")
        fl_win = st.number_input("Within (minutes)", 1, 1_440, fl.window_minutes, key="fl_win")
    with st.sidebar.expander("Unusual event volume", expanded=True):
        vs_max = st.number_input("More than (events)", 1, 1_000_000, vs.max_events, key="vs_max")
        vs_win = st.number_input("Within (minutes)", 1, 1_440, vs.window_minutes, key="vs_win")
    with st.sidebar.expander("Success after failures", expanded=True):
        sf_min = st.number_input("Failures before the success", 1, 10_000, sf.min_failures, key="sf_min")
        sf_win = st.number_input("Within (minutes)", 1, 1_440, sf.window_minutes, key="sf_win")
    return AppConfig(
        failed_logins=FailedLoginConfig(window_minutes=fl_win, min_failures=fl_min),
        volume_spike=VolumeSpikeConfig(window_minutes=vs_win, max_events=vs_max),
        success_after_failures=SuccessAfterFailuresConfig(window_minutes=sf_win, min_failures=sf_min),
    )


def choose_filters(events: pd.DataFrame):
    st.sidebar.header("Filters")
    st.sidebar.caption("Filters change what is shown. Detection always runs on every event.")
    severities = st.sidebar.multiselect(
        "Alert severity", [s.label for s in Severity], default=[s.label for s in Severity], key="f_severity"
    )
    types = sorted(events[schema.EVENT_TYPE].unique())
    event_types = st.sidebar.multiselect("Event type", types, default=types, key="f_types")
    source_text = st.sidebar.text_input("Source contains", key="f_source", placeholder="e.g. 203.0.113")
    return severities, event_types, source_text


# --------------------------------------------------------------------------
# Main page
# --------------------------------------------------------------------------
def show_validation(validation) -> None:
    for message in validation.errors:
        st.error(message)
    if validation.warnings:
        with st.expander(f"{len(validation.warnings)} warning(s): some rows were skipped or noted", expanded=True):
            for message in validation.warnings:
                st.warning(message)


def show_alert_details(alert, events: pd.DataFrame) -> None:
    st.subheader(f"{alert.alert_id}: {alert.rule_name}")
    st.write(alert.description)
    severity, count, source, user = st.columns(4)
    severity.metric("Severity", alert.severity.label.title())
    count.metric("Matching events", alert.event_count)
    source.metric("Source", alert.source_ip or "-")
    user.metric("User", alert.user or "-")
    st.caption(f"Time range: {utc_text(alert.start_time)} to {utc_text(alert.end_time)}")
    st.caption("Thresholds that triggered this alert")
    st.dataframe(pd.DataFrame([alert.thresholds]), hide_index=True)
    st.caption(f"Supporting log records ({alert.event_count})")
    st.dataframe(analytics.evidence(events, alert), hide_index=True)
    st.caption("A rule match is a pattern worth reviewing, not a confirmed compromise.")


def main() -> None:
    st.title("AI-Powered Security Log Analyser")
    st.caption("Learning prototype using synthetic data only. Not a production security tool.")

    events, validation = choose_data()
    show_validation(validation)
    if events is None:
        st.stop()

    config = choose_thresholds()
    severities, event_types, source_text = choose_filters(events)

    alerts = run_detection(events, config)
    view = analytics.filter_events(events, event_types, source_text)
    shown = analytics.filter_alerts(alerts, severities, source_text)

    total, alert_count, kinds = st.columns(3)
    total.metric("Total events", f"{len(events):,}")
    alert_count.metric("Alerts", len(alerts))
    kinds.metric("Event types", events[schema.EVENT_TYPE].nunique())
    st.caption(f"Showing {len(view):,} of {len(events):,} events and {len(shown)} of {len(alerts)} alerts after filters.")

    over_time, by_severity, by_type = st.columns([3, 2, 2])
    counts = analytics.events_over_time(view)
    with over_time:
        st.subheader("Events over time")
        st.plotly_chart(charts.events_over_time_chart(counts), config={"displayModeBar": False})
    with by_severity:
        st.subheader("Alerts by severity")
        st.plotly_chart(charts.alerts_by_severity_chart(analytics.alerts_by_severity(shown)), config={"displayModeBar": False})
    with by_type:
        st.subheader("Events by type")
        st.dataframe(analytics.event_type_counts(view), hide_index=True)

    st.header("Alerts")
    if not alerts:
        st.info("No detection rules matched in this dataset.")
    elif not shown:
        st.info("No alerts match the current filters.")
    else:
        st.dataframe(analytics.alerts_table(shown), hide_index=True)
        by_id = {a.alert_id: a for a in shown}
        chosen = st.selectbox(
            "Inspect an alert",
            list(by_id),
            format_func=lambda i: f"{i}  |  {by_id[i].severity.label.title()}  |  {by_id[i].rule_name}  |  {by_id[i].source_ip}",
            key="alert_choice",
        )
        show_alert_details(by_id[chosen], events)


main()
