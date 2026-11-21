"""Plotly figures for the dashboard.

Outcome colours are fixed so a colour always means the same outcome, whatever is filtered out.
Severity uses one blue ramp, low to high.
"""
import pandas as pd
import plotly.graph_objects as go

OUTCOME_ORDER = ("success", "failure", "denied")
OUTCOME_COLORS = {"success": "#2a78d6", "failure": "#eb6834", "denied": "#1baf7a"}
SEVERITY_COLORS = {"low": "#86b6ef", "medium": "#2a78d6", "high": "#104281"}


def events_over_time_chart(counts: pd.DataFrame) -> go.Figure:
    """Stacked bars of events per time bucket, split by outcome. ``counts`` is analytics.events_over_time()."""
    fig = go.Figure()
    for outcome in OUTCOME_ORDER:
        part = counts[counts["outcome"] == outcome]
        if part.empty:
            continue
        fig.add_bar(
            x=part["time"],
            y=part["count"],
            name=outcome.title(),
            marker_color=OUTCOME_COLORS[outcome],
            hovertemplate=f"%{{x|%Y-%m-%d %H:%M}} UTC<br>{outcome.title()}: %{{y}}<extra></extra>",
        )
    fig.update_layout(
        barmode="stack",
        height=320,
        margin=dict(l=10, r=10, t=40, b=10),
        legend=dict(orientation="h", y=1.12, x=0, traceorder="normal"),
        xaxis_title="Time (UTC)",
        yaxis_title="Events",
    )
    return fig


def alerts_by_severity_chart(counts: pd.DataFrame) -> go.Figure:
    """One bar per severity with its count on top. ``counts`` is analytics.alerts_by_severity()."""
    fig = go.Figure(
        go.Bar(
            x=counts["severity"].str.title(),
            y=counts["count"],
            marker_color=[SEVERITY_COLORS[s] for s in counts["severity"]],
            text=counts["count"],
            textposition="outside",
            cliponaxis=False,
            hovertemplate="%{x}: %{y} alerts<extra></extra>",
        )
    )
    fig.update_layout(
        height=320,
        margin=dict(l=10, r=10, t=40, b=10),
        yaxis=dict(title="Alerts", rangemode="tozero", tickformat=",d"),
        showlegend=False,
    )
    return fig
