"""Runs the three rules, orders the alerts and numbers them."""
from dataclasses import replace

import pandas as pd

from ..config import AppConfig
from ..models import Alert
from .rules import event_volume_spike, failed_login_burst, success_after_failures


def run_detection(events: pd.DataFrame, config: AppConfig) -> list[Alert]:
    """Return all alerts, highest severity first, then by time, numbered A-001, A-002, ..."""
    alerts = (
        failed_login_burst(events, config.failed_logins)
        + event_volume_spike(events, config.volume_spike)
        + success_after_failures(events, config.success_after_failures)
    )
    alerts.sort(key=lambda a: (-a.severity, a.start_time, a.rule_id, a.source_ip or "", a.user or ""))
    return [replace(alert, alert_id=f"A-{n:03d}") for n, alert in enumerate(alerts, start=1)]
