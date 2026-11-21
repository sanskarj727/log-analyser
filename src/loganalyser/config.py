"""Detection thresholds: one small dataclass per rule, with defaults in code.

The UI shows these values and lets the user change them. Why each default was
chosen is explained in docs/thresholds.md, as the brief requires.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FailedLoginConfig:
    """Rule 1: at least `min_failures` failed logins from one source within the window."""

    window_minutes: int = 5
    min_failures: int = 5


@dataclass(frozen=True)
class VolumeSpikeConfig:
    """Rule 2: more than `max_events` events from one source within the window."""

    window_minutes: int = 1
    max_events: int = 100


@dataclass(frozen=True)
class SuccessAfterFailuresConfig:
    """Rule 3: a successful login after at least `min_failures` failures within the window."""

    window_minutes: int = 10
    min_failures: int = 5


@dataclass(frozen=True)
class AppConfig:
    failed_logins: FailedLoginConfig = field(default_factory=FailedLoginConfig)
    volume_spike: VolumeSpikeConfig = field(default_factory=VolumeSpikeConfig)
    success_after_failures: SuccessAfterFailuresConfig = field(default_factory=SuccessAfterFailuresConfig)
