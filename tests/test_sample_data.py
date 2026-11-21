"""Check the detection engine against the sample datasets and their expected results."""
import json
from pathlib import Path

from loganalyser.config import AppConfig
from loganalyser.detection.engine import run_detection
from loganalyser.ingestion.loader import load_events

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample"
COMPARED = ("rule_id", "severity", "source_ip", "user", "start_time", "end_time", "event_count", "evidence_event_ids")


def load(name):
    """Load through the real loader; the sample files must load with no errors or warnings."""
    events, validation = load_events(SAMPLE / name)
    assert validation.ok and validation.warnings == []
    return events


def key(alert):
    return (alert["rule_id"], alert["source_ip"], alert["start_time"])


def test_normal_dataset_raises_no_alerts():
    assert run_detection(load("normal.csv"), AppConfig()) == []


def test_suspicious_dataset_raises_exactly_the_expected_alerts():
    expected = json.loads((SAMPLE / "expected_alerts.json").read_text())["suspicious.csv"]
    actual = [a.to_dict() for a in run_detection(load("suspicious.csv"), AppConfig())]

    assert len(actual) == len(expected) == 8
    for got, want in zip(sorted(actual, key=key), sorted(expected, key=key)):
        assert {k: got[k] for k in COMPARED} == {k: want[k] for k in COMPARED}


def test_every_rule_fires_on_the_suspicious_dataset():
    alerts = run_detection(load("suspicious.csv"), AppConfig())
    assert {a.rule_id for a in alerts} == {"failed_login_burst", "event_volume_spike", "success_after_failures"}
