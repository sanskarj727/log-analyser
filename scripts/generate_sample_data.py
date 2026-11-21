"""Generate the synthetic sample datasets and the expected detection results.

Run from the project root:   python scripts/generate_sample_data.py

All data is synthetic. IP addresses come from ranges reserved for documentation
(RFC 5737), so none can belong to a real network. Output is fully deterministic.

Expected alerts are derived from how each attack scenario is built (which events
belong to it), NOT by running the detection engine, so the tests check the engine
against an independent answer.

event_id convention: files are written in time order, so event_id is the 0-based
row number in the file.
"""
import csv
import io
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "sample"
DAY = datetime(2026, 3, 2, tzinfo=timezone.utc)

# Internal workstation addresses (192.0.2.0/24 and 198.51.100.0/24 are documentation ranges).
USER_IPS = {
    "alice": "198.51.100.11", "bob": "198.51.100.12", "carol": "198.51.100.13",
    "dave": "198.51.100.14", "erin": "198.51.100.15", "frank": "198.51.100.16",
}
BACKUP_IP = "192.0.2.50"
# Users whose first login of the day is scripted below (mistyped passwords).
SCRIPTED_LOGIN_TIME = {"bob": (8, 24), "carol": (8, 45), "dave": (8, 6)}


def at(hours, minutes=0, seconds=0):
    return DAY + timedelta(hours=hours, minutes=minutes, seconds=seconds)


def ev(when, ip, event_type, outcome, user="", groups=()):
    """One event. ``groups`` names the expected alerts this event is evidence for."""
    return dict(when=when, ip=ip, event_type=event_type, outcome=outcome, user=user, groups=list(groups))


# --------------------------------------------------------------------------
# Normal activity: must produce NO alerts, including these deliberate near-misses.
# --------------------------------------------------------------------------
def normal_events():
    rng = random.Random(42)
    events = []

    # Routine day for six users: login, ~20 resource accesses, logout.
    for user, ip in USER_IPS.items():
        if user in SCRIPTED_LOGIN_TIME:
            login_at = at(*SCRIPTED_LOGIN_TIME[user])
        else:
            login_at = at(8, rng.randint(0, 90), rng.randint(0, 59))
            events.append(ev(login_at, ip, "login", "success", user))
        logout_at = at(17, rng.randint(0, 59), rng.randint(0, 59))
        span = int((logout_at - login_at).total_seconds())
        for i in range(20):
            when = login_at + timedelta(seconds=rng.randint(60, span - 60))
            outcome = "denied" if i == 7 and user in ("alice", "dave") else "success"
            events.append(ev(when, ip, "access", outcome, user))
        events.append(ev(logout_at, ip, "logout", "success", user))

    # N1 bob forgets his password: 4 failures then success (below the 5-failure threshold).
    ip = USER_IPS["bob"]
    for h, m, s in [(8, 20, 5), (8, 21, 0), (8, 22, 10), (8, 23, 20)]:
        events.append(ev(at(h, m, s), ip, "login", "failure", "bob"))
    events.append(ev(at(8, 24), ip, "login", "success", "bob"))
    events.append(ev(at(8, 25), ip, "password_change", "success", "bob"))

    # N2 carol mistypes twice, then succeeds.
    ip = USER_IPS["carol"]
    events.append(ev(at(8, 43, 10), ip, "login", "failure", "carol"))
    events.append(ev(at(8, 44, 20), ip, "login", "failure", "carol"))
    events.append(ev(at(8, 45), ip, "login", "success", "carol"))

    # N3 dave: isolated single mistypes, each followed by a success.
    ip = USER_IPS["dave"]
    events.append(ev(at(8, 5, 30), ip, "login", "failure", "dave"))
    events.append(ev(at(8, 6), ip, "login", "success", "dave"))
    events.append(ev(at(14, 0), ip, "login", "failure", "dave"))
    events.append(ev(at(14, 0, 40), ip, "login", "success", "dave"))

    # N4 frank: 5 failures, but spread over 10 minutes (never 5 inside any 5-minute window),
    # and the success comes 30 minutes later, outside the 10-minute success-after-failures window.
    ip = USER_IPS["frank"]
    for h, m, s in [(12, 0, 0), (12, 2, 30), (12, 5, 0), (12, 7, 30), (12, 10, 0)]:
        events.append(ev(at(h, m, s), ip, "login", "failure", "frank"))
    events.append(ev(at(12, 40), ip, "login", "success", "frank"))

    # N5 erin (admin) is granted a privilege: a different event type, one event.
    events.append(ev(at(10, 15), USER_IPS["erin"], "privilege_change", "success", "erin"))

    # N6 nightly backup job: 60 events in under a minute. This is the busiest normal
    # minute, and it stays below the 100-event volume threshold.
    events.append(ev(at(1, 59, 30), BACKUP_IP, "login", "success", "svc_backup"))
    for i in range(60):
        events.append(ev(at(2, 0, i * 54 // 59), BACKUP_IP, "access", "success", "svc_backup"))
    events.append(ev(at(2, 5), BACKUP_IP, "logout", "success", "svc_backup"))
    return events


# --------------------------------------------------------------------------
# Attack scenarios: each one is designed to raise specific alerts (see EXPECTED).
# --------------------------------------------------------------------------
def attack_events():
    events = []

    # S1 brute force: 12 failures in under 2 minutes against one account, never succeeds.
    for i in range(12):
        events.append(ev(at(3, 10, i * 10), "203.0.113.10", "login", "failure", "admin", ["S1"]))

    # S2 guessing then success: 8 failures against erin, then a success from the same IP.
    for i in range(8):
        events.append(ev(at(11, 20, i * 20), "203.0.113.20", "login", "failure", "erin", ["S2_rule1", "S2_rule3"]))
    events.append(ev(at(11, 22, 40), "203.0.113.20", "login", "success", "erin", ["S2_rule3"]))

    # S3 scanner: 150 access attempts in 60 seconds, mostly denied, no username.
    for i in range(150):
        outcome = "success" if i % 5 == 0 else "denied"
        events.append(ev(at(13, 0, i * 59 // 149), "203.0.113.30", "access", outcome, "", ["S3"]))

    # S4 password spraying: one failure each against 10 accounts in under 4 minutes.
    targets = ["alice", "bob", "carol", "dave", "erin", "frank", "admin", "guest", "test", "svc_backup"]
    for i, user in enumerate(targets):
        events.append(ev(at(14, 30, i * 25), "203.0.113.40", "login", "failure", user, ["S4"]))

    # S5 two separate bursts from the same source, 12 hours apart.
    for hour, group in [(4, "S5a"), (16, "S5b")]:
        for i in range(6):
            events.append(ev(at(hour, 0, i * 10), "203.0.113.50", "login", "failure", "admin", [group]))

    # S6 slow guessing: 5 failures two minutes apart (no 5 inside any 5-minute window), then a success.
    for i in range(5):
        events.append(ev(at(15, i * 2), "203.0.113.60", "login", "failure", "dave", ["S6"]))
    events.append(ev(at(15, 9), "203.0.113.60", "login", "success", "dave", ["S6"]))
    return events


# One entry per alert the engine must raise on suspicious.csv.
EXPECTED = [
    dict(group="S1", rule_id="failed_login_burst", severity="medium", source_ip="203.0.113.10", user=None,
         scenario="S1 brute force on one account",
         note="12 failures in 110 seconds; no success, so rule 3 stays silent."),
    dict(group="S2_rule1", rule_id="failed_login_burst", severity="medium", source_ip="203.0.113.20", user=None,
         scenario="S2 guessing then success",
         note="8 failures from one source inside 5 minutes."),
    dict(group="S2_rule3", rule_id="success_after_failures", severity="high", source_ip="203.0.113.20", user="erin",
         scenario="S2 guessing then success",
         note="The same 8 failures followed by a success for the same user and source."),
    dict(group="S3", rule_id="event_volume_spike", severity="low", source_ip="203.0.113.30", user=None,
         scenario="S3 scanner",
         note="150 events in 59 seconds (threshold: more than 100 per minute). Not logins, so rule 1 is silent."),
    dict(group="S4", rule_id="failed_login_burst", severity="medium", source_ip="203.0.113.40", user=None,
         scenario="S4 password spraying",
         note="10 failures against 10 different accounts; grouping by source catches it. No success."),
    dict(group="S5a", rule_id="failed_login_burst", severity="medium", source_ip="203.0.113.50", user=None,
         scenario="S5 two bursts",
         note="First burst of 6 failures."),
    dict(group="S5b", rule_id="failed_login_burst", severity="medium", source_ip="203.0.113.50", user=None,
         scenario="S5 two bursts",
         note="Second burst, 12 hours later, is a separate alert, not merged with the first."),
    dict(group="S6", rule_id="success_after_failures", severity="high", source_ip="203.0.113.60", user="dave",
         scenario="S6 slow guessing then success",
         note="5 failures 2 minutes apart never trip rule 1, but rule 3 sees them within 10 minutes of the success."),
]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def in_time_order(events):
    return sorted(events, key=lambda e: e["when"])  # stable: ties keep insertion order


def to_csv(events):
    severity = {"success": "info", "failure": "low", "denied": "medium"}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["timestamp", "source_ip", "event_type", "outcome", "user", "severity"])
    for e in events:
        level = "high" if e["event_type"] == "privilege_change" else severity[e["outcome"]]
        writer.writerow([e["when"].strftime("%Y-%m-%dT%H:%M:%SZ"), e["ip"], e["event_type"],
                         e["outcome"], e["user"], level])
    return out.getvalue()


def expected_alerts(events):
    """Build expected alerts from scenario membership (independent of the engine)."""
    alerts = []
    for spec in EXPECTED:
        members = [(i, e) for i, e in enumerate(events) if spec["group"] in e["groups"]]
        alert = {k: spec[k] for k in ("scenario", "rule_id", "severity", "source_ip", "user", "note")}
        alert.update(
            start_time=min(e["when"] for _, e in members).isoformat(),
            end_time=max(e["when"] for _, e in members).isoformat(),
            event_count=len(members),
            evidence_event_ids=[i for i, _ in members],
        )
        alerts.append(alert)
    return sorted(alerts, key=lambda a: (a["start_time"], a["rule_id"]))


def render():
    """Return {filename: text} for every generated file."""
    normal = in_time_order(normal_events())
    suspicious = in_time_order(normal_events() + attack_events())
    expected = {"normal.csv": [], "suspicious.csv": expected_alerts(suspicious)}
    return {
        "normal.csv": to_csv(normal),
        "suspicious.csv": to_csv(suspicious),
        "expected_alerts.json": json.dumps(expected, indent=2) + "\n",
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT_DIR / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUT_DIR / name}")


if __name__ == "__main__":
    main()
