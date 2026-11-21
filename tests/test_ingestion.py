import io

import pandas as pd

from loganalyser import schema
from loganalyser.ingestion.loader import load_events

HEADER = "timestamp,source_ip,event_type,outcome,user,severity\n"
GOOD = "2026-03-02T09:00:00Z,203.0.113.10,login,failure,alice,low\n"


def load(body, header=HEADER):
    return load_events(io.BytesIO((header + body).encode("utf-8")))


def utc(text):
    return pd.Timestamp(text, tz="UTC")


# ------------------------------------------------------------ valid files
def test_valid_file_loads_in_normalised_form():
    events, validation = load(
        "2026-03-02T09:05:00Z,203.0.113.10,login,success,alice,info\n" + GOOD
    )
    assert validation.ok and validation.warnings == []
    assert list(events.columns) == list(schema.NORMALISED_COLUMNS)
    assert str(events["timestamp"].dt.tz) == "UTC"
    # Sorted by time, and event_id numbers the rows in that order.
    assert list(events["timestamp"]) == [utc("2026-03-02 09:00"), utc("2026-03-02 09:05")]
    assert list(events["event_id"]) == [0, 1]
    assert list(events["outcome"]) == ["failure", "success"]


# ------------------------------------------------------- whole-file errors
def test_empty_uploads_are_rejected():
    for data in (b"", b"  \n\n \n", b",,,\n"):
        events, validation = load_events(io.BytesIO(data))
        assert events is None and validation.errors == ["The file is empty."]


def test_missing_required_column_names_it_and_lists_what_was_found():
    events, validation = load_events(io.BytesIO(
        b"timestamp,source_ip,event_type\n2026-03-02T09:00:00Z,203.0.113.10,login\n"
    ))
    assert events is None and not validation.ok
    message = validation.errors[0]
    assert "outcome" in message and "Found columns: timestamp, source_ip, event_type" in message


# ----------------------------------------------------- malformed records
def test_unreadable_timestamps_are_skipped_with_line_numbers_and_an_example():
    events, validation = load(
        GOOD
        + "not-a-time,203.0.113.10,login,failure,alice,low\n"        # line 3
        + GOOD
        + "03/02/2026 09:00,203.0.113.10,login,failure,alice,low\n"  # line 5
    )
    assert len(events) == 2 and validation.ok
    warning = validation.warnings[0]
    assert "2 rows" in warning and "lines 3, 5" in warning and "'not-a-time'" in warning
    assert "ISO 8601" in warning


def test_timestamps_are_converted_to_utc_and_naive_ones_are_treated_as_utc():
    # Offsets, "Z", naive values and a date-only value mixed in one file, in any order.
    events, validation = load(
        "2026-03-02T10:00:00+01:00,203.0.113.10,login,success,a,info\n"
        "2026-03-02T09:30:00,203.0.113.10,login,success,b,info\n"
        "2026-03-02 09:45:00,203.0.113.10,login,success,c,info\n"
        "2026-03-02T10:00:00-05:00,203.0.113.10,login,success,d,info\n"
        "2026-03-02T09:10:00Z,203.0.113.10,login,success,e,info\n"
        "2026-03-02,203.0.113.10,login,success,f,info\n"
    )
    assert validation.warnings == []
    assert dict(zip(events["user"], events["timestamp"])) == {
        "f": utc("2026-03-02 00:00"),  # date only = midnight UTC
        "a": utc("2026-03-02 09:00"),  # 10:00 at +01:00
        "e": utc("2026-03-02 09:10"),
        "b": utc("2026-03-02 09:30"),  # naive, taken as UTC
        "c": utc("2026-03-02 09:45"),
        "d": utc("2026-03-02 15:00"),  # 10:00 at -05:00
    }
    assert list(events["user"]) == ["f", "a", "e", "b", "c", "d"]  # sorted by UTC time


def test_missing_required_values_are_skipped_and_named():
    events, validation = load(GOOD + "2026-03-02T09:01:00Z,,login,failure,alice,low\n")  # line 3
    assert len(events) == 1
    assert "missing 'source_ip' value" in validation.warnings[0] and "line 3" in validation.warnings[0]
