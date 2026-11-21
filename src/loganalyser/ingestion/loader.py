"""Load a CSV log file and check it.

``load_events`` never raises for bad input. It returns ``(events, validation)``:

* ``validation.errors``   the file cannot be analysed, and ``events`` is None.
* ``validation.warnings`` some rows were skipped; the rest is still returned.

The checks are: empty file, missing required columns, missing values and unreadable
timestamps. Skipped rows are reported with their file line numbers (the header is line 1).

``events`` has the columns in ``schema.NORMALISED_COLUMNS``: timestamps in UTC (timestamps
without an offset are treated as UTC), rows sorted by time with ties kept in file order, and
``event_id`` numbering the rows from 0 in that order.
"""
import csv
import io
from pathlib import Path
from typing import Optional

import pandas as pd

from .. import schema
from ..models import ValidationResult

MAX_LINES_SHOWN = 5
# A UTC offset ("Z", "+01:00", "-0500") after a time such as ":30" or ":30.5". Needing the
# time part stops a date-only value like "2026-03-02" being mistaken for one with an offset.
_OFFSET_AT_END = r":\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)$"


def _lines(numbers: list[int]) -> str:
    """'line 3' or 'lines 3, 5, 9 and 4 more'."""
    shown = ", ".join(str(n) for n in numbers[:MAX_LINES_SHOWN])
    more = len(numbers) - MAX_LINES_SHOWN
    return f"{'line' if len(numbers) == 1 else 'lines'} {shown}" + (f" and {more} more" if more > 0 else "")


def _rows(count: int) -> str:
    return f"{count} row" + ("" if count == 1 else "s")


def load_events(source) -> tuple[Optional[pd.DataFrame], ValidationResult]:
    """``source`` is a file path, or an open file such as a Streamlit upload."""
    result = ValidationResult()
    table = _read_table(source, result)
    events = _clean(table, result) if table is not None else None
    return events, result


def _read_table(source, result: ValidationResult) -> Optional[pd.DataFrame]:
    """Read the CSV into a table of strings plus a ``_line`` column, checking the header."""
    if isinstance(source, (str, Path)):
        data = Path(source).read_bytes()
    else:
        data = source.getvalue() if hasattr(source, "getvalue") else source.read()
    text = data if isinstance(data, str) else data.decode("utf-8-sig", errors="replace")  # also drops an Excel BOM

    reader = csv.reader(io.StringIO(text))
    header = next((row for row in reader if any(cell.strip() for cell in row)), None)
    if header is None:
        result.errors.append("The file is empty.")
        return None

    columns = [name.strip().lower() for name in header]
    missing = [name for name in schema.REQUIRED_COLUMNS if name not in columns]
    if missing:
        result.errors.append(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Found columns: {', '.join(columns)}. "
            f"Required columns are: {', '.join(schema.REQUIRED_COLUMNS)}."
        )
        return None

    records, lines = [], []
    for row in reader:
        if not any(cell.strip() for cell in row):
            continue  # blank line
        # A short row is padded so its absent fields show up as missing values below.
        records.append((row + [""] * len(columns))[: len(columns)])
        lines.append(reader.line_num)
    if not records:
        result.errors.append("The file has a header row but no data rows.")
        return None

    table = pd.DataFrame(records, columns=columns)
    keep = [name for name in schema.INPUT_COLUMNS if name in columns]
    return table[keep].apply(lambda column: column.str.strip()).assign(_line=lines)


def _parse_timestamps(values: pd.Series) -> pd.Series:
    """Parse ISO 8601 strings to UTC; naive values are taken to be UTC, bad values become NaT.

    Values with a UTC offset and values without one are parsed separately: pandas 2.x
    applies the first row's offset to naive rows when they are mixed in one column.
    """
    has_offset = values.str.contains(_OFFSET_AT_END, regex=True)
    parts = [
        pd.to_datetime(values[mask], format="ISO8601", utc=True, errors="coerce")
        for mask in (has_offset, ~has_offset)
        if mask.any()
    ]
    if not parts:  # no rows at all
        return pd.to_datetime(values, format="ISO8601", utc=True, errors="coerce")
    return pd.concat(parts).reindex(values.index)


def _skip(table: pd.DataFrame, bad: pd.Series, reason: str, result: ValidationResult, hint: str = ""):
    """Drop the rows flagged in ``bad`` and record one warning that says why."""
    if bad.any():
        lines = table.loc[bad, "_line"].tolist()
        result.warnings.append(f"Skipped {_rows(len(lines))} with {reason}: {_lines(lines)}.{hint}")
    return table[~bad]


def _clean(table: pd.DataFrame, result: ValidationResult) -> Optional[pd.DataFrame]:
    """Skip rows with missing values or bad timestamps and build the normalised events table."""
    for name in schema.REQUIRED_COLUMNS:
        table = _skip(table, table[name] == "", f"a missing '{name}' value", result)

    when = _parse_timestamps(table[schema.TIMESTAMP])
    bad = when.isna()
    hint = (
        f" Expected ISO 8601, for example 2026-03-02T09:15:42Z. First bad value: "
        f"{table.loc[bad, schema.TIMESTAMP].iloc[0]!r}."
        if bad.any() else ""
    )
    table = _skip(table.assign(**{schema.TIMESTAMP: when}), bad, "an unreadable timestamp", result, hint)

    if table.empty:
        result.errors.append("No usable rows remain after validation; see the warnings for what was skipped.")
        return None

    # The rules compare these as lower case, so "Failure" and "LOGIN" still match.
    table = table.assign(**{
        schema.EVENT_TYPE: table[schema.EVENT_TYPE].str.lower(),
        schema.OUTCOME: table[schema.OUTCOME].str.lower(),
    })

    # Optional columns always exist in the output; empty cells become missing values.
    for name in schema.OPTIONAL_COLUMNS:
        if name in table.columns:
            values = table[name].mask(table[name] == "")
        else:
            values = pd.Series([None] * len(table), index=table.index, dtype="object")
        table = table.assign(**{name: values})

    events = table.sort_values(schema.TIMESTAMP, kind="stable").reset_index(drop=True)
    events[schema.EVENT_ID] = range(len(events))
    return events[list(schema.NORMALISED_COLUMNS)]
