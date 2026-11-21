# AI-Powered Security Log Analyser

A small web app that reads synthetic security event logs, checks them for suspicious
authentication patterns using explainable rules, and shows the results with the evidence
behind each alert. This is a learning prototype, not a production security tool, and it
uses synthetic data only.

> **Status:** CSV loading and validation, the three detection rules, the sample datasets and the
> Streamlit dashboard are built. Demo notes and the reflection are still to come.

## Stack

| Choice | Why |
|---|---|
| Python 3.10+ | Strong data and testing libraries. |
| pandas | Time-window and grouping logic over CSV data. |
| Streamlit | Interactive dashboard with no frontend code. |
| Plotly | Charts with hover and filtering. |
| pytest | Unit tests for parsing and detection. |

Rules come first; any AI summary would be an optional extra, so the app works fully without it.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

No environment variables or secrets are needed.

## Run

```bash
streamlit run app.py
```

In the sidebar, choose a sample dataset or upload your own CSV, adjust the detection
thresholds, and filter by alert severity, event type or source. The page shows
summary counts, an events-over-time chart, an alerts-by-severity chart and a table of alerts.
Pick an alert to see why it fired, the thresholds it used and the log records behind it.
Filters change only what is displayed; detection always runs on every event.

## Test

```bash
pytest
```

The tests (18) cover:

- **Parsing** (`tests/test_ingestion.py`): a valid file loads in the normalised form, and
  timestamps with and without a UTC offset are converted to UTC.
- **Invalid input** (same file): an empty file, a missing required column, an unreadable
  timestamp and a missing value each give a clear error or a warning with line numbers.
- **Each rule** (`tests/test_rules.py`): below, at and above the threshold, the time window,
  and the engine's ordering and repeatable results.
- **Sample data** (`tests/test_sample_data.py`): `normal.csv` gives 0 alerts, `suspicious.csv`
  gives exactly the 8 alerts in `expected_alerts.json` with the same supporting records, and
  every rule fires at least once.

The dashboard has no automated tests; run `streamlit run app.py` and check it by eye.

## Event schema

| Column | Required | Notes |
|---|---|---|
| `timestamp` | Yes | ISO 8601, treated as UTC, e.g. `2026-03-02T09:15:42Z` |
| `source_ip` | Yes | Where the activity came from |
| `event_type` | Yes | `login`, `logout`, `access`, `password_change`, `privilege_change` |
| `outcome` | Yes | `success`, `failure` or `denied` |
| `user` | No | Account name; may be blank |
| `severity` | No | As reported by the log source |

The app adds an `event_id` (row number after sorting by time) so alerts can point back to
the exact records that triggered them.

## Input checks

`load_events` (in `src/loganalyser/ingestion/loader.py`) reads a CSV and never crashes on bad
input; it returns the cleaned events plus a list of errors and warnings.

| Problem | What happens |
|---|---|
| Empty file, or a header with no data rows | **Error**: nothing is analysed. |
| Missing required column | **Error** naming the column and listing the columns found. |
| Missing `timestamp`, `source_ip`, `event_type` or `outcome` value | Row skipped, **warning** naming the column and lines. A row that ends early counts as missing values. |
| Unreadable timestamp | Row skipped, **warning** with lines and the first bad value. |
| Every row skipped | **Error**; the warnings explain what was skipped. |

Line numbers match the file (the header is line 1). Timestamps are ISO 8601; values with a
UTC offset are converted to UTC and values without one are treated as UTC. Column names and
the `event_type` and `outcome` values are case-insensitive. Blank lines and extra columns are
ignored. Other problems, such as an unknown `outcome` value, are not checked.

## Detection rules

All thresholds are configurable in the dashboard sidebar (defaults live in
`src/loganalyser/config.py`). Why each default was chosen is in
[`docs/thresholds.md`](docs/thresholds.md).

| Rule | Fires when | Defaults | Severity |
|---|---|---|---|
| Repeated failed logins | at least N failed logins from one source in the window | 5 in 5 min | Medium |
| Unusual event volume | more than N events from one source in the window | 100 in 1 min | Low |
| Success after failures | a successful login follows at least N failures for the same source and user | 5 in 10 min | High |

Alerts describe a matched pattern, not a confirmed compromise.

## Sample data

`data/sample/` holds two synthetic datasets (IP addresses come from ranges reserved for
documentation) and the alerts each should produce:

- `normal.csv`: an ordinary working day, including near-misses. Expected: no alerts.
- `suspicious.csv`: the same day plus six attack scenarios. Expected: 8 alerts, listed in
  `expected_alerts.json`.

Regenerate them with `python scripts/generate_sample_data.py`. The generator uses a fixed
seed and no clock, so every run reproduces the files byte for byte.

## Project layout

```
app.py                         Streamlit entry point
src/loganalyser/
    schema.py                  column names
    models.py                  Severity, Alert, ValidationResult
    config.py                  detection thresholds
    ingestion/loader.py        CSV loading, validation, normalisation
    detection/
        rules.py               the three rules
        engine.py              runs the rules, orders and numbers alerts
    analytics.py               summaries, filters and evidence lookup for the dashboard
    charts.py                  the two Plotly charts
docs/thresholds.md             why the default thresholds were chosen
data/sample/                   synthetic datasets and expected results
scripts/                       sample data generator
tests/                         parsing, invalid input, each rule, sample data
```

## Known limitations

- Fixed thresholds know nothing about what is normal for a given source, so a busy server and
  a quiet laptop are treated alike.
- "Low and slow" attacks that stay under the thresholds are not detected.
- Success-after-failures matches on source and user, so spraying across many accounts that ends
  in one success is not caught by that rule.
- The whole file is held in memory, so very large logs will be slow.
- The loader checks only the four things listed under "Input checks". Unknown `outcome` or
  `event_type` values, duplicate column names and non-UTF-8 files are not checked. An unknown
  outcome is never treated as a failure, so it cannot trigger an alert, but it is also not
  reported.
