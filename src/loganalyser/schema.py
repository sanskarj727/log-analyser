"""Event schema: the column names set out in the brief."""

TIMESTAMP = "timestamp"
SOURCE_IP = "source_ip"
EVENT_TYPE = "event_type"
OUTCOME = "outcome"
USER = "user"          # optional
SEVERITY = "severity"  # optional, as reported by the log source
EVENT_ID = "event_id"  # added by the normaliser, never read from the file

REQUIRED_COLUMNS = (TIMESTAMP, SOURCE_IP, EVENT_TYPE, OUTCOME)
OPTIONAL_COLUMNS = (USER, SEVERITY)
INPUT_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS

# The table every rule receives after normalisation: all input columns (optional ones
# present but possibly empty), timestamps in UTC, plus a unique event_id.
NORMALISED_COLUMNS = INPUT_COLUMNS + (EVENT_ID,)

