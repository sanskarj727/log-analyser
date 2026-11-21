# How the default thresholds were chosen

The defaults are starting points chosen against the two synthetic datasets in `data/sample/`.
They are not tuned for any real environment. Every value can be changed in the dashboard
sidebar (or in `src/loganalyser/config.py`), and the values that fired are shown on each alert.

The method is the same for each rule: find the busiest ordinary behaviour in `normal.csv`,
find the weakest attack in `suspicious.csv`, and set the threshold between them.

| Rule | Busiest normal behaviour | Weakest attack | Default |
|---|---|---|---|
| Repeated failed logins | 4 failures in 5 min (`bob`, a mistyped password) | 6 failures in 5 min (`203.0.113.50`) | 5 failures in 5 min |
| Unusual event volume | 60 events in 1 min (`192.0.2.50`, a backup job) | 150 events in 59 s (`203.0.113.30`, a scanner) | more than 100 in 1 min |
| Success after failures | 5 failures over 10 min, then a success 30 min later (`frank`) | 5 failures 2 min apart, then a success (`dave`, slow guessing) | 5 failures within 10 min |

## Repeated failed logins: 5 in 5 minutes

People mistype passwords, so one or two failures is normal. The sample's worst ordinary case is
four failures in a row, so 5 sits just above it. Lowering it to 4 would alert on that user.
Raising it to 7 or more would miss the smaller bursts in `suspicious.csv`. Five minutes is long
enough to catch a person or a script retrying, and short enough that unrelated failures
spread across a day do not add up.

## Unusual event volume: more than 100 in 1 minute

The backup job is the busiest ordinary source at 60 events in a minute, so the threshold needs
to be clearly above that to avoid alerting on routine automation. The scanner produces 150 in
under a minute. 100 leaves room on both sides. This rule is the weakest signal (volume alone says
nothing about intent), which is why it has the lowest severity.

## Success after failures: 5 failures within 10 minutes

This is the highest-severity rule because it describes a failed guessing run that may have
ended in access. The failure count matches the first rule so the two are easy to compare.
The 10-minute window is wider than 5 minutes so that slower guessing is still caught:
`dave` fails five times two minutes apart and succeeds, which the first rule misses.
The ordinary near-miss, `frank`, also fails five times spread over ten minutes but logs in 30
minutes after the last failure. That is well outside the window, so it does not alert.

## Limits of this approach

- The thresholds are tuned to a few hundred synthetic events, so they show the method rather
  than prove a value. Real logs need real baselines.
- One fixed value applies to every source. A busy server and a quiet laptop are treated alike.
- Setting a threshold just above the normal sample means an attacker who stays just under it
  is not detected.
- The `suspicious.csv` attacks were written to exercise the rules, so catching them says little
  about how the rules would perform on unseen activity.
