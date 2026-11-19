# The program return values corresponding to failure(s) encountered, warning(s) encountered, connection errors, and no problems found, respectively.
FAILURE = 3
WARNING = 2
CONNECTION_ERROR = 1
GOOD = 0
UNKNOWN_ERROR = -1

# Extended return values used by historical baseline comparisons (see ssh_audit/baseline.py).  These are intentionally larger than the legacy values so that, when a baseline is in use, a regression or an incomparable result is never masked by an ordinary failure/warning.
REGRESSION = 4        # One or more security regressions (after exceptions were applied) were found relative to the baseline.
EXCEPTION_ONLY = 5    # No regressions remain, but at least one candidate regression was suppressed by a registered, unexpired exception.
INCOMPARABLE = 6      # The baseline cannot be compared against the current scan (corrupt/unknown baseline, incomplete scan, or incompatible software fingerprint).
