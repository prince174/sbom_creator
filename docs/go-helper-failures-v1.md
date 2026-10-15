# R54: passive Go reader negative inputs

Date: 2026-10-15. Frozen helper checks only; runtime unchanged.

Hypothesis: malformed and over-budget inputs fail under bounded invocation,
while a valid source with a panicking init function can still be parsed without
running project code.

The existing Windows helpers rejected four deterministic temporary fixtures:
non-Go executable bytes, a 64 MiB + 1 byte binary, malformed Go imports and a
Go source file larger than 1 MiB. Each subprocess had a five-second timeout and
4 KiB output limit. Rejection means a failed invocation, not a dependency count
of zero. The valid source with `init(){panic(...)}` returned the expected `fmt`
import and root main directory. [Results and timings](go-helper-failures-v1.json).

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_helper_failures.py
.venv/Scripts/ruff.exe check benchmarks/check_go_helper_failures.py
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_acquire.py benchmarks/test_go_g2_context.py -q
```

Ruff passed; 40 tests passed and one platform-specific test was skipped. The
acquisition suite includes subprocess output-limit and timeout checks. No helper
or frozen classifier source changed. Temporary fixtures were removed.

Limits: deterministic examples only, not fuzzing, memory profiling or a general
parser-security proof. Binary reader's internal 64 MiB ceiling remains distinct
from the experimental acquisition planner's stricter 32 MiB ceiling. No new
direct accuracy or corpus coverage claim follows from these checks.
Next: assess eligibility and explicit UNKNOWN reasons across the original Go
corpus before production adoption; keep new paired reference builds separate
from known-fixture replay.
