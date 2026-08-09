# Checks

| ID | Severity | What it proves |
|---|---|---|
| `INV_AWS_001` | CRITICAL | The candidate SCP/RCP denies every `(action, resource, principal)` request its reference (baseline or paired manifest entry) explicitly denied. |

Failing `INV_AWS_001`: review the counterexample. If the widened permission
is intentional, add a [`_suppressions`](suppressions.md) entry (or update
your own reference, for `regression`) and document why in the PR
description. If not, revert the `Condition`/`Resource`/`Action` change that
removed the denial.
