# Proposal: suppressions outside the policy JSON

Status: **proposal, not implemented.** For Isaac to decide. Nothing in this
document changes current behaviour.

## Problem

Today a suppression is a top-level `_suppressions` array inside the
candidate policy file (see [Suppressions](../suppressions.md)). Invariant
strips the key before solving, but nothing else does. Landing Zone
Accelerator deploys `service-control-policies/`, `rcp-policies/` and
`iam-policies/` files to AWS as they are, and AWS policy documents only
accept `Version`, `Id` and `Statement` at the top level. A file carrying
`_suppressions` would most likely be rejected at deploy time. So on an LZA
config, which is the main target, suppressions can't be used at all.

Two more gaps in the current mechanism (from IS-09 on the spec):

- `reason` is documented but not enforced. Only `check_id` is read.
- A suppression covers a check for the whole file, for good. If the file is
  later widened further, the existing suppression silently covers the new
  widening too.

## Proposed design

### A file next to the config, not inside it

One JSON file, by default `.invariant/suppressions.json` at the repository
root. `--suppressions PATH` on `run`, `scan` and `regression` overrides the
location. A missing default file means no suppressions. A missing file that
was named explicitly is an error (exit 2), so a typo can't silently turn
suppression off in the other direction.

```json
{
  "version": 1,
  "suppressions": [
    {
      "check_id": "INV_AWS_003",
      "path": "modules/base/default/iam-policies/sample-end-user-policy.json",
      "sid": "AllowEndUserIamOutsideAccelerator",
      "reason": "SEC-412: end-user boundary grants these outside the accelerator prefix by design",
      "statement_sha256": "3f1c…",
      "expires": "2027-05-01"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `check_id` | yes | One check ID. No wildcards. |
| `path` | yes | Candidate file, relative to the directory holding `.invariant/` (the repository root), with `/` separators. Exact match; no globs in version 1. |
| `reason` | yes | Non-empty. A ticket or decision reference is expected. Enforced: an entry without one is an error. |
| `sid` | no | Limits the suppression to findings whose reported statement (the SARIF region's statement) has this `Sid`. Without it, the whole file is covered for that check. |
| `statement_sha256` | no | SHA-256 of the suppressed statement in canonical JSON (sorted keys, no whitespace). If the statement changes, the suppression lapses and the finding fails again, with a note saying why. |
| `expires` | no | ISO date. After it, the suppression lapses the same way. |

The policy files stay exactly what LZA deploys. The suppression file sits
outside the scanned directories, so discovery never mistakes it for a
policy.

### Behaviour

- A suppressed check is reported the way it is today: a `SKIPPED … (suppressed: <reason>)`
  note, counted in the skip total, never as a pass. The JSON report keeps it
  as a skip record with the entry's `reason`.
- A lapsed entry (statement changed, or expired) doesn't suppress, and the
  CLI notes it.
- An entry that matched nothing in the run is listed as unused (a note, not
  a failure), so stale entries get cleaned up.
- An invalid file (bad JSON, unknown `version`, missing `check_id`, `path`
  or `reason`) is an error with exit code 2. It never means "no
  suppressions".
- Suppression only changes reporting. It never changes the policy handed
  to the solver or the predicates (as IS-09 requires today).

### SARIF

Two options:

1. Leave suppressed findings out of SARIF, as today.
2. Emit them with SARIF's `suppressions` property
   (`[{"kind": "external", "justification": "<reason>"}]`), so the record
   of what was suppressed, and why, travels with the report.

Option 2 keeps the audit trail. How GitHub and GitLab display results that
carry `suppressions` would need checking on a real pipeline first.

### Helper (optional)

`invariant suppress --check INV_AWS_003 --file PATH --sid SID --reason "…"`
would append an entry with `statement_sha256` filled in from the current
file, so nobody has to compute hashes by hand.

## Migration of `_suppressions`

Options:

- **A (recommended):** keep reading `_suppressions` for one more minor
  release, with a deprecation warning on stderr that names the file, then
  remove it. Non-LZA users who never deploy the files directly keep working
  in the meantime.
- **B:** keep both permanently. That leaves two places to audit.
- **C:** remove it in the same release as the new file. Simplest, but it
  breaks anyone who uses it today.

## Decisions needed

1. File location and name (`.invariant/suppressions.json`?) and whether
   `--suppressions` is enough to override it.
2. Whether `statement_sha256` and `expires` are optional (as above) or
   required for some checks. For example, require `statement_sha256` for
   INV_AWS_001 and INV_AWS_002, where a later widening is the main risk.
3. SARIF option 1 or 2.
4. Migration option A, B or C.
5. Whether unused entries should ever fail the run (for example, behind
   `--strict-suppressions`).

## Acceptance (once approved)

Tests for: matching by path, check and `sid`; a missing `reason` rejected;
a lapsed entry on statement change and on expiry; unused entries reported;
invalid files exiting 2; a missing default file meaning none; a missing
explicit file being an error; suppression never altering solver input; and
an LZA config with suppressions whose policy files are byte-identical to
upstream. Docs updated: Suppressions page, README, CLI reference, check
remediation text (INV_AWS_003 currently says "add a _suppressions entry").
Spec IS-09 updated.
