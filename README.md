# Invariant

SMT-based guardrail SAST for AWS Service Control Policies (SCPs), Resource
Control Policies (RCPs), and IAM identity/permission-boundary policies.
Instead of pattern-matching JSON, Invariant hands your policies to the
[Z3](https://github.com/Z3Prover/z3) theorem prover and asks precise
questions like:

> Is there any `(action, resource, principal)` request that used to be
> denied, but isn't anymore?

> Does this IAM policy grant a known privilege-escalation primitive
> (`iam:PassRole`, `iam:CreatePolicyVersion`, ...) on some resource, once
> every `NotAction`/`NotResource`/`Condition` clause is accounted for?

If Z3 finds one, that's a finding, and you get a concrete counterexample
(the exact action/resource it found) instead of a vague warning.

## Why

Checkov, Semgrep, and LZA's own config validation are great at "does this
statement look dangerous" or "is this config file well-formed" — but none of
them reason about the *semantics* of a policy edit:

- Checkov/cfn-nag pattern-match individual statements. They can flag a bare
  `"Action": "iam:*"`, but can't tell you whether a *combination* of
  `NotAction`/`NotResource`/`Condition` clauses across several statements
  still leaves a dangerous action reachable — or whether editing a
  `Condition` block quietly widened who a `Deny` (or narrowed who an
  `Allow`) applies to. That requires reasoning about the full set of
  requests a policy allows, not just its syntax.
- Semgrep is a general-purpose structural pattern matcher. It's excellent at
  "this shape of statement appears in this file," but has no model of IAM's
  `Allow`/`Deny`/`Condition` evaluation semantics, so it can't prove
  anything about the *set of requests* a policy resolves to.
- **LZA-Validate** (the Landing Zone Accelerator's own config validation)
  checks that your config is well-formed and internally consistent against
  the LZA schema — it's a schema/lint layer, not a security-property prover.
  It won't tell you that a permission-boundary edit just made
  `iam:CreateRole` reachable without a boundary, because that's not a schema
  question.

Invariant answers these with a solver instead of a regex, across both
account-level guardrails (SCP/RCP, `Deny`-only) and identity-level policies
(`iam-policies/`, `Allow`+`Deny`) — see [IAM policy support](#iam-policy-support-permission-boundaries--privilege-escalation)
below for why that second half matters as much as the first.

## Three checks, two engines

- **`INV_AWS_001`** (SCP/RCP permissiveness regression) — proves the
  candidate `Deny` statement set still denies everything its reference did.
  This is the original account-guardrail check.
- **`INV_AWS_002`** (IAM grant regression) — the `Allow`-side mirror of
  001, scoped to `iam-policies/`: proves the candidate doesn't *grant*
  anything its reference didn't.
- **`INV_AWS_003`** (IAM privilege-escalation primitive) — an *absolute*
  property, no reference needed: proves whether a single IAM policy grants
  a known escalation primitive on any resource.

Three subcommands drive all three:

- **`invariant run`** — the default entry point. Always runs the baseline
  tier (below); also runs the diff tier when you pass `--diff-base` (e.g.
  `--diff-base origin/main`). One command, no need to decide up front
  whether you want `scan` or `regression` — it runs whichever tiers have
  something to check.

- **`invariant scan`** — baseline tier. Point it at a directory and it
  walks `service-control-policies/`, `rcp-policies/`, and `iam-policies/`.
  Files with a same-named counterpart in the **default AWS Landing Zone
  Accelerator (LZA) guardrails** bundled with the package
  (`src/invariant/baseline/`) get the full relative-check treatment
  (001/002). Files with no baseline counterpart — the normal case for
  `iam-policies/`, since custom IAM policies aren't part of the LZA default
  catalog — still get every reference-free check (003) run against them. No
  reference file, no manifest, nothing to set up — this is the "just run it"
  entry point.

- **`invariant regression --manifest manifest.json`** — diff tier. Proves
  each candidate still denies/grants exactly what *its own paired reference*
  did. Use this when you want to check against something other than the
  bundled LZA defaults — your org's own last-known-good policies, an
  upstream release, whatever you supply. `build_manifest.py` derives the
  pairing from a git diff so you don't hand-maintain it (see
  [CI integration](#ci-integration)). `invariant run --diff-base <ref>`
  does this same pairing internally, so `regression` is mainly useful when
  you want the diff tier as its own CI job/artifact, independent of the
  baseline tier (see [CI integration](#ci-integration)).

All three share the same check registry, output formats, and exit-code
convention: `0` = no findings (or `--soft-fail`), `1` = a check failed.

## Install

Requires Python 3.10+. `z3-solver` is installed automatically as a
dependency.

```bash
# from PyPI (distribution name is invariant-sast; the CLI and import stay `invariant`)
pip install invariant-sast

# or straight from source
git clone https://github.com/Ikurira/invariant.git
cd invariant
pip install .
```

## Quickstart

From the root of your AWS LZA config repo (wherever your
`service-control-policies/`, `rcp-policies/`, and `iam-policies/`
directories live):

```bash
invariant run
```

```
[PASS] INV_AWS_001  service-control-policies/lza-core-guardrails-1.json  No regression found.
[PASS] INV_AWS_001  service-control-policies/lza-quarantine.json         No regression found.
[FAIL (critical)] INV_AWS_001  service-control-policies/lza-quarantine.json  Candidate no longer denies a request the reference denied: {'action': '""', 'resource': '""', 'principal': '""'}
[FAIL (high)] INV_AWS_003  iam-policies/end-user-boundary.json  Grants 7 privilege-escalation primitive(s) unconditionally on at least one resource: iam:CreatePolicyVersion, iam:AttachRolePolicy, iam:PutRolePolicy, iam:UpdateAssumeRolePolicy, iam:PassRole, sts:AssumeRole, iam:SetDefaultPolicyVersion
```

That's the baseline tier — no reference file, no manifest, nothing to set
up first. To also prove every file changed since some ref still holds up
against its own `reference/` counterpart, add `--diff-base`:

```bash
invariant run --diff-base origin/main
```

A `FAIL` line means Z3 found a concrete counterexample: a request the
bundled baseline guardrail denies but your SCP/RCP no longer does
(`INV_AWS_001`), a request your IAM policy now grants that its reference
didn't (`INV_AWS_002`), or a known privilege-escalation primitive your IAM
policy grants unconditionally (`INV_AWS_003`). Exit code is `1` whenever any
check fails, so it's CI-friendly out of the box.

Only files with a same-named counterpart in the bundled baseline catalog get
`INV_AWS_001`/`002` (the relative checks) — a custom SCP or IAM policy with
no LZA-default analog has nothing to prove *that* property against yet;
`invariant run`/`scan` reports it (to stderr) as skipped for those checks
rather than silently ignoring it, and pair it against something of your own
choosing with `invariant run --diff-base <ref>` (or `invariant regression`)
instead. `INV_AWS_003` doesn't need a baseline at all, so it still runs on
every `iam-policies/*.json` file found — that's true for the vast majority
of real-world `iam-policies/` content, since custom identity policies and
permission boundaries are org-specific by nature, not part of any shipped
default catalog.

## CLI reference

All three subcommands accept:

| Flag | Default | Meaning |
|---|---|---|
| `--check IDS` | all | Comma-separated check IDs to run |
| `--skip-check IDS` | none | Comma-separated check IDs to exclude |
| `--output`, `-o` | `cli` | `cli`, `json`, and/or `sarif` — repeatable |
| `--soft-fail` | off | Always exit `0`, regardless of findings |
| `--compact` | off | Suppress `PASS` lines in `cli` output |
| `--out-dir` | `solver-results` | Where `json`/`sarif` reports get written |

`invariant run` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--directory`, `-d` | `.` | Root to scan for `service-control-policies/`, `rcp-policies/`, and `iam-policies/` |
| `--diff-base` | none | Git ref to diff against (e.g. `origin/main`) — enables the regression tier; omit to run the baseline tier only |
| `--reference-dir` | `reference` | Where last-known-good copies live, used only when `--diff-base` is given |

`invariant scan` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--directory`, `-d` | `.` | Root to scan for `service-control-policies/`, `rcp-policies/`, and `iam-policies/` |

`invariant regression` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--manifest`, `-m` | `manifest.json` | Reference↔candidate pairing (see `build_manifest.py`) |

## Suppressing a finding

A candidate JSON file can carry a top-level `_suppressions` array (raw AWS
policy JSON has no comment syntax to piggyback a suppression on, unlike
HCL/YAML checks):

```json
{
  "Version": "2012-10-17",
  "Statement": [ ... ],
  "_suppressions": [
    {"check_id": "INV_AWS_001", "reason": "JIRA-1234: intentional widen"}
  ]
}
```

This key is stripped before the policy is handed to the solver, so it never
affects the request semantics Z3 reasons about.

## Checks

| ID | Severity | Reference needed? | What it proves |
|---|---|---|---|
| `INV_AWS_001` | CRITICAL | Yes | The candidate SCP/RCP denies every `(action, resource, principal)` request its reference (baseline or paired manifest entry) explicitly denied. |
| `INV_AWS_002` | CRITICAL | Yes | The candidate IAM policy (`iam-policies/`) grants no `(action, resource)` request its reference didn't already grant. |
| `INV_AWS_003` | HIGH | No | The candidate IAM policy grants no known privilege-escalation primitive unconditionally on any resource. |

Failing `INV_AWS_001`/`002`: review the counterexample. If the widened
permission is intentional, add a `_suppressions` entry (or update your own
reference, for `regression`) and document why in the PR description. If
not, revert the `Condition`/`Resource`/`NotResource`/`Action` change that
removed the restriction.

Failing `INV_AWS_003`: see [IAM policy support](#iam-policy-support-permission-boundaries--privilege-escalation)
below — a permission-boundary or admin-delegation policy is *expected* to
trip several of these outside a protected role/policy prefix, that's
usually the point of the policy. A least-privilege workload policy tripping
this is a real signal to scope the flagged action down or remove it.

## IAM policy support: permission boundaries & privilege escalation

SCPs and RCPs are account-level, `Deny`-only guardrails — they're the
outermost fence. But most of the day-to-day IAM risk in a landing zone
lives one layer in, in **identity-based policies**: the customer-managed
policies and permission boundaries under `iam-policies/` that a landing
zone builder attaches to roles, users, and groups (`iam-config.yaml`'s
`policySets`/`roleSets` in LZA). That layer is `Allow`+`Deny`, has its own
`NotAction`/`NotResource` carve-outs, and is exactly where an
innocuous-looking edit — narrowing a `NotResource` exclusion list, dropping
a `Condition` that pinned `iam:PermissionsBoundary` — quietly opens a
privilege-escalation path. `INV_AWS_002`/`003` extend the same Z3 model to
this layer:

- **`iam:PermissionsBoundary`** is modeled as its own symbolic ARN, so
  `ArnLike`/`ArnNotLike` conditions gating role/policy creation on a pinned
  boundary policy (the standard LZA "end-user boundary" pattern) are
  reasoned about precisely, not treated as opaque.
- **`NotResource`** (used throughout permission boundaries to carve
  accelerator-managed roles/policies out of an otherwise broad grant) is
  modeled the same way `NotAction` already was for SCP/RCP `Deny`
  statements.
- **Explicit `Deny` wins**, matching real IAM evaluation: a policy grants a
  request only if some `Allow` statement matches *and* no `Deny` statement
  in the same policy also matches.

`INV_AWS_003`'s built-in list (`PRIVILEGE_ESCALATION_ACTIONS` in
`policy_check.py`) covers the IAM primitives publicly documented as
privilege-escalation vectors (policy-version tampering, self-attaching an
admin policy, `PassRole` abuse, login-profile/access-key creation on
another identity, etc.) — the same category of primitive tools like
cloudsplaining scan for, but proven per-statement-combination via Z3 with a
concrete resource ARN, rather than matched by pattern. Add or trim entries
in that list to match your org's own risk model.

**A permission boundary tripping most of `INV_AWS_003` is expected, not a
bug in the check** — a boundary's entire job is to allow broad
administrative actions everywhere *except* the accelerator's own managed
roles/policies, so it will legitimately grant most of these primitives
outside that prefix. Use `_suppressions` to document that's intentional for
a given file; save the unsuppressed `FAIL` for policies where it isn't
expected (a workload's least-privilege role policy, for instance). What
`INV_AWS_002` catches that's *never* expected is the boundary **silently
getting weaker over time** — that's the one to treat as CI-blocking by
default.

## How the solver works, and where it's intentionally conservative

Every `Deny` statement becomes a Z3 predicate over a symbolic request
context (one variable per condition key actually observed in the LZA
guardrail set); every `Allow` statement becomes the same kind of predicate
for the identity-policy model; wildcard `Action`/`Resource`/ARN patterns
compile to Z3 regular expressions. For SCP/RCP, `invariant` asks the solver
to find a request the reference denies that the candidate doesn't
(`INV_AWS_001`). For IAM policies, it asks the mirror question — a request
the candidate grants (`Allow` matches, no `Deny` in the same policy
matches) that the reference didn't (`INV_AWS_002`) — or, for
`INV_AWS_003`, whether a specific known-dangerous action is grantable on
*any* resource at all. See `policy_check.py` for the full model. A few gaps
are called out there and worth knowing about:

- **`aws:CalledVia`** is modeled as a single representative string, not a
  true call chain, so `ForAllValues:StringNotEquals` on it is sound for
  catching "the whole chain is now unconstrained" but can miss a regression
  that only appears with one specific multi-hop chain.
- **`aws:ResourceTag/*` (`StringEquals`)** is left unconstrained — there's no
  resource-tag model — which makes the checker conservative (won't
  false-negative a real regression) but can over-report on tag-gated
  statements.
- Any condition operator not in the model (currently seen in the wild:
  `StringLike`, `StringNotLike`, `ForAnyValue:StringLike` on keys like
  `rds:DatabaseEngine`) is treated as **non-constraining** and prints a
  `WARNING`. A statement using one of these may be reported as denying more
  than it actually does — verify those findings by hand.

None of this changes the exit-code contract; it just means a `PASS` on a
statement using one of the flagged operators is a weaker guarantee than a
`PASS` elsewhere, and the tool tells you when that's the case.

### A note on the wildcard alphabet (and a correctness fix worth knowing about)

Wildcards (`*`/`?`) compile to a Z3 regex over an "any character" building
block. That building block is deliberately restricted to **printable ASCII**
(`chr(0x20)`–`chr(0x7E)`), not the full Unicode codepoint space — AWS action
names and ARNs are always printable ASCII (see the IAM policy grammar), so
this loses no soundness for anything the tool actually models, and it's the
difference between a `NotResource`-heavy permission-boundary statement
solving in single-digit seconds versus taking well over a minute (negating
a wildcard match — exactly what `NotResource`/`NotAction` do — requires
automaton complementation, and that gets expensive fast as the alphabet
grows).

Earlier revisions of this codebase built that "any character" block as
`Range(chr(0), chr(0x10FFFF))` (the full Unicode range) — which is not just
slow but **silently wrong** under `z3-solver>=5.0` (the version a fresh
`pip install z3-solver` resolves to today): that construction degrades to
matching only the empty string, meaning every `*`/`?` in every
Action/Resource/ARN pattern silently stopped matching anything real,
defeating every check's soundness guarantee with no error or warning. If
you're running a version of this tool from before this was fixed, treat any
`PASS` you've gotten from it as unverified and re-run against a current
build.

## CI integration

`.gitlab-ci.yml` and `.github/workflows/invariant.yml` are **templates**,
meant to be copied into your own AWS LZA config repo (not into a fork of
this one) — each wires up a diff-scoped `regression` job plus a full-sweep
`scan` job, and publishes `solver-results*/results.sarif` so GitLab/GitHub
render findings natively. Both assume `invariant` is installed from wherever
you publish it — set `INVARIANT_PIP_SPEC` (GitLab) / `INVARIANT_PIP_SPEC` env
(GitHub) to your private index, package registry, or a `git+https://` URL.
Both templates now include `iam-policies` in their candidate directories;
`REFERENCE_DIR`/`reference/` only needs an `iam-policies/` counterpart for
the specific files you want an `INV_AWS_002` grant-regression proof on —
`INV_AWS_003` runs regardless.

### Why two separate jobs instead of one `invariant run`

The templates run `scan` and `regression` as independent jobs rather than a
single `invariant run --diff-base ...` call, because in CI they differ on
two axes that are each worth keeping separate:

- **What they prove against.** `guardrail-baseline` (`invariant scan`)
  checks every file against the **LZA default guardrails bundled with the
  package itself** — a fixed reference nobody in your org maintains, so it
  needs no setup and still catches drift even when nothing changed in this
  MR/PR (e.g. a package upgrade moves the bundled catalog, or a file was
  never part of that catalog to begin with — `INV_AWS_003` still runs on
  it). `guardrail-regression` (`invariant regression`) checks only the
  files this MR/PR touched against **your own `reference/` copies** — the
  thing you actually approved and updated last time a widening was
  intentional. One answers "do we still match the reference architecture,
  everywhere, right now"; the other answers "did this diff make something
  worse relative to what we already signed off on."
- **What they cost.** `scan` is a full sweep, every run, independent of git
  history. `regression` is diff-scoped (`build_manifest.py` derives the
  pairing from `git diff` against the target branch), which keeps runtime
  bounded as the number of guardrail files grows — the split lets you tune
  `SOLVER_TIMEOUT_SECONDS`/job timeouts for each independently instead of
  one job absorbing both costs.

Splitting them also means GitLab/GitHub attribute each job's findings to
its own `solver-results*/results.sarif` artifact, so a baseline drift and a
this-PR regression don't get conflated in the same report. For local,
ad-hoc use where that separation doesn't matter, `invariant run
--diff-base <ref>` runs both tiers in one command — see
[Quickstart](#quickstart).

Note that `reference/` mirrors the candidate subdirectory now
(`reference/iam-policies/foo.json`, not a flat `reference/foo.json`) — see
`build_manifest.py`'s docstring for why a flat layout stopped being safe
once more than one policy-type directory could plausibly share a basename.

## Development

```bash
git clone https://github.com/YOUR_ORG/invariant.git
cd invariant
python -m venv .venv
. .venv/Scripts/activate   # .venv/bin/activate on macOS/Linux
pip install -e ".[dev]"
invariant --help
pytest
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
