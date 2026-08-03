# Invariant

SMT-based guardrail SAST for AWS Service Control Policies (SCPs) and Resource
Control Policies (RCPs). Instead of pattern-matching JSON, Invariant hands
your policies to the [Z3](https://github.com/Z3Prover/z3) theorem prover and
asks a precise question:

> Is there any `(action, resource, principal)` request that used to be
> denied, but isn't anymore?

If Z3 finds one, that's a guardrail regression, and you get a concrete
counterexample instead of a vague warning.

## Why

Checkov, cfn-nag, and friends are great at "does this statement look
dangerous," but they can't tell you whether an edit to a `Condition` block
quietly widened who a `Deny` statement applies to. That requires reasoning
about the full set of requests a policy allows, not just its syntax. Invariant
answers that question with a solver instead of a regex.

## Two checks, one engine

- **`invariant scan`** — baseline check. Point it at a directory and it
  proves each `service-control-policies/*.json` / `rcp-policies/*.json` file
  still upholds the security properties of the **default AWS Landing Zone
  Accelerator (LZA) guardrails**, a copy of which ships inside the package
  (`src/invariant/baseline/`). No reference file, no manifest, nothing to set
  up — this is the "just run it" entry point.

- **`invariant regression --manifest manifest.json`** — diff check. Proves
  each candidate still denies everything *its own paired reference* denied.
  Use this when you want to check against something other than the bundled
  LZA defaults — your org's own last-known-good policies, an upstream
  release, whatever you supply. `build_manifest.py` derives the pairing from
  a git diff so you don't hand-maintain it (see [CI integration](#ci-integration)).

Both share the same check registry, output formats, and exit-code
convention: `0` = no findings (or `--soft-fail`), `1` = a check failed.

## Install

Requires Python 3.10+. `z3-solver` is installed automatically as a
dependency.

```bash
# from a package index, once published
pip install invariant

# or straight from source
git clone https://github.com/YOUR_ORG/invariant.git
cd invariant
pip install .
```

## Quickstart

From the root of your AWS LZA config repo (wherever your
`service-control-policies/` and `rcp-policies/` directories live):

```bash
invariant scan
```

```
[PASS] INV_AWS_001  service-control-policies/lza-core-guardrails-1.json  No regression found.
[PASS] INV_AWS_001  service-control-policies/lza-quarantine.json         No regression found.
[FAIL (critical)] INV_AWS_001  service-control-policies/lza-quarantine.json  Candidate no longer denies a request the reference denied: {'action': '""', 'resource': '""', 'principal': '""'}
```

A `FAIL` line means Z3 found a concrete `(action, resource, principal)`
tuple that the bundled baseline guardrail denies but your policy no longer
does. Exit code is `1` whenever any check fails, so it's CI-friendly out of
the box.

Only files with a same-named counterpart in the bundled baseline catalog are
checked. A custom SCP with no LZA-default analog has nothing to prove a
baseline property against yet — `invariant scan` reports it (to stderr) as
skipped rather than silently ignoring it. Pair it against something of your
own choosing with `invariant regression` instead.

## CLI reference

Both subcommands accept:

| Flag | Default | Meaning |
|---|---|---|
| `--check IDS` | all | Comma-separated check IDs to run |
| `--skip-check IDS` | none | Comma-separated check IDs to exclude |
| `--output`, `-o` | `cli` | `cli`, `json`, and/or `sarif` — repeatable |
| `--soft-fail` | off | Always exit `0`, regardless of findings |
| `--compact` | off | Suppress `PASS` lines in `cli` output |
| `--out-dir` | `solver-results` | Where `json`/`sarif` reports get written |

`invariant scan` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--directory`, `-d` | `.` | Root to scan for `service-control-policies/` and `rcp-policies/` |

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

| ID | Severity | What it proves |
|---|---|---|
| `INV_AWS_001` | CRITICAL | The candidate SCP/RCP denies every `(action, resource, principal)` request its reference (baseline or paired manifest entry) explicitly denied. |

Failing `INV_AWS_001`: review the counterexample. If the widened permission
is intentional, add a `_suppressions` entry (or update your own reference,
for `regression`) and document why in the PR description. If not, revert the
`Condition`/`Resource`/`Action` change that removed the denial.

## How the solver works, and where it's intentionally conservative

Every `Deny` statement becomes a Z3 predicate over a symbolic request
context (one variable per condition key actually observed in the LZA
guardrail set); wildcard `Action`/`Resource`/ARN patterns compile to Z3
regular expressions. `invariant` then asks the solver to find a request the
reference denies that the candidate doesn't. See `policy_check.py` for the
full model. A few gaps are called out there and worth knowing about:

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

## CI integration

`.gitlab-ci.yml` and `.github/workflows/invariant.yml` are **templates**,
meant to be copied into your own AWS LZA config repo (not into a fork of
this one) — each wires up a diff-scoped `regression` job plus a full-sweep
`scan` job, and publishes `solver-results*/results.sarif` so GitLab/GitHub
render findings natively. Both assume `invariant` is installed from wherever
you publish it — set `INVARIANT_PIP_SPEC` (GitLab) / `INVARIANT_PIP_SPEC` env
(GitHub) to your private index, package registry, or a `git+https://` URL.

## Development

```bash
git clone https://github.com/YOUR_ORG/invariant.git
cd invariant
python -m venv .venv
. .venv/Scripts/activate   # .venv/bin/activate on macOS/Linux
pip install -e .
invariant --help
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
