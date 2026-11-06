# CI integration

`.gitlab-ci.yml` and `.github/workflows/invariant.yml` (in the repo root)
are **templates**, meant to be copied into your own AWS LZA config repo (not
into a fork of this one) — each wires up a diff-scoped `regression` job plus
a full-sweep `scan` job, and publishes `solver-results*/results.sarif` so
GitLab/GitHub render findings natively. Both assume `invariant` is installed
from wherever you publish it — set `INVARIANT_PIP_SPEC` (GitLab) /
`INVARIANT_PIP_SPEC` env (GitHub) to your private index, package registry,
or a `git+https://` URL.

## GitLab

GitLab ingests a report's findings only when the job that produced it
succeeds, and `allow_failure` doesn't change that. So the template splits
reporting from gating:

- `invariant:guardrail-regression` and `invariant:guardrail-baseline` run
  with `--soft-fail`, exit 0, and publish their SARIF with
  `artifacts:reports:sarif`.
- `invariant:gate` reads both `results.json` files and fails the pipeline
  if any check failed, or if a results file is missing.

SARIF ingestion needs GitLab Ultimate and is generally available from
GitLab 19.2. Findings then appear in the merge request security widget, the
pipeline **Security** tab and the vulnerability report. On other tiers the
gate still blocks the merge, and the reports are downloadable as job
artifacts.

Invariant's SARIF results name the policy file but carry no line `region`.
GitLab identifies a finding by rule, file and line, so if one file has
several findings for the same check, GitLab keeps only the first. The job
log and `results.json` list every finding.

`SOLVER_TIMEOUT_SECONDS` limits each whole `invariant` command, not each
file. A timeout fails the check job, so the pipeline fails.

## GitHub

The GitHub template fails the check step on findings and uploads SARIF with
`if: always()`, so code scanning receives findings from failed runs. Code
scanning on a private repository needs GitHub Advanced Security; without
it, the upload step is skipped and the check step still gates the run.
