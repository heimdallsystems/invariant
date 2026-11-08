# CI integration

`.gitlab-ci.yml` and `.github/workflows/invariant.yml` (in the repo root)
are **templates**, meant to be copied into your own AWS LZA config repo (not
into a fork of this one) — each wires up a diff-scoped `regression` job plus
a full-sweep `scan` job, and publishes `solver-results*/results.sarif` so
GitLab/GitHub render findings natively. Both assume `invariant` is installed
from wherever you publish it — set `INVARIANT_PIP_SPEC` (GitLab) /
`INVARIANT_PIP_SPEC` env (GitHub) to your private index, package registry,
or a `git+https://` URL.

On GitHub, a push with no usable previous commit skips the regression job
with a notice instead of failing it. That covers the first push to a branch,
where `github.event.before` is all zeros, and a force push whose previous
commit isn't in the clone. The baseline scan still runs.
