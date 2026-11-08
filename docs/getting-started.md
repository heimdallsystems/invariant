# Getting started

## Install

Requires Python 3.10+. `z3-solver` is installed automatically as a
dependency.

```bash
# from PyPI (distribution name is invariant-sast; the CLI and import stay `invariant`)
pip install invariant-sast

# or straight from source
git clone https://github.com/heimdallsystems/invariant.git
cd invariant
pip install .
```

## Quickstart

From the root of your AWS LZA config repo (wherever your
`service-control-policies/` and `rcp-policies/` directories live):

```bash
invariant scan
```

```text
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

The bundled catalog (`src/invariant/baseline/`) is an unmodified copy of the
`service-control-policies/` and `rcp-policies/` files in
[LZA Universal Configuration](https://github.com/aws/lza-universal-configuration)
v1.4.0 (`modules/base/default/`, commit `96aa5e7`). A config still on an
older release gets `INV_AWS_001` findings for denials added since; compare
it against your own reviewed copies with `invariant regression` instead.

## Next steps

- [CLI reference](cli-reference.md) for every flag both subcommands accept.
- [Checks](checks.md) for what `INV_AWS_001` actually proves.
- [Suppressions](suppressions.md) if you need to intentionally accept a
  finding.
- [CI integration](ci-integration.md) to wire this into GitHub Actions or
  GitLab CI.
