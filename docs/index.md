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
  a git diff so you don't hand-maintain it (see [CI integration](ci-integration.md)).

Both share the same check registry, output formats, and exit-code
convention: `0` = no findings (or `--soft-fail`), `1` = a check failed.

[Get started :material-arrow-right:](getting-started.md){ .md-button .md-button--primary }
[View on GitHub :fontawesome-brands-github:](https://github.com/Ikurira/invariant){ .md-button }
