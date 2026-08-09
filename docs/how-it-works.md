# How the solver works, and where it's intentionally conservative

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
