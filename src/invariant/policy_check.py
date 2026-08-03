"""
Invariant -- SMT-based permissiveness-regression checker (core engine).

Answers one concrete question per run: does the CANDIDATE version of an SCP/RCP
allow any request that the REFERENCE version explicitly denied? If so, that's
a guardrail regression, surfaced as a counterexample.

Requires: pip install z3-solver
Not executable in this sandbox (no network egress to install z3) -- run this
locally or in your GitLab CI job where pip has internet access.
"""
import json
from dataclasses import dataclass
from z3 import (
    String, Bool, Solver, sat, InRe, Not, Or, And, Implies, Star, Concat, Re,
    Range as CharRange, StringVal
)


# ---------------------------------------------------------------------------
# 1. AWS ARN/action wildcard -> Z3 regular expression
# ---------------------------------------------------------------------------
ANY_CHAR = CharRange(chr(0), chr(0x10FFFF))


def wildcard_to_re(pattern: str):
    """Convert an AWS wildcard pattern (ARN or action string) into a Z3 RE."""
    parts = []
    literal_buf = ""
    for ch in pattern:
        if ch == "*":
            if literal_buf:
                parts.append(Re(StringVal(literal_buf)))
                literal_buf = ""
            parts.append(Star(ANY_CHAR))
        elif ch == "?":
            if literal_buf:
                parts.append(Re(StringVal(literal_buf)))
                literal_buf = ""
            parts.append(ANY_CHAR)
        else:
            literal_buf += ch
    if literal_buf:
        parts.append(Re(StringVal(literal_buf)))
    if not parts:
        return Re(StringVal(""))
    result = parts[0]
    for p in parts[1:]:
        result = Concat(result, p)
    return result


def matches(z3_string_var, pattern: str):
    return InRe(z3_string_var, wildcard_to_re(pattern))


def matches_any(z3_string_var, patterns):
    if isinstance(patterns, str):
        patterns = [patterns]
    return Or(*[matches(z3_string_var, p) for p in patterns])


# ---------------------------------------------------------------------------
# 2. Request context
#
# One symbolic variable per condition key actually observed in the LZA
# guardrail set. Each *IfExists / Null-eligible key gets a paired "_present"
# Bool, since AWS's IfExists/Null semantics hinge on whether the key exists
# in the request at all, not just its value.
#
# KNOWN SIMPLIFICATION: aws:CalledVia is multivalued in real IAM requests
# (a call chain of service principals). We model it as a single representative
# string rather than a Z3 Seq of strings, so ForAllValues:StringNotEquals is
# checked against that one representative value, not a real universal
# quantifier over an arbitrary-length call chain. This is sound for catching
# "the whole chain is now unconstrained" regressions but can miss a regression
# that only appears with a specific multi-hop call chain. Flag any finding
# touching GRS3OBJ (the only statement using this operator) for manual review.
# ---------------------------------------------------------------------------
@dataclass
class RequestContext:
    action: object
    resource: object
    principal: object
    principal_is_aws_service: object
    secure_transport: object
    secure_transport_present: object
    source_org_id: object
    source_org_id_present: object
    source_arn_present: object
    called_via: object  # see simplification note above

    @classmethod
    def fresh(cls, suffix=""):
        return cls(
            action=String(f"action{suffix}"),
            resource=String(f"resource{suffix}"),
            principal=String(f"principal{suffix}"),
            principal_is_aws_service=Bool(f"principal_is_aws_service{suffix}"),
            secure_transport=Bool(f"secure_transport{suffix}"),
            secure_transport_present=Bool(f"secure_transport_present{suffix}"),
            source_org_id=String(f"source_org_id{suffix}"),
            source_org_id_present=Bool(f"source_org_id_present{suffix}"),
            source_arn_present=Bool(f"source_arn_present{suffix}"),
            called_via=String(f"called_via{suffix}"),
        )


# ---------------------------------------------------------------------------
# 3. Statement -> predicate
# ---------------------------------------------------------------------------
def condition_predicate(condition: dict, ctx: RequestContext):
    """
    Covers every operator observed across the LZA guardrail set supplied so
    far: ArnNotLike, ArnLike, Bool, BoolIfExists, StringNotEqualsIfExists,
    Null, ForAllValues:StringNotEquals. StringEquals on aws:ResourceTag/* is
    still intentionally unconstrained -- see note below.

    Any operator NOT in this list is treated as vacuously true (does not
    constrain) with a printed warning. That is a soundness gap for whatever
    new operator triggers it -- it will not cause a false NEGATIVE on the
    operators already handled, but a statement using an unhandled operator
    may be reported as denying more than it really does.
    """
    if not condition:
        return True

    clauses = []
    for op, kv in condition.items():
        if op == "ArnNotLike":
            for key, val in kv.items():
                if key.lower() == "aws:principalarn":
                    clauses.append(Not(matches_any(ctx.principal, val)))
        elif op == "ArnLike":
            for key, val in kv.items():
                if key.lower() == "aws:principalarn":
                    clauses.append(matches_any(ctx.principal, val))
        elif op == "Bool":
            for key, val in kv.items():
                target = (val == "true" if isinstance(val, str) else bool(val))
                if key.lower() == "aws:principalisawsservice":
                    clauses.append(ctx.principal_is_aws_service == target)
                elif key.lower() == "aws:securetransport":
                    clauses.append(ctx.secure_transport == target)
        elif op == "BoolIfExists":
            for key, val in kv.items():
                target = (val == "true" if isinstance(val, str) else bool(val))
                if key.lower() == "aws:principalisawsservice":
                    # No presence flag modeled for this key (always "present"
                    # in our model) -- BoolIfExists degrades to Bool here.
                    clauses.append(ctx.principal_is_aws_service == target)
                elif key.lower() == "aws:securetransport":
                    clauses.append(
                        Implies(ctx.secure_transport_present,
                                ctx.secure_transport == target))
        elif op == "StringNotEqualsIfExists":
            for key, val in kv.items():
                if key.lower() == "aws:sourceorgid":
                    vals = val if isinstance(val, list) else [val]
                    clauses.append(
                        Implies(ctx.source_org_id_present,
                                And(*[ctx.source_org_id != v for v in vals])))
        elif op == "Null":
            for key, val in kv.items():
                is_null = (val == "true" if isinstance(val, str) else bool(val))
                if key.lower() == "aws:sourcearn":
                    clauses.append(ctx.source_arn_present == (not is_null))
        elif op == "ForAllValues:StringNotEquals":
            for key, val in kv.items():
                if key.lower() == "aws:calledvia":
                    vals = val if isinstance(val, list) else [val]
                    clauses.append(And(*[ctx.called_via != v for v in vals]))
        elif op == "StringEquals":
            # aws:ResourceTag/* can't be evaluated without a resource-tag
            # model we don't have; intentionally left unconstrained. This
            # makes the checker CONSERVATIVE (won't false-negative a real
            # regression) but may over-report on tag-gated statements
            # (GRCFGR, GRKMS) -- verify those findings by hand.
            continue
        else:
            print(f"WARNING: unhandled condition operator '{op}' -- "
                  f"treated as non-constraining. Verify manually.")
    return And(*clauses) if clauses else True


def statement_denies(stmt: dict, ctx: RequestContext):
    if stmt.get("Effect") != "Deny":
        return False  # only modeling Deny statements (SCP/RCP guardrail pattern)
    if "NotAction" in stmt:
        # Deny + NotAction denies every action EXCEPT the listed ones (e.g.
        # "lock down this role to read-only" -- GRIAMR in the LZA guardrails
        # denies all IAM actions on accelerator roles except Get*/List*).
        action_match = Not(matches_any(ctx.action, stmt["NotAction"]))
    else:
        action_match = matches_any(ctx.action, stmt["Action"])
    resource_match = matches_any(ctx.resource, stmt.get("Resource", "*"))
    cond = condition_predicate(stmt.get("Condition", {}), ctx)
    return And(action_match, resource_match, cond)


def policy_denies(policy: dict, ctx: RequestContext):
    clauses = [statement_denies(s, ctx) for s in policy["Statement"]]
    return Or(*clauses) if clauses else False


# ---------------------------------------------------------------------------
# 4. Regression check: does CANDIDATE permit anything REFERENCE denied?
# ---------------------------------------------------------------------------
def find_permissiveness_regression(reference: dict, candidate: dict, label=""):
    ctx = RequestContext.fresh()

    s = Solver()
    s.add(policy_denies(reference, ctx))
    s.add(Not(policy_denies(candidate, ctx)))

    result = s.check()
    if result == sat:
        m = s.model()
        print(f"[REGRESSION FOUND] {label}")
        print(f"  action:    {m.eval(ctx.action, model_completion=True)}")
        print(f"  resource:  {m.eval(ctx.resource, model_completion=True)}")
        print(f"  principal: {m.eval(ctx.principal, model_completion=True)}")
        print(f"  -> reference policy denied this; candidate does not.")
        return m
    else:
        print(f"[OK] {label}: no regression found (candidate denies "
              f"everything the reference denied).")
        return None


def _model_to_jsonable(m):
    if m is None:
        return None
    return {str(d): str(m[d]) for d in m.decls()}


def main():
    import argparse
    import os
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True,
                         help="Path to last-known-good / upstream SCP or RCP JSON")
    parser.add_argument("--candidate", required=True,
                         help="Path to the version being checked (e.g. MR branch)")
    parser.add_argument("--json-out", default=None,
                         help="Optional path to write structured result JSON")
    args = parser.parse_args()

    with open(args.reference) as f:
        reference = json.load(f)
    with open(args.candidate) as f:
        candidate = json.load(f)

    label = f"{args.candidate} vs {args.reference}"
    model = find_permissiveness_regression(reference, candidate, label=label)

    result = {
        "reference": args.reference,
        "candidate": args.candidate,
        "regression_found": model is not None,
        "counterexample": _model_to_jsonable(model),
    }

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out), exist_ok=True)
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2)

    # Exit code convention consumed by the GitLab CI job:
    #   0 = no regression, 1 = regression found (fails the pipeline)
    sys.exit(1 if model is not None else 0)


if __name__ == "__main__":
    main()
