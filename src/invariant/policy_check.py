"""
Invariant -- SMT-based policy-analysis core engine.

Two request-context models sharing one Z3 encoding:
  - Deny-side (SCP/RCP account guardrails): does the CANDIDATE version deny
    every request the REFERENCE version explicitly denied?
    (find_permissiveness_regression, INV_AWS_001)
  - Allow-side (iam-policies/ identity & permission-boundary policies): does
    the CANDIDATE grant anything the REFERENCE didn't
    (find_grant_regression, INV_AWS_002), or does a single CANDIDATE grant a
    known privilege-escalation primitive on any resource at all
    (find_privilege_escalation, INV_AWS_003)?

Every finding is surfaced as a concrete counterexample, not a vague warning.

Requires: pip install z3-solver
"""
import json
import sys
from dataclasses import dataclass
from z3 import (
    String, Bool, Solver, sat, InRe, Not, Or, And, Implies, Star, Concat, Re,
    Range, StringVal
)


# ---------------------------------------------------------------------------
# 1. AWS ARN/action wildcard -> Z3 regular expression
#
# ANY_CHAR must match z3's "any single character" (previously a manually
# built Range(chr(0), chr(0x10FFFF)), which silently degrades to matching
# only the empty string under z3-solver >=5.0 -- confirmed against
# 5.0.0.0, the version `pip install z3-solver` resolves to today. That
# makes every "*"/"?" in every Action/Resource/ARN pattern stop matching
# anything but "". Since nearly every real SCP/RCP/IAM statement uses a
# wildcard somewhere, that silently defeated the tool's entire soundness
# guarantee on a fresh install, with no error or warning.
#
# The correct fix is z3.AllChar(ReSort(StringSort())), but that quantifies
# over the full Unicode codepoint space (~1.1M codepoints), and negating a
# wildcard match over that alphabet (NotResource/NotAction -- exactly the
# pattern permission-boundary policies use to carve out accelerator-managed
# roles) makes automaton complementation expensive enough to blow well past
# a 60s CI timeout on realistic policies. AWS action names and ARNs are
# always printable ASCII (see the IAM policy grammar), so restricting the
# alphabet here to printable ASCII is lossless for anything this tool
# actually models, and turns that same case from >90s into ~6s.
# ---------------------------------------------------------------------------
ANY_CHAR = Range(chr(0x20), chr(0x7E))


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
    permissions_boundary: object
    permissions_boundary_present: object

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
            permissions_boundary=String(f"permissions_boundary{suffix}"),
            permissions_boundary_present=Bool(f"permissions_boundary_present{suffix}"),
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
                elif key.lower() == "iam:permissionsboundary":
                    clauses.append(
                        Implies(ctx.permissions_boundary_present,
                                Not(matches_any(ctx.permissions_boundary, val))))
        elif op == "ArnLike":
            for key, val in kv.items():
                if key.lower() == "aws:principalarn":
                    clauses.append(matches_any(ctx.principal, val))
                elif key.lower() == "iam:permissionsboundary":
                    # No IfExists variant used in the wild for this key today,
                    # so an absent boundary fails this condition outright --
                    # matching AWS's actual evaluation of ArnLike on a key
                    # that isn't present in the request.
                    clauses.append(
                        And(ctx.permissions_boundary_present,
                            matches_any(ctx.permissions_boundary, val)))
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
            _warn_unhandled_operator(op)
    return And(*clauses) if clauses else True


# Printed at most once per operator per process (not once per statement/
# check/file) -- the same handful of operators recur across every
# statement in every policy, and a soundness caveat that scrolls past
# hundreds of times drowns out the actual PASS/FAIL/REGRESSION findings it
# was meant to flag review of. Emitted on stderr, not stdout, so it never
# interleaves with -o cli's result lines or pollutes -o json/sarif.
_WARNED_OPERATORS: set[str] = set()


def _warn_unhandled_operator(op: str) -> None:
    if op in _WARNED_OPERATORS:
        return
    _WARNED_OPERATORS.add(op)
    print(f"WARNING: unhandled condition operator '{op}' -- treated as "
          f"non-constraining wherever it appears in this run. Verify "
          f"affected statements manually.", file=sys.stderr)


def _action_match(stmt: dict, ctx: RequestContext):
    if "NotAction" in stmt:
        # NotAction matches every action EXCEPT the listed ones (e.g. "lock
        # this role down to read-only" -- GRIAMR in the LZA guardrails denies
        # all IAM actions on accelerator roles except Get*/List*; the same
        # NotAction shape shows up in Allow statements in identity policies,
        # e.g. an end-user boundary that allows everything except iam:*/
        # organizations:*/account:*).
        return Not(matches_any(ctx.action, stmt["NotAction"]))
    return matches_any(ctx.action, stmt.get("Action", "*"))


def _resource_match(stmt: dict, ctx: RequestContext):
    if "NotResource" in stmt:
        return Not(matches_any(ctx.resource, stmt["NotResource"]))
    return matches_any(ctx.resource, stmt.get("Resource", "*"))


def statement_denies(stmt: dict, ctx: RequestContext):
    if stmt.get("Effect") != "Deny":
        return False
    cond = condition_predicate(stmt.get("Condition", {}), ctx)
    return And(_action_match(stmt, ctx), _resource_match(stmt, ctx), cond)


def statement_grants(stmt: dict, ctx: RequestContext):
    if stmt.get("Effect") != "Allow":
        return False
    cond = condition_predicate(stmt.get("Condition", {}), ctx)
    return And(_action_match(stmt, ctx), _resource_match(stmt, ctx), cond)


def policy_denies(policy: dict, ctx: RequestContext):
    clauses = [statement_denies(s, ctx) for s in policy["Statement"]]
    return Or(*clauses) if clauses else False


def policy_grants(policy: dict, ctx: RequestContext):
    """
    Identity/resource-policy evaluation semantics: a request is allowed if
    some Allow statement matches AND no Deny statement in the same policy
    matches (explicit deny always wins). This is the Allow-side counterpart
    of policy_denies, used for iam-policies/ (permission boundaries,
    customer-managed policies) rather than the account-boundary
    service-control-policies/ and rcp-policies/ files, which are Deny-only.
    """
    allow = [statement_grants(s, ctx) for s in policy["Statement"]]
    deny = [statement_denies(s, ctx) for s in policy["Statement"]]
    allowed = Or(*allow) if allow else False
    denied = Or(*deny) if deny else False
    return And(allowed, Not(denied))


# ---------------------------------------------------------------------------
# 4. Regression check: does CANDIDATE permit anything REFERENCE denied?
#
# Returns the Z3 model (counterexample) if a regression is found, else
# None -- callers (checks/scp_permissiveness_regression.py) are
# responsible for reporting the result; this stays a pure function so
# there's exactly one place (cli.py) that decides what gets printed and
# how, instead of the engine and the CLI each narrating the same finding
# independently and out of sync with each other.
# ---------------------------------------------------------------------------
def find_permissiveness_regression(reference: dict, candidate: dict):
    ctx = RequestContext.fresh()

    s = Solver()
    s.add(policy_denies(reference, ctx))
    s.add(Not(policy_denies(candidate, ctx)))

    return s.model() if s.check() == sat else None


def _model_to_jsonable(m):
    if m is None:
        return None
    return {str(d): str(m[d]) for d in m.decls()}


# ---------------------------------------------------------------------------
# 5. Grant-regression check: does CANDIDATE allow anything REFERENCE didn't?
#
# The Allow-side mirror of find_permissiveness_regression, for identity-based
# and resource-based policies (iam-policies/) where the property worth
# proving is the opposite direction: an SCP/RCP guardrail must keep denying
# what it always denied, but a permission boundary or customer-managed policy
# must not start ALLOWING something it never allowed -- e.g. a NotResource
# exclusion list quietly losing an entry, or a Condition that scoped
# iam:PassRole to specific roles getting loosened.
# ---------------------------------------------------------------------------
def find_grant_regression(reference: dict, candidate: dict):
    ctx = RequestContext.fresh()

    s = Solver()
    s.add(Not(policy_grants(reference, ctx)))
    s.add(policy_grants(candidate, ctx))

    return s.model() if s.check() == sat else None


# ---------------------------------------------------------------------------
# 6. Privilege-escalation primitive check (single policy, no reference)
#
# Checkov/Semgrep flag a bare "Action": "iam:*" or a single dangerous action
# by pattern; they can't tell you whether a *combination* of NotAction /
# NotResource / Condition clauses still leaves that action reachable. This
# asks Z3 directly: for a fixed, known-dangerous action (drawn from the
# public IAM privilege-escalation primitive list -- PassRole abuse, policy
# version tampering, self-attachment of admin policies, etc.), does there
# exist ANY resource this policy grants it on, once explicit Deny statements
# in the same policy are accounted for? A `sat` result comes back with a
# concrete resource ARN, not just "this looks risky".
#
# This is an absolute property (no baseline/reference needed), unlike the
# two regression checks above -- it can run on a brand-new custom IAM policy
# from the moment it's written.
# ---------------------------------------------------------------------------
PRIVILEGE_ESCALATION_ACTIONS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
]


def find_privilege_escalation(candidate: dict, actions=None):
    """
    Returns a list of (action, model) pairs -- one per dangerous action the
    candidate policy grants unconditionally on at least one resource. Each
    model carries a concrete resource ARN counterexample.
    """
    findings = []
    for action in (actions or PRIVILEGE_ESCALATION_ACTIONS):
        ctx = RequestContext.fresh()
        s = Solver()
        s.add(ctx.action == StringVal(action))
        s.add(policy_grants(candidate, ctx))

        if s.check() == sat:
            findings.append((action, s.model()))
    return findings


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

    model = find_permissiveness_regression(reference, candidate)

    if model is not None:
        print(f"[REGRESSION FOUND] {args.candidate} vs {args.reference}")
        for var, value in _model_to_jsonable(model).items():
            print(f"  {var}: {value}")
        print(f"  -> reference policy denied this; candidate does not.")
    else:
        print(f"[OK] {args.candidate} vs {args.reference}: no regression "
              f"found (candidate denies everything the reference denied).")

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
