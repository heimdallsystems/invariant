"""
INV_AWS_004: unconstrained-operator structural diff guard.

condition_predicate() in policy_check.py only models a hardcoded set of
(operator, key) pairs -- see the docstring there. Any Condition operator
outside that set (StringNotLike, StringNotEquals, StringNotEqualsIgnoreCase,
ArnNotLike on a key other than aws:PrincipalArn/iam:PermissionsBoundary,
etc.) contributes nothing to the Z3 predicate: it's treated as vacuously
true on BOTH the reference and candidate side. That means
find_permissiveness_regression/find_grant_regression (INV_AWS_001/002) are
structurally blind to a change that narrows or widens a request only
through one of those operators' values -- the solver never sees the
operator's actual arguments, so ref and candidate produce identical
predicates regardless of what changed.

This check can't fix that blind spot with more solving -- Z3 still won't
model these operators -- so instead it does a plain structural (non-SMT)
diff: any statement using one of the operators in
ast_diff.UNCONSTRAINED_OPERATORS that changed between reference and
candidate is flagged for manual review. It's a deliberately partial,
conservative fallback for exactly the case the SMT checks can't see, not a
replacement for them -- see ast_diff.py for the operator list and its
limits (it doesn't cover every operator condition_predicate leaves
unconstrained, and it doesn't apply to INV_AWS_003, which has no
reference to diff against).
"""
from invariant.ast_diff import detect_ast_regression_with_degradation
from invariant.checks.base import BaseCheck, CheckResult, Severity, register


@register
class AstUnconstrainedOperatorDiff(BaseCheck):
    check_id = "INV_AWS_004"
    name = "Unconstrained-operator structural diff guard"
    severity = Severity.MEDIUM
    description = (
        "Flags statements whose Condition uses an operator the Z3 encoding "
        "doesn't model (StringNotLike, StringNotEquals, "
        "StringNotEqualsIgnoreCase, ArnNotLike on an unmodeled key, and "
        "their ForAnyValue/ForAllValues variants) when that statement "
        "changed between reference and candidate. INV_AWS_001/002 treat "
        "these operators as non-constraining on both sides, so a real "
        "narrowing or widening hidden behind one of them would otherwise "
        "pass silently."
    )
    remediation = (
        "Manually review the ref/candidate statement diff below -- the "
        "solver could not evaluate whether this change is a real "
        "permissiveness regression. If the change is confirmed safe, "
        "suppress this check_id for the file with a reason; if not, revert "
        "or fix the condition."
    )

    def applies_to(self, file_path: str) -> bool:
        parts = file_path.replace("\\", "/").split("/")
        return bool({"service-control-policies", "rcp-policies",
                      "iam-policies"} & set(parts))

    def run(self, reference: dict, candidate: dict, file_path: str) -> CheckResult:
        findings = detect_ast_regression_with_degradation(reference, candidate)
        if not findings:
            return CheckResult(
                check_id=self.check_id, passed=True, severity=self.severity,
                file_path=file_path,
                message="No changes to statements using unconstrained "
                        "operators.",
            )
        sids = ", ".join(f["sid"] for f in findings)
        return CheckResult(
            check_id=self.check_id, passed=False, severity=self.severity,
            file_path=file_path,
            message=(
                f"{len(findings)} statement(s) using operators the solver "
                f"can't model changed and need manual review: {sids}"
            ),
            counterexample={"findings": findings},
        )
