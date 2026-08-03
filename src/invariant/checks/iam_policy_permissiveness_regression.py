"""
INV_AWS_002: IAM identity-policy permissiveness regression.

The Allow-side mirror of INV_AWS_001. service-control-policies/ and
rcp-policies/ are Deny-only account guardrails, where "weaker" means
"denies less than it used to". iam-policies/ holds identity-based and
permission-boundary policies, which are Allow-based -- there "weaker" means
the opposite: the candidate now GRANTS a request the reference never did,
e.g. a NotResource exclusion list losing an accelerator-role entry, or a
Condition that scoped iam:PassRole to specific roles getting loosened.

Requires a reference/ counterpart (see INV_AWS_002 in the README for how to
seed one), same as INV_AWS_001 -- there's nothing to diff a brand-new policy
against yet. For absolute, no-reference-needed analysis of a single IAM
policy, see INV_AWS_003.
"""
from invariant.checks.base import BaseCheck, CheckResult, Severity, register
from invariant.policy_check import find_grant_regression, _model_to_jsonable


@register
class IamPolicyPermissivenessRegression(BaseCheck):
    check_id = "INV_AWS_002"
    name = "IAM identity-policy permissiveness regression"
    severity = Severity.CRITICAL
    description = (
        "Detects whether a change to a customer-managed IAM policy or "
        "permission-boundary policy (iam-policies/) grants any "
        "(action, resource) request that the reference version did not."
    )
    remediation = (
        "Review the counterexample below. If the widened grant is "
        "intentional, update reference/ to match and document why in the PR "
        "description. If not, restore the Condition/Resource/NotResource "
        "scoping that removed the restriction -- this is the same pattern "
        "that guards permission-boundary escape hatches like "
        "iam:PermissionsBoundary and NotResource exclusions for "
        "accelerator-managed roles."
    )

    def applies_to(self, file_path: str) -> bool:
        parts = file_path.replace("\\", "/").split("/")
        return "iam-policies" in parts

    def run(self, reference: dict, candidate: dict, file_path: str) -> CheckResult:
        model = find_grant_regression(
            reference, candidate, label=f"{self.check_id}: {file_path}"
        )
        if model is None:
            return CheckResult(
                check_id=self.check_id, passed=True, severity=self.severity,
                file_path=file_path, message="No regression found.",
            )
        return CheckResult(
            check_id=self.check_id, passed=False, severity=self.severity,
            file_path=file_path,
            message=(
                f"Candidate grants a request the reference did not: "
                f"{_model_to_jsonable(model)}"
            ),
            counterexample=_model_to_jsonable(model),
        )
