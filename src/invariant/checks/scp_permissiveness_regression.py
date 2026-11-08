"""
INV_AWS_001: SCP/RCP permissiveness regression.

Fails if the candidate policy fails to deny a request that the reference
policy explicitly denied -- i.e. the guardrail got weaker.
"""
from invariant.checks.base import BaseCheck, CheckResult, Severity, register
from invariant.policy_check import (
    find_permissiveness_regression, weakened_statement_index, _model_to_jsonable,
)
from invariant.policy_dirs import SCP_DIR, RCP_DIR


@register
class ScpPermissivenessRegression(BaseCheck):
    check_id = "INV_AWS_001"
    name = "SCP/RCP permissiveness regression"
    severity = Severity.CRITICAL
    description = (
        "Detects whether a change to a Service Control Policy or Resource "
        "Control Policy allows any (action, resource, principal) request "
        "that the reference version explicitly denied."
    )
    remediation = (
        "Review the counterexample below. If the widened permission is "
        "intentional, update reference/ to match and document why in the MR "
        "description. If unintentional, revert the Condition/Resource/Action "
        "change that removed the denial."
    )

    def applies_to(self, file_path: str) -> bool:
        # Path-component check (not a string prefix): `regression` gets
        # repo-root-relative paths from git diff (always "/"-separated),
        # `scan` gets --directory-prefixed, OS-native-separator paths. Both
        # just need service-control-policies/ or rcp-policies/ anywhere in
        # the path, not necessarily at the front of it.
        parts = file_path.replace("\\", "/").split("/")
        return SCP_DIR in parts or RCP_DIR in parts

    def run(self, reference: dict, candidate: dict, file_path: str) -> CheckResult:
        model = find_permissiveness_regression(reference, candidate)
        if model is None:
            return CheckResult(
                check_id=self.check_id, passed=True, severity=self.severity,
                file_path=file_path, message="No regression found.",
            )
        return CheckResult(
            check_id=self.check_id, passed=False, severity=self.severity,
            file_path=file_path,
            message=(
                f"Candidate no longer denies a request the reference denied: "
                f"{_model_to_jsonable(model)}"
            ),
            counterexample=_model_to_jsonable(model),
            statement_index=weakened_statement_index(reference, candidate, model),
        )
