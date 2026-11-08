"""
INV_AWS_003: IAM privilege-escalation primitive check.

Unlike INV_AWS_001/002, this is an absolute property of a single candidate
policy -- no reference or baseline required, so it runs on a brand-new
custom IAM policy the moment it's written (NEEDS_REFERENCE = False).

Checkov/cloudsplaining-style tools flag a single dangerous action by
pattern (`"Action": "iam:*"`). They can't tell you whether a *combination*
of NotAction/NotResource/Condition clauses still leaves a known escalation
primitive (PassRole abuse, policy-version tampering, self-attaching an
admin policy, etc.) reachable on some resource. Z3 answers that directly,
with a concrete resource ARN counterexample instead of a pattern match.

A permission-boundary or "end-user" policy is *expected* to grant most of
these outside a protected prefix (aws-controltower-*, the accelerator's own
roles) -- that's its whole job. Findings here are for review/suppression,
not an assumption that every hit is a bug; INV_AWS_002 is what catches an
*unintentional* widening of that same policy over time.
"""
from invariant.checks.base import BaseCheck, CheckResult, Severity, register
from invariant.policy_check import find_privilege_escalation, granting_statement_index
from invariant.policy_dirs import IAM_DIR


@register
class IamPrivilegeEscalation(BaseCheck):
    check_id = "INV_AWS_003"
    name = "IAM privilege-escalation primitive"
    severity = Severity.HIGH
    NEEDS_REFERENCE = False
    description = (
        "Proves whether a candidate IAM policy grants a known IAM "
        "privilege-escalation primitive (e.g. iam:PassRole, "
        "iam:CreatePolicyVersion, iam:AttachRolePolicy) on any resource, "
        "accounting for NotAction/NotResource/Condition scoping rather than "
        "matching the action name in isolation."
    )
    remediation = (
        "If this policy is a permission boundary or admin-delegation policy "
        "and the grant is intentional (scoped away from accelerator-managed "
        "roles), add a _suppressions entry documenting that. If this is "
        "meant to be a least-privilege workload policy, restrict the "
        "Resource/Condition so the flagged action isn't reachable, or "
        "remove it if unused."
    )

    def applies_to(self, file_path: str) -> bool:
        parts = file_path.replace("\\", "/").split("/")
        return IAM_DIR in parts

    def run(self, reference, candidate: dict, file_path: str) -> CheckResult:
        findings = find_privilege_escalation(candidate)
        if not findings:
            return CheckResult(
                check_id=self.check_id, passed=True, severity=self.severity,
                file_path=file_path,
                message="No known privilege-escalation primitive granted "
                        "unconditionally.",
            )
        detail = {
            action: {str(d): str(m[d]) for d in m.decls()}
            for action, m in findings
        }
        actions = ", ".join(action for action, _ in findings)
        return CheckResult(
            check_id=self.check_id, passed=False, severity=self.severity,
            file_path=file_path,
            message=(
                f"Grants {len(findings)} privilege-escalation primitive(s) "
                f"unconditionally on at least one resource: {actions}"
            ),
            counterexample=detail,
            statement_index=granting_statement_index(candidate, findings[0][1]),
        )
