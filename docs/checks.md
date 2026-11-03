# Checks

Auto-generated from the check registry -- do not edit by hand. Run `python -m invariant.generate_checks_doc` after adding or changing a check, and commit the result.

| ID | Severity | Needs reference | What it proves |
|---|---|---|---|
| `INV_AWS_001` | CRITICAL | yes | Detects whether a change to a Service Control Policy or Resource Control Policy allows any (action, resource, principal) request that the reference version explicitly denied. |
| `INV_AWS_002` | CRITICAL | yes | Detects whether a change to a customer-managed IAM policy or permission-boundary policy (iam-policies/) grants any (action, resource) request that the reference version did not. |
| `INV_AWS_003` | HIGH | no | Proves whether a candidate IAM policy grants a known IAM privilege-escalation primitive (e.g. iam:PassRole, iam:CreatePolicyVersion, iam:AttachRolePolicy) on any resource, accounting for NotAction/NotResource/Condition scoping rather than matching the action name in isolation. |
| `INV_AWS_004` | MEDIUM | yes | Flags statements whose Condition uses an operator the Z3 encoding doesn't model (StringNotLike, StringNotEquals, StringNotEqualsIgnoreCase, ArnNotLike on an unmodeled key, and their ForAnyValue/ForAllValues variants) when that statement changed between reference and candidate. INV_AWS_001/002 treat these operators as non-constraining on both sides, so a real narrowing or widening hidden behind one of them would otherwise pass silently. |

## `INV_AWS_001` -- SCP/RCP permissiveness regression

**Severity:** CRITICAL &nbsp;·&nbsp; **Needs reference:** yes

Detects whether a change to a Service Control Policy or Resource Control Policy allows any (action, resource, principal) request that the reference version explicitly denied.

**Remediation:** Review the counterexample below. If the widened permission is intentional, update reference/ to match and document why in the MR description. If unintentional, revert the Condition/Resource/Action change that removed the denial.

## `INV_AWS_002` -- IAM identity-policy permissiveness regression

**Severity:** CRITICAL &nbsp;·&nbsp; **Needs reference:** yes

Detects whether a change to a customer-managed IAM policy or permission-boundary policy (iam-policies/) grants any (action, resource) request that the reference version did not.

**Remediation:** Review the counterexample below. If the widened grant is intentional, update reference/ to match and document why in the PR description. If not, restore the Condition/Resource/NotResource scoping that removed the restriction -- this is the same pattern that guards permission-boundary escape hatches like iam:PermissionsBoundary and NotResource exclusions for accelerator-managed roles.

## `INV_AWS_003` -- IAM privilege-escalation primitive

**Severity:** HIGH &nbsp;·&nbsp; **Needs reference:** no

Proves whether a candidate IAM policy grants a known IAM privilege-escalation primitive (e.g. iam:PassRole, iam:CreatePolicyVersion, iam:AttachRolePolicy) on any resource, accounting for NotAction/NotResource/Condition scoping rather than matching the action name in isolation.

**Remediation:** If this policy is a permission boundary or admin-delegation policy and the grant is intentional (scoped away from accelerator-managed roles), add a _suppressions entry documenting that. If this is meant to be a least-privilege workload policy, restrict the Resource/Condition so the flagged action isn't reachable, or remove it if unused.

## `INV_AWS_004` -- Unconstrained-operator structural diff guard

**Severity:** MEDIUM &nbsp;·&nbsp; **Needs reference:** yes

Flags statements whose Condition uses an operator the Z3 encoding doesn't model (StringNotLike, StringNotEquals, StringNotEqualsIgnoreCase, ArnNotLike on an unmodeled key, and their ForAnyValue/ForAllValues variants) when that statement changed between reference and candidate. INV_AWS_001/002 treat these operators as non-constraining on both sides, so a real narrowing or widening hidden behind one of them would otherwise pass silently.

**Remediation:** Manually review the ref/candidate statement diff below -- the solver could not evaluate whether this change is a real permissiveness regression. If the change is confirmed safe, suppress this check_id for the file with a reason; if not, revert or fix the condition.
