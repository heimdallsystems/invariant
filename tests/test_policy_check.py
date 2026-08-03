"""
Engine-level tests for invariant.policy_check.

No tests existed for this repo before this change. These cover both a
sanity check for the pre-existing Deny-side regression engine (INV_AWS_001)
and the new Allow-side model added for iam-policies/ support
(INV_AWS_002/003): NotResource handling, iam:PermissionsBoundary condition
scoping, explicit-deny-wins semantics, grant regression, and the
privilege-escalation primitive check.
"""
import copy

from invariant.policy_check import (
    find_grant_regression,
    find_permissiveness_regression,
    find_privilege_escalation,
)


def scp(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


# ---------------------------------------------------------------------------
# Pre-existing Deny-side engine (INV_AWS_001) -- no coverage existed before.
# ---------------------------------------------------------------------------
def test_deny_regression_none_on_identical_policy():
    policy = scp({
        "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*",
    })
    assert find_permissiveness_regression(policy, policy) is None


def test_deny_regression_found_when_action_dropped_from_deny_list():
    reference = scp({
        "Effect": "Deny",
        "Action": ["s3:DeleteBucket", "s3:DeleteObject"],
        "Resource": "*",
    })
    candidate = scp({
        "Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*",
    })
    model = find_permissiveness_regression(reference, candidate)
    assert model is not None


# ---------------------------------------------------------------------------
# New Allow-side engine (INV_AWS_002/003)
# ---------------------------------------------------------------------------
# Mirrors the real LZA "end-user boundary" pattern: broad Allow, then a
# statement that only allows iam:CreateRole when iam:PermissionsBoundary is
# pinned to the accelerator's own boundary policy, scoped away from
# accelerator-managed roles via NotResource.
def boundary_policy():
    return scp(
        {
            "Sid": "EnforceBoundary",
            "Effect": "Allow",
            "Action": ["iam:CreateRole"],
            "NotResource": ["arn:aws:iam::*:role/accelerator-*"],
            "Condition": {
                "ArnLike": {
                    "iam:PermissionsBoundary": "arn:aws:iam::*:policy/End-User-Policy"
                }
            },
        },
        {
            "Sid": "DenyTampering",
            "Effect": "Deny",
            "Action": "iam:DeleteRolePermissionsBoundary",
            "Resource": "*",
        },
    )


def test_not_resource_scopes_allow_statement():
    ctx_findings = find_privilege_escalation(
        boundary_policy(), actions=["iam:CreateRole"]
    )
    # iam:CreateRole is granted (with the boundary condition), but only on
    # resources outside accelerator-managed roles -- NotResource must still
    # let the solver find a permitted resource.
    assert len(ctx_findings) == 1
    action, model = ctx_findings[0]
    assert action == "iam:CreateRole"


def test_explicit_deny_overrides_allow_in_same_policy():
    policy = scp(
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
    )
    findings = find_privilege_escalation(policy, actions=["s3:DeleteBucket"])
    assert findings == []  # explicit Deny wins, so this is never granted


def test_grant_regression_none_on_identical_policy():
    policy = boundary_policy()
    assert find_grant_regression(policy, policy) is None


def test_grant_regression_found_when_boundary_condition_removed():
    reference = boundary_policy()
    candidate = copy.deepcopy(reference)
    for stmt in candidate["Statement"]:
        if stmt.get("Sid") == "EnforceBoundary":
            del stmt["Condition"]

    model = find_grant_regression(reference, candidate)
    assert model is not None


def test_grant_regression_found_when_notresource_exclusion_narrowed():
    reference = boundary_policy()
    candidate = copy.deepcopy(reference)
    for stmt in candidate["Statement"]:
        if stmt.get("Sid") == "EnforceBoundary":
            del stmt["NotResource"]  # now grants on accelerator-managed roles too

    model = find_grant_regression(reference, candidate)
    assert model is not None


def test_privilege_escalation_flags_unconditional_pass_role():
    policy = scp({
        "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
    })
    findings = find_privilege_escalation(policy, actions=["iam:PassRole"])
    assert len(findings) == 1


def test_privilege_escalation_silent_when_action_absent():
    policy = scp({
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
    })
    findings = find_privilege_escalation(policy, actions=["iam:PassRole"])
    assert findings == []
