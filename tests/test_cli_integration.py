"""
Integration tests through the cli.py discovery/run pipeline -- exercises
the NEEDS_REFERENCE split (a custom iam-policies/ file with no baseline
counterpart still gets INV_AWS_003, but not INV_AWS_001/002) and confirms
_suppressions still works for the new check IDs.
"""
import json

from invariant.cli import discover_candidates, run


def write_policy(path, statements, suppressions=None):
    body = {"Version": "2012-10-17", "Statement": statements}
    if suppressions:
        body["_suppressions"] = suppressions
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body))


def test_custom_iam_policy_has_no_baseline_but_is_still_discovered(tmp_path):
    write_policy(
        tmp_path / "iam-policies" / "custom-role-policy.json",
        [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    )

    entries = discover_candidates(str(tmp_path))
    assert len(entries) == 1
    assert entries[0]["reference"] is None
    assert entries[0]["candidate"].endswith("custom-role-policy.json")


def test_reference_free_check_runs_without_baseline_reference_needing_ones_skip(tmp_path):
    write_policy(
        tmp_path / "iam-policies" / "custom-role-policy.json",
        [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    )
    entries = discover_candidates(str(tmp_path))

    results = run(entries)
    by_check = {r.check_id: r for r in results if not isinstance(r, str)}

    assert "INV_AWS_003" in by_check
    assert by_check["INV_AWS_003"].passed is False  # unconditional PassRole

    skip_lines = [r for r in results if isinstance(r, str) and "SKIPPED" in r]
    assert any("INV_AWS_002" in line and "no reference" in line
               for line in skip_lines)


def test_suppression_silences_privilege_escalation_finding(tmp_path):
    write_policy(
        tmp_path / "iam-policies" / "custom-role-policy.json",
        [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
        suppressions=[{"check_id": "INV_AWS_003", "reason": "reviewed, intentional"}],
    )
    entries = discover_candidates(str(tmp_path))

    results = run(entries)
    skip_lines = [r for r in results if isinstance(r, str) and "suppressed" in r]
    assert any("INV_AWS_003" in line for line in skip_lines)
