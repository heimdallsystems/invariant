"""
SARIF regions: each result points at the statement a finding is about, so
GitHub code scanning can match alerts to changed lines and GitLab doesn't
collapse findings that share a rule and file.
"""
import json

from invariant.cli import run, to_sarif
from invariant.locate import locate_statements, region_for


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return str(path)


def dump(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements}, indent=2) + "\n"


def line_of(text, needle):
    """1-based line of the first line containing `needle`."""
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"{needle!r} not found")


def sarif_results(results):
    return to_sarif(results)["runs"][0]["results"]


def failed_region(results, check_id):
    [result] = [r for r in sarif_results(results) if r["ruleId"] == check_id]
    return result["locations"][0]["physicalLocation"].get("region")


# ---------------------------------------------------------------------------
# Locator
# ---------------------------------------------------------------------------
def test_locates_each_statement_in_an_array():
    text = (
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {"Sid": "A", "Effect": "Deny", "Action": "s3:*", "Resource": "*"},\n'
        '    {\n'
        '      "Sid": "B",\n'
        '      "Effect": "Deny",\n'
        '      "Action": "ec2:*",\n'
        '      "Resource": "*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )
    locations = locate_statements(text)
    first, second = locations.statements
    assert (first.start_line, first.start_column, first.end_line) == (4, 5, 4)
    assert first.end_column == 5 + len('{"Sid": "A", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}')
    assert (second.start_line, second.start_column) == (5, 5)
    assert (second.end_line, second.end_column) == (10, 6)  # exclusive, after "}"
    block = locations.statement_block
    assert (block.start_line, block.start_column, block.end_line) == (3, 3, 11)


def test_single_object_statement_is_one_statement():
    text = '{"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}}'
    locations = locate_statements(text)
    assert len(locations.statements) == 1
    assert locations.statements[0].start_column == len('{"Statement": ') + 1


def test_crlf_and_bom_do_not_shift_lines():
    text = '﻿{\r\n  "Statement": [\r\n    {"Effect": "Deny"},\r\n    {"Effect": "Allow"}\r\n  ]\r\n}\r\n'
    locations = locate_statements(text)
    assert [s.start_line for s in locations.statements] == [3, 4]


def test_strings_containing_brackets_and_keys_are_not_mistaken_for_structure():
    text = dump([
        {"Sid": "X", "Effect": "Deny", "Action": "s3:*",
         "Resource": "arn:aws:s3:::\"Statement\": [ }{"},
        {"Sid": "Y", "Effect": "Deny", "Action": "ec2:*", "Resource": "*"},
    ])
    locations = locate_statements(text)
    assert [s.start_line for s in locations.statements] == [
        line_of(text, '"Sid": "X"') - 1, line_of(text, '"Sid": "Y"') - 1]


def test_last_duplicate_statement_key_wins_like_json_loads():
    text = '{"Statement": [{"Sid": "old"}],\n "Statement": [{"Sid": "new"}]}'
    locations = locate_statements(text)
    assert locations.statements[0].start_line == 2


def test_unlocatable_text_gives_none():
    assert locate_statements("[]") is None
    assert locate_statements('{"Version": "2012-10-17"}') is None
    assert locate_statements('{"Statement": [') is None
    assert locate_statements("") is None


def test_region_for_falls_back_to_statement_block_then_none(tmp_path):
    text = dump([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
    path = write(tmp_path / "p.json", text)
    assert region_for(path, 0)["startLine"] == 4  # "{" of the statement
    assert region_for(path, None)["startLine"] == line_of(text, '"Statement"')
    assert region_for(path, 7)["startLine"] == line_of(text, '"Statement"')
    assert region_for(str(tmp_path / "missing.json"), 0) is None


# ---------------------------------------------------------------------------
# Regions per check, through the CLI pipeline
# ---------------------------------------------------------------------------
GUARDRAILS = [
    {"Sid": "GRCT", "Effect": "Deny", "Action": ["cloudtrail:StopLogging"], "Resource": "*"},
    {"Sid": "GRCFGR", "Effect": "Deny",
     "Action": ["config:DeleteConfigRule", "config:PutConfigRule"], "Resource": "*"},
    {"Sid": "GRS3", "Effect": "Deny", "Action": ["s3:PutAccountPublicAccessBlock"], "Resource": "*"},
]


def scp_pair(tmp_path, candidate_statements):
    ref = write(tmp_path / "reference" / "service-control-policies" / "g.json", dump(GUARDRAILS))
    text = dump(candidate_statements)
    cand = write(tmp_path / "service-control-policies" / "g.json", text)
    return [{"reference": ref, "candidate": cand}], text


def test_inv_aws_001_region_is_the_weakened_statement(tmp_path):
    candidate = json.loads(json.dumps(GUARDRAILS))
    candidate[1]["Action"] = ["config:PutConfigRule"]  # drop DeleteConfigRule
    entries, text = scp_pair(tmp_path, candidate)

    region = failed_region(run(entries, only_checks=["INV_AWS_001"]), "INV_AWS_001")
    assert region["startLine"] == line_of(text, '"GRCFGR"') - 1
    assert region["endLine"] == line_of(text, '"GRS3"') - 2


def test_inv_aws_001_region_follows_sid_when_statements_reorder(tmp_path):
    candidate = json.loads(json.dumps(GUARDRAILS))
    candidate[1]["Action"] = ["config:PutConfigRule"]
    candidate = [candidate[2], candidate[1], candidate[0]]
    entries, text = scp_pair(tmp_path, candidate)

    region = failed_region(run(entries, only_checks=["INV_AWS_001"]), "INV_AWS_001")
    assert region["startLine"] == line_of(text, '"GRCFGR"') - 1


def test_inv_aws_001_deleted_statement_points_at_statement_block(tmp_path):
    candidate = [GUARDRAILS[0], GUARDRAILS[2]]
    entries, text = scp_pair(tmp_path, candidate)

    region = failed_region(run(entries, only_checks=["INV_AWS_001"]), "INV_AWS_001")
    assert region["startLine"] == line_of(text, '"Statement"')
    assert region["endLine"] == len(text.splitlines()) - 1


def test_inv_aws_001_unnamed_statements_match_by_position(tmp_path):
    reference = [{k: v for k, v in s.items() if k != "Sid"} for s in GUARDRAILS]
    ref = write(tmp_path / "reference" / "service-control-policies" / "g.json", dump(reference))
    candidate = json.loads(json.dumps(reference))
    candidate[2]["Action"] = ["s3:GetObject"]
    text = dump(candidate)
    cand = write(tmp_path / "service-control-policies" / "g.json", text)

    region = failed_region(run([{"reference": ref, "candidate": cand}],
                               only_checks=["INV_AWS_001"]), "INV_AWS_001")
    assert region["startLine"] == locate_statements(text).statements[2].start_line


def test_inv_aws_003_region_is_the_granting_statement(tmp_path):
    text = dump([
        {"Sid": "Read", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Sid": "Pass", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
    ])
    cand = write(tmp_path / "iam-policies" / "custom.json", text)

    region = failed_region(run([{"reference": None, "candidate": cand}],
                               only_checks=["INV_AWS_003"]), "INV_AWS_003")
    assert region["startLine"] == line_of(text, '"Pass"') - 1


def test_inv_aws_002_region_is_the_widening_statement(tmp_path):
    reference = [
        {"Sid": "Read", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Sid": "Logs", "Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "*"},
    ]
    ref = write(tmp_path / "reference" / "iam-policies" / "p.json", dump(reference))
    candidate = json.loads(json.dumps(reference))
    candidate[1]["Action"] = ["logs:PutLogEvents", "logs:DeleteLogGroup"]
    text = dump(candidate)
    cand = write(tmp_path / "iam-policies" / "p.json", text)

    region = failed_region(run([{"reference": ref, "candidate": cand}],
                               only_checks=["INV_AWS_002"]), "INV_AWS_002")
    assert region["startLine"] == line_of(text, '"Logs"') - 1


def test_inv_aws_004_region_is_the_changed_statement(tmp_path):
    def stmt(sid, accounts):
        return {"Sid": sid, "Effect": "Deny", "Action": "s3:*", "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:PrincipalAccount": accounts}}}

    ref = write(tmp_path / "reference" / "service-control-policies" / "g.json",
                dump([stmt("Keep", ["1"]), stmt("Edit", ["2"])]))
    text = dump([stmt("Keep", ["1"]), stmt("Edit", ["2", "3"])])
    cand = write(tmp_path / "service-control-policies" / "g.json", text)

    region = failed_region(run([{"reference": ref, "candidate": cand}],
                               only_checks=["INV_AWS_004"]), "INV_AWS_004")
    assert region["startLine"] == line_of(text, '"Edit"') - 1


def test_findings_on_two_statements_get_distinct_regions(tmp_path):
    a = write(tmp_path / "iam-policies" / "a.json",
              dump([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]))
    b = write(tmp_path / "iam-policies" / "b.json", "\n\n" + dump(
        [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]))
    results = run([{"reference": None, "candidate": a}, {"reference": None, "candidate": b}],
                  only_checks=["INV_AWS_003"])
    lines = [r["locations"][0]["physicalLocation"]["region"]["startLine"]
             for r in sarif_results(results)]
    assert lines == [4, 6]


def test_result_without_readable_file_keeps_no_region_but_is_reported(tmp_path):
    from invariant.checks.base import CheckResult, Severity
    result = CheckResult("INV_AWS_003", False, Severity.HIGH,
                         str(tmp_path / "gone.json"), "msg", statement_index=0)
    [sarif] = sarif_results([result])
    assert sarif["ruleId"] == "INV_AWS_003"
    assert "region" not in sarif["locations"][0]["physicalLocation"]


def test_passing_checks_and_skips_still_produce_no_results(tmp_path):
    entries, _ = scp_pair(tmp_path, GUARDRAILS)
    results = run(entries)
    assert sarif_results(results) == []
