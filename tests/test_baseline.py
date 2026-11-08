"""
The bundled baseline catalog: LZA Universal Configuration v1.4.0
(aws/lza-universal-configuration 96aa5e7), modules/base/default.
"""
import json
import os

from invariant.cli import BASELINE_DIR, run

EXPECTED = {
    "rcp-policies": {"lza-core-rcp-guardrails-1.json"},
    "service-control-policies": {
        "lza-core-guardrails-1.json",
        "lza-core-guardrails-2.json",
        "lza-core-sandbox-guardrails-1.json",
        "lza-core-security-guardrails-1.json",
        "lza-core-workloads-guardrails-1.json",
        "lza-deployment-guardrails-1.json",
        "lza-deployment-guardrails-2.json",
        "lza-infrastructure-guardrails-1.json",
        "lza-quarantine.json",
        "lza-suspended-guardrails.json",
    },
}


def test_catalog_has_every_uc_1_4_0_guardrail():
    found = {d: set(os.listdir(os.path.join(BASELINE_DIR, d))) for d in EXPECTED}
    assert found == EXPECTED


def test_each_baseline_passes_against_itself():
    entries = [
        {"reference": os.path.join(BASELINE_DIR, d, f),
         "candidate": os.path.join(BASELINE_DIR, d, f)}
        for d, files in EXPECTED.items() for f in sorted(files)
    ]
    for entry in entries:
        with open(entry["candidate"], encoding="utf-8") as fh:
            assert "Statement" in json.load(fh)
    results = run(entries)
    failed = [r for r in results if not isinstance(r, str) and not r.passed]
    assert failed == []
    checked = {r.file_path for r in results if not isinstance(r, str)}
    assert len(checked) == 11
