"""
Invariant -- SMT-based guardrail SAST.

Three subcommands, sharing the same check registry (checks/), output
formats (cli/json/sarif), and exit-code convention (0 = no findings or
--soft-fail, 1 = a check failed):

  invariant run
      Default entry point -- runs both tiers below in one command instead
      of making the operator choose between them. Always runs the baseline
      scan; also runs the diff-scoped regression tier when --diff-base is
      given. This is what CI and a first-time operator should reach for.

  invariant scan
      Baseline tier. Recursively walks --directory, Checkov-style, looking
      for service-control-policies/, rcp-policies/, and iam-policies/
      directories at any depth (not just as direct children of --directory)
      and reading the JSON files inside them. Files with a same-named
      counterpart in the guardrail catalog bundled with this package
      (baseline/, copied from the LZA universal-configuration defaults) get
      the full relative-check treatment (INV_AWS_001/002): Z3 proves the
      candidate still denies/grants exactly what the baseline did. Files
      with no baseline counterpart -- the common case for iam-policies/,
      since custom IAM policies aren't part of the LZA default catalog --
      still get every reference-free check (INV_AWS_003, privilege
      escalation) run against them. No --manifest or --reference needed --
      this is the "just run it" entry point.

  invariant regression
      Diff tier. Reads --manifest (see build_manifest.py, which derives
      pairings from a git diff) and proves each candidate still denies/
      grants exactly what its *paired* reference did. Use this when you
      want to check against something other than the bundled baseline
      (e.g. your org's own last-known-good, or an upstream LZAUC release).

`scan` and `regression` remain as standalone subcommands because CI splits
them into separate, independently-scheduled jobs (see .gitlab-ci.yml /
.github/workflows/invariant.yml) -- `run` is the single-command equivalent
for local, ad-hoc use.

CLI conventions deliberately mirror Checkov:
  --check               run only these check IDs (comma-separated)
  --skip-check          exclude these check IDs (comma-separated)
  --output / -o         cli | json | sarif (repeatable, like Checkov)
  --soft-fail           always exit 0 regardless of findings
  --compact             suppress passed-check output in CLI mode

Inline suppression, Checkov-style: a candidate JSON file can carry a
top-level "_suppressions" array (since raw AWS policy JSON has no comment
syntax to piggyback on the way HCL/YAML checks do):
    "_suppressions": [
      {"check_id": "INV_AWS_001", "reason": "JIRA-1234: intentional widen"}
    ]
This key is stripped before the policy is handed to the solver.
"""
import argparse
import json
import os
import subprocess
import sys

import invariant.checks.scp_permissiveness_regression  # noqa: F401  (import = register)
import invariant.checks.iam_policy_permissiveness_regression  # noqa: F401
import invariant.checks.iam_privilege_escalation  # noqa: F401
import invariant.checks.ast_unconstrained_operator_diff  # noqa: F401
from invariant.build_manifest import build_manifest
from invariant.checks.base import all_checks, Severity
from invariant.policy_dirs import SCANNED_SUBDIRS


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                   Severity.LOW, Severity.INFO]

BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline")


def load_manifest(manifest_path: str) -> list[dict]:
    """
    Declarative pairing of reference <-> candidate, Semgrep-config-style,
    so most new file pairs need zero Python. Example manifest.json:
    [
      {"reference": "reference/lza-core-guardrails-1.json",
       "candidate": "service-control-policies/lza-core-guardrails-1.json"},
      ...
    ]
    """
    with open(manifest_path) as f:
        return json.load(f)


# Directories that are never worth descending into while looking for
# service-control-policies/, rcp-policies/, or iam-policies/ -- dotdirs
# (.git, .terraform, .venv, ...) and common vendored/dependency trees.
# Pruned during the walk purely for speed on large repos; matching a
# SCANNED_SUBDIRS name is still name-based, not content-sniffed, so this
# skip-list is an optimization, not part of the matching logic.
_SKIP_DIRS = {"node_modules", "__pycache__"}


def discover_candidates(directory: str) -> list[dict]:
    """
    Recursively walk `directory` -- Checkov-style, no fixed depth --
    looking for service-control-policies/, rcp-policies/, and
    iam-policies/ directories at any depth, and pair each *.json file
    found directly inside one with its same-named counterpart in the
    bundled baseline catalog, if one exists (basename matching, same
    convention build_manifest.py uses for git-diff-based pairing).

    Matching is still purely by directory *name* (not content, unlike
    Checkov's IaC-type sniffing) -- there's no ambiguity about what a
    service-control-policies/ directory means the way there is for "is
    this file Terraform", so a name match is all that's needed. What
    changes here is *where* that name is allowed to appear: any depth
    under `directory`, not just as its direct child, so `invariant scan`
    (or `invariant run`) can be pointed at a repo root the same way
    `checkov -d .` can, without the caller having to know how deep the
    policy directories happen to live.

    Unlike the old baseline-only discovery, a missing baseline counterpart
    no longer drops the file from the scan entirely -- it's still returned,
    with `"reference": None`. Relative (reference-needing) checks skip it
    at run() time and report why; absolute checks like INV_AWS_003
    (privilege escalation) run on it anyway, since they don't need a
    baseline to prove a property of a single policy. The bundled catalog
    only covers the default LZA guardrails (SCP/RCP), never an org's own
    custom iam-policies/ content, so this is the common case for that
    directory, not an edge case.
    """
    candidates = []
    no_baseline = []

    # os.walk()'s traversal/file order is OS-dependent (whatever readdir()
    # happens to hand back). Pruning dirs in place (not wrapping the walk
    # itself in sorted(), which would force it to exhaust -- and therefore
    # fully descend into -- every directory up front before anything could
    # be pruned) keeps _SKIP_DIRS effective; candidates/no_baseline are
    # sorted below so CLI/JSON/SARIF output doesn't reorder itself from run
    # to run on the same tree.
    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))

        subdir = os.path.basename(os.path.normpath(root))
        if subdir not in SCANNED_SUBDIRS:
            continue

        for entry in sorted(files):
            if not entry.endswith(".json"):
                continue
            candidate_path = os.path.join(root, entry)
            baseline_path = os.path.join(BASELINE_DIR, subdir, entry)
            if not os.path.isfile(baseline_path):
                no_baseline.append(candidate_path)
                candidates.append({"reference": None, "candidate": candidate_path})
                continue
            candidates.append({
                "reference": baseline_path,
                "candidate": candidate_path,
            })

    candidates.sort(key=lambda e: e["candidate"])
    no_baseline.sort()

    if no_baseline:
        print("The following files have no counterpart in the bundled "
              "baseline catalog -- checks that need a reference (e.g. "
              "INV_AWS_001, INV_AWS_002) are skipped for them, but "
              "reference-free checks (e.g. INV_AWS_003) still run:",
              file=sys.stderr)
        for f in no_baseline:
            print(f"  - {f}", file=sys.stderr)

    return candidates


def load_policy_and_suppressions(path: str):
    with open(path) as f:
        data = json.load(f)
    suppressions = {s["check_id"] for s in data.pop("_suppressions", [])}
    return data, suppressions


def run(manifest_entries, only_checks=None, skip_checks=None):
    results = []
    registry = all_checks()
    check_ids = set(registry.keys())
    if only_checks:
        check_ids &= set(only_checks)
    if skip_checks:
        check_ids -= set(skip_checks)

    for entry in manifest_entries:
        candidate_path = entry["candidate"]
        reference_path = entry.get("reference")
        reference = (load_policy_and_suppressions(reference_path)[0]
                     if reference_path else None)
        candidate, suppressed = load_policy_and_suppressions(candidate_path)

        for check_id in sorted(check_ids):
            check_cls = registry[check_id]
            check = check_cls()
            if not check.applies_to(candidate_path):
                continue
            if check_id in suppressed:
                results.append(f"SKIPPED {check_id} on {candidate_path} (suppressed)")
                continue
            if reference is None and check.NEEDS_REFERENCE:
                results.append(
                    f"SKIPPED {check_id} on {candidate_path} "
                    f"(no reference/baseline counterpart)")
                continue
            result = check.run(reference, candidate, candidate_path)
            results.append(result)
    return results


def to_sarif(results, tool_version=None):
    from invariant import __version__
    tool_version = tool_version or __version__
    """Minimal SARIF 2.1.0, enough for GitLab's SAST report ingestion."""
    rules = {}
    findings = []
    for r in results:
        if isinstance(r, str):
            continue
        rules[r.check_id] = {
            "id": r.check_id,
            "shortDescription": {"text": r.check_id},
        }
        if not r.passed:
            findings.append({
                "ruleId": r.check_id,
                "level": "error" if r.severity in
                         (Severity.CRITICAL, Severity.HIGH) else "warning",
                "message": {"text": r.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.file_path}
                    }
                }],
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "invariant",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": findings,
        }],
    }


def _add_common_args(parser):
    parser.add_argument("--check", default=None,
                         help="comma-separated check IDs to run (default: all)")
    parser.add_argument("--skip-check", default=None,
                         help="comma-separated check IDs to exclude")
    parser.add_argument("--output", "-o", action="append",
                         choices=["cli", "json", "sarif"], default=[])
    parser.add_argument("--soft-fail", action="store_true",
                         help="always exit 0 regardless of findings")
    parser.add_argument("--compact", action="store_true",
                         help="suppress passed-check output in CLI mode")
    parser.add_argument("--out-dir", default="solver-results")


def _emit_and_exit_code(results, args) -> int:
    outputs = args.output or ["cli"]
    os.makedirs(args.out_dir, exist_ok=True)
    failed = [r for r in results if not isinstance(r, str) and not r.passed]

    if "cli" in outputs:
        for r in results:
            if isinstance(r, str):
                print(r)
                continue
            if r.passed and args.compact:
                continue
            status = "PASS" if r.passed else f"FAIL ({r.severity.value})"
            print(f"[{status}] {r.check_id}  {r.file_path}  {r.message}")

    if "json" in outputs:
        path = os.path.join(args.out_dir, "results.json")

        def to_dict(r):
            if isinstance(r, str):
                return r
            d = dict(r.__dict__)
            d["severity"] = r.severity.value  # Severity.HIGH -> "high", not the enum repr
            return d

        with open(path, "w") as f:
            json.dump([to_dict(r) for r in results], f, indent=2, default=str)

    if "sarif" in outputs:
        path = os.path.join(args.out_dir, "results.sarif")
        with open(path, "w") as f:
            json.dump(to_sarif(results), f, indent=2)

    if args.soft_fail:
        return 0
    return 1 if failed else 0


def cmd_run(args) -> int:
    """
    The default entry point: always runs the baseline scan tier, plus the
    diff-scoped regression tier whenever --diff-base is given, so the
    operator doesn't have to know in advance to pick `scan` vs
    `regression` -- both run in one command when there's something for
    each to check.
    """
    only = args.check.split(",") if args.check else None
    skip = args.skip_check.split(",") if args.skip_check else None

    scan_entries = discover_candidates(args.directory)
    if not scan_entries:
        print(f"No SCP/RCP/IAM policy files were found under "
              f"{args.directory}", file=sys.stderr)
    results = run(scan_entries, only_checks=only, skip_checks=skip)

    if args.diff_base:
        try:
            regression_entries = build_manifest(
                args.diff_base, args.reference_dir, list(SCANNED_SUBDIRS))
        except subprocess.CalledProcessError as e:
            print(f"Could not diff against {args.diff_base!r}: {e}",
                  file=sys.stderr)
            return 1
        results += run(regression_entries, only_checks=only, skip_checks=skip)
    else:
        print("Skipping the regression tier (no --diff-base given) -- "
              "pass e.g. --diff-base origin/main to also prove every "
              "file changed since that ref still denies/grants exactly "
              "what its reference/ counterpart did.", file=sys.stderr)

    return _emit_and_exit_code(results, args)


def cmd_scan(args) -> int:
    only = args.check.split(",") if args.check else None
    skip = args.skip_check.split(",") if args.skip_check else None
    entries = discover_candidates(args.directory)
    if not entries:
        print(f"No SCP/RCP/IAM policy files were found under "
              f"{args.directory}", file=sys.stderr)
    results = run(entries, only_checks=only, skip_checks=skip)
    return _emit_and_exit_code(results, args)


def cmd_regression(args) -> int:
    only = args.check.split(",") if args.check else None
    skip = args.skip_check.split(",") if args.skip_check else None
    entries = load_manifest(args.manifest)
    results = run(entries, only_checks=only, skip_checks=skip)
    return _emit_and_exit_code(results, args)


def main():
    parser = argparse.ArgumentParser(
        prog="invariant", description="Invariant: SMT-based guardrail SAST")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Default entry point: baseline scan always, plus a "
             "diff-scoped regression check when --diff-base is given -- "
             "runs both tiers in one command instead of choosing between "
             "`scan` and `regression`")
    run_parser.add_argument(
        "--directory", "-d", default=".",
        help="root to recursively scan for service-control-policies/, "
             "rcp-policies/, and iam-policies/ directories at any depth "
             "(default: current directory)")
    run_parser.add_argument(
        "--diff-base", default=None,
        help="git ref to diff against for the regression tier (e.g. "
             "origin/main); omit to run the baseline scan tier only")
    run_parser.add_argument(
        "--reference-dir", default="reference",
        help="directory holding last-known-good reference/ copies, used "
             "only when --diff-base is given (default: reference)")
    _add_common_args(run_parser)
    run_parser.set_defaults(func=cmd_run)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Prove every SCP/RCP/IAM policy under --directory upholds the "
             "bundled LZA default guardrail properties where a baseline "
             "counterpart exists, plus every reference-free check (e.g. "
             "IAM privilege escalation) regardless")
    scan_parser.add_argument(
        "--directory", "-d", default=".",
        help="root to recursively scan for service-control-policies/, "
             "rcp-policies/, and iam-policies/ directories at any depth "
             "(default: current directory)")
    _add_common_args(scan_parser)
    scan_parser.set_defaults(func=cmd_scan)

    regression_parser = subparsers.add_parser(
        "regression",
        help="Diff each candidate in --manifest against its paired "
             "reference (see build_manifest.py)")
    regression_parser.add_argument("--manifest", "-m", default="manifest.json")
    _add_common_args(regression_parser)
    regression_parser.set_defaults(func=cmd_regression)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
