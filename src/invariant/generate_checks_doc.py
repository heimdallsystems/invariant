"""
Regenerates docs/checks.md from the check registry (checks/base.py's
all_checks()), so the documented catalog can't silently drift from the
code the way the hand-written version did -- it only ever documented
INV_AWS_001, even after 002/003/004 were added.

Run with: python -m invariant.generate_checks_doc
Add --check to verify docs/checks.md is up to date without writing to it
(exits 1 if regenerating would change the file) -- suitable for a
pre-commit hook or a CI job.
"""
import argparse
import os
import sys

import invariant.checks.scp_permissiveness_regression  # noqa: F401  (import = register)
import invariant.checks.iam_policy_permissiveness_regression  # noqa: F401
import invariant.checks.iam_privilege_escalation  # noqa: F401
import invariant.checks.ast_unconstrained_operator_diff  # noqa: F401
from invariant.checks.base import all_checks

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS_PATH = os.path.join(REPO_ROOT, "docs", "checks.md")


def render(registry) -> str:
    checks = sorted(registry.values(), key=lambda c: c.check_id)

    lines = [
        "# Checks",
        "",
        "Auto-generated from the check registry -- do not edit by hand. Run "
        "`python -m invariant.generate_checks_doc` after adding or changing "
        "a check, and commit the result.",
        "",
        "| ID | Severity | Needs reference | What it proves |",
        "|---|---|---|---|",
    ]
    for c in checks:
        needs_ref = "yes" if c.NEEDS_REFERENCE else "no"
        summary = " ".join(c.description.split())
        lines.append(f"| `{c.check_id}` | {c.severity.value.upper()} | {needs_ref} | {summary} |")
    lines.append("")

    for c in checks:
        lines.append(f"## `{c.check_id}` -- {c.name}")
        lines.append("")
        lines.append(
            f"**Severity:** {c.severity.value.upper()} &nbsp;·&nbsp; "
            f"**Needs reference:** {'yes' if c.NEEDS_REFERENCE else 'no'}"
        )
        lines.append("")
        lines.append(c.description)
        lines.append("")
        lines.append(f"**Remediation:** {c.remediation}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="verify docs/checks.md is up to date; exit 1 if regenerating "
             "it would change the file, without writing anything")
    args = parser.parse_args()

    content = render(all_checks())

    if args.check:
        current = (open(DOCS_PATH, encoding="utf-8").read()
                   if os.path.isfile(DOCS_PATH) else "")
        if current != content:
            print(f"{DOCS_PATH} is out of date -- run "
                  f"`python -m invariant.generate_checks_doc` and commit "
                  f"the result.", file=sys.stderr)
            return 1
        print(f"{DOCS_PATH} is up to date.")
        return 0

    with open(DOCS_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {DOCS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
