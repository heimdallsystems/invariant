"""
Builds manifest.json for Invariant's CLI by diffing the current branch
against a base ref, scoped to the guardrail policy directories, and pairing
each changed candidate file with its reference/<subdir>/<basename>
counterpart -- reference/ mirrors the candidate directory structure (e.g.
service-control-policies/foo.json pairs with
reference/service-control-policies/foo.json), not a single flat basename
directory. With only service-control-policies/ and rcp-policies/ as
candidate dirs a flat reference/<basename> layout mostly avoided collisions
by luck; with iam-policies/ added as a third candidate dir (INV_AWS_002/003)
the odds of two unrelated files sharing a basename across policy types goes
up, so the pairing preserves the subdir instead of risking a silent
cross-directory match.

Files with no reference counterpart are reported (not silently dropped) and
excluded from the manifest -- new guardrail files have nothing to regress
against yet, so INV_AWS_001/002 can't run on them. Add a reference copy as
part of the same MR/PR that introduces a new guardrail file.
"""
import argparse
import json
import os
import subprocess
import sys

# Kept in sync with cli.SCANNED_SUBDIRS by convention rather than imported,
# so this stays a standalone git-diff utility with no dependency on the
# check registry cli.py pulls in.
KNOWN_SUBDIRS = ("service-control-policies", "rcp-policies", "iam-policies")


def changed_files(diff_base: str, candidate_dirs: list[str]) -> list[str]:
    cmd = ["git", "diff", "--name-only", "--diff-filter=d",
           f"{diff_base}...HEAD", "--", *candidate_dirs]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def _reference_subpath(candidate_path: str) -> str:
    """
    "<anything>/iam-policies/foo.json" -> "iam-policies/foo.json", i.e. the
    reference/ counterpart mirrors the policy-type subdir + basename, not
    just the basename. See module docstring for why a flat basename-only
    layout stops being safe once more than one policy-type directory is in
    play.
    """
    parts = candidate_path.replace("\\", "/").split("/")
    for i, part in enumerate(parts):
        if part in KNOWN_SUBDIRS:
            return "/".join(parts[i:])
    return os.path.basename(candidate_path)


def build_manifest(diff_base: str, reference_dir: str,
                    candidate_dirs: list[str]) -> list[dict]:
    manifest = []
    skipped = []

    for candidate_path in changed_files(diff_base, candidate_dirs):
        if not candidate_path.endswith(".json"):
            continue
        reference_path = os.path.normpath(
            os.path.join(reference_dir, _reference_subpath(candidate_path)))

        if not os.path.isfile(reference_path):
            skipped.append((candidate_path, reference_path))
            continue

        manifest.append({
            "reference": reference_path,
            "candidate": candidate_path,
        })

    if skipped:
        print("The following changed files have no reference/ counterpart "
              "and were excluded from this run:", file=sys.stderr)
        for candidate_path, reference_path in skipped:
            print(f"  - {candidate_path}  (expected {reference_path})",
                  file=sys.stderr)

    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diff-base", required=True,
                         help="git ref to diff against (branch or SHA)")
    parser.add_argument("--reference-dir", required=True)
    parser.add_argument("--candidate-dirs", nargs="+", required=True)
    parser.add_argument("--out", default="manifest.json")
    args = parser.parse_args()

    manifest = build_manifest(args.diff_base, args.reference_dir,
                               args.candidate_dirs)

    with open(args.out, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Wrote {len(manifest)} entr{'y' if len(manifest)==1 else 'ies'} "
          f"to {args.out}")


if __name__ == "__main__":
    main()
