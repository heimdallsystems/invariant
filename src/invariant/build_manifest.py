"""
Builds manifest.json for Invariant's CLI by diffing the current branch
against a base ref, scoped to the guardrail policy directories, and pairing
each changed candidate file with its reference/<basename> counterpart.

Files with no reference counterpart are reported (not silently dropped) and
excluded from the manifest -- new guardrail files have nothing to regress
against yet, so INV_AWS_001 can't run on them. Add a reference copy as part
of the same MR that introduces a new guardrail file.
"""
import argparse
import json
import os
import subprocess
import sys


def changed_files(diff_base: str, candidate_dirs: list[str]) -> list[str]:
    cmd = ["git", "diff", "--name-only", "--diff-filter=d",
           f"{diff_base}...HEAD", "--", *candidate_dirs]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def build_manifest(diff_base: str, reference_dir: str,
                    candidate_dirs: list[str]) -> list[dict]:
    manifest = []
    skipped = []

    for candidate_path in changed_files(diff_base, candidate_dirs):
        if not candidate_path.endswith(".json"):
            continue
        basename = os.path.basename(candidate_path)
        reference_path = os.path.join(reference_dir, basename)

        if not os.path.isfile(reference_path):
            skipped.append(candidate_path)
            continue

        manifest.append({
            "reference": reference_path,
            "candidate": candidate_path,
        })

    if skipped:
        print("The following changed files have no reference/ counterpart "
              "and were excluded from this run:", file=sys.stderr)
        for f in skipped:
            print(f"  - {f}  (expected reference/{os.path.basename(f)})",
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
