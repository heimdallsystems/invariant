"""
AST-level structural diff pre-flight guard for invariant-sast.
Detects changes in policies containing complex/unconstrained SMT operators
(e.g., ArnNotLike, StringNotLike) before or alongside formal verification.
"""

from typing import Any, Dict, List, Set, Tuple

# Operators that Z3 treats as non-constraining or complementary regexes
UNCONSTRAINED_OPERATORS: Set[str] = {
    "ArnNotLike",
    "StringNotLike",
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "ForAnyValue:StringNotLike",
    "ForAllValues:StringNotLike",
    "ForAnyValue:ArnNotLike",
    "ForAllValues:ArnNotLike",
}


def extract_unconstrained_statements(policy_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Inspects an AWS JSON policy AST and retrieves statements using complex operators."""
    flagged_statements = []
    statements = policy_json.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, stmt in enumerate(statements):
        conditions = stmt.get("Condition", {})
        found_ops = []
        for op in conditions.keys():
            if any(unconstrained_op.lower() in op.lower() for unconstrained_op in UNCONSTRAINED_OPERATORS):
                found_ops.append(op)

        if found_ops:
            # Sid is optional in AWS policy JSON and commonly omitted. Falling
            # back to a shared literal like "UnnamedStatement" for every
            # statement without one causes them to collide on the same key
            # once indexed below -- in a dict comprehension only the last one
            # survives, so an earlier unnamed statement's change silently
            # vanishes from the diff if a later unnamed statement happens to
            # be unchanged. Suffixing with the statement's position keeps
            # every statement's key unique regardless of Sid.
            sid = stmt.get("Sid")
            key = sid if sid else f"UnnamedStatement#{index}"
            flagged_statements.append({
                "Key": key,
                "Sid": sid or key,
                "Effect": stmt.get("Effect", "Allow"),
                "Operators": found_ops,
                "RawStatement": stmt,
            })
    return flagged_statements


def detect_ast_regression_with_degradation(
    ref_policy: Dict[str, Any], candidate_policy: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Compares reference and candidate policy ASTs.
    Returns findings for structural diffs on statements using unconstrained operators.
    """
    findings = []
    ref_unconstrained = extract_unconstrained_statements(ref_policy)
    cand_unconstrained = extract_unconstrained_statements(candidate_policy)

    # Index by the collision-safe Key (see extract_unconstrained_statements),
    # not by raw Sid, so two unnamed statements never overwrite each other.
    ref_by_key = {s["Key"]: s for s in ref_unconstrained}
    cand_by_key = {s["Key"]: s for s in cand_unconstrained}

    all_keys = set(ref_by_key.keys()).union(set(cand_by_key.keys()))

    for key in all_keys:
        ref_stmt = ref_by_key.get(key)
        cand_stmt = cand_by_key.get(key)

        # Case 1: Statement modified or removed/added containing unconstrained operators
        if ref_stmt != cand_stmt:
            sid = (ref_stmt or cand_stmt)["Sid"]
            ops_used = (ref_stmt or cand_stmt)["Operators"]
            findings.append({
                "check_id": "INV_AWS_WARN_001",
                "severity": "WARNING",
                "sid": sid,
                "status": "PARTIAL_SOUNDNESS_DEGRADATION",
                "message": (
                    f"Structural change detected in statement '{sid}' using unconstrained operator(s) {ops_used}. "
                    "SMT impact analysis degraded to manual review due to regex complement/solver limitations."
                ),
                "ref_statement": ref_stmt["RawStatement"] if ref_stmt else None,
                "cand_statement": cand_stmt["RawStatement"] if cand_stmt else None,
            })

    return findings