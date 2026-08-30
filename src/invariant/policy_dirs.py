"""
Single source of truth for the guardrail policy-type subdirectory names
(service-control-policies/, rcp-policies/, iam-policies/).

Kept as its own leaf module -- no z3, no check registry -- so
build_manifest.py can import it without pulling in cli.py's check-registry
side effects, and so renaming or adding a policy-type directory is a
one-line change instead of one made in cli.py and separately in
build_manifest.py.

declarative-policies is deliberately excluded here: its @@assign schema
isn't a Deny/Allow-statement IAM policy, so no registered check's
applies_to() matches it anyway.

Named individually (not just as tuple members) so each check's applies_to()
can import the specific directory/directories it cares about instead of
repeating the literal string -- renaming a directory then only requires
updating the value here.
"""
SCP_DIR = "service-control-policies"
RCP_DIR = "rcp-policies"
IAM_DIR = "iam-policies"

SCANNED_SUBDIRS = (SCP_DIR, RCP_DIR, IAM_DIR)
