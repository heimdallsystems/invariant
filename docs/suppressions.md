# Suppressing a finding

A candidate JSON file can carry a top-level `_suppressions` array (raw AWS
policy JSON has no comment syntax to piggyback a suppression on, unlike
HCL/YAML checks):

```json
{
  "Version": "2012-10-17",
  "Statement": [ ... ],
  "_suppressions": [
    {"check_id": "INV_AWS_001", "reason": "JIRA-1234: intentional widen"}
  ]
}
```

This key is stripped before the policy is handed to the solver, so it never
affects the request semantics Z3 reasons about.

!!! warning "Not usable on LZA configs"
    Landing Zone Accelerator deploys policy files to AWS as they are, and
    AWS rejects unknown top-level keys, so a file carrying `_suppressions`
    would most likely fail to deploy. A suppression file kept outside the
    policy JSON is [proposed](proposals/suppression-file.md) but not
    implemented.
