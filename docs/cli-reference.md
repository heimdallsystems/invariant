# CLI reference

Both subcommands accept:

| Flag | Default | Meaning |
|---|---|---|
| `--check IDS` | all | Comma-separated check IDs to run |
| `--skip-check IDS` | none | Comma-separated check IDs to exclude |
| `--output`, `-o` | `cli` | `cli`, `json`, and/or `sarif` — repeatable |
| `--soft-fail` | off | Always exit `0`, regardless of findings |
| `--compact` | off | Suppress `PASS` lines in `cli` output |
| `--out-dir` | `solver-results` | Where `json`/`sarif` reports get written |

`invariant scan` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--directory`, `-d` | `.` | Root to recursively scan for `service-control-policies/`, `rcp-policies/`, and `iam-policies/` directories at any depth |

`invariant regression` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--manifest`, `-m` | `manifest.json` | Reference↔candidate pairing (see `build_manifest.py`) |

## Report locations

`results.sarif` (SARIF 2.1.0) has one result per failed check. Each result's
region spans the candidate statement the finding is about, so GitHub code
scanning can tell whether an alert is in lines a pull request changed:

| Check | Region |
|---|---|
| `INV_AWS_001` | The candidate statement (matched by `Sid`, or by position when it has no `Sid`) that replaced a reference statement denying the counterexample request |
| `INV_AWS_002` | The first candidate `Allow` statement granting the counterexample request |
| `INV_AWS_003` | The first `Allow` statement granting the first flagged action |
| `INV_AWS_004` | The first changed statement still in the candidate |

If no single statement applies (for example, the statement was deleted),
the region spans the whole `Statement` value. If the file can't be read back
when the report is written, the result has no region. `results.json`
carries the same choice as `statement_index` (0-based, `null` for the whole
`Statement` value).
