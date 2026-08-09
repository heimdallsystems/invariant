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
| `--directory`, `-d` | `.` | Root to scan for `service-control-policies/` and `rcp-policies/` |

`invariant regression` also takes:

| Flag | Default | Meaning |
|---|---|---|
| `--manifest`, `-m` | `manifest.json` | Reference↔candidate pairing (see `build_manifest.py`) |
