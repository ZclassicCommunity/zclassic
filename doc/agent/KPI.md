# Tree-health floor (`zcl-lint kpi`)

`zcl-lint kpi` prints one row per metric, with today's value, the floor and a status, and fails when a metric is
worse than its floor. The floors live in `zcutil/lint/kpi-floor.txt` (`<metric><TAB><floor>`) and only shrink:
`zcl-lint kpi --tighten` lowers them to today's values and refuses while any metric is worse or unavailable.
The same command creates the file when it is missing.

## 0 versus could not look

A metric is never reported as 0 when its source cannot be read. It is `UNAVAILABLE`, the command exits 2, and a
floor is never written, because "found none" and "could not look" are different facts. Exit codes: 0 ok,
1 a metric is worse (the output names the metric, the floor and the new value) or has no floor row, 2 a metric
is unavailable or the floor file is malformed.

## Metrics

| Metric | Read from | Meaning |
| --- | --- | --- |
| `python_files` | tracked file list | tracked `.py` and `.pyw` files (the target is 0) |
| `hosted_ci_files` | tracked file list | hosted CI definitions such as `.github/workflows/*` (the target is 0) |
| `shell_lines` | tracked shell files, vendored trees excluded | lines of shell |
| `bash_lines` | `zcutil/lint/no-new-bash.txt` | bash shebang and bashism lines |
| `jq_uses` | `zcutil/lint/no-new-jq.txt` | lines that use jq in shell scripts |
| `banned_str` | `zcutil/lint/banned-str.txt` | calls to strcpy, strcat, sprintf, vsprintf, gets |
| `files_over_1500` | `zcutil/lint/filesize.txt` | files above the 1500-line limit |
| `complexity_debt` | `zcutil/lint/complexity.txt` | sum over functions of complexity above 15 |
| `undocumented_flags` | `zcutil/dev/gen/flags-undocumented.txt` | read-but-undocumented command-line flags |
| `broken_md_links` | `zcutil/lint/md-links.txt` | broken relative links and anchors |
| `doc_path_debt` | `zcutil/lint/doc-paths.txt` | backticked paths that do not exist |
| `secret_log_sites` | `zcutil/lint/secretlog.txt` | secret-bearing names in log calls |
| `unregistered_tests` | `src/test`, `src/gtest` and their `Makefile.*include` | test sources the build never names |
| `unmapped_paths` | `zcutil/bin/zcl-dev check-rules` | tracked files that no impact rule matches |
| `tracked_lessons_open` | `doc/agent/LESSONS.md` | lessons still marked `OPEN` |

The metrics that read a rule baseline read the baseline file, which is a ceiling that the rule itself enforces
per path. A hand edit that raises a baseline therefore trips this floor too. A baseline that has shrunk but not
yet been lowered shows as `better` here until `zcl-lint <rule> --update-baseline` is run.

## Wiring

`zcl-lint wiring` keeps three lists identical: the rule names in `zcutil/lint/rules.def`, the documented list
between `<!-- LINT-RULES-BEGIN -->` and `<!-- LINT-RULES-END -->` in `doc/local-ci.md`, and the rules this
binary runs for `zcl-lint all`. A rule missing from the document, a documented name that is not a rule, a
duplicate, an absent block or a stale binary fails.
