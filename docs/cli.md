# CLI

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

`craggy-classify` wraps the engine for shells, CI and agents.

```sh
go install github.com/craggy-io/classification-services/cmd/craggy-classify@latest
```

## Commands

| Command | Does |
| --- | --- |
| `craggy-classify [classify] PATH...` | Classify files; directories are walked. `--depth quick\|standard\|deep`, `--tree` (list children), `--explain TYPE`, `--fail-on info\|warning\|critical`. |
| `types [PREFIX]` | List catalogue types: parents, extensions, MIME type. |
| `check FILE.star` | Validate a module and run its tests; exit 1 if any fail. |
| `preview FILE.star [PATH...]` | Show what installing the module would change (default: known files). |
| `define FILE.star` | Test and install a module (`--name` overrides the file name). |
| `remove NAME` | Uninstall a module. |
| `definitions` | List installed modules. |
| `test` | Run every installed module's inline tests. |
| `maintain` | Prune the cache. |

Common flags: `--workdir DIR` (default `$CRAGGY_CLASSIFY_WORKDIR`, else
`<user cache dir>/craggy/classification`) and `--json`. Flags may come before
or after paths.

Exit status: 0 on success, 1 for errors and failed tests, 2 when an anomaly
at or above `--fail-on` was reported. When both an error and such an anomaly
occur, the exit status is 1 regardless of argument order. `-h`/`--help`
prints usage and exits 0. A `--` argument ends flag parsing, so files whose
names look like flags can follow it.

## Output

```
$ craggy-classify --tree slip.zip data.json
slip.zip: archive.zip (validated)
  ! critical zip.path-traversal: entry names are absolute or escape the extraction directory
  └ ../../etc/cron.d/x -> text
  └ readme.txt -> text
data.json: data.json (validated)
  also: text
```

With `--json`, each file is one line:
`{"path": ..., "result": {...}, "explanation": {...}}`; a file that cannot
be classified is `{"path": ..., "error": ...}`. Children are included
only with `--tree`. Other commands print their reports (`CheckReport`,
`PreviewReport`, test results) as JSON objects.

## In CI

```sh
craggy-classify --fail-on critical --json dist/ > classification.jsonl
```

This fails the build if any artifact contains, for example, a ZIP-slip path,
an executable disguised by its extension, or a PDF launch action.
