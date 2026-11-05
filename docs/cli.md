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
| `check BUNDLE` | Validate the bundle's modules and run their tests together; exit 1 if any fail. |
| `preview BUNDLE [PATH...]` | Show what installing the modules would change (default: known files). |
| `define BUNDLE` | Test the modules and, only if every test passes, install them in one step into the workdir's installed bundle. |
| `remove NAME` | Uninstall a module. |

`BUNDLE` is a directory with a written `bundle.yaml` listing its modules as
`classify.module@1` contributions ([bundles](definitions.md#bundles)); a
folder without one is an error, and single `.star` files are not accepted.
Module names are contribution IDs, never file names. Every module in the
bundle is used, as one change with one report. The bundle is loaded with
`bundle.Load`, so every problem in it is reported with its file and line. Other kinds in the bundle (such as `classify.cyberchef@1`)
are compiled but not installed.
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
