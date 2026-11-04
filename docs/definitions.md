# Definitions

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

Package `definitions` loads Starlark modules; package `classify` installs them.

## Purpose

Let a new format be added at runtime, by a person or an agent, with real
parsing logic and tests, without changing Go code or restarting.

## A module

One `.star` file declares everything at its top level. Nothing reads content
at load time.

```python
"""Acme widgets: text starting with WIDGET:."""

type("acme", abstract = True)
type("acme.widget", parents = ["acme", "text"], mime = "text/x-acme-widget", ext = ["wdg"])
signature("acme.widget", at(0, b"WIDGET:"), id = "magic")

def _widget(ctx):
    if ctx.prefix(7) != b"WIDGET:":
        return ctx.reject("acme.widget")
    version = ctx.text()[7:].strip()
    if version == "0":
        ctx.anomaly("acme.legacy", severity = "warning", message = "version 0 widgets are unsupported")
    return ctx.match("acme.widget", level = "validated", version = version)

classifier("widget", produces = ["acme.widget"], requires = ["text"], run = _widget)

test("widget", data = "WIDGET: 2\n", expect = ["acme.widget"], primary = "acme.widget")
test("legacy", data = "WIDGET: 0\n", anomalies = ["acme.legacy"])
test("gadget", data = "GADGET: 2\n", absent = ["acme.widget"])
```

The module name is the file name without `.star`: lower-case letters,
digits, `_`, `.` and `-`. A leading docstring becomes `CheckReport.Doc`.

## Declarations

| Call | Meaning |
| --- | --- |
| `type(name, parents=, mime=, ext=, priority=, description=, abstract=)` | Add a type. `parents` defaults to `["bytes"]`. See [catalog](catalog.md) for naming rules. |
| `signature(type, at(...), ..., level="candidate", id=)` | Add a rule; all patterns must match. Compiled into the shared matcher, so no Starlark runs at classify time. |
| `at(offset, pattern)` | A pattern: hex string with optional spaces and `??` wildcards, or `b"..."` bytes. |
| `classifier(id, run=, produces=, requires=["bytes"], derives=False)` | Add a classifier. It runs once `requires` hold and may only assert or reject `produces`. |
| `test(name, data= / hex=, text=, filename=, expect=, absent=, primary=, anomalies=)` | An inline test run (at `Deep`) by `Check`, `Define`, `Preview` and `Engine.Test`. The name must be non-empty, at least one expectation is required, and expected types must exist in the catalogue. |

Helpers: `base64.encode/decode`, `hex.encode/decode`, and Starlark's `json`
module.

## The ctx API

Every read is budgeted and every view memoised by the engine.

| Member | Returns |
| --- | --- |
| `ctx.size`, `ctx.digest`, `ctx.name` | Size, SHA-256, name hint. |
| `ctx.prefix(limit=16MiB)`, `ctx.read(off, n)`, `ctx.text(limit=16MiB)` | Bytes, bytes, string. An omitted limit reads at most 16 MiB; pass `limit` explicitly for more. |
| `ctx.u8/u16le/u16be/u32le/u32be/u64le/u64be(off)` | Unsigned integers; reading past the end is an error. |
| `ctx.find(needle, start=0, limit=size)` | Offset or `-1`. |
| `ctx.json(limit=16MiB)` | Decoded JSON value (errors if not exactly one value). |
| `ctx.facet(type)` / `ctx.has(type)` | Metadata of an established type (or `None`) / whether it holds. |
| `ctx.view.<name>()` | Any [registered view](recognisers.md#views) as a read-only struct. `ctx.view.zip()` also has `has`, `has_prefix`, `read(name, limit=)` and `entries()`. |
| `ctx.match(type, level="recognised", **metadata)` | Assert a type; returns an assertion. |
| `ctx.reject(type, level="validated")` | Refute weaker assertions of a type. |
| `ctx.anomaly(code, severity="info", message=, **metadata)` | Report an anomaly. |
| `ctx.derive(name, data, speculative=False)` | Derive bytes (needs `derives = True`). |
| `ctx.derive_range(name, offset, length, speculative=False)` | Derive a byte range of the input, with no copy. |
| `ctx.derive_entry(zip, entry, speculative=False)` | Derive a ZIP entry. |

`run` may return `None`, an assertion or a list of assertions. Calling
`ctx.match` already records the assertion, so returning it is optional.

## Trust model

Definitions are trusted code. Starlark is used because it is hermetic and
deterministic, which makes results cacheable, not as an isolation boundary.
Scripts have no file system, network or clock. The step limit
(`Limits.ScriptSteps`) and context cancellation stop runaway scripts, and
reads go through the node's read budget.

## Lifecycle

```go
rep, err := e.Check(ctx, "acme", src)          // compile, validate, run tests; installs nothing
prev, err := e.Preview(ctx, "acme", src)       // + diff classifications of known files
rep, err = e.Define(ctx, "acme", src)          // + persist and swap in, only if tests pass
err = e.Remove(ctx, "acme")                    // uninstall (restores a shadowed built-in)
changed, err := e.Refresh(ctx)                 // pick up other processes' changes
results, err := e.Test(ctx)                    // run every installed module's tests
```

- **Validation** (all of `Check`, `Preview` and `Define`): the module compiles; every type it references exists in the resulting catalogue; the catalogue stays acyclic and namespace-consistent; classifier IDs are unique; signatures reference known types.
- **`CheckReport`** lists added, changed and removed types, the module's classifiers, its signature count, and each test's outcome (primary, types, anomalies, failures).
- **`Define`** returns a `*CheckError` carrying the report when any test fails, and installs nothing. Otherwise it writes `workdir/definitions/<name>.star` atomically and swaps the snapshot; calls in flight keep theirs. Re-defining a name replaces it; defining a built-in's name shadows the built-in.
- **`Preview`** classifies each given source, or with none up to `PreviewLimit` (500) files the engine has classified before that are unchanged on disk, under the current and the candidate snapshot. It returns the changes: primary before/after, added and removed types and anomaly codes.

Cached results are keyed by classifier revision, so after `Define` only the
new or changed classifiers run on content already seen.
