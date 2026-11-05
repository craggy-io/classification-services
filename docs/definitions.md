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

## Bundles

Modules are loaded from bundles only (foundation-kit's
[`bundle`](https://github.com/craggy-io/foundation-kit/blob/main/bundle/README.md)).
A bundle is a folder, or embedded file system, with a `bundle.yaml` at its
root that lists every module. **A folder without a `bundle.yaml` is not
loaded**, and a `.star` file the manifest doesn't list is ignored: nothing is
discovered from the folder layout or file names.

```yaml
apiVersion: craggy.io/bundle/v1
metadata:
  id: acme.definitions
  version: 1.0.0
contributions:
  - id: acme                  # the module name
    kind: classify.module@1
    path: modules/widgets.star
  - id: acme-signatures       # optional: a CyberChef-format JSON signature set
    kind: classify.cyberchef@1
    path: signatures/acme.json
```

- **Module name:** the contribution `id`, not the file name. It must be lower-case letters, digits, `_`, `.` and `-`, starting and ending with a letter or digit.
- **Kinds:** `classify.module@1` (`definitions.ModuleKind`, compiled by `definitions.Compile`) and `classify.cyberchef@1` (`signatures.CyberChefKind`, compiled by `signatures.CompileCyberChef`, which keeps `ParseCyberChef`'s lenient parsing). Both are global: a name is unique across every loaded bundle, and a clash is a `bundle.id_conflict` error.
- **Errors** are bundle diagnostics with the file and line (code `classify.module_invalid` or `classify.cyberchef_invalid`), and every problem in every bundle is reported at once.
- **Built-ins:** `defs/` is the bundle `classify.builtin`, embedded. Add a new built-in module to `defs/bundle.yaml` as well as to its folder.
- **Shipped by an importer:** pass bundles to `classify.Open` with `WithSources(bundle.Dir(path))` or `bundle.Embedded(name, fsys)`. They have no override over the built-ins, so they can't reuse a built-in's name.
- **Installed at run time:** `Define` keeps every runtime module in one bundle, `classify.installed`, at `workdir/definitions/classify.installed/`. It overrides the built-ins, so defining a built-in's name replaces it on purpose.

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
mods := map[string][]byte{"acme": src}        // module name -> Starlark source
rep, err := e.Check(ctx, mods)                 // compile, validate, run tests; installs nothing
prev, err := e.Preview(ctx, mods)              // + diff classifications of known files
rep, err = e.Define(ctx, mods)                 // + install into the workdir bundle, only if tests pass
err = e.Remove(ctx, "acme")                    // uninstall (restores a replaced built-in)
changed, err := e.Refresh(ctx)                 // reload bundles: other processes' changes
results, err := e.Test(ctx)                    // run every installed module's tests
```

`Check`, `Preview` and `Define` treat every module given as one change:
they are validated and tested together, so they may use each other's types,
and `Define` installs all of them in one `Live.Edit` or none. The CLI's
`check`, `preview` and `define` load a bundle and pass all its modules.

- **Validation** (all of `Check`, `Preview` and `Define`): the candidate is built by making the same `Live.Edit` that `Define` would make, on a copy of the installed bundle in a temporary folder, so it loads through `bundle.Live` like any other bundle (so a name clash with a `WithSources` module is rejected); the module compiles; every type it references exists in the resulting catalogue; the catalogue stays acyclic and namespace-consistent; classifier IDs are unique; signatures reference known types.
- **`CheckReport`** covers the whole change: the module names, which of them replace existing modules, the added, changed and removed types, the classifiers, the signature count, and each test's outcome (primary, types, anomalies, failures).
- **`Define`** returns a `*CheckError` carrying the report when any test fails, and installs nothing. Otherwise `bundle.Live.Edit` writes each module as `<name>.star` into the installed bundle, with its entry in that bundle's `bundle.yaml`, and installs it, validating the reload and rolling back on failure; then the snapshot is swapped, and calls in flight keep theirs. Re-defining a name replaces it; defining a built-in's name replaces the built-in. `Edit` reads the installed bundle when it installs, so a module another process installed while the tests ran is kept. There is no lock between processes, so two processes changing the installed bundle at the same instant can still lose one change.
- **`Remove`** drops the module from the installed bundle with `Live.Edit`, which uninstalls the bundle when it was the last one. Modules from `classify.builtin` or a `WithSources` bundle can't be removed.
- **`Preview`** returns the check report in `PreviewReport.Check`, and classifies each given source, or with none up to `PreviewLimit` (500) files the engine has classified before that are unchanged on disk, under the current and the candidate snapshot. It returns the changes: primary before/after, added and removed types and anomaly codes.

Cached results are keyed by classifier revision, so after `Define` only the
new or changed classifiers run on content already seen.
