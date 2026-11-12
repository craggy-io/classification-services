# Classification Services: coding-agent integration guide

Use this guide when editing this repository or integrating its Go module,
`github.com/craggy-io/classification-services`, into a consumer. Repository
development rules below apply to work here. Consumers should explicitly provide
this guide to their coding agent; installing a dependency does not imply its
AGENTS.md is read. Start with the [walkthrough](docs/walkthrough.md).

## Choose the owning package

| Need | Package and contract |
| --- | --- |
| Classify content, read results, explain, batch, install definitions | [`classify`](docs/classify.md) |
| Write a Starlark definition (types, signatures, classifiers, tests), or a definitions bundle | [`definitions`](docs/definitions.md) |
| Type names, parents, `IsA` | foundation-kit's `taxonomy`; file-format facts and the classifier's rules in [`catalog`](docs/catalog.md) |
| Byte signatures | [`signatures`](docs/signatures.md) |
| A new structural parser or native recogniser | [`views`, `probes`](docs/recognisers.md) |
| Store results in artifact-services | [`adapters/artifactsvc`](docs/artifact-services.md) (separate module) |
| Shell or CI use | [`cmd/craggy-classify`](docs/cli.md) |

Dependencies run one way: `evidence` ← `catalog`, `signatures`, `views`;
`views` ← `probes`; `views`, `catalog`, `signatures` ← `definitions`; all ←
`classify` ← `cmd`. `probes` never imports `classify`, and `definitions` never
imports `probes`. The core module imports only the standard library,
`go.starlark.net` and `github.com/craggy-io/foundation-kit/...` (bundle
loading is the shared path). It keeps its own Starlark evaluation and does
not use script-services. It must never import artifact-services: integration
belongs in `adapters/`. `arch_test.go` enforces these rules.

## Types

The type graph is foundation-kit's `taxonomy` package, shared with other
libraries. Never add a second graph, name check or `IsA` here: change
`taxonomy`, or keep a classifier-only rule in `catalog`. `catalog.TypeInfo`
carries what only this library knows (MIME type, extensions, priority),
keyed by type name. A host that owns a `taxonomy.Live` joins the engine to
it with `classify.WithTaxonomy`.

## Loading definitions

Definitions load only through foundation-kit's `bundle` package; nothing else
reads definition files.

- **Every folder of definitions is a bundle with a `bundle.yaml`** listing each module (`classify.module@1`, contribution `id` = module name) and any CyberChef set (`classify.cyberchef@1`). Never generate a manifest or derive a module name from a file name; an unlisted file isn't loaded.
- **Kinds live next to their types:** `definitions.ModuleKind` and `definitions.Compile`, `signatures.CyberChefKind` and `signatures.CompileCyberChef`. Both kinds are global. Compilers have no side effects and keep no caches: `bundle.Live` reuses compiled values across reloads.
- **Built-ins:** `defs/` is the embedded bundle `classify.builtin`. A new built-in file needs its entry in `defs/bundle.yaml`.
- **Importers:** `classify.WithSources(...bundle.Source)`, added with no override, so a name clash is `bundle.id_conflict`.
- **Runtime installs:** `Define`/`Remove` change the one bundle `classify.installed` under `workdir/definitions/` with `Live.Edit`, which writes its files and `bundle.yaml`; `Check`/`Preview` make the same `Edit` on a temporary copy; a `BundleOverride` lets it replace built-ins. `Refresh` is `Live.Reload`.

## Adding a format

Prefer, in order:

1. **A Starlark module** when the logic fits the `ctx` API. Put built-ins in `defs/classifiers/` with `test()` cases, and list the file in `defs/bundle.yaml`. Runtime users call `Check`, then `Preview`, then `Define`.
2. **A view plus a probe** when parsing needs Go: add `views/<format>.go` (standard library only, bounded reads, `Describe()` for Starlark) and register it in `views.go`; add the probe to `probes/` and to `Builtins()`; bump `probes.Revision`.
3. **Types** go in `defs/types/<namespace>.star` under an existing namespace (a new file also needs its `defs/bundle.yaml` entry). A new namespace needs an abstract namespace type. Every concrete type needs a description.

Then add tests: a view test, a probe test, and a sample in
`integration/corpus_test.go` (regenerate with `go test ./integration -update`
and review the golden diff).

## Using the engine

- `Open` needs a workdir. One workdir may be shared by several processes; `Refresh` (or `WithAutoRefresh`) picks up their definitions. Call `Maintain` periodically; nothing prunes the cache implicitly.
- Read `Result.Primary`, `Is`/`IsAtLeast`, `Anomalies`, `Children`. `Complete` and `Limitations` describe one node: use `AllLimitations()` to see truncation anywhere in the DAG.
- Switch on anomaly `Code`, never `Message`. Severities are `info`, `warning` and `critical`.
- Name hints (`Source.Named`, `File`) only add `extension-mismatch`; they never change types.
- `Define` refuses a module whose tests fail (`*CheckError`). Write tests for every definition, including a negative test (`absent=`).
- Native classifiers: set `Spec.Revision` and change it with behaviour; only assert types in `Produces`; return failures as errors (they become limitations and are not cached).
- Definitions are trusted code; never install modules from untrusted sources.

## Developing and verifying in this repository

- Preserve concurrent edits and reread before patching. Use `rg` for searches.
- Check existing helpers before adding boilerplate (`internal/testkit` builds sample files; extend it rather than adding binary fixtures).
- After changing a data model, trace every reader, encoder (`classify/codec.go`), printer (`cmd`), adapter table and doc. Bump `codecVersion` when the cache encoding changes.
- Fully remove obsolete code rather than adding compatibility shims or aliases.
- Keep docs and the golden file in step with behaviour. The anomaly table in `docs/recognisers.md` must list every code.
- Verify by running the affected tests. Report what ran and any limits; an unrun check is not a pass.

```sh
go build ./... && go vet ./... && go test ./...
go test -race ./...
(cd adapters/artifactsvc && go test ./...)
```

See [verification](docs/verification.md) for fuzzing, benchmarks and the
last recorded run.
