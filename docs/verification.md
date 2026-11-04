# Verification

[Project](../README.md) · [Documentation index](README.md)

## Commands

From the repository root (Go 1.27 or newer):

```sh
go build ./... && go vet ./... && go test ./...
go test -race ./...
go test ./integration                       # golden corpus
(cd adapters/artifactsvc && go test -race ./...)
go test ./views    -run xxx -fuzz FuzzViews               -fuzztime 60s
go test ./probes   -run xxx -fuzz FuzzProbes              -fuzztime 60s
go test ./classify -run xxx -fuzz FuzzClassifyNeverPanics -fuzztime 60s
go test ./classify -run xxx -fuzz FuzzDefineNeverPanics   -fuzztime 60s
go test ./classify -run xxx -bench .
```

## What the tests cover

| Area | Where |
| --- | --- |
| Views: ZIP layout anomalies, ELF/PE geometry and overlays, Mach-O vs Java class, AXML manifests, APK Signing Block, compound files, pcap, ar; no panics on any truncation | `views/views_test.go` |
| Every probe family, including bombs, traversal, macros, PDF obfuscation, PEM/X.509, JWT | `probes/probes_test.go` |
| Catalogue rules, signature matching and the CyberChef set, module loading and errors, paged budgets, cache immutability and maintenance | `catalog`, `signatures`, `definitions`, `internal/*` |
| Engine: roots, JSON/text, ZIP/JAR/APK with children, Quick depth, rejection, explain, shared DAG nodes, Deep speculation, sources, anomalies (including name hints and cached-root isolation), limits, nesting, bombs, concurrency, cache equality, cancellation, observer events | `classify/classify_test.go` |
| Definitions lifecycle: check, define, persist, remove, failing tests, invalid modules, cache reuse across engines, only-new-classifier reruns, in-flight snapshot stability, refresh across engines, preview, ctx primitives, step limits, WithDefinitions, built-in module tests, batch, directory walk, maintenance | `classify/define_test.go` |
| Built-in catalogue conventions | `classify/catalogue_test.go` |
| CLI commands and exit codes | `cmd/craggy-classify/main_test.go` |
| Golden results for 26 generated files; two engines sharing one workdir concurrently | `integration/corpus_test.go` |
| Every file in `samples/` classifies as its README says, and `widgets.star` passes its tests | `integration/samples_test.go` |
| Adapter: classify an artifact, publish report and typed tables, sql-v1 query, lineage records, idempotent republish, observability bridge | `adapters/artifactsvc/artifactsvc_test.go` |

Test inputs are generated in code (`internal/testkit`). The only binary files
in the repository are the small examples in `samples/`, generated the same way
for people to try. The golden file is regenerated with
`go test ./integration -update`. Review its diff: it is the record of
behaviour changes.

## Last recorded run

On 2026-11-04, with Go 1.27.3 on linux/amd64 and the dependencies pinned in
`go.mod` (Starlark `v0.0.0-20261021141710-4f4267fb140d`, artifact-services
`v0.0.0-20261104150947-32b176f8c2fa`):

- `go build`, `go vet`, `go test` and `go test -race` passed for every package, and for the adapter module.
- Fuzzing ran without failures: views 20 s, probes 30 s, classify 45 s, define 20 s.
- Benchmarks (2 vCPU): warm APK classification 1.9 µs/op (memory cache), cold 12.5 ms/op (fresh workdir: every classifier runs and writes its cache entries), Quick depth 0.21 ms/op.

This run was not on Windows. Windows-specific behaviour (rename over an
existing definition file, path handling in the stat index) follows the same
code paths as artifact-services but has not been exercised here. Run
`go test ./...` on Windows before relying on it.

## Known limits

- The xz and zstd payloads are not derived: the standard library has no decoder, and the core takes no third-party compression dependency. Headers are validated.
- ZIP64 archives are parsed, but the prepended-data estimate is skipped for them.
- The compound-file directory walk follows only the FAT sectors listed in the header (the first 109 DIFAT entries), which covers files up to about 7 MiB with 512-byte sectors and far more with 4 KiB sectors.
- PDF scanning reads at most 32 MiB (and `MaxBytes`) and does not decompress object streams, so names inside compressed streams are not seen.
- Polyglot detection considers validated direct matches only.
- A classifier's cache key covers its own identity and the definitions of the types it produces and requires, not the metadata other classifiers attach to those types. Classifiers should decide from content and from whether required types hold; one that branches on another classifier's facet metadata can serve a stale cached answer after that other classifier changes.
