# Artifact Services

[Project](../README.md) · [Documentation index](README.md) · [Walkthrough](walkthrough.md)

`adapters/artifactsvc` connects classification to
[artifact-services](https://github.com/craggy-io/artifact-services). It is a
separate Go module
(`github.com/craggy-io/classification-services/adapters/artifactsvc`), so
the classification core never depends on artifact-services.

## Purpose

Classify immutable artifact snapshots and record the results as queryable,
provenance-linked artifacts.

## Interfaces

```go
c := &artifactsvc.Classifier{
    Engine: engine, Artifacts: store, CAS: content, // required
    Objects: typed,   // optional: publish validated tables
    Lineage: history, // optional: record an activity and table revisions
}
rep, err := c.ClassifyArtifact(ctx, artifactID, classify.Observe(artifactsvc.Observer(ctx)))
pub, err := c.Publish(ctx, rep)
```

- **`ClassifyArtifact`** lists every file of the snapshot and classifies it with its path as the name hint. Artifact readers are streams, so each file is staged (in memory up to 32 MiB, otherwise in `TempDir`, bounded by `MaxFileBytes`). Each CAS reader is closed, and so verified, before classification. Per-file failures go into `FileResult.Error`.
- **`Publish`** stores, in order:
  1. `classification.json`, the full report, as an artifact with metadata `kind = "classification-report"`;
  2. with `Objects`, two validated `ndjson-rows-v1` tables, **types** (`path, digest, type, level, direct, primary`) and **anomalies** (`path, node, code, severity, by, message`), each published through Objects validation;
  3. with `Lineage`, an activity of kind `classification` from the input artifact to everything published (metadata: engine revision, depth, report version), and a revision record for each table.

  The activity ID is deterministic (`classification:<artifact>:<engine revision>:<depth>`), so publishing again is an idempotent retry. Each stage is a separate commitment; on error, the returned `Published` lists what was already stored.
- **`Observer(ctx)`** returns a `classify.Observer` that mirrors classification events as observability spans under `ctx`, in layer `classification`. Per-classifier runs and maintenance are marked Internal, so default reporting shows classify calls and nodes.

## Querying

```go
stream, err := typed.Query(ctx, objects.QueryRequest{
    Language:   objects.SQL,
    Text:       "SELECT path, code FROM a WHERE severity = :sev",
    Parameters: map[string]any{"sev": "critical"},
    Inputs:     []objects.Input{{Alias: "a", Artifact: pub.Anomalies, Revision: string(pub.AnomaliesRevision)}},
})
```

## Development

The repository's `go.work` joins the adapter to the root module and resolves
the root to this checkout, so changes to both are developed and tested
together. The adapter's own `go.mod` pins a published commit of the core,
which is what consumers get. Re-pin it after pushing core changes the adapter
needs:

```sh
cd adapters/artifactsvc
GOWORK=off go get github.com/craggy-io/classification-services@<commit>
GOWORK=off go mod tidy
```

The repository is private, so Go must fetch it directly rather than through
the public module proxy:

```sh
go env -w GOPRIVATE=github.com/craggy-io/classification-services
```
